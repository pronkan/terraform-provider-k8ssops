package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"

	"github.com/pronkan/terraform-provider-k8ssops/internal/k8sgen"
	"github.com/pronkan/terraform-provider-k8ssops/internal/sopsengine"
)

// plaintextHashSentinel is stored in PlaintextHash by ModifyPlan when the
// source files are absent and string_data has changed. Update detects this
// sentinel and forces re-encryption via the decrypt-merge-encrypt path.
const plaintextHashSentinel = "__k8ssops_hash_needs_update__"

// Ensure secretResource implements resource.Resource.
var _ resource.Resource = &secretResource{}
var _ resource.ResourceWithModifyPlan = &secretResource{}
var _ resource.ResourceWithImportState = &secretResource{}
var _ resource.ResourceWithConfigure = &secretResource{}

type secretResource struct {
	providerData any
}

func NewSecretResource() resource.Resource {
	return &secretResource{}
}

func (r *secretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.providerData = req.ProviderData
}

func (r *secretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Kubernetes secret manifest encrypted with SOPS.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The resource identifier, formatted as `<namespace>/<name>`.",
			},
			"metadata": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"namespace": schema.StringAttribute{
						Optional: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"labels": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"annotations": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
			},
			"type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("Opaque"),
			},
			"aws_kms_arns": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"gcp_kms_resources": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"azure_kv_urls": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"age_keys": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
			},
			"pgp_keys": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
			},
			"file_data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
			},
			"string_data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
			},
			"output_path": schema.StringAttribute{
				Optional: true,
			},
			"secret": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "The final encrypted SOPS YAML manifest.",
			},
			"secret_raw": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Sensitive:   true,
			},
			"plaintext_hash": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan K8sSopsSecretResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	kmsConfig, kmsDiags := resolveKMS(ctx, r.providerData, plan)
	resp.Diagnostics.Append(kmsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	fileBytes, err := readFiles(ctx, plan.FileData)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Files", err.Error())
		return
	}

	stringData := mapTypesToStringMap(plan.StringData)

	namespace := plan.Metadata.Namespace.ValueString()
	if namespace == "" {
		namespace = "default"
	}

	k8sConfig := k8sgen.SecretConfig{
		Name:        plan.Metadata.Name.ValueString(),
		Namespace:   namespace,
		Labels:      mapTypesToStringMap(plan.Metadata.Labels),
		Annotations: mapTypesToStringMap(plan.Metadata.Annotations),
		Type:        plan.Type.ValueString(),
	}

	plaintextYaml, err := k8sgen.BuildManifest(k8sConfig, fileBytes, stringData)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Manifest", err.Error())
		return
	}

	encryptedYaml, err := sopsengine.Encrypt(plaintextYaml, kmsConfig)
	if err != nil {
		resp.Diagnostics.AddError("Encryption Failed", err.Error())
		return
	}

	if !plan.OutputPath.IsNull() && !plan.OutputPath.IsUnknown() {
		outPath := plan.OutputPath.ValueString()
		if pathErr := validatePath(outPath); pathErr != nil {
			resp.Diagnostics.AddError("Invalid Path", pathErr.Error())
			return
		}
		err = os.WriteFile(outPath, encryptedYaml, 0600)
		if err != nil {
			resp.Diagnostics.AddError("Error Writing Output File", err.Error())
			return
		}
	}

	plan.Secret = types.StringValue(string(encryptedYaml))
	plan.PlaintextHash = types.StringValue(sopsengine.CalculateHash(fileBytes, stringData))

	rawMap, getErr := getExtractSecretRaw(plaintextYaml)
	if getErr != nil {
		resp.Diagnostics.AddError("Error Extracting Raw Secret", getErr.Error())
		return
	}
	plan.SecretRaw = rawMap

	plan.Id = types.StringValue(namespace + "/" + plan.Metadata.Name.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state K8sSopsSecretResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Enforce output_path presence: if the file is missing, recreate it immediately
	// from the encrypted value stored in state rather than issuing a warning and
	// requiring a manual apply. The state value is the source of truth; the file
	// on disk is a GitOps artifact that must always be present when output_path is set.
	if !state.OutputPath.IsNull() && !state.OutputPath.IsUnknown() && !state.Secret.IsNull() {
		outPath := state.OutputPath.ValueString()
		if pathErr := validatePath(outPath); pathErr != nil {
			resp.Diagnostics.AddError("Invalid Path", pathErr.Error())
			return
		}
		if _, err := os.Stat(outPath); os.IsNotExist(err) {
			if mkdirErr := os.MkdirAll(filepath.Dir(outPath), 0750); mkdirErr != nil {
				resp.Diagnostics.AddError("Error Creating Output Directory",
					"Could not create parent directories for output_path: "+mkdirErr.Error())
				return
			}
			if writeErr := os.WriteFile(outPath, []byte(state.Secret.ValueString()), 0600); writeErr != nil {
				resp.Diagnostics.AddError("Error Recreating Output File",
					"output_path file was missing and could not be recreated: "+writeErr.Error())
				return
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state K8sSopsSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	kmsConfig, kmsDiags := resolveKMS(ctx, r.providerData, plan)
	resp.Diagnostics.Append(kmsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plaintextYaml []byte
	var stringData = mapTypesToStringMap(plan.StringData)
	var fileBytes map[string][]byte
	var err error

	allFilesExist := checkFilesExist(ctx, plan.FileData)

	if allFilesExist {
		// Fresh Generation
		fileBytes, err = readFiles(ctx, plan.FileData)
		if err != nil {
			resp.Diagnostics.AddError("Error Reading Files", err.Error())
			return
		}

		updateNamespace := plan.Metadata.Namespace.ValueString()
		if updateNamespace == "" {
			updateNamespace = "default"
		}

		k8sConfig := k8sgen.SecretConfig{
			Name:        plan.Metadata.Name.ValueString(),
			Namespace:   updateNamespace,
			Labels:      mapTypesToStringMap(plan.Metadata.Labels),
			Annotations: mapTypesToStringMap(plan.Metadata.Annotations),
			Type:        plan.Type.ValueString(),
		}

		plaintextYaml, err = k8sgen.BuildManifest(k8sConfig, fileBytes, stringData)
		if err != nil {
			resp.Diagnostics.AddError("Error Building Manifest", err.Error())
			return
		}
	} else {
		// Decrypt, Merge, Encrypt Loop
		decryptedYaml, decErr := sopsengine.DecryptState([]byte(state.Secret.ValueString()), kmsConfig)
		if decErr != nil {
			resp.Diagnostics.AddError("Error Decrypting Previous State", decErr.Error())
			return
		}

		plaintextYaml, err = k8sgen.MergeStringData(decryptedYaml, stringData)
		if err != nil {
			resp.Diagnostics.AddError("Error Merging New Data", err.Error())
			return
		}
	}

	var encryptedYaml []byte

	// Calculate current hash if possible
	var currentHash string
	if allFilesExist {
		currentHash = sopsengine.CalculateHash(fileBytes, stringData)
	}

	if allFilesExist && !state.PlaintextHash.IsNull() && state.PlaintextHash.ValueString() == currentHash && !state.Secret.IsNull() {
		// Optimization & consistency check: if the content didn't change, reuse the existing ciphertext.
		// This prevents "inconsistent result after apply" errors due to SOPS's random nonces
		// when only metadata like output_path changes.
		encryptedYaml = []byte(state.Secret.ValueString())
	} else if !allFilesExist && !state.PlaintextHash.IsNull() && state.PlaintextHash.ValueString() == plaintextHashSentinel {
		// If string_data triggered the update during fallback, we must re-encrypt.
		encryptedYaml, err = sopsengine.Encrypt(plaintextYaml, kmsConfig)
		if err != nil {
			resp.Diagnostics.AddError("Encryption Failed", err.Error())
			return
		}
	} else if !allFilesExist && mapsEqual(plan.StringData, state.StringData) {
		// If string_data didn't change and we're in fallback (e.g. testing file_data change to missing file),
		// we MUST NOT re-encrypt because the plaintext content didn't actually change.
		encryptedYaml = []byte(state.Secret.ValueString())
	} else {
		encryptedYaml, err = sopsengine.Encrypt(plaintextYaml, kmsConfig)
		if err != nil {
			resp.Diagnostics.AddError("Encryption Failed", err.Error())
			return
		}
	}

	if !plan.OutputPath.IsNull() && !plan.OutputPath.IsUnknown() {
		outPath := plan.OutputPath.ValueString()
		if pathErr := validatePath(outPath); pathErr != nil {
			resp.Diagnostics.AddError("Invalid Path", pathErr.Error())
			return
		}
		err = os.WriteFile(outPath, encryptedYaml, 0600)
		if err != nil {
			resp.Diagnostics.AddError("Error Writing Output File", err.Error())
			return
		}
	}

	plan.Secret = types.StringValue(string(encryptedYaml))

	if allFilesExist {
		plan.PlaintextHash = types.StringValue(currentHash)
	} else {
		// In fallback, we set PlaintextHash to force update if string_data changes.
		// After a successful update during fallback, what should it be?
		// We could use the old state hash if string_data didn't trigger an update (ModifyPlan prevents this),
		// but since we updated, the hash is technically different.
		// Best approach is a fallback hash marker that forces next evaluation to check string_data again.
		// Using the state hash effectively tells ModifyPlan next time "nothing changed" unless string_data changes.
		plan.PlaintextHash = state.PlaintextHash
	}

	rawMap, getErr := getExtractSecretRaw(plaintextYaml)
	if getErr != nil {
		resp.Diagnostics.AddError("Error Extracting Raw Secret", getErr.Error())
		return
	}
	plan.SecretRaw = rawMap

	namespace := plan.Metadata.Namespace.ValueString()
	if namespace == "" {
		namespace = "default"
	}
	plan.Id = types.StringValue(namespace + "/" + plan.Metadata.Name.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state K8sSopsSecretResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !state.OutputPath.IsNull() && !state.OutputPath.IsUnknown() {
		err := os.Remove(state.OutputPath.ValueString())
		if err != nil && !os.IsNotExist(err) {
			resp.Diagnostics.AddError(
				"Error Deleting Output File",
				"Could not delete secret file: "+err.Error(),
			)
		}
	}
}

func (r *secretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		// Creation or Destruction. Nothing to suppress.
		return
	}

	var plan, state K8sSopsSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	allFilesExist := checkFilesExist(ctx, plan.FileData)

	if allFilesExist {
		// Scenario 1: Source files exist locally. Calculate drift via hash.
		fileBytes, err := readFiles(ctx, plan.FileData)
		if err != nil {
			resp.Diagnostics.AddError("Error Reading Files", err.Error())
			return
		}
		stringData := mapTypesToStringMap(plan.StringData)

		currentHash := sopsengine.CalculateHash(fileBytes, stringData)

		if !state.PlaintextHash.IsNull() && currentHash == state.PlaintextHash.ValueString() {
			// No config drift. Suppress.
			plan.Secret = state.Secret
			plan.SecretRaw = state.SecretRaw
			plan.PlaintextHash = state.PlaintextHash
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
			return
		}

		// Drift detected.
		plan.PlaintextHash = types.StringValue(currentHash)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	// Scenario 2/3: Fallback state. Some files are missing.
	if state.Secret.IsNull() || state.Secret.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing Source Files",
			"Source files are missing and no previous state exists to fall back on.",
		)
		return
	}

	if !mapsEqual(plan.StringData, state.StringData) {
		// string_data changed. We must update.
		// Set the sentinel hash to trigger the Update method which will handle the merge.
		plan.PlaintextHash = types.StringValue(plaintextHashSentinel)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	// Steady state GitOps. Config hasn't changed. Suppress.
	plan.PlaintextHash = state.PlaintextHash
	plan.Secret = state.Secret
	plan.SecretRaw = state.SecretRaw
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// ImportState enables `terraform import` for the k8ssops_secret resource.
//
// Supported import ID formats:
//
//	namespace/name                          — minimal import; no file is read
//	namespace/name:output_path              — reads the encrypted file at output_path,
//	                                          stores raw ciphertext in state, and parses
//	                                          metadata from the YAML without decrypting
//
// When output_path is provided the function reads the encrypted YAML as plain text
// (no KMS credentials are required at import time) and parses the unencrypted YAML
// fields (apiVersion, kind, metadata) to extract name and namespace. The full
// decryption of secret values will occur on the next `terraform plan` / `terraform apply`.
func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := req.ID

	// Split on ":" to detect the optional :output_path suffix.
	idPart := importID
	outputPath := ""
	if colonIdx := strings.Index(importID, ":"); colonIdx >= 0 {
		idPart = importID[:colonIdx]
		outputPath = importID[colonIdx+1:]
	}

	// Parse namespace/name from the id part.
	name := idPart
	namespace := "default"
	if parts := strings.SplitN(idPart, "/", 2); len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	} else {
		resp.Diagnostics.AddWarning(
			"Import ID Missing Namespace",
			fmt.Sprintf("Import ID %q does not contain a namespace component (expected namespace/name). Defaulting to namespace \"default\".", importID),
		)
	}

	resourceID := namespace + "/" + name

	if outputPath == "" {
		// Minimal import — set id and metadata only. Remaining computed attributes
		// will be populated on the next plan/apply cycle.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), resourceID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("metadata").AtName("name"), name)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("metadata").AtName("namespace"), namespace)...)
		return
	}

	// output_path provided: read the encrypted YAML from disk without decrypting it.
	if pathErr := validatePath(outputPath); pathErr != nil {
		resp.Diagnostics.AddError("Invalid output_path", fmt.Sprintf("The output_path %q in the import ID is invalid: %s", outputPath, pathErr.Error()))
		return
	}

	rawYAML, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		resp.Diagnostics.AddError(
			"Cannot Read output_path",
			fmt.Sprintf("Failed to read the encrypted file at %q: %s", outputPath, readErr.Error()),
		)
		return
	}

	// Parse the YAML without decryption to extract metadata.name and metadata.namespace.
	// SOPS-encrypted YAML keeps apiVersion, kind, and metadata in plaintext; only the
	// values under data/stringData are encrypted. A generic map unmarshal is sufficient.
	var manifest map[string]any
	if parseErr := yaml.Unmarshal(rawYAML, &manifest); parseErr == nil {
		if meta, ok := manifest["metadata"].(map[string]any); ok {
			if n, ok := meta["name"].(string); ok && n != "" {
				name = n
			}
			if ns, ok := meta["namespace"].(string); ok && ns != "" {
				namespace = ns
			}
		}
	}
	// Parsing errors are non-fatal: the id/metadata values from the import ID are used
	// as the fallback, and the operator will reconcile on the next plan.

	resourceID = namespace + "/" + name

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), resourceID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("metadata").AtName("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("metadata").AtName("namespace"), namespace)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("output_path"), outputPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("secret"), string(rawYAML))...)

	resp.Diagnostics.AddWarning(
		"Import Complete — Plan Required",
		"Import complete. Run `terraform plan` to reconcile remaining state attributes (secret_raw, plaintext_hash, file_data, string_data). These will be populated on the next apply cycle.",
	)
}
