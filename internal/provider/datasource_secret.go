package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	corev1 "k8s.io/api/core/v1"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/pronkan/terraform-provider-k8ssops/internal/k8sgen"
)

// Ensure secretDataSource implements the required interfaces.
var _ datasource.DataSource = &secretDataSource{}
var _ datasource.DataSourceWithConfigure = &secretDataSource{}

// secretDataSourceModel is the Terraform state model for the k8ssops_secret data source.
type secretDataSourceModel struct {
	ID              types.String `tfsdk:"id"`
	EncryptedYAML   types.String `tfsdk:"encrypted_yaml"`
	Path            types.String `tfsdk:"path"`
	AwsKmsArns      types.List   `tfsdk:"aws_kms_arns"`
	GcpKmsResources types.List   `tfsdk:"gcp_kms_resources"`
	AzureKvUrls     types.List   `tfsdk:"azure_kv_urls"`
	AgeKeys         types.List   `tfsdk:"age_keys"`
	PgpKeys         types.List   `tfsdk:"pgp_keys"`
	Name            types.String `tfsdk:"name"`
	Namespace       types.String `tfsdk:"namespace"`
	Data            types.Map    `tfsdk:"data"`
	StringData      types.Map    `tfsdk:"string_data"`
	AllData         types.Map    `tfsdk:"all_data"`
}

type secretDataSource struct {
	providerData any
}

// NewSecretDataSource returns a new instance of the k8ssops_secret data source.
func NewSecretDataSource() datasource.DataSource {
	return &secretDataSource{}
}

// Configure stores the provider-level data for later use in Read.
func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.providerData = req.ProviderData
}

// Metadata sets the type name for this data source.
func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

// Schema defines the HCL schema for the k8ssops_secret data source.
func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decrypts a SOPS-encrypted Kubernetes Secret manifest and exposes its data fields as Terraform outputs.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier formatted as `<namespace>/<name>` derived from the manifest metadata.",
			},
			"encrypted_yaml": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Inline SOPS-encrypted Kubernetes Secret YAML. Mutually exclusive with `path`.",
			},
			"path": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to a SOPS-encrypted Kubernetes Secret YAML file on disk. Mutually exclusive with `encrypted_yaml`.",
			},
			"aws_kms_arns": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "AWS KMS key ARNs used for decryption. Falls back to provider-level `aws.kms_arns` when omitted.",
			},
			"gcp_kms_resources": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "GCP Cloud KMS resource IDs. Falls back to provider-level `gcp.kms_resources` when omitted.",
			},
			"azure_kv_urls": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Azure Key Vault key URLs. Falls back to provider-level `azure.kv_urls` when omitted.",
			},
			"age_keys": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Age keys or 32-byte hex-encoded symmetric keys for offline decryption. Falls back to provider-level `age.keys` when omitted.",
			},
			"pgp_keys": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "PGP key fingerprints. Falls back to provider-level `pgp.keys` when omitted.",
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Kubernetes Secret name from the manifest metadata.",
			},
			"namespace": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Kubernetes Secret namespace from the manifest metadata.",
			},
			"data": schema.MapAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Base64-decoded values from the `data` field of the decrypted Secret manifest.",
			},
			"string_data": schema.MapAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Values from the `stringData` field of the decrypted Secret manifest.",
			},
			"all_data": schema.MapAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Merged union of `data` and `string_data`. When a key appears in both, `string_data` wins.",
			},
		},
	}
}

// Read decrypts the manifest, parses the Kubernetes Secret, and writes all
// computed fields into state.
func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state secretDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plaintext := loadAndDecrypt(ctx, d.providerData,
		state.Path, state.EncryptedYAML,
		state.AwsKmsArns, state.GcpKmsResources, state.AzureKvUrls, state.AgeKeys, state.PgpKeys,
		&resp.Diagnostics,
	)
	if plaintext == nil {
		return
	}

	// Parse the full Kubernetes Secret to extract separate data fields.
	var secret corev1.Secret
	if err := k8syaml.Unmarshal(plaintext, &secret); err != nil {
		resp.Diagnostics.AddError("Parse Failed", "failed to parse the decrypted manifest; ensure the source is a valid Kubernetes Secret YAML")
		return
	}

	// Build the `data` map: corev1.Secret.Data already holds decoded []byte values.
	dataMap, err := buildStringMapFromBytes(secret.Data)
	if err != nil {
		resp.Diagnostics.AddError("State Error", "failed to build the data map from the decrypted Secret")
		return
	}

	// Build the `string_data` map directly from the string values.
	stringDataMap, err := buildStringMapFromStrings(secret.StringData)
	if err != nil {
		resp.Diagnostics.AddError("State Error", "failed to build the string_data map from the decrypted Secret")
		return
	}

	// Build `all_data` via k8sgen.ExtractSecretRaw which merges both fields
	// with string_data winning on collision.
	allRaw, err := k8sgen.ExtractSecretRaw(plaintext)
	if err != nil {
		resp.Diagnostics.AddError("Extraction Failed", "failed to extract key/value pairs from the decrypted manifest; ensure the source is a valid Kubernetes Secret")
		return
	}
	allDataMap, err := buildStringMapFromStrings(allRaw)
	if err != nil {
		resp.Diagnostics.AddError("State Error", "failed to build the all_data map from the decrypted Secret")
		return
	}

	namespace := secret.Namespace
	if namespace == "" {
		namespace = "default"
	}

	state.Name = types.StringValue(secret.Name)
	state.Namespace = types.StringValue(namespace)
	state.ID = types.StringValue(namespace + "/" + secret.Name)
	state.Data = dataMap
	state.StringData = stringDataMap
	state.AllData = allDataMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// buildStringMapFromBytes converts map[string][]byte into a types.Map of string
// values by re-encoding each byte slice as a UTF-8 string (direct cast).
// The corev1.Secret unmarshaler already base64-decodes the `data` field, so the
// []byte values contain the raw payload — we cast to string directly.
func buildStringMapFromBytes(src map[string][]byte) (types.Map, error) {
	m := make(map[string]attr.Value, len(src))
	for k, v := range src {
		m[k] = types.StringValue(base64.StdEncoding.EncodeToString(v))
	}
	result, diags := types.MapValue(types.StringType, m)
	if diags.HasError() {
		return types.MapNull(types.StringType), fmt.Errorf("failed to construct data map")
	}
	return result, nil
}

// buildStringMapFromStrings converts map[string]string into a types.Map.
func buildStringMapFromStrings(src map[string]string) (types.Map, error) {
	m := make(map[string]attr.Value, len(src))
	for k, v := range src {
		m[k] = types.StringValue(v)
	}
	result, diags := types.MapValue(types.StringType, m)
	if diags.HasError() {
		return types.MapNull(types.StringType), fmt.Errorf("failed to construct string map")
	}
	return result, nil
}

// errMutualExclusion is returned by resolveCiphertext when both or neither of
// path and encrypted_yaml are set. Callers use isPathMutualExclusionError to
// distinguish this configuration error from an I/O error.
var errMutualExclusion = errors.New("exactly one of path or encrypted_yaml must be set")

// isPathMutualExclusionError reports whether err originated from the mutual-exclusion
// check inside resolveCiphertext so callers can emit the right diagnostic summary.
func isPathMutualExclusionError(err error) bool {
	return errors.Is(err, errMutualExclusion)
}

// resolveCiphertext returns the raw ciphertext bytes when exactly one of path
// or encryptedYAML is set.
//   - Both set or neither set: returns errMutualExclusion (use isPathMutualExclusionError).
//   - File-read failure: returns a wrapped I/O error.
func resolveCiphertext(path, encryptedYAML types.String) ([]byte, error) {
	pathSet := !path.IsNull() && !path.IsUnknown() && path.ValueString() != ""
	yamlSet := !encryptedYAML.IsNull() && !encryptedYAML.IsUnknown() && encryptedYAML.ValueString() != ""

	switch {
	case pathSet && yamlSet:
		return nil, errMutualExclusion
	case !pathSet && !yamlSet:
		return nil, errMutualExclusion
	case pathSet:
		if pathErr := validatePath(path.ValueString()); pathErr != nil {
			return nil, fmt.Errorf("invalid path %q: %w", path.ValueString(), pathErr)
		}
		data, err := os.ReadFile(path.ValueString())
		if err != nil {
			return nil, fmt.Errorf("reading encrypted file %q: %w", path.ValueString(), err)
		}
		return data, nil
	default:
		return []byte(encryptedYAML.ValueString()), nil
	}
}
