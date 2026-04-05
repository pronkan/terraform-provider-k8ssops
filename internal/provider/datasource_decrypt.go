package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pronkan/terraform-provider-k8ssops/internal/k8sgen"
	"github.com/pronkan/terraform-provider-k8ssops/internal/sopsengine"
)

// Ensure decryptDataSource implements the required interfaces.
var _ datasource.DataSource = &decryptDataSource{}
var _ datasource.DataSourceWithConfigure = &decryptDataSource{}

// decryptDataSourceModel is the Terraform state model for the k8ssops_decrypt data source.
type decryptDataSourceModel struct {
	ID              types.String `tfsdk:"id"`
	EncryptedYAML   types.String `tfsdk:"encrypted_yaml"`
	Path            types.String `tfsdk:"path"`
	Key             types.String `tfsdk:"key"`
	Plaintext       types.String `tfsdk:"plaintext"`
	AwsKmsArns      types.List   `tfsdk:"aws_kms_arns"`
	GcpKmsResources types.List   `tfsdk:"gcp_kms_resources"`
	AzureKvUrls     types.List   `tfsdk:"azure_kv_urls"`
	AgeKeys         types.List   `tfsdk:"age_keys"`
	PgpKeys         types.List   `tfsdk:"pgp_keys"`
}

type decryptDataSource struct {
	providerData any
}

// NewDecryptDataSource returns a new instance of the k8ssops_decrypt data source.
func NewDecryptDataSource() datasource.DataSource {
	return &decryptDataSource{}
}

// Configure stores the provider-level data for later use in Read.
func (d *decryptDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.providerData = req.ProviderData
}

// Metadata sets the type name for this data source.
func (d *decryptDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decrypt"
}

// Schema defines the HCL schema for the k8ssops_decrypt data source.
func (d *decryptDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decrypts a single value from a SOPS-encrypted Kubernetes Secret manifest by key name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Deterministic identifier derived from the input ciphertext and key.",
			},
			"encrypted_yaml": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Inline SOPS-encrypted Kubernetes Secret YAML. Mutually exclusive with `path`.",
			},
			"path": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to a SOPS-encrypted Kubernetes Secret YAML file on disk. Mutually exclusive with `encrypted_yaml`.",
			},
			"key": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The key name to look up in the decrypted `data` or `stringData` fields of the Secret.",
			},
			"plaintext": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "The decrypted plaintext value for the requested `key`.",
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
		},
	}
}

// Read decrypts the manifest, extracts the merged key/value map, and writes the
// value for the requested key into the computed `plaintext` field.
func (d *decryptDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state decryptDataSourceModel
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

	allRaw, err := k8sgen.ExtractSecretRaw(plaintext)
	if err != nil {
		resp.Diagnostics.AddError("Extraction Failed", "failed to extract key/value pairs from the decrypted manifest; ensure the source is a valid Kubernetes Secret")
		return
	}

	key := state.Key.ValueString()
	value, found := allRaw[key]
	if !found {
		resp.Diagnostics.AddError(
			"Key Not Found",
			fmt.Sprintf("key %q was not found in the decrypted Secret's data or stringData fields", key),
		)
		return
	}

	// Use a hash of the decrypted manifest bytes and key name as the data source ID
	// to ensure uniqueness without exposing sensitive material.
	state.ID = types.StringValue(sopsengine.CalculateHash(
		map[string][]byte{"plaintext": plaintext},
		map[string]string{"key": key},
	))
	state.Plaintext = types.StringValue(value)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
