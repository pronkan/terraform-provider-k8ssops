package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure K8ssopsProvider implements provider.Provider.
var _ provider.Provider = &K8ssopsProvider{}

// K8ssopsProvider defines the provider implementation.
type K8ssopsProvider struct {
	// version is set to the provider version on creation.
	version string
}

// ---------------------------------------------------------------------------
// Per-provider nested config structs
// ---------------------------------------------------------------------------

// AWSProviderConfig groups all AWS KMS and credential settings under a single
// "aws = {}" block. Credentials resolve in this order:
//  1. HCL attribute (highest precedence)
//  2. Standard AWS SDK environment variable
//  3. AWS SDK default chain (shared config, instance profile, …)
type AWSProviderConfig struct {
	// KMSArns is the default list of AWS KMS key ARNs used for encryption when
	// the resource does not specify its own aws_kms_arns. All ARNs are placed
	// in a single SOPS KeyGroup so that any cluster holding one of the keys can
	// decrypt the secret independently — the intended model for multi-cluster
	// FluxCD GitOps repositories.
	KMSArns types.List `tfsdk:"kms_arns"`

	// Profile is the AWS named profile from ~/.aws/config to use for KMS calls.
	// Passed as SharedConfigProfile to the AWS SDK; falls back to AWS_PROFILE.
	Profile types.String `tfsdk:"profile"`

	// Region overrides the AWS region for KMS API calls. Usually unnecessary
	// because SOPS derives the region from the KMS key ARN; set this when
	// working with short-form key aliases. Falls back to AWS_DEFAULT_REGION /
	// AWS_REGION environment variables.
	Region types.String `tfsdk:"region"`

	// AssumeRole is an IAM role ARN to assume before calling KMS, enabling
	// cross-account encryption without storing long-lived credentials.
	// Mapped to the SOPS role_arn field on each KMS master key.
	AssumeRole types.String `tfsdk:"assume_role"`

	// AccessKeyID, SecretAccessKey, and SessionToken are explicit AWS credentials.
	// Prefer profile or AssumeRole-based auth in production; these are provided
	// for CI/CD pipelines that cannot use a named profile or instance role.
	// Fall back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN.
	AccessKeyID     types.String `tfsdk:"access_key_id"`
	SecretAccessKey types.String `tfsdk:"secret_access_key"`
	SessionToken    types.String `tfsdk:"session_token"`
}

// GCPProviderConfig groups GCP Cloud KMS settings.
// NOTE: GCP KMS support is not yet implemented in this provider version.
// This block is accepted by the schema and forwarded to the SOPS engine but
// encryption/decryption via GCP KMS will return an unsupported-operation error.
// Implementation is tracked as a future milestone.
type GCPProviderConfig struct {
	// KMSResources is the default list of GCP KMS resource IDs in the format:
	// projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>
	// PLACEHOLDER — not yet implemented.
	KMSResources types.List `tfsdk:"kms_resources"`
}

// AzureProviderConfig groups Azure Key Vault settings.
// NOTE: Azure Key Vault support is not yet implemented in this provider version.
// This block is accepted by the schema but encryption/decryption via Azure KV
// will return an unsupported-operation error.
// Implementation is tracked as a future milestone.
type AzureProviderConfig struct {
	// KVUrls is the default list of Azure Key Vault key URLs in the format:
	// https://<vault>.vault.azure.net/keys/<key>/<version>
	// PLACEHOLDER — not yet implemented.
	KVUrls types.List `tfsdk:"kv_urls"`
}

// PGPProviderConfig groups PGP key settings for SOPS encryption.
type PGPProviderConfig struct {
	// Keys is the default list of PGP key fingerprints (40-char hex) used as
	// fallback SOPS recipients when no cloud KMS is available.
	Keys types.List `tfsdk:"keys"`
}

// AgeProviderConfig groups age key settings. In this provider the "age keys"
// field doubles as the offline/test path: populate with a 32-byte hex-encoded
// symmetric key to use AES-256-GCM encryption without any external KMS call.
// This is the path exercised by unit tests and local development.
type AgeProviderConfig struct {
	// Keys is the default list of age public keys (or 32-byte hex-encoded
	// symmetric keys for the AES-256-GCM offline path).
	Keys types.List `tfsdk:"keys"`
}

// VaultProviderConfig groups HashiCorp Vault Transit KMS settings.
// NOTE: Vault Transit support is not yet implemented in this provider version.
// This block is accepted by the schema but encryption/decryption via Vault
// will return an unsupported-operation error.
// Implementation is tracked as a future milestone.
type VaultProviderConfig struct {
	// Address is the Vault server address, e.g. https://vault.example.com:8200.
	// PLACEHOLDER — not yet implemented.
	Address types.String `tfsdk:"address"`

	// Token is the Vault authentication token. Prefer AppRole or Kubernetes
	// auth methods in production.
	// PLACEHOLDER — not yet implemented.
	Token types.String `tfsdk:"token"`
}

// K8ssopsProviderModel is the top-level provider configuration model.
// Each cloud provider and key type is grouped under its own named block,
// mirroring the SOPS configuration structure and allowing the block to be
// sourced from a variable or local:
//
//	provider "k8ssops" {
//	  aws = var.aws_config   // or local.aws_config
//	  age = { keys = [local.dev_key] }
//	}
type K8ssopsProviderModel struct {
	AWS   *AWSProviderConfig   `tfsdk:"aws"`
	GCP   *GCPProviderConfig   `tfsdk:"gcp"`
	Azure *AzureProviderConfig `tfsdk:"azure"`
	PGP   *PGPProviderConfig   `tfsdk:"pgp"`
	Age   *AgeProviderConfig   `tfsdk:"age"`
	Vault *VaultProviderConfig `tfsdk:"vault"`
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

func (p *K8ssopsProvider) Metadata(ctx context.Context,
	req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "k8ssops"
	resp.Version = p.version
}

func (p *K8ssopsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The **k8ssops** provider generates SOPS-encrypted Kubernetes Secret manifests " +
			"for GitOps workflows. Each provider block corresponds to one set of KMS credentials. " +
			"Use provider aliases to encrypt a secret with keys from multiple accounts so that " +
			"every FluxCD-bootstrapped cluster can decrypt it independently with its own credentials.\n\n" +
			"Credential blocks (`aws`, `gcp`, `azure`, `pgp`, `age`, `vault`) can be inlined or " +
			"supplied via a variable/local object for reuse across modules.",
		Attributes: map[string]schema.Attribute{

			// ----------------------------------------------------------------
			// AWS KMS
			// ----------------------------------------------------------------
			"aws": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "AWS KMS configuration. Credentials resolve as: HCL attribute → environment variable → AWS SDK default chain.",
				Attributes: map[string]schema.Attribute{
					"kms_arns": schema.ListAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Default AWS KMS key ARNs. All ARNs are placed in one SOPS KeyGroup — any key can decrypt. Add one ARN per cluster account for multi-cluster GitOps.",
					},
					"profile": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "AWS named profile (`~/.aws/config`). Passed as `SharedConfigProfile`; takes precedence over `AWS_PROFILE`.",
					},
					"region": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "AWS region for KMS calls. Usually derived from the ARN; required for short-form key aliases. Falls back to `AWS_DEFAULT_REGION` / `AWS_REGION`.",
					},
					"assume_role": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "IAM role ARN to assume before calling KMS. Enables cross-account encryption without long-lived credentials.",
					},
					"access_key_id": schema.StringAttribute{
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "AWS access key ID. Falls back to `AWS_ACCESS_KEY_ID`. Prefer profile or `assume_role` in production.",
					},
					"secret_access_key": schema.StringAttribute{
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "AWS secret access key. Falls back to `AWS_SECRET_ACCESS_KEY`.",
					},
					"session_token": schema.StringAttribute{
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "AWS session token for temporary credentials. Falls back to `AWS_SESSION_TOKEN`.",
					},
				},
			},

			// ----------------------------------------------------------------
			// GCP Cloud KMS — PLACEHOLDER (not yet implemented)
			// ----------------------------------------------------------------
			"gcp": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "GCP Cloud KMS configuration.\n\n" +
					"> **Note:** GCP KMS support is not yet implemented. This block is reserved for " +
					"a future release. Configuring it will have no effect in the current version.",
				Attributes: map[string]schema.Attribute{
					"kms_resources": schema.ListAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "GCP KMS resource IDs (`projects/.../keyRings/.../cryptoKeys/...`). PLACEHOLDER — not yet implemented.",
					},
				},
			},

			// ----------------------------------------------------------------
			// Azure Key Vault — PLACEHOLDER (not yet implemented)
			// ----------------------------------------------------------------
			"azure": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Azure Key Vault configuration.\n\n" +
					"> **Note:** Azure Key Vault support is not yet implemented. This block is reserved " +
					"for a future release. Configuring it will have no effect in the current version.",
				Attributes: map[string]schema.Attribute{
					"kv_urls": schema.ListAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Azure Key Vault key URLs (`https://<vault>.vault.azure.net/keys/<key>/<version>`). PLACEHOLDER — not yet implemented.",
					},
				},
			},

			// ----------------------------------------------------------------
			// PGP keys
			// ----------------------------------------------------------------
			"pgp": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "PGP key configuration for SOPS encryption. Useful as a fallback when no cloud KMS is available.",
				Attributes: map[string]schema.Attribute{
					"keys": schema.ListAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "PGP key fingerprints (40-character hex) added as SOPS recipients.",
					},
				},
			},

			// ----------------------------------------------------------------
			// Age keys
			// ----------------------------------------------------------------
			"age": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Age key configuration.\n\n" +
					"In the current implementation the `keys` field also serves as the **offline/test path**: " +
					"populate it with a 32-byte hex-encoded symmetric key to use AES-256-GCM encryption " +
					"without any external KMS call. This is the mode used by unit tests and local development.",
				Attributes: map[string]schema.Attribute{
					"keys": schema.ListAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "Age public keys or 32-byte hex-encoded symmetric keys for offline AES-256-GCM encryption.",
					},
				},
			},

			// ----------------------------------------------------------------
			// HashiCorp Vault Transit — PLACEHOLDER (not yet implemented)
			// ----------------------------------------------------------------
			"vault": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "HashiCorp Vault Transit KMS configuration.\n\n" +
					"> **Note:** Vault Transit support is not yet implemented. This block is reserved " +
					"for a future release. Configuring it will have no effect in the current version.",
				Attributes: map[string]schema.Attribute{
					"address": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Vault server address (`https://vault.example.com:8200`). PLACEHOLDER — not yet implemented.",
					},
					"token": schema.StringAttribute{
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "Vault authentication token. PLACEHOLDER — not yet implemented.",
					},
				},
			},
		},
	}
}

func (p *K8ssopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data K8ssopsProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.AWS != nil {
		// Merge environment variable fallbacks for profile and region only.
		// Credentials (AccessKeyID, SecretAccessKey, SessionToken) are injected
		// per-call via sopsengine.withAWSEnv so they never mutate the process
		// environment globally.
		data.AWS.Profile = coalesceStringEnv(data.AWS.Profile, "AWS_PROFILE")
		data.AWS.Region = coalesceStringEnv(data.AWS.Region, "AWS_DEFAULT_REGION", "AWS_REGION")
	}

	// Warn when placeholder (not-yet-implemented) provider blocks are configured.
	// Without these warnings operators receive an opaque "no supported KMS key configured"
	// error at resource creation time with no indication that the configured block is a no-op.
	if data.GCP != nil {
		resp.Diagnostics.AddWarning(
			"GCP KMS Not Yet Implemented",
			"The gcp block is configured but GCP Cloud KMS support is not yet implemented. "+
				"Secrets using GCP KMS keys will fail at encryption time. "+
				"Remove the gcp block or wait for a future provider release that adds GCP support.",
		)
	}
	if data.Azure != nil {
		resp.Diagnostics.AddWarning(
			"Azure Key Vault Not Yet Implemented",
			"The azure block is configured but Azure Key Vault support is not yet implemented. "+
				"Secrets using Azure KV keys will fail at encryption time. "+
				"Remove the azure block or wait for a future provider release that adds Azure support.",
		)
	}
	if data.Vault != nil {
		resp.Diagnostics.AddWarning(
			"HashiCorp Vault Transit Not Yet Implemented",
			"The vault block is configured but HashiCorp Vault Transit KMS support is not yet implemented. "+
				"Secrets using Vault Transit keys will fail at encryption time. "+
				"Remove the vault block or wait for a future provider release that adds Vault support.",
		)
	}

	// Both resources and data sources receive the same provider model so they can
	// resolve KMS credentials (profile, region, assume_role, etc.) identically.
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *K8ssopsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSecretResource,
	}
}

func (p *K8ssopsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
		NewDecryptDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &K8ssopsProvider{
			version: version,
		}
	}
}
