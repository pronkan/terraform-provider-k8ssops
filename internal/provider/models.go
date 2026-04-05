package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// K8sSopsSecretResourceModel describes the resource data model.
type K8sSopsSecretResourceModel struct {
	Id              types.String  `tfsdk:"id"`
	Metadata        MetadataModel `tfsdk:"metadata"`
	Type            types.String  `tfsdk:"type"`
	AwsKmsArns      types.List    `tfsdk:"aws_kms_arns"`
	GcpKmsResources types.List    `tfsdk:"gcp_kms_resources"`
	AzureKvUrls     types.List    `tfsdk:"azure_kv_urls"`
	AgeKeys         types.List    `tfsdk:"age_keys"`
	PgpKeys         types.List    `tfsdk:"pgp_keys"`
	FileData        types.Map     `tfsdk:"file_data"`
	StringData      types.Map     `tfsdk:"string_data"`
	OutputPath      types.String  `tfsdk:"output_path"`
	Secret          types.String  `tfsdk:"secret"`
	SecretRaw       types.Map     `tfsdk:"secret_raw"`
	PlaintextHash   types.String  `tfsdk:"plaintext_hash"`
}

type MetadataModel struct {
	Name        types.String `tfsdk:"name"`
	Namespace   types.String `tfsdk:"namespace"`
	Labels      types.Map    `tfsdk:"labels"`
	Annotations types.Map    `tfsdk:"annotations"`
}
