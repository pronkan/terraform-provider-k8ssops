---
page_title: "k8ssops_secret Data Source - k8ssops"
description: |-
  Decrypts a SOPS-encrypted Kubernetes Secret manifest and exposes its data fields
  as Terraform outputs.
---

# k8ssops_secret (Data Source)

Decrypts a SOPS-encrypted Kubernetes Secret manifest and exposes its key/value pairs as computed
attributes. The ciphertext can be read from a file on disk or supplied inline as a string — for
example, directly from a `k8ssops_secret` resource output or from a `terraform_remote_state`
reference.

Use this data source when you need access to multiple values from a single encrypted Secret. When
you need only one value, prefer [`k8ssops_decrypt`](decrypt.md) to avoid pulling the entire Secret
into state.

-> **Note:** The `data` attribute re-encodes values as base64 strings, mirroring the Kubernetes
API behaviour for the `data` field (which stores binary-safe byte slices). If the original secret
was created using `string_data`, those values appear in `string_data` and `all_data` as plain
strings. Use `all_data` when you do not need to distinguish the source field.

## Argument Reference

Exactly one of `path` or `encrypted_yaml` must be set. Setting both or neither produces a
configuration error.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `path` | `string` | Optional | Path to a SOPS-encrypted Kubernetes Secret YAML file on disk. Mutually exclusive with `encrypted_yaml`. |
| `encrypted_yaml` | `string` | Optional | Inline SOPS-encrypted Kubernetes Secret YAML string. Mutually exclusive with `path`. Use to read from resource state or remote state without requiring the file on disk. |
| `aws_kms_arns` | `list(string)` | Optional | AWS KMS key ARNs. Falls back to provider-level `aws.kms_arns`. SOPS reads the actual key ARN from the ciphertext metadata; this field supplies credentials context, not key selection. |
| `gcp_kms_resources` | `list(string)` | Optional | GCP KMS resource IDs. Falls back to provider-level `gcp.kms_resources`. Not yet implemented. |
| `azure_kv_urls` | `list(string)` | Optional | Azure Key Vault key URLs. Falls back to provider-level `azure.kv_urls`. Not yet implemented. |
| `age_keys` | `list(string)` | Optional | Age keys or 32-byte hex-encoded symmetric keys. Falls back to provider-level `age.keys`. **Sensitive.** |
| `pgp_keys` | `list(string)` | Optional | PGP key fingerprints. Falls back to provider-level `pgp.keys`. |

## Attributes Reference

| Attribute | Type | Description |
|---|---|---|
| `id` | `string` | Identifier formatted as `<namespace>/<name>` derived from the manifest metadata. |
| `name` | `string` | Kubernetes Secret name from the manifest `metadata.name`. |
| `namespace` | `string` | Kubernetes Secret namespace from the manifest `metadata.namespace`. Defaults to `"default"` when not set in the manifest. |
| `data` | `map(string)` | Base64-encoded values from the decrypted `data` field. Each value is the raw payload re-encoded as standard base64. **Sensitive.** |
| `string_data` | `map(string)` | Values from the decrypted `stringData` field as plain strings. **Sensitive.** |
| `all_data` | `map(string)` | Merged union of `data` (base64-decoded to string) and `stringData`. When a key appears in both, `string_data` wins. This is the most convenient attribute for downstream consumption. **Sensitive.** |

## Examples

### From a file on disk

```hcl
data "k8ssops_secret" "license" {
  path       = "${path.module}/gitops/app-license.enc.yaml"
  depends_on = [k8ssops_secret.license]
}

output "license_environment" {
  value     = data.k8ssops_secret.license.all_data["environment"]
  sensitive = true
}
```

### From inline encrypted_yaml (within the same root module)

Use `encrypted_yaml` to consume the ciphertext directly from a `k8ssops_secret` resource output.
This avoids a dependency on a file path and works when `output_path` is not set.

```hcl
resource "k8ssops_secret" "api_token" {
  metadata = {
    name      = "api-token"
    namespace = "default"
  }
  string_data = {
    "token"    = var.api_token
    "endpoint" = var.api_endpoint
  }
}

data "k8ssops_secret" "api_token" {
  encrypted_yaml = k8ssops_secret.api_token.secret
}

output "api_endpoint" {
  value     = data.k8ssops_secret.api_token.all_data["endpoint"]
  sensitive = true
}
```

### From a cross-state reference

Read an encrypted Secret produced by a separate Terraform root module and decrypt it without
requiring the encrypted file to be present locally.

```hcl
data "terraform_remote_state" "secrets_module" {
  backend = "s3"
  config = {
    bucket = "my-terraform-state"
    key    = "secrets/terraform.tfstate"
    region = "us-east-1"
  }
}

data "k8ssops_secret" "tls" {
  # The remote state output holds the encrypted YAML string from k8ssops_secret.tls.secret
  encrypted_yaml = data.terraform_remote_state.secrets_module.outputs.tls_secret_encrypted
}

output "tls_cert" {
  value     = data.k8ssops_secret.tls.all_data["tls.crt"]
  sensitive = true
}
```