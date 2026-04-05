---
page_title: "k8ssops_decrypt Data Source - k8ssops"
description: |-
  Decrypts a single key from a SOPS-encrypted Kubernetes Secret manifest and
  exposes its plaintext value.
---

# k8ssops_decrypt (Data Source)

Decrypts a single key from a SOPS-encrypted Kubernetes Secret manifest and exposes the plaintext
value as a computed `plaintext` attribute. The key is looked up in the merged `data` +
`stringData` map of the decrypted manifest (`stringData` wins on collision).

Use this data source when only one value from a Secret is needed downstream — for example, to
pass a database password to a Kubernetes Deployment manifest or to a Helm values file. When
multiple values are needed, use [`k8ssops_secret`](secret.md) instead to avoid separate
decryption calls for each key.

The `id` attribute is a SHA-256 hash of the combined decrypted manifest bytes and the key name.
It is deterministic for a given ciphertext and key, and does not expose sensitive material.

## Argument Reference

Exactly one of `path` or `encrypted_yaml` must be set. Setting both or neither produces a
configuration error.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `path` | `string` | Optional | Path to a SOPS-encrypted Kubernetes Secret YAML file on disk. Mutually exclusive with `encrypted_yaml`. |
| `encrypted_yaml` | `string` | Optional | Inline SOPS-encrypted Kubernetes Secret YAML string. Mutually exclusive with `path`. Use to read from resource state or remote state without requiring the file on disk. |
| `key` | `string` | Required | Key name to look up in the decrypted `data` or `stringData` fields of the Secret. Returns an error if the key is not found. |
| `aws_kms_arns` | `list(string)` | Optional | AWS KMS key ARNs. Falls back to provider-level `aws.kms_arns`. SOPS reads the actual key ARN from the ciphertext metadata; this field supplies credentials context, not key selection. |
| `gcp_kms_resources` | `list(string)` | Optional | GCP KMS resource IDs. Falls back to provider-level `gcp.kms_resources`. Not yet implemented. |
| `azure_kv_urls` | `list(string)` | Optional | Azure Key Vault key URLs. Falls back to provider-level `azure.kv_urls`. Not yet implemented. |
| `age_keys` | `list(string)` | Optional | Age keys or 32-byte hex-encoded symmetric keys. Falls back to provider-level `age.keys`. **Sensitive.** |
| `pgp_keys` | `list(string)` | Optional | PGP key fingerprints. Falls back to provider-level `pgp.keys`. |

## Attributes Reference

| Attribute | Type | Description |
|---|---|---|
| `id` | `string` | Deterministic SHA-256 identifier derived from the ciphertext and key name. Does not contain sensitive material. |
| `plaintext` | `string` | The decrypted plaintext value for the requested `key`. **Sensitive.** |

## Examples

### From a file on disk

Decrypt the `token` key from an encrypted Secret written to the GitOps repository.

```hcl
data "k8ssops_decrypt" "api_token" {
  path = "${path.module}/gitops/api-token.enc.yaml"
  key  = "token"
}

# Pass the token to a Kubernetes ConfigMap or another resource.
output "api_token" {
  value     = data.k8ssops_decrypt.api_token.plaintext
  sensitive = true
}
```

### From a k8ssops_secret resource output

Consume a single value from a Secret created in the same root module without requiring the file to
be present on disk. This pattern avoids an explicit `depends_on` because the reference creates an
implicit dependency.

```hcl
resource "k8ssops_secret" "db_credentials" {
  metadata = {
    name      = "aurora-credentials"
    namespace = "app"
  }
  string_data = {
    "username" = local.db_creds.username
    "password" = local.db_creds.password
    "host"     = local.db_creds.host
  }
  output_path = "${path.module}/gitops/aurora-credentials.enc.yaml"
}

data "k8ssops_decrypt" "db_password" {
  encrypted_yaml = k8ssops_secret.db_credentials.secret
  key            = "password"
}

# Use the decrypted password in a downstream provider configuration.
provider "postgresql" {
  host     = local.db_creds.host
  username = local.db_creds.username
  password = data.k8ssops_decrypt.db_password.plaintext
}
```

-> **Use-case guidance:** Prefer `k8ssops_decrypt` over `k8ssops_secret` when you need exactly
one value. It is more explicit and avoids pulling the entire key/value map — and all its sensitive
values — into Terraform outputs unless they are needed.