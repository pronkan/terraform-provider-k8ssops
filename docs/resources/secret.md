---
page_title: "k8ssops_secret Resource - k8ssops"
description: |-
  Generates a SOPS-encrypted Kubernetes Secret manifest and optionally writes it
  to a file for GitOps commit.
---

# k8ssops_secret (Resource)

Generates a SOPS-encrypted Kubernetes `kind: Secret` manifest. Only the values under `data` and
`stringData` are encrypted; `apiVersion`, `kind`, and `metadata` remain plaintext. This layout is
compatible with FluxCD and ArgoCD Kustomize SOPS decryption without additional configuration.

## Bootstrap and lifecycle model

On create, the resource reads `file_data` paths and `string_data` values, builds the manifest,
encrypts it with SOPS using the configured KMS key, and stores the ciphertext in state. If
`output_path` is set, the encrypted YAML is written to that path so it can be committed to Git.

On subsequent plans, the resource compares a SHA-256 hash of the current plaintext inputs against
the hash stored in state. If the hash is unchanged, the plan suppresses all `secret`, `secret_raw`,
and `plaintext_hash` changes — SOPS uses random nonces on every encryption, so without this
suppression a no-op plan would always show a diff.

When source files listed in `file_data` are absent (post-bootstrap), the resource enters fallback
mode. In fallback mode:

- Changes to `file_data` paths are ignored (files are gone by design).
- Changes to `string_data` trigger a decrypt-merge-encrypt cycle: the previous ciphertext is
  decrypted, the new `string_data` values are merged into the plaintext manifest, and the result
  is re-encrypted.
- If neither `file_data` nor `string_data` changed, the existing ciphertext is reused without any
  KMS call.

On delete, if `output_path` is set, the file is removed from disk.

-> **Note:** `terraform import` populates only `metadata.name`, `metadata.namespace`, and `id` from
the import ID. The `secret` ciphertext, `secret_raw`, and `plaintext_hash` attributes remain
unknown until the next `apply`. You must set `output_path` or re-supply source data to produce a
complete state.

## Argument Reference

### `metadata` block (required)

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `name` | `string` | Required | Kubernetes Secret name. Written verbatim to `metadata.name`. |
| `namespace` | `string` | Optional | Kubernetes namespace. Defaults to `"default"` when omitted. |
| `labels` | `map(string)` | Optional | Key/value labels written to `metadata.labels`. |
| `annotations` | `map(string)` | Optional | Key/value annotations written to `metadata.annotations`. |

### Top-level arguments

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `type` | `string` | Optional | Kubernetes Secret type. Defaults to `"Opaque"`. Use `"kubernetes.io/dockerconfigjson"` for registry credentials and `"kubernetes.io/tls"` for TLS secrets. |
| `file_data` | `map(string)` | Optional | Map of Secret key name → local file path. File contents are read and base64-encoded into the `data` field of the manifest. Paths must not escape the Terraform working directory. **Sensitive.** |
| `string_data` | `map(string)` | Optional | Map of Secret key name → plaintext string value. Written to the `stringData` field. **Sensitive.** |
| `aws_kms_arns` | `list(string)` | Optional | AWS KMS key ARNs for this resource. Overrides the provider-level `aws.kms_arns` for this secret only. |
| `gcp_kms_resources` | `list(string)` | Optional | GCP KMS resource IDs. Overrides provider-level `gcp.kms_resources`. Not yet implemented. |
| `azure_kv_urls` | `list(string)` | Optional | Azure Key Vault key URLs. Overrides provider-level `azure.kv_urls`. Not yet implemented. |
| `age_keys` | `list(string)` | Optional | Age or 32-byte hex-encoded symmetric keys. Overrides provider-level `age.keys`. |
| `pgp_keys` | `list(string)` | Optional | PGP key fingerprints. Overrides provider-level `pgp.keys`. |
| `output_path` | `string` | Optional | Local file path where the encrypted YAML is written. Parent directories are created automatically on refresh if the file is missing. The path must not escape the Terraform working directory (no `..` components). On destroy, the file is deleted. |

## Attributes Reference

| Attribute | Type | Description |
|---|---|---|
| `id` | `string` | Resource identifier formatted as `<namespace>/<name>`. |
| `secret` | `string` | The full SOPS-encrypted Kubernetes Secret manifest in YAML format. Suitable for use as `encrypted_yaml` in `k8ssops_secret` and `k8ssops_decrypt` data sources. **Sensitive.** |
| `secret_raw` | `map(string)` | Decrypted key/value pairs extracted from the generated manifest. Merges `data` (after base64-decoding) and `stringData`, with `stringData` winning on collision. Stored in Terraform state as sensitive. **Sensitive.** |
| `plaintext_hash` | `string` | SHA-256 hex digest of the combined `file_data` contents and `string_data` values, used for drift detection across plans. **Sensitive.** |

## Examples

### Docker registry secret from string_data

```hcl
resource "k8ssops_secret" "registry" {
  metadata = {
    name      = "docker-registry"
    namespace = "default"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  type = "kubernetes.io/dockerconfigjson"

  string_data = {
    ".dockerconfigjson" = jsonencode({
      auths = {
        "registry.example.com" = {
          username = var.registry_user
          password = var.registry_password
          auth     = base64encode("${var.registry_user}:${var.registry_password}")
        }
      }
    })
  }

  output_path = "${path.module}/gitops/docker-registry.enc.yaml"
}
```

### TLS certificate from files

```hcl
resource "k8ssops_secret" "tls" {
  metadata = {
    name      = "ingress-tls"
    namespace = "ingress-nginx"
  }

  type = "kubernetes.io/tls"

  # Paths must resolve within the Terraform working directory.
  file_data = {
    "tls.crt" = "${path.module}/certs/tls.crt"
    "tls.key" = "${path.module}/certs/tls.key"
  }

  output_path = "${path.module}/gitops/ingress-tls.enc.yaml"
}
```

After the initial `terraform apply` you can delete `certs/tls.crt` and `certs/tls.key` from the
module. The provider will enter fallback mode and preserve the existing ciphertext on future plans
as long as `string_data` does not change.

### License file with output_path for GitOps commit

```hcl
resource "k8ssops_secret" "license" {
  metadata = {
    name      = "app-license"
    namespace = "production"
    labels = {
      "app.kubernetes.io/name"      = "myapp"
      "app.kubernetes.io/component" = "licensing"
    }
    annotations = {
      "reloader.stakater.com/match" = "true"
    }
  }

  type = "Opaque"

  file_data = {
    "license.lic" = "${path.module}/secrets/license.license"
  }

  string_data = {
    "environment" = var.environment
    "tier"        = "enterprise"
  }

  # Commit this file to your GitOps repository.
  output_path = "${path.module}/gitops/app-license.enc.yaml"
}
```

### RDS credential bridge (AWS Secrets Manager to Kubernetes)

Read an Aurora auto-rotated password from AWS Secrets Manager during the Terraform run and
encrypt it directly into a Kubernetes Secret. No plaintext intermediate file is required.

```hcl
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/aurora/credentials"
}

locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)
}

resource "k8ssops_secret" "db_credentials" {
  metadata = {
    name      = "aurora-credentials"
    namespace = "app"
  }

  type = "Opaque"

  string_data = {
    "username" = local.db_creds.username
    "password" = local.db_creds.password
    "host"     = local.db_creds.host
    "port"     = tostring(local.db_creds.port)
    "dbname"   = local.db_creds.dbname
  }

  # Use a resource-level ARN override when this secret requires a different key
  # from the provider default — for example, the database team's KMS key.
  aws_kms_arns = [data.aws_kms_key.db_team.arn]

  output_path = "${path.module}/gitops/aurora-credentials.enc.yaml"
}
```

## Import

Import an existing resource by passing `<namespace>/<name>` as the import ID:

```bash
terraform import k8ssops_secret.example production/app-license
```

~> **Warning:** Import populates only `id`, `metadata.name`, and `metadata.namespace`. The
`secret`, `secret_raw`, and `plaintext_hash` computed attributes remain unknown until the next
`terraform apply`. You must supply all required arguments (`metadata`, and at least one of
`file_data` or `string_data`, or a valid `aws_kms_arns`) in your configuration before running
apply after import.