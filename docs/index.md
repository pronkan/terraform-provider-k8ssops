---
page_title: "Provider: k8ssops"
description: |-
  The k8ssops provider generates SOPS-encrypted Kubernetes Secret manifests
  for GitOps workflows with FluxCD and ArgoCD.
---

# k8ssops Provider

The `k8ssops` provider generates SOPS-encrypted Kubernetes Secret manifests for GitOps
workflows. Each resource produces a fully-formed `kind: Secret` YAML document in which only
the `data` and `stringData` values are ciphertext — `apiVersion`, `kind`, and `metadata`
remain human-readable, which is the conventional GitOps SOPS layout for FluxCD and ArgoCD
Kustomize.

## Bootstrap model

The provider is designed to encrypt once and maintain by state. On the first apply, source files
(TLS certificates, license files, API tokens, Docker credentials) are read from disk, encrypted
with AWS KMS via SOPS, and written to `output_path` for Git commit. Source files can then be
removed from the Terraform module. Subsequent plans detect content drift via a SHA-256 hash of
the plaintext inputs; when source files are absent the provider falls back to a
decrypt-merge-encrypt loop that applies only `string_data` changes without requiring the original
files.

This model keeps the blast radius small: the encryption maintainer needs `kms:GenerateDataKey`
and read access to the raw secret material. CD tooling (FluxCD, ArgoCD) needs only `kms:Decrypt`.
Neither role requires the other's permission.

## Who this is for

- Platform engineering teams managing GitOps repositories where secrets must be encrypted at rest
  in Git
- Teams bridging cloud-provisioned secrets (AWS Secrets Manager, RDS auto-rotation) into
  Kubernetes without an intermediate Vault deployment
- CI/CD pipelines that must produce encrypted manifests without deploying a secrets manager

## Provider configuration

### Example usage

```hcl
provider "k8ssops" {
  aws = {
    kms_arns    = ["arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"]
    profile     = "prod-admin"
    region      = "us-east-1"
    assume_role = "arn:aws:iam::123456789012:role/sops-encryption"
  }
}
```

### Schema

#### `aws` block (optional)

AWS KMS configuration. Credentials resolve in this order for each attribute:
HCL value → environment variable → AWS SDK default credential chain.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `kms_arns` | `list(string)` | Optional | Default AWS KMS key ARNs used for encryption. All ARNs are placed in one SOPS KeyGroup — any key can decrypt independently. Add one ARN per cluster account for multi-cluster GitOps. |
| `profile` | `string` | Optional | AWS named profile from `~/.aws/config`. Falls back to `AWS_PROFILE`. |
| `region` | `string` | Optional | AWS region for KMS API calls. Usually derived from the ARN; set this for short-form key aliases. Falls back to `AWS_DEFAULT_REGION`, then `AWS_REGION`. |
| `assume_role` | `string` | Optional | IAM role ARN to assume before calling KMS. Enables cross-account encryption without long-lived credentials. |
| `access_key_id` | `string` | Optional | AWS access key ID. Falls back to `AWS_ACCESS_KEY_ID`. Prefer `profile` or `assume_role` in production. **Sensitive.** |
| `secret_access_key` | `string` | Optional | AWS secret access key. Falls back to `AWS_SECRET_ACCESS_KEY`. **Sensitive.** |
| `session_token` | `string` | Optional | AWS session token for temporary credentials. Falls back to `AWS_SESSION_TOKEN`. **Sensitive.** |

#### `gcp` block (optional)

~> **Not implemented.** This block is accepted by the schema for future compatibility. Configuring
it has no effect in the current version.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `kms_resources` | `list(string)` | Optional | GCP KMS resource IDs (`projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`). Reserved for a future release. |

#### `azure` block (optional)

~> **Not implemented.** This block is accepted by the schema for future compatibility. Configuring
it has no effect in the current version.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `kv_urls` | `list(string)` | Optional | Azure Key Vault key URLs (`https://<vault>.vault.azure.net/keys/<key>/<version>`). Reserved for a future release. |

#### `pgp` block (optional)

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `keys` | `list(string)` | Optional | PGP key fingerprints (40-character hex) added as SOPS recipients. |

#### `age` block (optional)

-> **Note:** In this provider the `keys` field serves a dual purpose. In addition to standard age
public keys, it accepts a 32-byte hex-encoded symmetric key to enable AES-256-GCM encryption
without any external KMS call. This offline path is used by unit tests and local development.
It is not suitable for production GitOps workflows because the symmetric key must be present for
both encryption and decryption, eliminating the split-role security model.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `keys` | `list(string)` | Optional | Age public keys or 32-byte hex-encoded symmetric keys for offline AES-256-GCM encryption. **Sensitive.** |

#### `vault` block (optional)

~> **Not implemented.** This block is accepted by the schema for future compatibility. Configuring
it has no effect in the current version.

| Argument | Type | Required/Optional | Description |
|---|---|---|---|
| `address` | `string` | Optional | Vault server address (`https://vault.example.com:8200`). Reserved for a future release. |
| `token` | `string` | Optional | Vault authentication token. Reserved for a future release. **Sensitive.** |

## Authentication

AWS credentials are resolved in this order for each field:

1. Explicit HCL value in the `aws` block (`access_key_id`, `secret_access_key`, `session_token`)
2. `profile` attribute (maps to `~/.aws/config` named profile)
3. `assume_role` attribute (STS AssumeRole, cross-account)
4. Standard AWS SDK environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
   `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_DEFAULT_REGION`)
5. AWS SDK default credential chain: shared credentials file, EC2 instance profile,
   ECS task role, etc.

Credentials are never written to the encrypted output file. The `profile` attribute is stripped
from SOPS key metadata before the file is serialized to prevent coupling the encrypted artifact to
a local AWS CLI profile name.

~> **Security note:** `access_key_id`, `secret_access_key`, and `session_token` are marked
sensitive in the Terraform schema and are never emitted to the SOPS output YAML. In production,
prefer `profile` or `assume_role` over static key pairs.

## Provider alias pattern for multi-cluster

Use provider aliases when different clusters use different KMS keys or live in different AWS
accounts. Each alias maps to one set of credentials.

```hcl
# Cluster A — us-east-1, account 111111111111
provider "k8ssops" {
  alias = "cluster_a"
  aws = {
    kms_arns = ["arn:aws:kms:us-east-1:111111111111:key/key-a"]
    profile  = "cluster-a-admin"
    region   = "us-east-1"
  }
}

# Cluster B — eu-west-1, account 222222222222
provider "k8ssops" {
  alias = "cluster_b"
  aws = {
    kms_arns = ["arn:aws:kms:eu-west-1:222222222222:key/key-b"]
    profile  = "cluster-b-admin"
    region   = "eu-west-1"
  }
}

resource "k8ssops_secret" "api_token_cluster_a" {
  provider = k8ssops.cluster_a
  metadata = { name = "api-token", namespace = "default" }
  string_data = { token = var.api_token }
  output_path = "gitops/cluster-a/api-token.enc.yaml"
}

resource "k8ssops_secret" "api_token_cluster_b" {
  provider = k8ssops.cluster_b
  metadata = { name = "api-token", namespace = "default" }
  string_data = { token = var.api_token }
  output_path = "gitops/cluster-b/api-token.enc.yaml"
}
```

To allow a single encrypted file to be decrypted by multiple clusters, include all cluster KMS
ARNs in a single provider's `kms_arns` list. SOPS places all ARNs in one KeyGroup so any key
decrypts the same file.

## Resources

- [k8ssops_secret](resources/secret.md)

## Data Sources

- [k8ssops_secret](data-sources/secret.md)
- [k8ssops_decrypt](data-sources/decrypt.md)