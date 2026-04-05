---
page_title: "Cross-State Decryption - k8ssops"
description: |-
  Decrypt a Kubernetes Secret encrypted by a separate Terraform root module using
  terraform_remote_state and the encrypted_yaml input on k8ssops data sources.
---

# Cross-State Decryption

The `encrypted_yaml` argument on both `k8ssops_secret` and `k8ssops_decrypt` data sources accepts
a SOPS-encrypted manifest string directly — without requiring the encrypted file to be present on
the local filesystem. This enables a root module that produces encrypted Secrets to share them
with a separate root module that needs to read the plaintext values, without duplicating the
encrypted file or creating a file-path dependency between modules.

The canonical pattern uses `terraform_remote_state` to pass the encrypted YAML string across
module boundaries.

## Scenario

- **Module A** (secrets root module): owns KMS access, produces encrypted Secrets, outputs
  `k8ssops_secret.<name>.secret` as a sensitive string.
- **Module B** (application root module): reads the encrypted YAML from Module A's remote state,
  decrypts it during its own plan/apply to configure downstream resources.

Module B requires the same AWS credentials as Module A's provider, because it performs the same
`kms:Decrypt` call. Module B does not need `kms:GenerateDataKey`.

## Module A — produce and export the encrypted Secret

```hcl
# modules/secrets/main.tf

terraform {
  required_providers {
    k8ssops = {
      source  = "pronkan/k8ssops"
      version = "~> 0.1"
    }
  }

  backend "s3" {
    bucket = "my-terraform-state"
    key    = "secrets/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "k8ssops" {
  aws = {
    kms_arns = ["arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"]
    profile  = "secrets-admin"
    region   = "us-east-1"
  }
}

resource "k8ssops_secret" "tls" {
  metadata = {
    name      = "ingress-tls"
    namespace = "ingress-nginx"
  }
  type = "kubernetes.io/tls"
  file_data = {
    "tls.crt" = "${path.module}/certs/tls.crt"
    "tls.key" = "${path.module}/certs/tls.key"
  }
  output_path = "${path.module}/gitops/ingress-tls.enc.yaml"
}
```

```hcl
# modules/secrets/outputs.tf

output "tls_secret_encrypted" {
  description = "SOPS-encrypted Kubernetes Secret manifest for ingress-tls."
  value       = k8ssops_secret.tls.secret
  sensitive   = true
}
```

## Module B — read and decrypt via remote state

```hcl
# modules/app/main.tf

terraform {
  required_providers {
    k8ssops = {
      source  = "pronkan/k8ssops"
      version = "~> 0.1"
    }
  }
}

provider "k8ssops" {
  aws = {
    # No kms_arns needed for decryption — SOPS reads the ARN from the ciphertext metadata.
    # Only credentials are required.
    profile = "app-deployer"
    region  = "us-east-1"
  }
}

data "terraform_remote_state" "secrets" {
  backend = "s3"
  config = {
    bucket = "my-terraform-state"
    key    = "secrets/terraform.tfstate"
    region = "us-east-1"
  }
}

# Decrypt all fields from the remote module's encrypted output.
data "k8ssops_secret" "tls" {
  encrypted_yaml = data.terraform_remote_state.secrets.outputs.tls_secret_encrypted
}

# Decrypt a single field if only one value is needed.
data "k8ssops_decrypt" "tls_cert" {
  encrypted_yaml = data.terraform_remote_state.secrets.outputs.tls_secret_encrypted
  key            = "tls.crt"
}

output "tls_namespace" {
  value = data.k8ssops_secret.tls.namespace
}

output "tls_cert_pem" {
  value     = data.k8ssops_decrypt.tls_cert.plaintext
  sensitive = true
}
```

## Important notes

-> **Note on KMS ARNs during decryption:** The `aws_kms_arns` argument on data sources is not
used for key selection during decryption. SOPS reads the KMS key ARN directly from the `sops`
metadata block embedded in the encrypted YAML. The data source's `aws_kms_arns` field exists for
schema consistency; what matters for decryption is that the AWS credentials in the provider block
have `kms:Decrypt` permission on the key identified in the metadata.

-> **Note on sensitive state:** The encrypted YAML string (`k8ssops_secret.tls.secret`) is marked
sensitive in Terraform state. Remote state backends that store state in plaintext (local, S3
without encryption) will contain the ciphertext string. The ciphertext is safe to store — it
requires the KMS key to decrypt — but treat the state file itself according to your security
policy.

~> **Warning:** Do not pass the decrypted `plaintext` or `all_data` values through
`terraform_remote_state` outputs. These attributes contain plaintext secret material. Only pass
the `secret` (ciphertext) output from Module A; let Module B perform its own decryption.