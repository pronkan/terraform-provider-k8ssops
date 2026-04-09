terraform {
  required_providers {
    k8ssops = {
      source  = "pronkan/k8ssops"
      version = "~> 0.1"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  aws_config = {
    kms_arns    = [data.aws_kms_key.main.arn]
    profile     = "basic"
    region      = "us-west-2"
  }
}

# ---------------------------------------------------------------------------
# AWS provider — resolves KMS key aliases to full ARNs
# ---------------------------------------------------------------------------
provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region
}

data "aws_kms_key" "main" {
  key_id = var.kms_alias
}

# ---------------------------------------------------------------------------
# k8ssops provider (default) — primary cluster encryption
# Credentials resolve in order: HCL attribute → env var → AWS SDK default chain
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# k8ssops provider (default) — primary cluster
#
# Each provider block maps to one set of KMS credentials. Use provider aliases
# to add more clusters. The `aws = var.aws_config` pattern lets you pass the
# entire block from a variable or local, keeping root-module configs DRY:
#
#   variable "aws_config" {
#     type = object({
#       kms_arns    = list(string)
#       profile     = optional(string)
#       region      = optional(string)
#       assume_role = optional(string)
#     })
#   }
# ---------------------------------------------------------------------------
provider "k8ssops" {
  # aws = {
  #   # One ARN per cluster account — any cluster can decrypt via its own key.
  #   kms_arns    = [data.aws_kms_key.main.arn]
  #   profile     = var.aws_profile
  #   region      = var.aws_region
  #   # assume_role      = "arn:aws:iam::ACCOUNT:role/sops-encryption"  # cross-account
  #   # access_key_id    = var.aws_access_key_id     # or AWS_ACCESS_KEY_ID env var
  #   # secret_access_key = var.aws_secret_access_key # or AWS_SECRET_ACCESS_KEY env var
  #   # session_token    = var.aws_session_token      # or AWS_SESSION_TOKEN env var
  # }
  aws = local.aws_config

  # gcp = {
  #   kms_resources = ["projects/my-proj/locations/global/keyRings/sops/cryptoKeys/key"]
  #   # PLACEHOLDER — GCP KMS not yet implemented
  # }

  # azure = {
  #   kv_urls = ["https://my-vault.vault.azure.net/keys/my-key/version"]
  #   # PLACEHOLDER — Azure Key Vault not yet implemented
  # }

  # pgp = {
  #   keys = ["FINGERPRINT1", "FINGERPRINT2"]
  # }

  # age = {
  #   keys = [local.dev_age_key]   # 32-byte hex key for offline/CI encryption
  # }

  # vault = {
  #   address = "https://vault.example.com:8200"
  #   token   = var.vault_token
  #   # PLACEHOLDER — Vault Transit not yet implemented
  # }
}

# ---------------------------------------------------------------------------
# k8ssops provider alias — secondary cluster (different account / KMS key)
# Uncomment to enable multi-cluster encryption in one apply.
# ---------------------------------------------------------------------------
# provider "k8ssops" {
#   alias = "cluster_b"
#   aws = {
#     kms_arns    = ["arn:aws:kms:us-east-1:222222222222:key/CLUSTER-B-KEY"]
#     profile     = "cluster-b-profile"
#     region      = "us-east-1"
#   }
# }

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

  output_path = "${path.module}/gitops/app-license.enc.yaml"
}

# ---------------------------------------------------------------------------
# k8ssops_secret — read back the encrypted file and expose all fields.
# Demonstrates cross-configuration consumption: a downstream module that only
# has the encrypted YAML on disk (e.g. pulled from Git) can surface every
# key without knowing the manifest structure up-front.
# ---------------------------------------------------------------------------
data "k8ssops_secret" "license" {
  path = k8ssops_secret.license.output_path

  # KMS credentials are inherited from the provider block above.
  # Override per-data-source if a different key or account is needed:
  # aws_kms_arns = ["arn:aws:kms:us-east-1:ACCOUNT:key/OTHER-KEY"]
  depends_on = [k8ssops_secret.license]
}

# ---------------------------------------------------------------------------
# k8ssops_decrypt — extract a single value from the encrypted secret.
# Useful when only one field is needed downstream (e.g. a connection string)
# without pulling the entire secret into a module output.
# ---------------------------------------------------------------------------
data "k8ssops_decrypt" "environment" {
  path = k8ssops_secret.license.output_path
  key  = "environment"

  depends_on = [k8ssops_secret.license]
}

# ---------------------------------------------------------------------------
# Inline-YAML variants — consume the encrypted secret string directly from
# resource state rather than from a file on disk.  This is the pattern for
# cross-state decryption: a downstream root module reads the encrypted YAML
# from a terraform_remote_state output and decrypts it without needing the
# file present locally.
# ---------------------------------------------------------------------------
data "k8ssops_secret" "license_inline" {
  encrypted_yaml = k8ssops_secret.license.secret
}

data "k8ssops_decrypt" "tier_inline" {
  encrypted_yaml = k8ssops_secret.license.secret
  key            = "tier"
}