---
page_title: "Multi-Cluster Encryption - k8ssops"
description: |-
  Encrypt Kubernetes Secrets for multiple clusters using provider aliases and
  per-resource KMS key overrides.
---

# Multi-Cluster Encryption

This guide covers two distinct patterns for managing secrets across multiple Kubernetes clusters:

1. **Single encrypted file, multiple recipients** — one SOPS file that any cluster can decrypt
   using its own KMS key (all keys in the same KeyGroup).
2. **Per-cluster encrypted files** — separate encrypted files, each encrypted with a different
   KMS key, using provider aliases.

## Pattern 1 — Single file, multiple recipient keys

Place all cluster KMS key ARNs in a single provider's `kms_arns` list. SOPS puts all ARNs in one
KeyGroup, so any cluster holding one of the listed keys can decrypt the file independently.

This is the recommended pattern when all clusters should share the same secret value.

```hcl
provider "k8ssops" {
  aws = {
    # Each ARN belongs to a different cluster account.
    # Any cluster can decrypt this secret with its own key.
    kms_arns = [
      "arn:aws:kms:us-east-1:111111111111:key/cluster-a-key",
      "arn:aws:kms:eu-west-1:222222222222:key/cluster-b-key",
      "arn:aws:kms:ap-southeast-1:333333333333:key/cluster-c-key",
    ]
    profile = "encryption-admin"
    region  = "us-east-1"
  }
}

resource "k8ssops_secret" "shared_api_token" {
  metadata = {
    name      = "api-token"
    namespace = "default"
  }
  string_data = {
    "token" = var.api_token
  }
  output_path = "${path.module}/gitops/shared/api-token.enc.yaml"
}
```

The encryption caller needs `kms:GenerateDataKey` on all three keys. Each cluster's CD tooling
needs only `kms:Decrypt` on its own key.

## Pattern 2 — Per-cluster files using provider aliases

Use provider aliases when clusters require different secret values, are isolated by AWS account
and IAM boundary, or need separate encrypted files for security or compliance reasons.

```hcl
# Cluster A — us-east-1, account 111111111111
provider "k8ssops" {
  alias = "cluster_a"
  aws = {
    kms_arns    = ["arn:aws:kms:us-east-1:111111111111:key/cluster-a-key"]
    profile     = "cluster-a-admin"
    region      = "us-east-1"
    assume_role = "arn:aws:iam::111111111111:role/sops-encryption"
  }
}

# Cluster B — eu-west-1, account 222222222222
provider "k8ssops" {
  alias = "cluster_b"
  aws = {
    kms_arns    = ["arn:aws:kms:eu-west-1:222222222222:key/cluster-b-key"]
    profile     = "cluster-b-admin"
    region      = "eu-west-1"
    assume_role = "arn:aws:iam::222222222222:role/sops-encryption"
  }
}

resource "k8ssops_secret" "registry_cluster_a" {
  provider = k8ssops.cluster_a

  metadata = {
    name      = "docker-registry"
    namespace = "default"
  }
  type = "kubernetes.io/dockerconfigjson"
  string_data = {
    ".dockerconfigjson" = var.dockerconfig_json_cluster_a
  }
  output_path = "${path.module}/gitops/cluster-a/docker-registry.enc.yaml"
}

resource "k8ssops_secret" "registry_cluster_b" {
  provider = k8ssops.cluster_b

  metadata = {
    name      = "docker-registry"
    namespace = "default"
  }
  type = "kubernetes.io/dockerconfigjson"
  string_data = {
    ".dockerconfigjson" = var.dockerconfig_json_cluster_b
  }
  output_path = "${path.module}/gitops/cluster-b/docker-registry.enc.yaml"
}
```

## Per-resource KMS key override

The `aws_kms_arns` argument on `k8ssops_secret` overrides the provider-level `kms_arns` for a
single resource. Use this when most secrets use the default provider key but one secret requires
a different key — for example, a database team's CMK that only they control.

```hcl
provider "k8ssops" {
  aws = {
    kms_arns = ["arn:aws:kms:us-east-1:123456789012:key/default-key"]
    profile  = "prod-admin"
    region   = "us-east-1"
  }
}

# This secret uses the default provider key.
resource "k8ssops_secret" "api_token" {
  metadata = { name = "api-token", namespace = "default" }
  string_data = { "token" = var.api_token }
  output_path = "${path.module}/gitops/api-token.enc.yaml"
}

# This secret uses the database team's key instead.
resource "k8ssops_secret" "db_credentials" {
  metadata = { name = "db-credentials", namespace = "app" }
  string_data = {
    "password" = var.db_password
  }
  # Resource-level override; provider-level kms_arns is not used for this resource.
  aws_kms_arns = ["arn:aws:kms:us-east-1:123456789012:key/db-team-key"]
  output_path  = "${path.module}/gitops/db-credentials.enc.yaml"
}
```

The `aws_kms_arns` override is complete — when set at the resource level, the provider-level
`aws.kms_arns` list is not appended. Specify all ARNs you want in the resource-level list.