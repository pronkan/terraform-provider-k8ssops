---
page_title: "Getting Started - k8ssops"
description: |-
  Step-by-step guide to encrypting your first Kubernetes Secret with the k8ssops
  provider and integrating the output into a FluxCD or ArgoCD GitOps repository.
---

# Getting Started

This guide walks through installing the provider, encrypting a Docker registry credential, and
integrating the output with FluxCD or ArgoCD. By the end you will have an encrypted YAML file
committed to Git that your CD tooling can decrypt autonomously using an AWS KMS key.

## Prerequisites

- Terraform 1.5 or later
- AWS CLI configured with a profile that has `kms:GenerateDataKey` on your target KMS key
- An existing AWS KMS symmetric key (CMK). Managed keys (`aws/s3` etc.) work but customer-managed
  keys give you full control over key policy

## Step 1 — Provider installation

Add the provider to your `required_providers` block:

```hcl
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
```

Run:

```bash
terraform init
```

## Step 2 — Resolve the KMS key ARN

Use the `aws_kms_key` data source to resolve a key alias to its full ARN. This avoids hardcoding
the ARN and handles key rotation transparently.

```hcl
provider "aws" {
  profile = "prod-admin"
  region  = "us-east-1"
}

data "aws_kms_key" "sops" {
  key_id = "alias/my-sops-key"
}

provider "k8ssops" {
  aws = {
    kms_arns = [data.aws_kms_key.sops.arn]
    profile  = "prod-admin"
    region   = "us-east-1"
  }
}
```

The `profile` in the `k8ssops` provider block and the `aws` provider block can differ. The
`k8ssops` provider uses its credentials only for SOPS KMS calls, independent of the AWS provider.

## Step 3 — Encrypt your first secret

Create a Docker registry credential. The `output_path` is the file you will commit to Git.

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

Run:

```bash
terraform apply
```

The provider calls `kms:GenerateDataKey`, encrypts the manifest, and writes the YAML to
`gitops/docker-registry.enc.yaml`.

## Step 4 — Verify the encrypted output

Inspect the file to confirm only the values are ciphertext and the metadata is readable:

```bash
cat gitops/docker-registry.enc.yaml
```

You should see something like:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry
  namespace: default
  labels:
    app.kubernetes.io/managed-by: terraform
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  kms:
  - arn: arn:aws:kms:us-east-1:123456789012:key/mrk-abc123
    created_at: "2026-04-07T00:00:00Z"
    enc: AQICAH...
  version: 3.9.4
```

Decrypt it manually with the SOPS CLI to verify the content before committing:

```bash
sops --decrypt gitops/docker-registry.enc.yaml
```

This requires the same AWS credentials that were used for encryption (or any profile with
`kms:Decrypt` on the key).

## Step 5 — GitOps integration

Commit the encrypted file to your GitOps repository:

```bash
git add gitops/docker-registry.enc.yaml
git commit -m "feat: add docker-registry secret (SOPS encrypted)"
git push
```

**FluxCD** — add a `Kustomization` with SOPS decryption configured:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: secrets
  namespace: flux-system
spec:
  interval: 10m
  path: ./gitops
  prune: true
  sourceRef:
    kind: GitRepository
    name: my-repo
  decryption:
    provider: sops
    secretRef:
      name: sops-aws-creds  # contains AWS credentials with kms:Decrypt
```

**ArgoCD** — configure the SOPS Helm plugin or use `argocd-vault-plugin` with SOPS support.
ArgoCD reads the KMS key ARN directly from the SOPS metadata embedded in the encrypted file; no
ARN configuration is needed in ArgoCD itself.

## Step 6 — Remove source files after bootstrap

Once the encrypted file is committed and your CD pipeline is verified, remove the plaintext source
material from the module:

```bash
rm -rf secrets/
# Remove file_data entries from the resource if no longer needed,
# or leave them — the provider enters fallback mode when files are absent.
```

On the next `terraform plan`, the provider detects the missing files and enters fallback mode.
The plan shows no diff as long as `string_data` has not changed. If you update `string_data`
(for example, to rotate a token), the provider decrypts the existing ciphertext from state,
merges the new values, and re-encrypts — no source files required.

This is the intended production steady state: the encryption maintainer no longer holds the
plaintext. FluxCD or ArgoCD holds only `kms:Decrypt` permission and never interacts with the
Terraform state.