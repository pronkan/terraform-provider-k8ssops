# terraform-provider-k8ssops

[![Terraform Registry](https://img.shields.io/badge/registry-pronkan%2Fk8ssops-5C4EE5?logo=terraform)](https://registry.terraform.io/providers/pronkan/k8ssops/latest)
[![Go Version](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Generate SOPS-encrypted Kubernetes Secret manifests for GitOps deployments with FluxCD and ArgoCD.

## Overview

The `k8ssops` provider implements a **bootstrap-once, maintain-by-state** model for Kubernetes
secrets in GitOps repositories. On the first `terraform apply`, the provider reads your raw secret
material (TLS certificates, license files, API tokens, Docker registry credentials), encrypts it
with AWS KMS via SOPS, and writes the encrypted YAML to a path you commit to Git. After that
initial run you can delete the source files from the module — the provider maintains state from the
encrypted ciphertext and falls back to a decrypt-merge-encrypt loop when `string_data` changes.
FluxCD or ArgoCD Kustomize decrypts the manifest autonomously using the cluster's KMS key; CD
operators never require decryption capability, which narrows the blast radius to the encryption
team only.

The provider also bridges cloud-provisioned secrets into Kubernetes: read a plaintext value from
`aws_secretsmanager_secret_version` during the Terraform run, pass it as `string_data`, and the
provider encrypts it immediately — no intermediate plaintext touches disk in the clear.

AWS KMS is production-ready. GCP Cloud KMS, Azure Key Vault, and HashiCorp Vault Transit are
scaffolded in the schema but not yet implemented. Age keys (32-byte hex-encoded symmetric keys)
are supported for offline CI testing without cloud credentials.

## Quick Start

```hcl
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
    kms_arns = ["arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"]
    profile  = "prod-admin"
    region   = "us-east-1"
  }
}

# Encrypt a Docker registry credential and write it to the GitOps repo.
resource "k8ssops_secret" "registry" {
  metadata = {
    name      = "docker-registry"
    namespace = "default"
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

resource "k8ssops_secret" "license" {
  metadata = {
    name      = "product-license"
    namespace = "default"
  }
  type = "Opaque"
  file_data = {
    "license.txt" = "${path.module}/license.txt" # Can be removed after bootstrap until next license renewal.
  }
  # output_path = "${path.module}/gitops/license.enc.yaml" # Optional and can be omitted in this case
}

resource "local_file" "flux_manifest" {
  content  = templatefile("${path.module}/flux.yaml.tmpl", {
    license_secret = k8ssops_secret.license.secret
  })
  filename = "${path.module}/gitops/license.decrypted.txt"
}

# Decrypt a single field during the same run for a downstream resource.
data "k8ssops_decrypt" "registry_password" {
  encrypted_yaml = k8ssops_secret.registry.secret
  key            = ".dockerconfigjson"
}

# Decrypt all fields from the encrypted file on disk.
data "k8ssops_secret" "registry" {
  path       = k8ssops_secret.registry.output_path
  depends_on = [k8ssops_secret.registry]
}
```

Where:
```yaml
# flux.yaml.tmpl
${license_secret}
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: product
  namespace: flux-system
spec:
  interval: 15m
  timeout: 5m
  chart:
    spec:
      chart: product
      version: '1.0.*'
      sourceRef:
        kind: HelmRepository
        name: product-charts
        namespace:
      interval: 5m
  releaseName: product
  targetNamespace: default
  values:
    license:
      secretRef:
        name: product-license
```

## Architecture

```text
  Terraform apply
       |
       v
  k8ssops provider
       |
       +-- reads file_data / string_data
       |
       v
  SOPS engine (getsops/sops v3.9.4)
       |
       +-- GenerateDataKey -------> AWS KMS
       |                               |
       |                        encrypted DEK returned
       |                               |
       +<------------------------------+
       |
       v
  Encrypted YAML
  (apiVersion, kind, metadata remain plaintext;
   only data/stringData values are ciphertext)
       |
       v
  output_path  -->  git commit  -->  FluxCD / ArgoCD Kustomize
                                              |
                                              v
                                       kms:Decrypt (AWS KMS)
                                              |
                                              v
                                    kubectl apply Secret
                                    to target cluster
```

## Requirements

| Dependency      | Minimum version | Notes                                                                           |
|-----------------|-----------------|---------------------------------------------------------------------------------|
| Go              | 1.25            | Required to build from source                                                   |
| Terraform       | 1.5             | Required to use the provider                                                    |
| AWS credentials | n/a             | `kms:GenerateDataKey` for encryption; `kms:Decrypt` for data source decryption |

No Kubernetes cluster connectivity is required. This provider generates manifest files only.

## Installation

Add the provider to your `required_providers` block and run `terraform init`:

```hcl
terraform {
  required_providers {
    k8ssops = {
      source  = "pronkan/k8ssops"
      version = "~> 0.1"
    }
  }
}
```

```bash
terraform init
```

## Development

**Prerequisites**: Go 1.25+, Terraform 1.5+, GNU Make.

Add `~/.terraformrc` file in the home directory:
```hcl
provider_installation {
  filesystem_mirror {
    path    = "~/.terraform.d/plugins"
    include = ["registry.terraform.io/pronkan/*"]
  }
  direct {
    exclude = ["registry.terraform.io/pronkan/*"]
  }
}
```

Use Make:
```bash
# Build the provider binary
make build

# Run unit tests (no cloud credentials required; uses offline AES-256-GCM path)
make test

# Build, install to ~/.terraform.d/plugins, and run terraform apply in test/
make cycle TF_VAR_kms_alias=alias/eks/eksKmsKey TF_VAR_aws_profile=default TF_VAR_aws_region=us-east-1
```

The `make cycle` target requires AWS credentials with `kms:GenerateDataKey` on the key referenced
by `TF_VAR_kms_alias`, aws profile `TF_VAR_aws_profile`, and region `TF_VAR_aws_region` set in
the environment.

## Documentation

Full provider, resource, and data source reference is in [`docs/`](docs/):

- [Provider configuration](docs/index.md)
- [`k8ssops_secret` resource](docs/resources/secret.md)
- [`k8ssops_secret` data source](docs/data-sources/secret.md)
- [`k8ssops_decrypt` data source](docs/data-sources/decrypt.md)
- [Getting started guide](docs/guides/getting-started.md)
- [Multi-cluster encryption](docs/guides/multi-cluster.md)
- [Cross-state decryption](docs/guides/cross-state-decryption.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT