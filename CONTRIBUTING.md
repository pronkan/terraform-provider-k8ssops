# Contributing to terraform-provider-k8ssops

## Prerequisites

| Tool | Version | Notes |
|---|---------|---|
| Go | 1.25+   | Required to build and test |
| Terraform | 1.5+    | Required for `make cycle` and acceptance tests |
| GNU Make | any     | Used to run build targets |
| AWS credentials | —       | Required for `make cycle` and integration tests; needs `kms:GenerateDataKey` on the test key |

Unit tests use an offline AES-256-GCM path and require no cloud credentials. Integration tests
require AWS credentials and a valid KMS key alias set via `TF_VAR_kms_alias`.

## Build targets

```bash
# Compile the provider binary
make build

# Run all unit tests (offline; no AWS credentials required)
make test

# Build, install to ~/.terraform.d/plugins, and run terraform apply in test/
# Requires: TF_VAR_kms_alias, AWS credentials with kms:GenerateDataKey
make cycle
```

`make cycle` installs the binary under the local mirror path that Terraform looks up for
`pronkan/k8ssops` and then runs `terraform -chdir=test apply -auto-approve`. Inspect the `test/`
directory to understand the full resource and data source configuration exercised by this target.

## Code organisation

```text
internal/
  provider/         Terraform plugin-framework resources and data sources
    provider.go     Provider schema and Configure implementation
    resource_secret.go  k8ssops_secret resource (CRUD + ModifyPlan + ImportState)
    datasource_secret.go  k8ssops_secret data source
    datasource_decrypt.go  k8ssops_decrypt data source
    helpers.go      Shared helpers: KMS config resolution, file I/O, path validation
  sopsengine/       SOPS encryption/decryption wrapper
    sopsengine.go   Encrypt, DecryptState, CalculateHash, AES-256-GCM offline path
  k8sgen/           Kubernetes manifest generation and manipulation
    fallback.go     MergeStringData and ExtractSecretRaw
test/               Integration test module (uses pronkan/k8ssops from local mirror)
```

## PR conventions

- **One resource or feature per PR.** A PR that adds a new KMS provider should contain only that
  change plus its tests and documentation update.
- **Table-driven tests are required** for any new behaviour in `sopsengine` or `k8sgen`. See
  existing `_test.go` files for the expected pattern.
- **Unit tests must pass without cloud credentials.** Use the offline AES-256-GCM path (supply a
  32-byte hex key via `age.keys` or `age_keys`) for all new test cases.
- **Update documentation** in `docs/` for any schema change before the PR is merged. The Registry
  renders documentation directly from the `docs/` tree.
- **Sensitive attributes must be marked `Sensitive: true`** in the framework schema. Never add a
  new attribute that holds a secret without this flag.

## How to add a new KMS provider backend

The following steps are required to add support for a new KMS provider (e.g. GCP Cloud KMS):

1. **`internal/sopsengine/sopsengine.go`** — add the new key type to `KMSConfig` and implement
   the encryption and decryption branches in `Encrypt` and `DecryptState`. Mirror the existing
   AWS KMS pattern: build master keys from the config list, add them to a `sops.KeyGroup`, and
   wire them into the SOPS tree.

2. **`internal/provider/provider.go`** — the provider-level block for the new backend already
   exists in the schema (e.g. `gcp`, `azure`, `vault`) marked as `PLACEHOLDER`. Remove the
   placeholder note from the `MarkdownDescription` and implement `Configure` wiring if the backend
   requires credentials beyond what is already in the provider model struct.

3. **`internal/provider/helpers.go`** — update `applyProviderDefaults` to propagate the new
   backend's keys and credentials from the provider model to `sopsengine.KMSConfig`. Add a
   corresponding block in `resolveKMS` and `resolveKMSFromLists` if resource- or data-source-level
   overrides are needed.

4. **Tests** — add table-driven unit tests in `internal/sopsengine/sopsengine_test.go` covering
   at minimum: successful encryption, successful decryption, and error on missing key. Add an
   acceptance test in `internal/provider/` if real credentials are available in CI.

5. **Documentation** — update `docs/index.md` to remove the "not yet implemented" warning from
   the relevant provider block section. Add an example to `docs/resources/secret.md` and update
   the getting-started guide if the authentication flow differs from AWS KMS.

## Reporting issues

Open a GitHub issue with:
- Terraform and provider version
- The HCL configuration (redact sensitive values)
- The full error output from `TF_LOG=DEBUG terraform apply`
- AWS region and KMS key type (CMK vs. managed key, single-region vs. multi-region)