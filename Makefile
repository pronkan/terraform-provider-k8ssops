# Makefile for terraform-provider-k8ssops
#
# Usage:
#   make build       — compile and install the provider binary
#   make test        — run Go unit tests
#   make cycle       — build, init, and apply (rapid iteration loop)
#   make help        — show all available targets
#
# Prerequisites:
#   - Go toolchain (https://go.dev/dl/)
#   - Terraform CLI (https://developer.hashicorp.com/terraform/install)
#   - golangci-lint (https://golangci-lint.run/usage/install/) for `make lint`
#   - jq (optional) for pretty-printing Terraform JSON output

.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

VERSION		 := 0.1.0
GOOS         := $(shell go env GOOS)
GOARCH       := $(shell go env GOARCH)
ARCHITECTURE := $(GOOS)_$(GOARCH)
BINARY_NAME  := terraform-provider-k8ssops_v$(VERSION)
INSTALL_DIR  := ~/.terraform.d/plugins/registry.terraform.io/pronkan/k8ssops/$(VERSION)/$(ARCHITECTURE)
INSTALL_PATH := $(INSTALL_DIR)/$(BINARY_NAME)
TEST_DIR     := ./test
GO_PKG       := github.com/pronkan/terraform-provider-k8ssops

export TF_VAR_kms_alias ?= alias/aws/thisObviouslyNotARealAlias
export TF_VAR_aws_profile ?= default
export TF_VAR_aws_region ?= us-east-1

# Guard: ensure TF_VAR_kms_alias is set before any Terraform mutating operation.
# Defined as a variable so it can be referenced in multiple targets.
define require_kms_alias
	@if [ -z "$$TF_VAR_kms_alias" ]; then \
		echo ""; \
		echo "ERROR: TF_VAR_kms_alias is not set."; \
		echo "       Export it before running this target:"; \
		echo "         export TF_VAR_kms_alias=<your-kms-alias>"; \
		echo ""; \
		exit 1; \
	fi
endef

# -----------------------------------------------------------------------------
# .PHONY declarations
# -----------------------------------------------------------------------------

.PHONY: build install test test/race \
        tf/init tf/apply tf/destroy tf/clean tf/plan tf/output \
        cycle clean lint fmt help

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

## build: Compile the provider and install it to the local Terraform plugin directory
build:
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p $(INSTALL_DIR)
	go build -o $(INSTALL_PATH) .
	@echo "==> Installed to $(INSTALL_PATH)"

## install: Alias for build — creates the plugin directory and installs the binary
install: build

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------

## test: Run Go unit tests for all internal packages (verbose, no cache)
test:
	@echo "==> Running unit tests..."
	go test ./internal/... -v -count=1

## test/race: Run Go unit tests with the race detector enabled
test/race:
	@echo "==> Running unit tests with race detector..."
	go test -race ./internal/... -v -count=1

# -----------------------------------------------------------------------------
# Terraform
# -----------------------------------------------------------------------------

## tf/init: Initialize the Terraform working directory under ./test
tf/init:
	@echo "==> Initializing Terraform in $(TEST_DIR)..."
	terraform -chdir=test init

## tf/plan: Show the Terraform execution plan (requires TF_VAR_kms_alias)
tf/plan:
	$(call require_kms_alias)
	@echo "==> Running Terraform plan in $(TEST_DIR)..."
	terraform -chdir=test plan

## tf/apply: Apply the Terraform configuration (requires TF_VAR_kms_alias)
tf/apply:
	$(call require_kms_alias)
	@echo "==> Applying Terraform configuration in $(TEST_DIR)..."
	terraform -chdir=test apply -auto-approve
	@echo ""
	@echo "==> Encrypted secret output:"
	@terraform -chdir=test output -json secret_encrypted | jq -r '.' || true

## tf/destroy: Destroy all Terraform-managed resources (requires TF_VAR_kms_alias)
tf/destroy:
	$(call require_kms_alias)
	@echo "==> Destroying Terraform resources in $(TEST_DIR)..."
	terraform -chdir=test destroy -auto-approve

## tf/clean: Remove Terraform state files, lock files, and generated GitOps YAML manifests
tf/clean:
	@echo "==> Cleaning Terraform working directory..."
	@cd test/ && bash cleanup.sh
	@echo "==> Removing generated GitOps manifests (gitops/*.yaml)..."
	@cd test/ && rm -f gitops/*.yaml
	@echo "==> Clean complete."

## tf/output: Show Terraform outputs (non-sensitive inline; sensitive via jq)
tf/output:
	@echo "==> resource_id:"
	@terraform -chdir=test output resource_id || true
	@echo ""
	@echo "==> output_path:"
	@terraform -chdir=test output output_path || true
	@echo ""
	@echo "==> secret_encrypted (sensitive — shown via JSON):"
	@terraform -chdir=test output -json secret_encrypted | jq -r '.' || true
	@echo ""
	@echo "==> secret_raw (sensitive — decrypted KV pairs):"
	@terraform -chdir=test output -json secret_raw | jq -r '.' || true
	@echo ""
	@echo "==> ds_secret_all_data (sensitive — merged data from data source):"
	@terraform -chdir=test output -json ds_secret_all_data | jq -r '.' || true
	@echo ""
	@echo "==> ds_environment (sensitive — single decrypted value):"
	@terraform -chdir=test output -json ds_environment | jq -r '.' || true

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

## cycle: Full iteration loop — build the provider, init Terraform, then apply
cycle: clean install tf/init tf/apply tf/output

## clean: Remove the installed provider binary and clean the Terraform working directory
clean:
	@echo "==> Removing installed binary at $(INSTALL_PATH)..."
	@rm -f $(INSTALL_PATH)
	$(MAKE) tf/clean

## lint: Run go vet and golangci-lint (golangci-lint must be installed separately)
lint:
	@echo "==> Running go vet..."
	go vet ./...
	@echo "==> Running golangci-lint..."
	@# Install: https://golangci-lint.run/usage/install/
	golangci-lint run ./...

## fmt: Format all Go source files with gofmt
fmt:
	@echo "==> Formatting Go source files..."
	gofmt -w .

## help: Show this help message (parsed from ## comments on each target)
help:
	@echo ""
	@echo "terraform-provider-k8ssops — available targets:"
	@echo ""
	@grep -E '^##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ": "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' \
		| sed 's/## //'
	@echo ""
	@echo "Environment variables:"
	@echo "  \033[33mTF_VAR_kms_alias\033[0m     (required for tf/apply, tf/destroy, tf/plan)"
	@echo "  \033[33mTF_VAR_environment\033[0m   (optional, defaults to \"production\")"
	@echo ""
