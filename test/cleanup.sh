#!/bin/bash

# Cleanup script to remove all Terraform execution artifacts
# Ensures clean provider test runs by removing state files, lock files, and cache directories

echo "Cleaning up Terraform artifacts..."

# Remove .terraform directory
if [ -d ".terraform" ]; then
    rm -rf .terraform
    echo "Removed .terraform directory"
fi

# Remove .terraform.lock.hcl
if [ -f ".terraform.lock.hcl" ]; then
    rm -f .terraform.lock.hcl
    echo "Removed .terraform.lock.hcl"
fi

# Remove all terraform.tfstate files (including backups)
if ls terraform.tfstate* 1> /dev/null 2>&1; then
    rm -f terraform.tfstate*
    echo "Removed terraform.tfstate files"
fi

# Remove any other .terraform.* files
if ls .terraform.* 1> /dev/null 2>&1; then
    rm -f .terraform.*
    echo "Removed .terraform.* files"
fi

if [ -f "gitops/app-license.enc.yaml" ]; then
    rm -f gitops/app-license.enc.yaml
    echo "Removed gitops/app-license.enc.yaml"
fi

echo "Cleanup complete!"
