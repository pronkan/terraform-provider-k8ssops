output "secret_encrypted" {
  description = "The full SOPS-encrypted Kubernetes Secret manifest written to state."
  value       = k8ssops_secret.license.secret
  sensitive   = true
}

output "secret_raw" {
  description = "Decrypted key/value pairs stored in state (sensitive — never printed by default)."
  value       = k8ssops_secret.license.secret_raw
  sensitive   = true
}

output "plaintext_hash" {
  description = "SHA-256 hash of the plaintext inputs used for drift detection."
  value       = k8ssops_secret.license.plaintext_hash
  sensitive   = true
}

output "resource_id" {
  description = "Resource ID in namespace/name format."
  value       = k8ssops_secret.license.id
}

output "output_path" {
  description = "Path where the encrypted SOPS YAML was written on disk."
  value       = "${path.module}/gitops/app-license.enc.yaml"
}

# ---------------------------------------------------------------------------
# Data source outputs — k8ssops_secret
# ---------------------------------------------------------------------------
output "ds_secret_name" {
  description = "Kubernetes Secret name parsed from the decrypted manifest."
  value       = data.k8ssops_secret.license.name
}

output "ds_secret_namespace" {
  description = "Kubernetes Secret namespace parsed from the decrypted manifest."
  value       = data.k8ssops_secret.license.namespace
}

output "ds_secret_all_data" {
  description = "Merged key/value map of data + string_data from the decrypted Secret."
  value       = data.k8ssops_secret.license.all_data
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Data source outputs — k8ssops_decrypt
# ---------------------------------------------------------------------------
output "ds_environment" {
  description = "Single decrypted value for the 'environment' key."
  value       = data.k8ssops_decrypt.environment.plaintext
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Inline-YAML data source outputs
# ---------------------------------------------------------------------------
output "ds_inline_secret_name" {
  description = "Secret name parsed from the inline encrypted_yaml input."
  value       = data.k8ssops_secret.license_inline.name
}

output "ds_inline_secret_all_data" {
  description = "All decrypted key/value pairs from the inline encrypted_yaml input."
  value       = data.k8ssops_secret.license_inline.all_data
  sensitive   = true
}

output "ds_inline_tier" {
  description = "Single decrypted 'tier' value read from inline encrypted_yaml."
  value       = data.k8ssops_decrypt.tier_inline.plaintext
  sensitive   = true
}