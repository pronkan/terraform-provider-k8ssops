variable "kms_alias" {
  description = "AWS KMS key Alias used to encrypt the Kubernetes secret via SOPS."
  type        = string
  # Set via: export TF_VAR_kms_alias="alias/aws/s3"
  # Or pass -var="kms_alias=alias/aws/s3" on the CLI.
}

variable "environment" {
  description = "Target deployment environment label written into string_data."
  type        = string
  default     = "production"
}

variable "aws_profile" {
  description = "Default AWS profile"
  type = string
  default = "default"
}

variable "aws_region" {
  description = "Default AWS region"
  type = string
  default = "us-east-1"
}
