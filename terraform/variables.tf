// terraform/variables.tf

variable "project_name" {
  description = "Project name used for naming and tags."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
}

variable "region" {
  description = "AWS region for all resources."
  type        = string
}

variable "logging_namespace" {
  description = "Namespace for Fluent Bit and log shipping."
  type        = string
}

variable "fluent_bit_service_account" {
  description = "Service account name for Fluent Bit."
  type        = string
}
