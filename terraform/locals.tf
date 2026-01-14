# terraform/locals.tf

locals {
  common = {
    project_name = var.project_name
    environment  = var.environment
    region       = var.region
  }

  tags = {
    Environment      = local.common.environment
    Project          = local.common.project_name
    TerraformManaged = true
  }
}
