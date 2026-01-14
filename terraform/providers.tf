# terraform/providers.tf

provider "aws" {
  region = local.common.region

  default_tags {
    tags = local.tags
  }
}
