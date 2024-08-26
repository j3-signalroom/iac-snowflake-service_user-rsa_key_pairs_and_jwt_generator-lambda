terraform {
    cloud {
      organization = "<TERRAFORM CLOUD ORGANIZATION NAME>"

        workspaces {
            name = "<TERRAFORM CLOUD ORGANIZATION's WORKSPACE NAME>"
        }
  }

  required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "~> 5.64.0"
        }
    }
}

locals {
  cloud = "AWS"
}
