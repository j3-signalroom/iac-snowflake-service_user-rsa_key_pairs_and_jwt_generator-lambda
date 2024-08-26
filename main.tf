terraform {
    cloud {
      #organization = "<TERRAFORM CLOUD ORGANIZATION NAME>"
      organization = "signalroom"

        workspaces {
            #name = "<TERRAFORM CLOUD ORGANIZATION's WORKSPACE NAME>"
            name = "aws-lambda-ecr-workspace"
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
  cloud     = "AWS"
  repo_name = "iac-snowflake_user-rsa_key_generator"
}
