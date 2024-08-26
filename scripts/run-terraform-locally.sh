#!/bin/bash

#
# *** Script Syntax ***
# scripts/run-terraform-locally.sh <create | delete> --profile=<SSO_PROFILE_NAME>
#
#

# Check required command (create or delete) was supplied
case $1 in
  create)
    create_action=true;;
  delete)
    create_action=false;;
  *)
    echo
    echo "(Error Message 001)  You did not specify one of the commands: create | delete."
    echo
    echo "Usage:  Require all four arguments ---> `basename $0` <create | delete> --profile=<SSO_PROFILE_NAME>"
    echo
    exit 85 # Common GNU/Linux Exit Code for 'Interrupted system call should be restarted'
    ;;
esac

# Get the arguments passed by shift to remove the first word
# then iterate over the rest of the arguments
shift
for arg in "$@" # $@ sees arguments as separate words
do
    case $arg in
        *"--profile="*)
            AWS_PROFILE=$arg;;
    esac
done

# Check required --profile argument was supplied
if [ -z $AWS_PROFILE ]
then
    echo
    echo "(Error Message 002)  You did not include the proper use of the --profile=<SSO_PROFILE_NAME> argument in the call."
    echo
    echo "Usage:  Require all four arguments ---> `basename $0 $1` --profile=<SSO_PROFILE_NAME>"
    echo
    exit 85 # Common GNU/Linux Exit Code for 'Interrupted system call should be restarted'
fi

# Set the AWS environment credential variables that are used
# by the AWS CLI commands to authenicate
aws sso login $AWS_PROFILE
eval $(aws2-wrap $AWS_PROFILE --export)
export AWS_REGION=$(aws configure get sso_region $AWS_PROFILE)
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

# Create terraform.tfvars file
printf "aws_account_id=\"${AWS_ACCOUNT_ID}\"\
\naws_profile=\"${AWS_PROFILE}\"\
\naws_region=\"${AWS_REGION}\"\
\naws_access_key_id=\"${AWS_ACCESS_KEY_ID}\"\
\naws_secret_access_key=\"${AWS_SECRET_ACCESS_KEY}\"\
\naws_session_token=\"${AWS_SESSION_TOKEN}\"" > terraform.tfvars

# Function to handle the repo exist error
repo_exist_handler() {
    aws ecr delete-repository --repository-name ${repo_name} ${AWS_PROFILE} --force || true
}

# Set the trap to catch repo exist error
trap 'repo_exist_handler' ERR

terraform init

# Execute the create or delete action
if [ "$create_action" = true ]
then
    #
    repo_name="iac-snowflake_user-rsa_key_generator"
    repo_url="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${repo_name}"

    #
    aws ecr create-repository --repository-name ${repo_name} ${AWS_PROFILE} || true
    aws ecr get-login-password --region ${AWS_REGION} ${AWS_PROFILE} | docker login --username AWS --password-stdin ${repo_url}
    docker build -t local.repo_name .
    docker tag local.repo_name:latest ${repo_url}:latest
    docker push ${repo_url}:latest

    # Create/Update/Destroy the Terraform configuration
    terraform plan -var-file=terraform.tfvars
    terraform apply -var-file=terraform.tfvars
else
    # Destroy the Terraform configuration
    terraform destroy -var-file=terraform.tfvars

    # Force the delete of the ECR Repository
    aws ecr delete-repository --repository-name ${repo_name} ${AWS_PROFILE} --force || true

    # Force the delete of the AWS Secret
    aws secretsmanager delete-secret --secret-id '/snowflake_resource' --force-delete-without-recovery || true
    aws secretsmanager delete-secret --secret-id '/snowflake_resource/rsa_private_key' --force-delete-without-recovery || true
fi
