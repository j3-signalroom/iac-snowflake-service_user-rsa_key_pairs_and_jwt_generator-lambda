#!/bin/bash

#
# *** Script Syntax ***
# ./remove_test_secrets.sh --profile=<SSO_PROFILE_NAME>
#
#

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
    echo "(Error Message 001)  You did not include the proper use of the --profile=<SSO_PROFILE_NAME> argument in the call."
    echo
    echo "Usage:  Require all four arguments ---> `basename $0` --profile=<SSO_PROFILE_NAME>"
    echo
    exit 85 # Common GNU/Linux Exit Code for 'Interrupted system call should be restarted'
fi

# Set the AWS environment credential variables that are used
# by the AWS CLI commands to authenicate
aws sso login $AWS_PROFILE
eval $(aws2-wrap $AWS_PROFILE --export)
export AWS_REGION=$(aws configure get sso_region $AWS_PROFILE)
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

# Read SECRETS_PATH from the .env file
SECRETS_PATH=$(grep "^SECRETS_PATH=" .env | cut -d'=' -f2)

# Set the Snowflake secrets path to lower case
snowflake_secrets_path=$(echo $SECRETS_PATH | tr '[:upper:]' '[:lower:]')

# Force the delete of the AWS Secrets
aws secretsmanager delete-secret --secret-id ${snowflake_secrets_path} --force-delete-without-recovery || true
