import json
import boto3
from botocore.exceptions import ClientError
import logging

from generate_key_pairs import GenerateKeyPairs


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings"]
__license__    = "MIT"
__maintainer__ = "Jeffrey Jonathan Jennings"
__email__      = "j3@thej3.com"
__status__     = "dev"


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)



def lambda_handler(event, context):
    """
    This AWS Lambda function creates two RSA key pairs (public and private), and then securely
    store them in AWS Secrets Manager.


    Args:
        event (dict): The event data passed to the Lambda function.
        context (object): The metadata about the invocation, function, and execution environment.

    Returns:
        statusCode: 200 for a successfully run of the function.
        body: List of the secret names updated by the function.
    """
    # Generate key pairs.
    key_pairs = GenerateKeyPairs(event.get("account"), event.get("user"))

    # Create a dictionary with the root secrets
    root_secret_value = {
        "account": event.get("account"),
        "user": event.get("user"),
        "rsa_public_key_1": key_pairs.get_snowflake_public_key_1_pem(),
        "rsa_public_key_2": key_pairs.get_snowflake_public_key_2_pem(),
    }
    
    root_secret_name = "/snowflake_resource" if event.get("secret_insert", "") == "" else "/snowflake_resource/" + event.get("secret_insert", "")

    # Store root secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        boto3.client('secretsmanager').get_secret_value(SecretId=root_secret_name)

        # If it exists, update the secret
        update_secret_string(root_secret_name, root_secret_value)
    except ClientError as e:
        raise e
        
    # Store RSA Private Key PEM 1 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        rsa_private_key_pem_1_branch_secret_name = f"{root_secret_name}/rsa_private_key_pem_1"
        boto3.client('secretsmanager').get_secret_value(SecretId=rsa_private_key_pem_1_branch_secret_name)

        # If it exists, update the secret
        update_secret_string(rsa_private_key_pem_1_branch_secret_name, key_pairs.get_private_key_pem_1())
    except ClientError as e:
        raise e
        
    # Store RSA Private Key PEM 2 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        rsa_private_key_pem_2_branch_secret_name = f"{root_secret_name}/rsa_private_key_pem_2"
        boto3.client('secretsmanager').get_secret_value(SecretId=rsa_private_key_pem_2_branch_secret_name)

        # If it exists, update the secret
        update_secret_string(rsa_private_key_pem_2_branch_secret_name, key_pairs.get_private_key_pem_2())
    except ClientError as e:
        raise e

    return {
        'statusCode': 200,
        'body': json.dumps(f'Root Secrets {root_secret_name}, RSA Private Key PEM 1 Branch Secrets {rsa_private_key_pem_1_branch_secret_name}, and RSA Private Key PEM 2 Branch Secrets {rsa_private_key_pem_2_branch_secret_name} written to Secrets Manager')
    }


def update_secret_string(secret_name, secret_value):
    """
    Update a secret in AWS Secrets Manager.

    Args:
        secret_name (string): AWS Secrets Manager secret name.
        secret_value (dict): AWS Secrets Manager secret value.

    Raises:
        e: when an error occurs while making a request to the 
        AWS Secrets Manager library.
    """
    try:
        response = boto3.client('secretsmanager').put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        logging.info("Updated secret: %s", response)
    except ClientError as e:
        logging.error("Failed to update secret: %s", e)
        raise e
