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
    account_identifier = event.get("account", "").upper()
    user = event.get("user", "").upper()
    secret_insert = event.get("secret_insert", "").lower()
    get_private_keys_from_aws_secrets = event.get("get_private_keys_from_aws_secrets", False)

    key_pairs = GenerateKeyPairs(account_identifier, user, get_private_keys_from_aws_secrets, secret_insert)

    # Create a dictionary with the root secrets
    root_secret_value = {
        "account": account_identifier,
        "user": user,
        "rsa_public_key_1": key_pairs.get_snowflake_public_key_1_pem(),
        "rsa_public_key_2": key_pairs.get_snowflake_public_key_2_pem(),
    }

    root_secret_name = "/snowflake_resource" if secret_insert == "" else "/snowflake_resource/" + secret_insert
    update_secret(f"{root_secret_name}", root_secret_value, False)
    update_secret(f"{root_secret_name}/rsa_private_key_pem_1", key_pairs.get_private_key_pem_1(), False)
    update_secret(f"{root_secret_name}/rsa_private_key_pem_2", key_pairs.get_private_key_pem_2(), False)
    update_secret(f"{root_secret_name}/rsa_private_key_1", key_pairs.get_private_key_1(), True)
    update_secret(f"{root_secret_name}/rsa_private_key_2", key_pairs.get_private_key_2(), True)
    
    return {
        'statusCode': 200,
        'body': 'success'
    }


def update_secret(secret_path: str, secret_value: any, is_binary: bool):
    """This function updates a secret in AWS Secrets Manager.

    Args:
        secret_path (str): The path to the secret in AWS Secrets Manager.
        secret_value (any): The value to be stored in the secret.
        is_binary (bool): Indicates if the secret value is binary.

    Raises:
        e: when an error occurs while making a request to the 
        AWS Secrets Manager library.
    """
    try:
        # Check if the secret already exists
        boto3.client('secretsmanager').get_secret_value(SecretId=secret_path)

        # If it exists, update the secret
        if is_binary:
            update_secret_binary(secret_path, secret_value)
        else:
            update_secret_string(secret_path, secret_value)
    except ClientError as e:
        raise e


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


def update_secret_binary(secret_name, secret_value):
    """
    Update a secret in AWS Secrets Manager.

    Args:
        secret_name (string): AWS Secrets Manager secret name.
        secret_value (bytes): AWS Secrets Manager secret value.

    Raises:
        e: when an error occurs while making a request to the 
        AWS Secrets Manager library.
    """
    try:
        response = boto3.client('secretsmanager').put_secret_value(
            SecretId=secret_name,
            SecretBinary=secret_value
        )
        logging.info("Updated secret: %s", response)
    except ClientError as e:
        logging.error("Failed to update secret: %s", e)
        raise e
