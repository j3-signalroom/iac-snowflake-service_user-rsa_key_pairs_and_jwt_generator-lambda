import json
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging
from typing import Tuple


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
    # Generate RSA key pairs.
    private_key_pem_1_result, snowflake_public_key_1_pem, private_key_pem_2_result, snowflake_public_key_2_pem = generate_rsa_key_pairs()

    # Create a dictionary with the root secrets
    root_secret_value = {
        "account": event.get("account"),
        "user": event.get("user"),
        "rsa_public_key_1": snowflake_public_key_1_pem,
        "rsa_public_key_2": snowflake_public_key_2_pem
    }
    
    root_secret_name = "/snowflake_resource" if event.get("secret_insert", "") == "" else "/snowflake_resource/" + event.get("secret_insert", "")

    # Store root secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        boto3.client('secretsmanager').get_secret_value(SecretId=root_secret_name)

        # If it exists, update the secret
        update_secret(root_secret_name, root_secret_value)
    except ClientError as e:
        raise e
        
    # Store RSA Private Key PEM 1 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        rsa_private_key_pem_1_branch_secret_name = f"{root_secret_name}/rsa_private_key_pem_1"
        boto3.client('secretsmanager').get_secret_value(SecretId=rsa_private_key_pem_1_branch_secret_name)

        # If it exists, update the secret
        update_secret(rsa_private_key_pem_1_branch_secret_name, private_key_pem_1_result)
    except ClientError as e:
        raise e
        
    # Store RSA Private Key PEM 2 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        rsa_private_key_pem_2_branch_secret_name = f"{root_secret_name}/rsa_private_key_pem_2"
        boto3.client('secretsmanager').get_secret_value(SecretId=rsa_private_key_pem_2_branch_secret_name)

        # If it exists, update the secret
        update_secret(rsa_private_key_pem_2_branch_secret_name, private_key_pem_2_result)
    except ClientError as e:
        raise e

    return {
        'statusCode': 200,
        'body': json.dumps(f'Root Secrets {root_secret_name}, RSA Private Key PEM 1 Branch Secrets {rsa_private_key_pem_1_branch_secret_name}, and RSA Private Key PEM 2 Branch Secrets {rsa_private_key_pem_2_branch_secret_name} written to Secrets Manager')
    }


def update_secret(secret_name, secret_value):
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
        logging.error("Updated secret: %s", response)
    except ClientError as e:
        logging.error("Failed to update secret: %s", e)
        raise e
    

def generate_rsa_key_pairs() -> Tuple[str, str, str, str]:
    """Generate an RSA key pairs.

    Returns:
        Tuple[str, str, str, str]: A tuple containing the private key PEM 1, public key PEM 1,
        private key PEM 2, and public key PEM 2.
    """
    # Generate the private key PEM 1.
    private_key_1 = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )
    private_key_pem_1 = private_key_1.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_pem_1_result = private_key_pem_1.decode()

    # Generate the public key PEM 1.
    public_key_pem_1 = private_key_1.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_1_pem_result = public_key_pem_1.decode()

    # RSA public key 1; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
    # so only one continuous string remains, which meet Snowflake's requirements
    snowflake_public_key_1_pem = public_key_1_pem_result[27:(len(public_key_1_pem_result)-25)].replace("\n", "").replace("\r", "")

    # Generate the private key PEM 2.
    private_key_2 = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )
    private_key_pem_2 = private_key_2.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_pem_2_result = private_key_pem_2.decode()

    # Generate the public key PEM 2.
    public_key_pem_2 = private_key_2.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_2_pem_result = public_key_pem_2.decode()

    # RSA public key 2; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
    # so only one continuous string remains, which meet Snowflake's requirements
    snowflake_public_key_2_pem = public_key_2_pem_result[27:(len(public_key_2_pem_result)-25)].replace("\n", "").replace("\r", "")

    return private_key_pem_1_result, snowflake_public_key_1_pem, private_key_pem_2_result, snowflake_public_key_2_pem
