import subprocess
import json
import boto3
from botocore.exceptions import ClientError

secretsmanager_client = boto3.client('secretsmanager')

def lambda_handler(event, context):
    """_summary_

    Args:
        event (dict): The event data passed to the Lambda function.
        context (object): The metadata about the invocation, function, and execution environment.

    Returns:
        statusCode: _description_
        body: _description_
    """

    #
    root_secret_name = "/snowflake_resource"
    root_secret_account_key = "account"
    root_secret_user_key = "user"
    root_secret_rsa_public_key_1 = "rsa_public_key_1"
    root_secret_rsa_public_key_2 = "rsa_public_key_2"
    root_secret_account_value = event.get(root_secret_account_key)
    root_secret_user_value = event.get(root_secret_user_key)
    rsa_private_key_pem_1_branch_secret_name = "/snowflake_resource/rsa_private_key_pem_1"
    rsa_private_key_pem_2_branch_secret_name = "/snowflake_resource/rsa_private_key_pem_2"

    # Command to generate a 2048-bit RSA key and convert it to PKCS#8 format
    private_key_command = "openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -nocrypt"

    # Run the command to generate the private key pem 1
    private_key_pem_1_result = subprocess.run(private_key_command, shell=True, check=True, capture_output=True, text=True)

    # Run the command to generate the public key 1 from the private key pem 1
    public_key_1_result = subprocess.run(['openssl', 'rsa', '-pubout'], input=private_key_pem_1_result.stdout, capture_output=True, text=True, check=True)

    # Run the command to generate the private key pem 2
    private_key_pem_2_result = subprocess.run(private_key_command, shell=True, check=True, capture_output=True, text=True)

    # Run the command to generate the public key 2 from the private key pem 2
    public_key_2_result = subprocess.run(['openssl', 'rsa', '-pubout'], input=private_key_pem_2_result.stdout, capture_output=True, text=True, check=True)

    # Create a dictionary with the root secrets
    root_secret_value = {
        root_secret_account_key: root_secret_account_value,
        root_secret_user_key: root_secret_user_value,
        root_secret_rsa_public_key_1: public_key_1_result.stdout[27:398],
        root_secret_rsa_public_key_2: public_key_2_result.stdout[27:398]
    }
    
    # Store root secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        response = secretsmanager_client.get_secret_value(SecretId=root_secret_name)
        # If it exists, update the secret
        update_secret(root_secret_name, root_secret_value)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If the secret does not exist, create a new one
            create_secret(root_secret_name, root_secret_value)
        else:
            raise e
        
    # Store RSA Private Key PEM 1 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        response = secretsmanager_client.get_secret_value(SecretId=rsa_private_key_pem_1_branch_secret_name)
        # If it exists, update the secret
        update_secret(rsa_private_key_pem_1_branch_secret_name, private_key_pem_1_result.stdout)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If the secret does not exist, create a new one
            create_secret(rsa_private_key_pem_1_branch_secret_name, private_key_pem_1_result.stdout)
        else:
            raise e
        
    # Store RSA Private Key PEM 2 Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        response = secretsmanager_client.get_secret_value(SecretId=rsa_private_key_pem_2_branch_secret_name)
        # If it exists, update the secret
        update_secret(rsa_private_key_pem_2_branch_secret_name, private_key_pem_2_result.stdout)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If the secret does not exist, create a new one
            create_secret(rsa_private_key_pem_2_branch_secret_name, private_key_pem_2_result.stdout)
        else:
            raise e

    return {
        'statusCode': 200,
        'body': json.dumps(f'Root Secrets {root_secret_name}, RSA Private Key PEM 1 Branch Secrets {rsa_private_key_pem_1_branch_secret_name}, and RSA Private Key PEM 2 Branch Secrets {rsa_private_key_pem_2_branch_secret_name} written to Secrets Manager')
    }

def create_secret(secret_name, secret_value):
    """
    Create a new secret in AWS Secrets Manager.

    Args:
        secret_name (string): AWS Secrets Manager secret name.
        secret_value (dict): AWS Secrets Manager secret value.

    Raises:
        e: when an error occurs while making a request to the 
        AWS Secrets Manager library.
    """

    try:
        response = secretsmanager_client.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_value)
        )
        print(f"Created secret: {response}")
    except ClientError as e:
        print(f"Failed to create secret: {e}")
        raise e

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
        response = secretsmanager_client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        print(f"Updated secret: {response}")
    except ClientError as e:
        print(f"Failed to update secret: {e}")
        raise e