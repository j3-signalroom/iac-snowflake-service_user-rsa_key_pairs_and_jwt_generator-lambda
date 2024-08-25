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
    root_secret_tf_user_key = "tf_user"
    root_secret_rsa_public_key = "rsa_public_key"
    root_secret_account_value = event.get(root_secret_account_key)
    root_secret_tf_user_value = event.get(root_secret_tf_user_key)
    rsa_private_key_branch_secret_name = "/snowflake_resource/rsa_private_key"

    # Command to generate a 2048-bit RSA key and convert it to PKCS#8 format
    private_key_command = "openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -nocrypt"

    # Run the command to generate the private key
    private_key_result = subprocess.run(private_key_command, shell=True, check=True, capture_output=True, text=True)

    # Run the command to generate the public key from the private key
    public_key_result = subprocess.run(['openssl', 'rsa', '-pubout'], input=private_key_result.stdout, capture_output=True, text=True, check=True)

    # Create a dictionary with the root secrets
    root_secret_value = {
        root_secret_account_key: root_secret_account_value,
        root_secret_tf_user_key: root_secret_tf_user_value,
        root_secret_rsa_public_key: public_key_result.stdout[27:398]
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
        
    # Store RSA Private Key Branch Secrets in the AWS Secrets Manager
    try:
        # Check if the secret already exists
        response = secretsmanager_client.get_secret_value(SecretId=rsa_private_key_branch_secret_name)
        # If it exists, update the secret
        update_secret(rsa_private_key_branch_secret_name, private_key_result.stdout)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If the secret does not exist, create a new one
            create_secret(rsa_private_key_branch_secret_name, private_key_result.stdout)
        else:
            raise e

    return {
        'statusCode': 200,
        'body': json.dumps(f'Root Secrets {root_secret_name} and RSA Private Key Branch Secrets {rsa_private_key_branch_secret_name} written to Secrets Manager')
    }

def create_secret(secret_name, secret_value):
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
    try:
        response = secretsmanager_client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        print(f"Updated secret: {response}")
    except ClientError as e:
        print(f"Failed to update secret: {e}")
        raise e