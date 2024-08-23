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
    secret_name = event.get('secret_name')
    secret_private_key = event.get('secret_private_key')
    secret_public_key = event.get('secret_public_key')

    # Command to generate a 2048-bit RSA key and convert it to PKCS#8 format
    private_key_command = "openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -nocrypt"

    # Run the command to generate the private key
    private_key_result = subprocess.run(private_key_command, shell=True, check=True, capture_output=True, text=True)

    # Run the command to generate the public key from the private key
    public_key_result = subprocess.run(['openssl', 'rsa', '-pubout'], input=private_key_result.stdout, capture_output=True, text=True, check=True)

    # Create a dictionary with the private and public keys
    secret_value = {
        secret_private_key: private_key_result.stdout,
        secret_public_key: public_key_result.stdout
    }
    
    try:
        # Check if the secret already exists
        response = secretsmanager_client.get_secret_value(SecretId=secret_name)
        # If it exists, update the secret
        update_secret(secret_name, secret_value)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If the secret does not exist, create a new one
            create_secret(secret_name, secret_value)
        else:
            raise e

    return {
        'statusCode': 200,
        'body': json.dumps(f'Secret {secret_name} written to Secrets Manager')
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