import json
import logging

import boto3

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
    # Validate the input event.
    try:
        # Generate key pairs.
        account_identifier = event.get("account_identifier", "").upper()
        snowflake_user = event.get("snowflake_user", "").upper()
        secrets_path = event.get("secrets_path", "").lower()
        get_private_keys_from_aws_secrets = event.get("get_private_keys_from_aws_secrets", True)
    except KeyError as e:
        logger.error("Missing required parameter in event: %s", e)
        return {
            'statusCode': 400,
            'data': {},
            'message': "Missing required parameter."
        }
    
    try:
        key_pairs = GenerateKeyPairs(account_identifier, snowflake_user, secrets_path, boto3.client('secretsmanager'), get_private_keys_from_aws_secrets)
        http_status_code, message, data = key_pairs.update_secrets(boto3.client('secretsmanager'))

        return {
            'statusCode': http_status_code,
            'data': json.loads(data),
            'message': message
        }
    except Exception as e:
        # Return an error response.
        logger.error("Failed to generate keys and tokens.")
        logger.error("Error details: %s", e)
        
        # Return a 500 status code with the error message.
        return {
            'statusCode': 500,
            'data': {},
            'message': "Failed to generate keys and tokens."
        }
