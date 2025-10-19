import logging
import boto3

from generate_key_pairs import GenerateKeyPairs


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings"]
__license__    = "MIT"
__maintainer__ = "Jeffrey Jonathan Jennings"
__email__      = "j3@thej3.com"
__status__     = "production/stable"


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
        # Retrieve parameters from the event.
        snowflake_account_identifier = event.get("snowflake_account_identifier", "").upper()
        snowflake_admin_service_user = event.get("snowflake_admin_service_user", "").upper()
        secrets_path = event.get("secrets_path", "").lower()
    except KeyError as e:
        # Return a 400 status code with the error message.
        message = f"Missing required parameter in event: {e}"
        logger.error(message)
        return {
            'statusCode': 400,
            'data': {},
            'message': message
        }
    
    logger.info("Account Identifier: %s", snowflake_account_identifier)
    logger.info("Snowflake Admin User: %s", snowflake_admin_service_user)
    logger.info("Secrets Path: %s", secrets_path)

    try:
        # Generate key pairs.
        key_pairs = GenerateKeyPairs(snowflake_account_identifier, snowflake_admin_service_user, secrets_path)

        # Store the keys in AWS Secrets Manager.
        http_status_code, message, data = key_pairs.update_secrets(boto3.client('secretsmanager'))

        return {
            # Return the status code, data, and message.
            'statusCode': http_status_code,
            'data': data,
            'message': message
        }
    except Exception as e:
        # Return an error response.
        message = f"Failed to generate keys and tokens, because {e}"
        logger.error(message)
        
        # Return a 500 status code with the error message.
        return {
            'statusCode': 500,
            'data': {},
            'message': message
        }
