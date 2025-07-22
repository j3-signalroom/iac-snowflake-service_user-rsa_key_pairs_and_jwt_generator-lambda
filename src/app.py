import json
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
    # Validate the input event.
    try:
        # Generate key pairs.
        account_identifier = event.get("account_identifier", "").upper()
        snowflake_user = event.get("snowflake_user", "").upper()
        secret_insert = event.get("secret_insert", "").lower()
        get_private_keys_from_aws_secrets = event.get("get_private_keys_from_aws_secrets", True)
    except KeyError as e:
        logger.error("Missing required parameter in event: %s", e)
        return {
            'statusCode': 400,
            'body': json.dumps({
                'status': 'error',
                'message': f'Missing required parameter: {str(e)}'
            }),
            'message': "Missing required parameter."
        }
    
    try:
        key_pairs = GenerateKeyPairs(account_identifier, snowflake_user, get_private_keys_from_aws_secrets, secret_insert)
        http_status_code, body_json_string, message = key_pairs.update_secrets()

        return {
            'statusCode': http_status_code,
            'body': body_json_string,
            'message': message
        }
    except Exception as e:
        # Return an error response.
        logger.error("Failed to generate keys and tokens.")
        logger.error("Error details: %s", e)
        
        # Return a 500 status code with the error message.
        return {
            'statusCode': 500,
            'body': json.dumps({
                'status': 'error',
                'message': str(e)
            }),
            'message': "Failed to generate keys and tokens."
        }
