import json
import time
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import boto3
from botocore.exceptions import ClientError
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
    private_key_pem_1_result, public_key_1_fingerprint, private_key_1, snowflake_public_key_1_pem, private_key_pem_2_result, public_key_2_fingerprint, private_key_2, snowflake_public_key_2_pem = generate_rsa_key_pairs()

    # Create a dictionary with the root secrets
    root_secret_value = {
        "account": event.get("account"),
        "user": event.get("user"),
        "rsa_public_key_1": snowflake_public_key_1_pem,
        "public_key_1_fingerprint": generate_jwt(public_key_1_fingerprint, private_key_1, event.get("account"), event.get("user")),
        "rsa_public_key_2": snowflake_public_key_2_pem,
        "public_key_2_fingerprint": generate_jwt(public_key_2_fingerprint, private_key_2, event.get("account"), event.get("user")),
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
        logging.info("Updated secret: %s", response)
    except ClientError as e:
        logging.error("Failed to update secret: %s", e)
        raise e
    

def generate_rsa_key_pairs() -> Tuple[str, str, any, str, str, any, str]:
    """The function uses the `cryptography` library to generate the RSA keys. It creates two private keys,
    each with a size of 2048 bits and a public exponent of 65537. The private keys are serialized
    to PEM format without encryption, and the public keys are also serialized to PEM format.

    The function returns the private key PEMs, public key fingerprints, and the public keys formatted
    for Snowflake. The public keys are stripped of line feeds, carriage returns, and the header and footer,
    resulting in a continuous string that meets Snowflake's requirements for key-pair authentication.

    The fingerprints of the public keys are computed as base64-encoded SHA-256 hashes of the public keys
    in DER format. These fingerprints are used for JWT creation and storage in AWS Secrets Manager.

    Note:
    - The function does not handle any exceptions that may occur during key generation or serialization.
    - The generated keys are suitable for use in secure communications, such as JWT authentication with Snowflake.

    The function also computes the public key fingerprints, which are used for JWT creation and
    storage in AWS Secrets Manager. The fingerprints are base64-encoded SHA-256 hashes of the
    public keys in DER format.

    Returns:
        Tuple[str, str, any, str, str, any, str]: A tuple containing:
            - private_key_pem_1_result: The private key PEM for the first key pair.
            - public_key_1_fingerprint: The fingerprint of the public key for the first key pair.
            - private_key_1: The private key object for the first key pair.
            - snowflake_public_key_1_pem: The public key PEM for the first key pair, formatted for Snowflake.
            - private_key_pem_2_result: The private key PEM for the second key pair.
            - public_key_2_fingerprint: The fingerprint of the public key for the second key pair.
            - private_key_2: The private key object for the second key pair.
            - snowflake_public_key_2_pem: The public key PEM for the second key pair, formatted for Snowflake.
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

    # Get the public key 1 for fingerprinting.
    public_key_1 = private_key_1.public_key()
    
    # Get the public key fingerprint.
    # This is used to create the JWT and to store in the AWS Secrets Manager.
    # The fingerprint is a base64-encoded SHA-256 hash of the public key in DER format.
    public_key_1_der = public_key_1.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_1_fingerprint = base64.b64encode(hashlib.sha256(public_key_1_der).digest()).decode('utf-8').rstrip('=')

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

    # Get the public key 2 for fingerprinting.
    public_key_2 = private_key_2.public_key()
    
    # Get the public key fingerprint.
    # This is used to create the JWT and to store in the AWS Secrets Manager.
    # The fingerprint is a base64-encoded SHA-256 hash of the public key in DER format.
    public_key_2_der = public_key_2.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_2_fingerprint = base64.b64encode(hashlib.sha256(public_key_2_der).digest()).decode('utf-8').rstrip('=')

    # RSA public key 2; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
    # so only one continuous string remains, which meet Snowflake's requirements
    snowflake_public_key_2_pem = public_key_2_pem_result[27:(len(public_key_2_pem_result)-25)].replace("\n", "").replace("\r", "")

    return private_key_pem_1_result, public_key_1_fingerprint, private_key_1, snowflake_public_key_1_pem, private_key_pem_2_result, public_key_2_fingerprint, private_key_2, snowflake_public_key_2_pem


def generate_jwt(public_key_fingerprint: str, private_key, account: str, user: str) -> str:
    """    Generate a JSON Web Token (JWT) using the provided public key fingerprint, private key,
    account, and user information.

    Args:
        public_key_fingerprint (str): The fingerprint of the public key used for JWT creation.
        private_key: The private key used to sign the JWT.
        account (str): The Snowflake account identifier.
        user (str): The Snowflake user identifier.

    Returns:
        str: A JSON string containing the generated JWT.
    """
    # Create JWT header
    header = {
        "alg": "RS256",
        "typ": "JWT"
    }
    
    # Create JWT payload
    now = int(time.time())
    payload = {
        "iss": f"{account}.{user}.SHA256:{public_key_fingerprint}",
        "sub": f"{account}.{user}",
        "iat": now,
        "exp": now + 3600  # 1 hour expiration
    }
    
    # Encode header and payload
    def base64url_encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    
    header_encoded = base64url_encode(header)
    payload_encoded = base64url_encode(payload)
    
    # Create signature
    message = f"{header_encoded}.{payload_encoded}".encode()
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    # Return complete JWT
    return json.dumps({"jwt": f"{header_encoded}.{payload_encoded}.{signature_encoded}"})