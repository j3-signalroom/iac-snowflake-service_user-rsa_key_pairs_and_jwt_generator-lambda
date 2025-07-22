import base64
import hashlib
from datetime import datetime, timedelta, timezone
import json
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import boto3
from botocore.exceptions import ClientError
import logging


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


class GenerateKeyPairs():
    """This class is responsible for generating RSA key pairs and JWTs for Snowflake authentication.
    It uses the `cryptography` library to generate the keys and the `PyJWT` library to create JWTs.
    """

    def __init__(self, account_identifier: str, snowflake_user: str, get_private_keys_from_aws_secrets: bool = False, secret_insert: str = ""):
        """Initialize the GenerateKeyPairs class.

        Args:
            account_identifier (str): The account identifier for the Snowflake user.
            snowflake_user (str): The username for the Snowflake user.
            get_private_keys_from_aws_secrets (bool): If True, retrieve private keys from AWS Secrets Manager.
            secret_insert (str): Optional suffix to append to the secret path in AWS Secrets Manager.
        """
        self.account_identifier = account_identifier.upper()
        self.snowflake_user = snowflake_user.upper()
        self.root_secrets_path = "/snowflake_resource" if secret_insert == "" else "/snowflake_resource/" + secret_insert

        if get_private_keys_from_aws_secrets:
            self.__get_private_keys_from_aws_secrets(secret_insert.lower())
        else:
            self.__generate_key_pairs()

        logger.info("Snowflake Private Key 1 PEM: \n%s\n", self.get_snowflake_private_key_1_pem())
        logger.info("Snowflake Public Key 1 PEM: \n%s\n", self.get_snowflake_public_key_1_pem())
        logger.info("Snowflake Private Key 2 PEM: \n%s\n", self.get_snowflake_private_key_2_pem())
        logger.info("Snowflake Public Key 2 PEM: \n%s\n", self.get_snowflake_public_key_2_pem())
        logger.info("Private Key 1: \n%s\n", self.get_private_key_1())
        logger.info("Private Key 2: \n%s\n", self.get_private_key_2())
        logger.info("Private Key PEM 1: \n%s\n", self.get_private_key_pem_1())
        logger.info("Private Key PEM 2: \n%s\n", self.get_private_key_pem_2())

        # Generate the JWT tokens using the private keys.
        self.jwt_token_1 = self.__generate_jwt(self.get_private_key_1(), self.get_private_key_pem_1())
        self.jwt_token_2 = self.__generate_jwt(self.get_private_key_2(), self.get_private_key_pem_2())

    def update_secrets(self) -> Tuple[int, str, str]:
        try:
            # Create a dictionary with the root secrets
            root_secret_value = {
                "account_identifier": self.account_identifier,
                "snowflake_user": self.snowflake_user,
                "rsa_public_key_1": self.snowflake_public_key_1_pem,
                "rsa_public_key_2": self.snowflake_public_key_2_pem,
            }

            result = {
                "account_identifier": self.account_identifier,
                "snowflake_user": self.snowflake_user,
                "root_secrets_path": self.root_secrets_path,
                "rsa_public_key_pem_1": self.snowflake_public_key_1_pem,
                "rsa_public_key_pem_2": self.snowflake_public_key_2_pem,
                "rsa_private_key_pem_1": self.private_key_pem_1,
                "rsa_private_key_pem_2": self.private_key_pem_2,
                "rsa_private_key_1": self.private_key_1,
                "rsa_private_key_2": self.private_key_2,
                "jwt_token_1": self.jwt_token_1,
                "jwt_token_2": self.jwt_token_2
            }

            # Update the root secret with the account identifier, user, and public keys in the AWS Secrets Manager.
            self.__update_secret(f"{self.root_secrets_path}", root_secret_value, False)
            self.__update_secret(f"{self.root_secrets_path}/rsa_private_key_pem_1", self.private_key_pem_1, False)
            self.__update_secret(f"{self.root_secrets_path}/rsa_private_key_pem_2", self.private_key_pem_2, False)
            self.__update_secret(f"{self.root_secrets_path}/rsa_private_key_1", self.private_key_1, True)
            self.__update_secret(f"{self.root_secrets_path}/rsa_private_key_2", self.private_key_2, True)
            logger.info("Successfully updated secrets in AWS Secrets Manager.")
            
            # Return the result as a JSON response.
            return 200, json.dumps(result, indent=4, sort_keys=True), "Generated keys and tokens successfully."
        except Exception as e:
            return 500, str(e), "Failed to update secrets in AWS Secrets Manager."

    def get_root_secrets_path(self) -> str:
        """Returns the root secrets path."""
        return self.root_secrets_path
    
    def get_private_key_1(self) -> rsa.RSAPrivateKey:
        """Returns the private key 1."""
        return self.private_key_1

    def get_private_key_pem_1(self) -> bytes:
        """Returns the private key PEM 1."""
        return self.private_key_pem_1

    def get_private_key_pem_1_result(self) -> str:
        """Returns the private key PEM 1 result."""
        return self.private_key_pem_1_result
    
    def get_snowflake_private_key_1_pem(self) -> str:
        """Returns the Snowflake private key 1 PEM."""
        return self.snowflake_private_key_1_pem

    def get_snowflake_public_key_1_pem(self) -> str:
        """Returns the Snowflake public key 1 PEM."""
        return self.snowflake_public_key_1_pem

    def get_jwt_token_1(self) -> str:
        """Returns the generated JWT token 1."""
        return self.jwt_token_1

    def get_private_key_2(self) -> rsa.RSAPrivateKey:
        """Returns the private key 2."""
        return self.private_key_2

    def get_private_key_pem_2(self) -> bytes:
        """Returns the private key PEM 2."""
        return self.private_key_pem_2

    def get_snowflake_private_key_2_pem(self) -> str:
        """Returns the Snowflake private key 2 PEM."""
        return self.snowflake_private_key_2_pem

    def get_snowflake_public_key_2_pem(self) -> str:
        """Returns the Snowflake public key 2 PEM."""
        return self.snowflake_public_key_2_pem

    def get_jwt_token_2(self) -> str:
        """Returns the generated JWT token 2."""
        return self.jwt_token_2


    def __generate_key_pairs(self):
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
        """
        # Generate the private key PEM 1.
        self.private_key_1 = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.private_key_pem_1 = self.private_key_1.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_pem_1_result = self.private_key_pem_1.decode()

        self.snowflake_private_key_1_pem = self.private_key_pem_1_result[27:(len(self.private_key_pem_1_result)-26)].replace("\n", "").replace("\r", "")

        # Generate the public key PEM 1.
        self.public_key_pem_1 = self.private_key_1.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_1_pem_result = self.public_key_pem_1.decode()

        # RSA public key 1; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
        # so only one continuous string remains, which meet Snowflake's requirements
        self.snowflake_public_key_1_pem = self.public_key_1_pem_result[27:(len(self.public_key_1_pem_result)-25)].replace("\n", "").replace("\r", "")

        # Generate the private key PEM 2.
        self.private_key_2 = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.private_key_pem_2 = self.private_key_2.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_pem_2_result = self.private_key_pem_2.decode()

        self.snowflake_private_key_2_pem = self.private_key_pem_2_result[27:(len(self.private_key_pem_2_result)-26)].replace("\n", "").replace("\r", "")

        # Generate the public key PEM 2.
        self.public_key_pem_2 = self.private_key_2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_2_pem_result = self.public_key_pem_2.decode()

        # RSA public key 2; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
        # so only one continuous string remains, which meet Snowflake's requirements
        self.snowflake_public_key_2_pem = self.public_key_2_pem_result[27:(len(self.public_key_2_pem_result)-25)].replace("\n", "").replace("\r", "")

    def __to_public_key_fingerprint(self, private_key_pem: rsa.RSAPrivateKey) -> str:
        """Generate a public key fingerprint from the provided private key PEM.

        Args:
            private_key_pem (rsa.RSAPrivateKey): The RSA private key used to derive the public key.

        Returns:
            str: The base64-encoded SHA-256 fingerprint of the public key.
        """
        # Get the public key from the private key.
        public_key_raw = private_key_pem.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Get the sha256 hash of the raw bytes.
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_raw)

        # Base64-encode the value and prepend the prefix 'SHA256:'.
        return 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')

    def __generate_jwt(self, pem: rsa.RSAPrivateKey, pem_bytes: bytes) -> str:
        """Generate a JWT token using the provided private key PEM and account/user information.

        Args:
            pem (rsa.RSAPrivateKey): The RSA private key used to sign the JWT.
            pem_bytes (bytes): The PEM-encoded private key bytes.

        Returns:
            str: The generated JWT token.
        """
        # Create the account identifier.
        issuer = f"{self.account_identifier}.{self.snowflake_user}"

        # Get current time in UTC and set JWT lifetime to 59 minutes.
        now = datetime.now(timezone.utc)
        lifetime = timedelta(minutes=59)

        # Create JWT payload
        payload = {
            "iss": f"{issuer}.{self.__to_public_key_fingerprint(pem)}",
            "sub": issuer,
            "iat": int(now.timestamp()),
            "exp": int((now + lifetime).timestamp())
        }

        return jwt.encode(payload, key=pem_bytes, algorithm="RS256")

    def __get_private_keys_from_aws_secrets(self, secret_insert: str):
        """Retrieve private keys from AWS Secrets Manager.

        Args:
            secret_insert (str): Suffix to append to the secret path.
        """
        logger.info("Retrieving private keys from AWS Secrets Manager.")

        # Construct the root secret name based on the secret_insert value.
        root_secrets_path = "/snowflake_resource" if secret_insert == "" else "/snowflake_resource/" + secret_insert

        # Retrieve the private keys from AWS Secrets Manager.
        secrets = self.__get_aws_secret(root_secrets_path)
        secrets_json = json.loads(secrets)
        self.account_identifier = secrets_json.get("account_identifier", "").upper()
        self.snowflake_user = secrets_json.get("snowflake_user", "").upper()
        self.private_key_1 = self.__get_aws_secret(f"{root_secrets_path}/rsa_private_key_1")
        self.private_key_2 = self.__get_aws_secret(f"{root_secrets_path}/rsa_private_key_2")
        self.private_key_pem_1 = self.__get_aws_secret(f"{root_secrets_path}/rsa_private_key_pem_1")
        self.private_key_pem_2 = self.__get_aws_secret(f"{root_secrets_path}/rsa_private_key_pem_2")

    def __get_aws_secret(self, secret_path: str):
        """Retrieve a secret from AWS Secrets Manager.

        Args:
            secret_path (str): The path to the secret in AWS Secrets Manager.

        Returns:
            str: The secret value, either as a string or binary data.
        
        Raises:
            ClientError: If there is an error retrieving the secret.
        """
        try:
            # Check if the secret already exists
            response = boto3.client('secretsmanager').get_secret_value(SecretId=secret_path)
            if 'SecretString' in response:
                secret = response['SecretString']
            else:
                # Handle binary data, potentially base64 decoding
                secret = response['SecretBinary']

            return secret
        except ClientError as e:
            raise e
        
    def __update_secret(self, secret_path: str, secret_value: any, is_binary: bool):
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
                self.__update_secret_binary(secret_path, secret_value)
            else:
                self.__update_secret_string(secret_path, secret_value)
        except ClientError as e:
            logger.error("Secret %s does not exist. Creating a new secret.", secret_path)
            logger.error("Error details: %s", e)
            raise e
    
    def __update_secret_string(self, secret_name, secret_value):
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
            logging.info("Updated %s secret: %s", secret_name, response)
        except ClientError as e:
            logging.error("Failed to update %s secret: %s", secret_name, e)
            raise e

    def __update_secret_binary(self, secret_name, secret_value):
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
            logging.info("Updated %s secret: %s", secret_name, response)
        except ClientError as e:
            logging.error("Failed to update %s secret: %s", secret_name, e)
            raise e
