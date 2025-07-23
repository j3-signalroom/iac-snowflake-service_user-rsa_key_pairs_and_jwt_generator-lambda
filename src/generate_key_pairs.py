import base64
import hashlib
from datetime import datetime, timedelta, timezone
import json
from typing import Dict, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
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

    def __init__(self, account_identifier: str, snowflake_user: str, secrets_path: str):
        """Initialize the GenerateKeyPairs class.

        Args:
            account_identifier (str): The account identifier for the Snowflake user.
            snowflake_user (str): The username for the Snowflake user.
            secrets_path (str): The secret path in AWS Secrets Manager.
        """
        self.account_identifier = account_identifier.upper()
        self.snowflake_user = snowflake_user.upper()
        self.secrets_path = secrets_path

        self.__generate_key_pairs()

        logger.info("Snowflake RSA Public Key 1 PEM: \n%s\n", self.get_snowflake_rsa_public_key_1_pem())
        logger.info("Snowflake RSA Public Key 2 PEM: \n%s\n", self.get_snowflake_rsa_public_key_2_pem())
        logger.info("RSA Private Key 1: \n%s\n", self.get_rsa_private_key_1())
        logger.info("RSA Private Key 2: \n%s\n", self.get_rsa_private_key_2())
        logger.info("RSA Private Key PEM 1: \n%s\n", self.get_rsa_private_key_pem_1())
        logger.info("RSA Private Key PEM 2: \n%s\n", self.get_rsa_private_key_pem_2())

        # Generate the JWT tokens using the private keys.
        self.rsa_jwt_1 = self.__generate_jwt(self.get_rsa_private_key_1(), self.get_rsa_private_key_pem_1())
        self.rsa_jwt_2 = self.__generate_jwt(self.get_rsa_private_key_2(), self.get_rsa_private_key_pem_2())

    def update_secrets(self, client) -> Tuple[int, str, Dict]:
        """Update the secrets in AWS Secrets Manager with the generated keys and tokens.

        Args:
            client (boto3.client): Boto3 client for AWS Secrets Manager.
            
        Returns:
            Tuple[int, str, str]: HTTP status code, JSON string of the updated secrets, and a message.
        """
        try:
            # Create a dictionary with the root secrets
            secrets = {
                "account_identifier": self.account_identifier,
                "snowflake_user": self.snowflake_user,
                "secrets_path": self.secrets_path,
                "snowflake_rsa_public_key_1": self.snowflake_rsa_public_key_1_pem,
                "snowflake_rsa_public_key_2": self.snowflake_rsa_public_key_2_pem,
                "rsa_private_key_pem_1": base64.b64encode(self.rsa_private_key_pem_1).decode('utf-8'),
                "rsa_private_key_pem_2": base64.b64encode(self.rsa_private_key_pem_2).decode('utf-8'),
            }

            # Update the root secret with the account identifier, user, and public keys in the AWS Secrets Manager.
            self.__update_secret(client, self.secrets_path, secrets)

            secrets["rsa_jwt_1"] = self.rsa_jwt_1
            secrets["rsa_jwt_2"] = self.rsa_jwt_2
            
            # Return the result as a JSON response.
            return 200, "Generated keys and tokens successfully.", secrets
        except Exception:
            return 500, "Failed to update secrets in AWS Secrets Manager.", {}

    def get_secrets_path(self) -> str:
        """Returns the secrets path."""
        return self.secrets_path
    
    def get_rsa_private_key_1(self) -> rsa.RSAPrivateKey:
        """Returns the RSA private key 1."""
        return self.rsa_private_key_1

    def get_rsa_private_key_pem_1(self) -> bytes:
        """Returns the RSA private key PEM 1."""
        return self.rsa_private_key_pem_1

    def get_snowflake_rsa_public_key_1_pem(self) -> str:
        """Returns the Snowflake public key 1 PEM."""
        return self.snowflake_rsa_public_key_1_pem

    def get_rsa_jwt_1(self) -> str:
        """Returns the generated RSA JWT token 1."""
        return self.rsa_jwt_1

    def get_rsa_private_key_2(self) -> rsa.RSAPrivateKey:
        """Returns the RSA private key 2."""
        return self.rsa_private_key_2

    def get_rsa_private_key_pem_2(self) -> bytes:
        """Returns the RSA private key PEM 2."""
        return self.rsa_private_key_pem_2

    def get_snowflake_rsa_public_key_2_pem(self) -> str:
        """Returns the Snowflake RSA public key 2 PEM."""
        return self.snowflake_rsa_public_key_2_pem

    def get_rsa_jwt_2(self) -> str:
        """Returns the generated RSA JWT token 2."""
        return self.rsa_jwt_2


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
        self.rsa_private_key_1 = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.rsa_private_key_pem_1 = self.rsa_private_key_1.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )

        # Generate the public key PEM 1.
        public_key_pem_1 = self.rsa_private_key_1.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_1_pem_result = public_key_pem_1.decode()

        # RSA public key 1; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
        # so only one continuous string remains, which meet Snowflake's requirements
        self.snowflake_rsa_public_key_1_pem = public_key_1_pem_result[27:(len(public_key_1_pem_result)-25)].replace("\n", "").replace("\r", "")

        # Generate the private key PEM 2.
        self.rsa_private_key_2 = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.rsa_private_key_pem_2 = self.rsa_private_key_2.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )

        # Generate the public key PEM 2.
        public_key_pem_2 = self.rsa_private_key_2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_2_pem_result = public_key_pem_2.decode()

        # RSA public key 2; used for key-pair authentication.  Strips line-feeds, carriage returns, and the header and footer.
        # so only one continuous string remains, which meet Snowflake's requirements
        self.snowflake_rsa_public_key_2_pem = public_key_2_pem_result[27:(len(public_key_2_pem_result)-25)].replace("\n", "").replace("\r", "")

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

    def __update_secret(self, client, secrets_path: str, value: Dict):
        """This function updates a secret in AWS Secrets Manager.

        Args:
            client (boto3.client): Boto3 client for AWS Secrets Manager.
            secrets_path (str): The path to the secrets in AWS Secrets Manager.
            value (Dict): The value to be stored in the secret.
        """
        try:
            # Check if the secret already exists
            client.get_secret_value(SecretId=secrets_path)

            # If it exists, update the secret
            try:
                response = client.put_secret_value(
                    SecretId=secrets_path,
                    SecretString=json.dumps(value)
                )
                logging.info("Updated %s secret: %s", secrets_path, response)
            except ClientError as e:
                logging.error("Failed to update %s secret: %s", secrets_path, e)
        except ClientError:
            logger.info("Secret %s does not exist. Creating a new secret.", secrets_path)
            try:
                response = client.create_secret(Name=secrets_path, SecretString=json.dumps(value))
                logger.info("Secret %s created successfully.", secrets_path)
                logger.info("Secret ARN: %s", response['ARN'])
            except ClientError as e:
                logger.error("Failed to create secret %s: %s", secrets_path, e)
    