import base64
import hashlib
from datetime import datetime, timedelta, timezone
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import boto3
from botocore.exceptions import ClientError


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings"]
__license__    = "MIT"
__maintainer__ = "Jeffrey Jonathan Jennings"
__email__      = "j3@thej3.com"
__status__     = "dev"


class GenerateKeyPairs():
    """
    This class is responsible for generating RSA key pairs and JWTs for Snowflake authentication.
    It uses the `cryptography` library to generate the keys and the `PyJWT` library to create JWTs.
    """

    def __init__(self, account_identifier: str, user: str, get_private_keys_from_aws_secrets: bool = False, secret_insert: str = ""):
        self.account_identifier = account_identifier.upper()
        self.user = user.upper()

        if get_private_keys_from_aws_secrets:
            self.__get_private_keys_from_aws_secrets(secret_insert)
        else:
            self.__generate_key_pairs()

        self.jwt_token_1 = self.__generate_jwt(self.get_private_key_1(), self.get_private_key_pem_1())
        self.jwt_token_2 = self.__generate_jwt(self.get_private_key_2(), self.get_private_key_pem_2())

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

    def __to_public_key_fingerprint(self, private_key_pem) -> str:
        # Get the raw bytes of public key.
        public_key_raw = private_key_pem.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Get the sha256 hash of the raw bytes.
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_raw)

        # Base64-encode the value and prepend the prefix 'SHA256:'.
        return 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')

    def __generate_jwt(self, pem, pem_bytes: bytes) -> str:
        """ Generate a JSON Web Token (JWT) using the provided public key fingerprint, private key,
        account, and user information.
        """
        # Create the account identifier.
        issuer = f"{self.account_identifier}.{self.user}"

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
        """ Retrieve private keys from AWS Secrets Manager. """

        root_secret_name = "/snowflake_resource" if secret_insert == "" else "/snowflake_resource/" + secret_insert

        # Retrieve the private keys from AWS Secrets Manager.
        secrets = self.__get_aws_secret(root_secret_name)
        secrets_json = json.loads(secrets)
        self.account_identifier = secrets_json.get("account", "").upper()
        self.user = secrets_json.get("user", "").upper()
        self.private_key_1 = self.__get_aws_secret(f"{root_secret_name}/rsa_private_key_1")
        self.private_key_2 = self.__get_aws_secret(f"{root_secret_name}/rsa_private_key_2")
        self.private_key_pem_1 = self.__get_aws_secret(f"{root_secret_name}/rsa_private_key_pem_1")
        self.private_key_pem_2 = self.__get_aws_secret(f"{root_secret_name}/rsa_private_key_pem_2")

    def __get_aws_secret(self, secret_path: str):
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
