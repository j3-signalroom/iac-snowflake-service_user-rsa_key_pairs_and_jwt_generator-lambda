import json
import os
import logging
import pytest
import boto3
from botocore.exceptions import SSOTokenLoadError, ProfileNotFound
from dotenv import load_dotenv

from src.generate_key_pairs import GenerateKeyPairs


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings (J3)"]
__maintainer__ = "Jeffrey Jonathan Jennings (J3)"
__email__      = "j3@thej3.com"
__status__     = "production/stable"
 

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Account Config Keys.
ACCOUNT_CONFIG = {
    "snowflake_account_identifier": "snowflake_account_identifier",
    "snowflake_admin_service_user": "snowflake_admin_service_user",
    "secrets_path": "secrets_path"
}

# Initialize the global variables.
account_config = {}

@pytest.fixture(autouse=True)
def load_configurations():
    """Fixture to load configurations before each test."""
    # Load configurations here if needed
    load_dotenv()
 
    # Set the AWS profile name for SSO.
    global sso_profile_name
    sso_profile_name = os.getenv("SSO_PROFILE_NAME", "")

    # Set the Snowflake Account Configuration.
    global account_config
    account_config[ACCOUNT_CONFIG["snowflake_account_identifier"]] = os.getenv("SNOWFLAKE_ACCOUNT_IDENTIFIER")
    account_config[ACCOUNT_CONFIG["snowflake_admin_service_user"]] = os.getenv("SNOWFLAKE_USER")
    account_config[ACCOUNT_CONFIG["secrets_path"]] = os.getenv("SECRETS_PATH")

    logger.info("Snowflake Account Identifier: %s", account_config[ACCOUNT_CONFIG["snowflake_account_identifier"]])
    logger.info("Snowflake User: %s", account_config[ACCOUNT_CONFIG["snowflake_admin_service_user"]])
    logger.info("Secrets Path: %s", account_config[ACCOUNT_CONFIG["secrets_path"]])


def test_generate_key_pairs():
    """Test the key pairs generation function."""
    key_pairs = GenerateKeyPairs(account_config[ACCOUNT_CONFIG["snowflake_account_identifier"]], account_config[ACCOUNT_CONFIG["snowflake_admin_service_user"]], account_config[ACCOUNT_CONFIG["secrets_path"]])
    logger.info("Snowflake RSA Public Key 1 PEM: \n%s\n", key_pairs.get_snowflake_rsa_public_key_1_pem())
    logger.info("Snowflake RSA Public Key 2 PEM: \n%s\n", key_pairs.get_snowflake_rsa_public_key_2_pem())
    logger.info("RSA JWT 1: \n%s\n", key_pairs.get_rsa_jwt_1())
    logger.info("RSA JWT 2: \n%s\n", key_pairs.get_rsa_jwt_2())
    logger.info("RSA Private Key 1: \n%s\n", key_pairs.get_rsa_private_key_1())
    logger.info("RSA Private Key 2: \n%s\n", key_pairs.get_rsa_private_key_2())
    logger.info("RSA Private Key 1 PEM: \n%s\n", key_pairs.get_rsa_private_key_1_pem())
    logger.info("RSA Private Key 2 PEM: \n%s\n", key_pairs.get_rsa_private_key_2_pem())

    # Check that the keys are not None
    assert key_pairs.get_snowflake_rsa_public_key_1_pem() is not None
    assert key_pairs.get_snowflake_rsa_public_key_2_pem() is not None
    assert key_pairs.get_rsa_private_key_1() is not None
    assert key_pairs.get_rsa_private_key_2() is not None
    assert key_pairs.get_rsa_private_key_1_pem() is not None
    assert key_pairs.get_rsa_private_key_2_pem() is not None
    assert key_pairs.get_rsa_jwt_1() is not None
    assert key_pairs.get_rsa_jwt_2() is not None


def create_sso_session(profile_name: str) -> boto3.Session:
        """Create SSO session or fail with clear message"""
        try:
            session = boto3.Session(profile_name=profile_name)
            # Validate SSO token by making a call
            sts = session.client('sts')
            sts.get_caller_identity()
            return session
        except ProfileNotFound:
            pytest.fail(f"SSO profile '{profile_name}' not found. Configure in ~/.aws/config")
        except SSOTokenLoadError:
            pytest.fail(f"SSO token expired for '{profile_name}'. Run: aws sso login --profile {profile_name}")


def test_sso_authentication():
    """Test SSO authentication for each environment"""
    session = create_sso_session(sso_profile_name)
    
    sts = session.client('sts')
    identity = sts.get_caller_identity()
    
    # Verify SSO response structure
    assert 'Account' in identity
    assert 'UserId' in identity
    assert 'Arn' in identity
    assert 'assumed-role' in identity['Arn']  # SSO always creates assumed roles
    
    logger.info(f"Account {identity['Account']}, Role {identity['Arn'].split('/')[-2]}")


def test_generate_key_pairs_with_secret_insert():
    """Test the key pairs generation function with secret insert."""
    session = create_sso_session(sso_profile_name)

    key_pairs = GenerateKeyPairs(account_config[ACCOUNT_CONFIG["snowflake_account_identifier"]], account_config[ACCOUNT_CONFIG["snowflake_admin_service_user"]], account_config[ACCOUNT_CONFIG["secrets_path"]])
    http_status_code, message, data = key_pairs.update_secrets(session.client('secretsmanager'))

    logger.info("HTTP Status Code: %s", http_status_code)
    logger.info("JSON: %s", json.dumps(data, indent=4))
    logger.info("Message: %s", message)
