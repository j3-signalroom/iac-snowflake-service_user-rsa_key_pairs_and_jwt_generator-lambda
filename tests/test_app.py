import os
import logging
import pytest
from dotenv import load_dotenv

from src.generate_key_pairs import GenerateKeyPairs


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings (J3)"]
__maintainer__ = "Jeffrey Jonathan Jennings (J3)"
__email__      = "j3@thej3.com"
__status__     = "dev"
 

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Account Config Keys.
ACCOUNT_CONFIG = {
    "account_identifier": "account_identifier",
    "snowflake_user": "snowflake_user",
    "secret_insert": "secret_insert"
}

# Initialize the global variables.
account_config = {}

@pytest.fixture(autouse=True)
def load_configurations():
    """
    Fixture to load configurations before each test.
    """
    # Load configurations here if needed
    load_dotenv()
 
    # Set the Snowflake Account Configuration.
    global account_config
    account_config[ACCOUNT_CONFIG["account_identifier"]] = os.getenv("ACCOUNT_IDENTIFIER")
    account_config[ACCOUNT_CONFIG["snowflake_user"]] = os.getenv("SNOWFLAKE_USER")
    account_config[ACCOUNT_CONFIG["secret_insert"]] = os.getenv("SECRET_INSERT")

    logger.info("Account Identifier: %s", account_config[ACCOUNT_CONFIG["account_identifier"]])
    logger.info("Snowflake User: %s", account_config[ACCOUNT_CONFIG["snowflake_user"]])
    logger.info("Secret Insert: %s", account_config[ACCOUNT_CONFIG["secret_insert"]])


def test_generate_key_pairs():
    """Test the key pairs generation function.
    """
    key_pairs = GenerateKeyPairs(account_config[ACCOUNT_CONFIG["account_identifier"]], account_config[ACCOUNT_CONFIG["snowflake_user"]])
    logger.info("Snowflake Private Key 1 PEM: \n%s\n", key_pairs.get_snowflake_private_key_1_pem())
    logger.info("Snowflake Public Key 1 PEM: \n%s\n", key_pairs.get_snowflake_public_key_1_pem())
    logger.info("Snowflake Private Key 2 PEM: \n%s\n", key_pairs.get_snowflake_private_key_2_pem())
    logger.info("Snowflake Public Key 2 PEM: \n%s\n", key_pairs.get_snowflake_public_key_2_pem())
    logger.info("Public Key 1 JWT: \n%s\n", key_pairs.get_jwt_token_1())
    logger.info("Public Key 2 JWT: \n%s\n", key_pairs.get_jwt_token_2())

    # Check that the keys are not None
    assert key_pairs.get_snowflake_private_key_1_pem() is not None
    assert key_pairs.get_snowflake_public_key_1_pem() is not None
    assert key_pairs.get_snowflake_private_key_2_pem() is not None
    assert key_pairs.get_snowflake_public_key_2_pem() is not None
    assert key_pairs.get_jwt_token_1() is not None
    assert key_pairs.get_jwt_token_2() is not None
