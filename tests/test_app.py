import sys
import os
import jwt
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import logging
import pytest
from dotenv import load_dotenv
import os

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
    "user": "user",
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
    account_config[ACCOUNT_CONFIG["user"]] = os.getenv("USER")
    account_config[ACCOUNT_CONFIG["secret_insert"]] = os.getenv("SECRET_INSERT")


def test_generate_key_pairs():
    """Test the key pairs generation function.
    """
    key_pairs = GenerateKeyPairs(account_config[ACCOUNT_CONFIG["account_identifier"]], account_config[ACCOUNT_CONFIG["user"]])
    logger.info("Snowflake Private Key 1 PEM: \n%s", key_pairs.get_snowflake_private_key_1_pem())
    logger.info("Snowflake Public Key 1 PEM: \n%s", key_pairs.get_snowflake_public_key_1_pem())
    logger.info("Public Key 1 JWT: %s", key_pairs.get_jwt_token_1())
    logger.info("Public Key 2 JWT: %s", key_pairs.get_jwt_token_2())
    logger.info("Snowflake Private Key 2 PEM: \n%s", key_pairs.get_snowflake_private_key_2_pem())
    logger.info("Snowflake Public Key 2 PEM: \n%s", key_pairs.get_snowflake_public_key_2_pem())
    logger.info("Generated JWT Token 1: %s", key_pairs.get_jwt_token_1())  
    logger.info("Generated JWT Token 2: %s", key_pairs.get_jwt_token_2())
    logger.info("Generated a JWT 1 with the following payload: %s", jwt.decode(key_pairs.get_jwt_token_1(), key=key_pairs.get_private_key_1().public_key(), algorithms=["RS256"]))
    logger.info("Generated a JWT 2 with the following payload: %s", jwt.decode(key_pairs.get_jwt_token_2(), key=key_pairs.get_private_key_2().public_key(), algorithms=["RS256"]))

    # Check that the keys are not None
    assert key_pairs.get_snowflake_private_key_1_pem() is not None
    assert key_pairs.get_snowflake_public_key_1_pem() is not None
    assert key_pairs.get_snowflake_private_key_2_pem() is not None
    assert key_pairs.get_snowflake_public_key_2_pem() is not None
    assert key_pairs.get_jwt_token_1() is not None
    assert key_pairs.get_jwt_token_2() is not None
