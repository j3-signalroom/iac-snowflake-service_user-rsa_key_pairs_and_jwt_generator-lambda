import sys
import os

import jwt
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import logging
import pytest
import requests
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

    # Check that the keys are not None
    assert key_pairs.get_snowflake_private_key_1_pem() is not None
    assert key_pairs.get_snowflake_public_key_1_pem() is not None
    assert key_pairs.get_snowflake_private_key_2_pem() is not None
    assert key_pairs.get_snowflake_public_key_2_pem() is not None


def test_restful_api_with_jwt():
    account_identifier = account_config[ACCOUNT_CONFIG["account_identifier"]]
    user = account_config[ACCOUNT_CONFIG["user"]]

    key_pairs = GenerateKeyPairs(account_identifier, user)

    url = f"https://{account_identifier}.snowflakecomputing.com/api/v2/statements"

    logger.info("Generated JWT Token: %s", key_pairs.get_jwt_token_1())  
    logger.info("Request URL: %s", url)
    logger.info("Generated a JWT with the following payload: %s", jwt.decode(key_pairs.get_jwt_token_1(), key=key_pairs.get_private_key_1().public_key(), algorithms=["RS256"]))

    response = requests.post(url=url,
                             headers={"Content-Type": "application/json",
                                      "Authorization": f"Bearer {key_pairs.get_jwt_token_1()}",
                                      "Accept": "application/json",
                                      "User-Agent": "Tableflow-AWS-Glue-Kickstarter-External-Volume",
                                      "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT"},
                             json={"statement": "SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_WAREHOUSE()",
                                   "timeout": 60,
                                   "resultSetMetaData": {
                                       "format": "json"
                                   }})

    logger.info("Response Status Code: %s", response.status_code)
    logger.info("Response JSON: %s", response.json())

    assert response.status_code == 200
    assert response.json() == {"message": "Success"}
    assert key_pairs.get_jwt_token_1() is not None
    assert isinstance(key_pairs.get_jwt_token_1(), str) and len(key_pairs.get_jwt_token_1()) > 0, "JWT token should be a non-empty string"
