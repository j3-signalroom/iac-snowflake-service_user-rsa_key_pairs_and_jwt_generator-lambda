import json
import logging
import pytest
import requests
from dotenv import load_dotenv
import os
from src.app import generate_key_pairs, generate_jwt


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
    "organization_name": "organization_name",
    "account": "account"
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
    account_config[ACCOUNT_CONFIG["organization_name"]] = os.getenv("ORGANIZATION_NAME")
    account_config[ACCOUNT_CONFIG["account"]] = os.getenv("ACCOUNT")
    

def test_generate_key_pairs():
    """Test the key pairs generation function.
    """
    private_key_pem_1_result, public_key_1_fingerprint, private_key_1, snowflake_public_key_1_pem, private_key_pem_2_result, public_key_2_fingerprint, private_key_2, snowflake_public_key_2_pem = generate_key_pairs()

    logger.info("Private Key 1 PEM: \n%s", private_key_pem_1_result)
    logger.info("Public Key 1 Fingerprint: %s", public_key_1_fingerprint)
    logger.info("Snowflake Public Key 1 PEM: \n%s", snowflake_public_key_1_pem)
    logger.info("Public Key 1 JWT: %s", generate_jwt(public_key_1_fingerprint, private_key_1, "test_account", "test_user"))
    logger.info("Private Key 2 PEM: \n%s", private_key_pem_2_result)
    logger.info("Public Key 2 Fingerprint: %s", public_key_2_fingerprint)
    logger.info("Public Key 2 JWT: %s", generate_jwt(public_key_2_fingerprint, private_key_2, "test_account", "test_user")) 
    logger.info("Snowflake Public Key 2 PEM: \n%s", snowflake_public_key_2_pem)

    # Check that the keys are not None
    assert private_key_pem_1_result is not None
    assert public_key_1_fingerprint is not None
    assert private_key_1 is not None
    assert snowflake_public_key_1_pem is not None
    assert private_key_pem_2_result is not None
    assert public_key_2_fingerprint is not None
    assert private_key_2 is not None
    assert snowflake_public_key_2_pem is not None   


def test_restful_api_with_jwt():
    from src.app import generate_key_pairs

    _, public_key_1_fingerprint, private_key_1, _, _, _, _, _ = generate_key_pairs()

    account_identifier = f"{account_config[ACCOUNT_CONFIG["organization_name"]]}-{account_config[ACCOUNT_CONFIG["account"]]}"

    jwt_token = generate_jwt(public_key_1_fingerprint, private_key_1, account_config[ACCOUNT_CONFIG["account"]], "TABLEFLOW_KICKSTARTER")
    jwt_token = json.loads(jwt_token)['jwt']
    url = f"https://{account_identifier}.snowflakecomputing.com/api/v2/databases"

    logger.info("Generated JWT Token: %s", jwt_token)  
    logger.info("Request URL: %s", url)

    response = requests.get(url=url,
                            headers={"Content-Type": "application/json",
                                     "Authorization": f"Bearer {jwt_token}",
                                     "Accept": "application/json",
                                     "User-Agent": "Tableflow-AWS-Glue-Kickstarter-External-Volume",
                                     "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT"})

    logger.info("Response Status Code: %s", response.status_code)
    logger.info("Response JSON: %s", response.json())
    assert response.status_code == 200
    assert response.json() == {"message": "Success"}

    # Check that the JWT token is not None
    assert jwt_token is not None
    assert isinstance(jwt_token, str) and len(jwt_token) > 0, "JWT token should be a non-empty string"
    
    # Additional assertions can be added based on the expected behavior of your API