import logging
import pytest

from src.app import generate_jwt


__copyright__  = "Copyright (c) 2025 Jeffrey Jonathan Jennings"
__credits__    = ["Jeffrey Jonathan Jennings (J3)"]
__maintainer__ = "Jeffrey Jonathan Jennings (J3)"
__email__      = "j3@thej3.com"
__status__     = "dev"
 

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.fixture(autouse=True)
def load_configurations():
    """
    Fixture to load configurations before each test.
    """
    # Load configurations here if needed
    pass


def test_generate_rsa_key_pairs():
    """
    Test the RSA key pair generation function.
    """
    from src.app import generate_rsa_key_pairs

    private_key_pem_1_result, public_key_1_fingerprint, private_key_1, snowflake_public_key_1_pem, private_key_pem_2_result, public_key_2_fingerprint, private_key_2, snowflake_public_key_2_pem = generate_rsa_key_pairs()

    logger.info("Private Key 1 PEM: \n%s", private_key_pem_1_result)
    logger.info("Public Key 1 Fingerprint: %s", public_key_1_fingerprint)
    logger.info("Snowflake Public Key 1 PEM: \n%s", snowflake_public_key_1_pem)
    logger.info("JWT for Public Key 1: %s", generate_jwt(public_key_1_fingerprint, private_key_1, "test_account", "test_user"))
    logger.info("Private Key 2 PEM: \n%s", private_key_pem_2_result)
    logger.info("Public Key 2 Fingerprint: %s", public_key_2_fingerprint)
    logger.info("JWT for Public Key 2: %s", generate_jwt(public_key_2_fingerprint, private_key_2, "test_account", "test_user")) 
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
