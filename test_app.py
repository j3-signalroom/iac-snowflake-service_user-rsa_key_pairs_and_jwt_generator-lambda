import logging
import pytest


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
    from app import generate_rsa_key_pairs

    private_key_pem_1_result, public_key_1_pem_result, private_key_pem_2_result, public_key_2_pem_result = generate_rsa_key_pairs()

    logger.info("Private Key 1 PEM: \n%s", private_key_pem_1_result)
    logger.info("Public Key 1 PEM: \n%s", public_key_1_pem_result)
    logger.info("Private Key 2 PEM: \n%s", private_key_pem_2_result)
    logger.info("Public Key 2 PEM: \n%s", public_key_2_pem_result)

    # Check that the keys are not None
    assert private_key_pem_1_result is not None
    assert public_key_1_pem_result is not None
    assert private_key_pem_2_result is not None
    assert public_key_2_pem_result is not None