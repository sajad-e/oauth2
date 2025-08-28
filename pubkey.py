import os
import time
import json
import requests
from threading import Thread
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class PublicKey:
    """
    Handles fetching, refreshing, and storing a remote RSA public key.

    The public key is periodically retrieved from a configured URL and
    updated in memory. It runs in a background thread to ensure the key
    is refreshed without blocking the main application.
    """

    def __init__(self):
        """
        Start the background thread to fetch and update the public key.
        """
        # Run public_key() in a separate thread so it refreshes continuously
        Thread(target=self.public_key, args=()).start()
        self.pubkey = None  # Will hold the PEM-encoded public key

    def public_key(self):
        """
        Continuously fetch and refresh the public key from the remote server.

        Uses configuration from `pubkey.json`, which should define:
            - pubkey_url: The URL to fetch the public key (JWKS format).
            - failed_delay: Retry interval (seconds) if request fails.
            - success_delay: Refresh interval (seconds) when successful.

        The fetched key is converted from modulus (n) and exponent (e)
        into an RSA public key and stored as PEM bytes.
        """
        # Load configuration for public key retrieval
        conf = PublicKey.conf("pubkey.json")

        while True:
            try:
                # Fetch JWKS (JSON Web Key Set) from remote server
                resp: dict = requests.get(conf.get("pubkey_url")).json()
            except Exception as e:
                # If request fails, wait and retry
                print(e.__str__())
                time.sleep(conf.get("failed_delay"))
                continue

            # Extract first key from JWKS response
            key: dict = resp.get("keys")[0]
            n_b64: str = key.get("n")  # Base64url-encoded modulus
            e_b64: str = key.get("e")  # Base64url-encoded exponent

            # Convert base64url values into integers
            n_int = int.from_bytes(base64url_decode(n_b64.encode()), byteorder="big")
            e_int = int.from_bytes(base64url_decode(e_b64.encode()), byteorder="big")

            # Construct RSA public key from modulus & exponent
            public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
            public_key = public_numbers.public_key(backend=default_backend())

            # Store the key in PEM format for JWT verification
            self.pubkey = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Wait before refreshing again
            time.sleep(conf.get("success_delay"))

    @staticmethod
    def conf(file: str) -> dict:
        """
        Load JSON configuration from the `config` directory.

        Args:
            file (str): The name of the configuration file.

        Returns:
            dict: Parsed configuration as a dictionary.
        """
        with open(os.path.dirname(__file__) + f"/config/{file}") as file:
            return json.load(file)
