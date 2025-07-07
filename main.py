import argparse
import logging
import json
import time
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API endpoints and rate limits (requests per second)
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY")  # Securely retrieve API key
ETHERSCAN_RATE_LIMIT = 5  # Etherscan allows 5 requests/second for free tier
BLOCKCHAIR_API_URL = 'https://api.blockchair.com/ethereum/'
BLOCKCHAIR_RATE_LIMIT = 2  # Blockchair rate limit is around 2 requests/second. Check their API docs

# Global variable to track last API call time
last_api_call_time = 0


def rate_limit(api_name, rate_limit_rps):
    """
    Implements basic rate limiting.  Adjust the sleep time if needed to comply
    with the API rate limits.
    """
    global last_api_call_time
    now = time.time()
    time_since_last_call = now - last_api_call_time

    if time_since_last_call < (1 / rate_limit_rps):
        sleep_time = (1 / rate_limit_rps) - time_since_last_call
        logging.info(f"Rate limiting {api_name}. Sleeping for {sleep_time:.2f} seconds.")
        time.sleep(sleep_time)

    last_api_call_time = time.time()


def fetch_etherscan_data(address, api_key=ETHERSCAN_API_KEY):
    """
    Fetches data from Etherscan API.
    """
    if not api_key:
        logging.error("Etherscan API key not found. Please set the ETHERSCAN_API_KEY environment variable.")
        return None

    try:
        rate_limit("Etherscan", ETHERSCAN_RATE_LIMIT)
        url = f"{ETHERSCAN_API_URL}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={api_key}"

        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if data['status'] == '1':
            logging.info(f"Successfully fetched Etherscan data for address: {address}")
            return data['result']
        else:
            logging.warning(f"Etherscan API error for address {address}: {data['message']}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching Etherscan data for address {address}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching Etherscan data for address {address}: {e}")
        return None


def fetch_blockchair_data(address):
    """
    Fetches data from Blockchair API.
    """
    try:
        rate_limit("Blockchair", BLOCKCHAIR_RATE_LIMIT)

        url = urljoin(BLOCKCHAIR_API_URL, f"dashboards/address/{address}")  # Use urljoin for proper URL construction

        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        address_data = data['data'][address]['transactions']

        logging.info(f"Successfully fetched Blockchair data for address: {address}")
        return address_data

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching Blockchair data for address {address}: {e}")
        return None
    except KeyError as e:
        logging.error(f"KeyError while parsing Blockchair data for address {address}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching Blockchair data for address {address}: {e}")
        return None


def aggregate_data(etherscan_data, blockchair_data):
    """
    Aggregates data from different sources.
    """
    aggregated_data = {}
    if etherscan_data:
        aggregated_data['etherscan'] = etherscan_data
    if blockchair_data:
        aggregated_data['blockchair'] = blockchair_data

    return aggregated_data


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2HMAC."""
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt if none provided

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Increased number of iterations for stronger security
        backend=default_backend()
    )

    hashed_password = kdf.derive(password.encode())
    return base64.b64encode(salt).decode(), base64.b64encode(hashed_password).decode()


def verify_password(password, stored_salt, stored_hashed_password):
    """Verifies a password against a stored hash and salt."""
    salt = base64.b64decode(stored_salt)
    hashed_password = base64.b64decode(stored_hashed_password)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )

    try:
        kdf.verify(password.encode(), hashed_password)
        return True
    except Exception:  # In general avoid catch-all exceptions, but for password verification catching all exceptions avoids leaking information.
        return False


def encrypt_message(message, key):
    """Encrypts a message using AES-CBC with PKCS7 padding."""
    key = base64.b64decode(key)
    message = message.encode('utf-8')
    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode('utf-8')


def decrypt_message(ciphertext, key):
    """Decrypts a message encrypted with AES-CBC and PKCS7 padding."""
    key = base64.b64decode(key)
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')

def generate_aes_key():
    """Generates a random AES key (256-bit) and returns it as a base64 encoded string."""
    key = os.urandom(32)  # 32 bytes for AES-256
    return base64.b64encode(key).decode('utf-8')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Scrapes and aggregates data from multiple block explorer APIs.')
    parser.add_argument('--address', type=str, help='The cryptocurrency address to search for.')
    parser.add_argument('--password', type=str, help='Password to use for crypto operations. WARNING: Use with extreme caution. Avoid using plaintext passwords on CLI, consider using other secure methods.')
    parser.add_argument('--hash_password', action='store_true', help='Hashes a password. Requires --password.')
    parser.add_argument('--verify_password', nargs=3, metavar=('password', 'salt', 'hashed_password'), help='Verifies a password. Requires password, stored salt, and stored hashed password.')
    parser.add_argument('--encrypt', nargs=2, metavar=('message', 'key'), help='Encrypts a message with a given key.')
    parser.add_argument('--decrypt', nargs=2, metavar=('ciphertext', 'key'), help='Decrypts a ciphertext with a given key.')
    parser.add_argument('--generate_key', action='store_true', help='Generates an AES key.')


    return parser


def main():
    """
    Main function to execute the block explorer scraper.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.address:
        # Input validation
        if not isinstance(args.address, str):
            logging.error("Address must be a string.")
            return

        logging.info(f"Scraping data for address: {args.address}")

        etherscan_data = fetch_etherscan_data(args.address)
        blockchair_data = fetch_blockchair_data(args.address)

        aggregated_data = aggregate_data(etherscan_data, blockchair_data)

        print(json.dumps(aggregated_data, indent=4)) # Output JSON for easy readability

    elif args.hash_password:
        if not args.password:
            logging.error("Please provide a password to hash using --password.")
            return
        salt, hashed_password = hash_password(args.password)
        print(f"Salt: {salt}")
        print(f"Hashed Password: {hashed_password}")

    elif args.verify_password:
        password, salt, hashed_password = args.verify_password
        if verify_password(password, salt, hashed_password):
            print("Password verified successfully!")
        else:
            print("Password verification failed.")

    elif args.encrypt:
        message, key = args.encrypt
        encrypted_message = encrypt_message(message, key)
        print(f"Encrypted message: {encrypted_message}")

    elif args.decrypt:
        ciphertext, key = args.decrypt
        try:
            decrypted_message = decrypt_message(ciphertext, key)
            print(f"Decrypted message: {decrypted_message}")
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            print("Decryption failed. Check your key and ciphertext.")

    elif args.generate_key:
        key = generate_aes_key()
        print(f"Generated AES Key: {key}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

# Example Usage

# 1.  Basic scraping (Requires ETHERSCAN_API_KEY environment variable to be set):
# python main.py --address 0xdAC17F958D2ee523a2206206994597C13D831ec7

# 2. Hashing a password:
# python main.py --hash_password --password "mysecretpassword"

# 3. Verifying a password (using the salt and hashed password from hashing):
# python main.py --verify_password "mysecretpassword" "<salt_from_hashing>" "<hashed_password_from_hashing>"

# 4. Generating an AES key:
# python main.py --generate_key

# 5. Encrypting a message (Requires generated AES Key)
# python main.py --encrypt "This is a secret message" "<generated_AES_key>"

# 6. Decrypting a message (Requires generated AES Key and encrypted message)
# python main.py --decrypt "<encrypted_message>" "<generated_AES_key>"