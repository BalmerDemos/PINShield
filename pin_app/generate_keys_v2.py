import os
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Set up logging for key generation
default_log = logging.getLogger('default')
default_log.setLevel(logging.DEBUG)
default_log_handler = logging.FileHandler('default.log')  # Save logs in the logs folder
default_log.addHandler(default_log_handler)

# Create the Logs directory if it doesn't exist
def create_Logs_folder():
    # Create the keys directory if it doesn't exist
    try:
        os.makedirs('Logs', exist_ok=True)
        default_log.info("Logs directory created or already exists.")
    except Exception as e:
        default_log.error(f"Error creating Logs directory: {e}")

# Create the keys directory if it doesn't exist
def create_keys_folder():
    # Create the keys directory if it doesn't exist
    try:
        os.makedirs('keys', exist_ok=True)
        default_log.info("Keys directory created or already exists.")
    except Exception as e:
        default_log.error(f"Error creating keys directory: {e}")

create_Logs_folder()
create_keys_folder()

# Set up logging for key generation, logs folder was created.
key_log = logging.getLogger('key')
key_log.setLevel(logging.DEBUG)
key_log_handler = logging.FileHandler('logs/key.log')  # Save logs in the logs folder
key_log.addHandler(key_log_handler)

# Set up logging for encrypted PIN, logs folder was created.
pin_log = logging.getLogger('pin')
pin_log.setLevel(logging.DEBUG)
pin_log_handler = logging.FileHandler('logs/pin.log')  # Save logs in the logs folder
pin_log.addHandler(pin_log_handler)

def generate_keys():
    """Generates a private and public RSA key pair and saves them."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Save the private key to a file with error handling
    try:
        with open("keys/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # Save without encryption
            ))
        key_log.info("Private key saved successfully.")
    except Exception as e:
        key_log.error(f"Error saving private key: {e}")
        default_log.error(f"Error saving private key: {e}")

    # Save the public key to a file with error handling
    try:
        with open("keys/public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        key_log.info("Public key saved successfully.")
    except Exception as e:
        key_log.error(f"Error saving public key: {e}")

    default_log.info(f"Keys generated and attempted to save in 'keys/' folder.")

    return public_key  # Return the public key for later use

def encrypt_and_log_pin(pin, public_key):
    """
    Encrypts the given PIN using the public key and logs the encrypted PIN.
    Args:
        pin (str): The PIN to encrypt.
        public_key: The public key to use for encryption.
    """
    encrypted_pin = public_key.encrypt(
        pin.encode(),  # Convert PIN to bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    # Save the encrypted PIN to a log file
    try:
        with open("logs/pin.log", "ab") as log_file:  # Append mode
            log_file.write(encrypted_pin + b'\n')  # Log the encrypted PIN
        default_log.info("PIN encrypted and logged successfully.")
    except Exception as e:
        default_log.error(f"Error logging encrypted PIN: {e}")

    default_log.info(f"PIN encrypted and logged.")


# Example usage uncomnment and excute out front end.
'''
if __name__ == "__main__":
    public_key = generate_keys()
    encrypt_and_log_pin("1234", public_key)  # Example PIN

'''


