import math, hashlib, secrets, argparse, base64, os, unittest, logging, base64, os
import numpy as np
from collections import Counter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from scipy.stats import chisquare
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class MockKMS:
    def __init__(self, base, divisions, passphrase, key_storage_path='key_storage.txt'):
        self.base = base
        self.divisions = divisions
        self.passphrase = passphrase.encode()  # Ensure the passphrase is bytes-like
        self.key_storage_path = key_storage_path
        self.load_or_generate_keys()

    def _get_encryption_key(self, salt):
        """Derive an encryption key from the passphrase."""
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        return kdf.derive(self.passphrase)

    def _encrypt_data(self, data, key):
        """Encrypt data using AES."""
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct

    def _decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES."""
        iv, ct = encrypted_data[:16], encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def store_keys(self):
        """Encrypt and store keys to the file."""
        try:
            salt = os.urandom(16)
            encryption_key = self._get_encryption_key(salt)
            # Prepare data for encryption
            data_to_store = '\n'.join([
                base64.b64encode(self.aes_key).decode(),
                base64.b64encode(self.ecdsa_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())).decode(),
                base64.b64encode(self.ecdsa_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            ]).encode()
            encrypted_data = self._encrypt_data(data_to_store, encryption_key)
            with open(self.key_storage_path, 'wb') as key_file:
                key_file.write(salt + encrypted_data)
            logging.info("Keys stored securely with encryption.")
        except Exception as e:
            logging.error(f"Failed to store keys securely: {e}")

    def load_or_generate_keys(self):
        """Decrypt and load keys from storage, or generate them if they don't exist."""
        try:
            with open(self.key_storage_path, 'rb') as key_file:
                salt = key_file.read(16)  # The first 16 bytes are the salt
                encrypted_data = key_file.read()
                encryption_key = self._get_encryption_key(salt)
                decrypted_data = self._decrypt_data(encrypted_data, encryption_key)
                stored_keys = decrypted_data.decode().splitlines()

                # Deserialize and set the AES key
                self.aes_key = base64.b64decode(stored_keys[0])

                # Deserialize and set the ECDSA private key
                ecdsa_private_key_pem = base64.b64decode(stored_keys[1])
                self.ecdsa_private_key = serialization.load_pem_private_key(
                    ecdsa_private_key_pem,
                    password=None,
                    backend=default_backend()
                )

                # Deserialize and set the ECDSA public key
                ecdsa_public_key_pem = base64.b64decode(stored_keys[2])
                self.ecdsa_public_key = serialization.load_pem_public_key(
                    ecdsa_public_key_pem,
                    backend=default_backend()
                )

                logging.info("Keys loaded from encrypted storage.")
        except FileNotFoundError:
            logging.info("Encrypted key storage not found, generating new keys.")
            # Generate new keys if loading from storage fails
            self.aes_key = self._generate_aes_key()
            self.ecdsa_private_key, self.ecdsa_public_key = self._generate_ecdsa_keys()
            self.store_keys()  # Store the newly generated keys

    def _generate_ecdsa_keys(self):
        """Generate ECDSA keys."""
        choices = self._generate_entropy()
        seed = self._generate_seed(choices)
        return generate_ecdsa_keys(seed)

    def _generate_aes_key(self):
        """Generate an AES key for encryption/decryption."""
        choices = self._generate_entropy()
        seed = self._generate_seed(choices)
        return self._derive_key(seed)

    def _generate_master_key(self):
        """Generate the master key using Penrose tiling-based entropy."""
        choices = self._generate_entropy()
        seed = self._generate_seed(choices)
        return self._derive_ecdsa_keys(seed)

    def _derive_key(self, seed):
        """Derive a cryptographic key from the seed."""
        salt = secrets.token_bytes(16)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'penrose-tiling-key', backend=default_backend())
        derived_key = hkdf.derive(seed)
        if not isinstance(derived_key, bytes):
            logging.error("_derive_key: The derived key is not in bytes format.")
        return derived_key

    def _generate_entropy(self):
        """Generate entropy based on Penrose tiling."""
        _, choices = subdivide_triangles(initialize_triangles(self.base), self.divisions, (1 + math.sqrt(5)) / 2)
        return ''.join(choices)

    def _generate_seed(self, choices):
        """Generate a seed from the choices."""
        return hashlib.sha256(choices.encode()).digest()

    def _derive_ecdsa_keys(self, seed):
        """Derive ECDSA keys from the seed."""
        return generate_ecdsa_keys(seed)

    def generate_data_key(self):
        """Generate a new data encryption key using Penrose tiling-based entropy."""
        choices = self._generate_entropy()
        return self._derive_key(self._generate_seed(choices))

    def encrypt_data_key(self, key):
        """Encrypt the data encryption key with the AES key."""
        try:
            aesgcm = AESGCM(self.aes_key)
            nonce = secrets.token_bytes(12)
            encrypted_key = aesgcm.encrypt(nonce, key, None)  # 'key' must be a bytes-like object
            return nonce + encrypted_key
        except Exception as e:
            logging.error(f"Data key encryption error: {e}")
            return None

    def decrypt_data_key(self, encrypted_key):
        """Decrypt the data encryption key with the AES key."""
        try:
            aesgcm = AESGCM(self.aes_key)  # Use the AES key dedicated for encryption/decryption
            nonce = encrypted_key[:12]
            return aesgcm.decrypt(nonce, encrypted_key[12:], None)
        except Exception as e:
            logging.error(f"Data key decryption error: {e}")
            return None

    def sign_message(self, message):
        """Sign a message using the ECDSA private key."""
        return sign_message(self.ecdsa_private_key, message)  # Use ECDSA private key

    def verify_signature(self, message, signature):
        """Verify a message signature using the ECDSA public key."""
        return verify_signature(self.ecdsa_public_key, message, signature)  # Use ECDSA public key

def generate_ecdsa_keys(seed):
    """Generate ECDSA keys using entropy from a seed."""
    private_key = ec.derive_private_key(int.from_bytes(seed, byteorder='big'), ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()

def sign_message(private_key, message):
    """Sign a message using the ECDSA private key."""
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, message, signature):
    """Verify a message signature using the ECDSA public key."""
    try:
        public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def initialize_triangles(base):
    """Initialize triangles for Penrose tiling."""
    triangles = []
    for i in range(base * 2):
        angle = (2 * i * math.pi) / base
        v2 = complex(math.cos(angle), math.sin(angle))
        triangles.append(("thin", 0 + 0j, v2, v2 * complex(math.cos(math.pi / base), math.sin(math.pi / base))))
    return triangles

def subdivide_triangles(triangles, iterations, phi):
    """Subdivide triangles and collect choices as entropy."""
    choices = []
    for _ in range(iterations):
        new_triangles = []
        for shape, v1, v2, v3 in triangles:
            choice = secrets.choice(['A', 'B'])
            choices.append(choice)
            new_triangles.extend(subdivision_logic(shape, v1, v2, v3, phi, choice))
        triangles = new_triangles
    return triangles, ''.join(choices)

def subdivision_logic(shape, v1, v2, v3, phi, choice):
    """Logic for subdividing triangles based on shape and choice."""
    if shape == "thin":
        p = v1 + (v2 - v1) / phi
        return [("thin", v3, p, v2), ("thick", p, v3, v1)]
    else:
        p = v2 + (v3 - v2) / phi
        return [("thin", v2, p, v1), ("thick", p, v3, v2)]

def generate_seed(choices, base):
    """
    Generate a cryptographic seed from the choices and Penrose tiling base,
    incorporating the Penrose tiling 'choices' into the hash input.
    """
    # Use the Penrose tiling choices directly in the hash input
    seed_input = choices + str(base)
    return hashlib.sha256(seed_input.encode()).digest()

def derive_key(seed, salt):
    """Derive a cryptographic key using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'penrose-tiling-key', backend=default_backend())
    return hkdf.derive(seed)

def initialize_cipher(key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    return cipher, iv

def generate_iv(base, divisions):
    """Generate an IV based on Penrose tiling."""
    _, choices = subdivide_triangles(initialize_triangles(base), divisions, (1 + math.sqrt(5)) / 2)
    # Use the generated choices to create a seed for the IV
    seed = hashlib.sha256(''.join(choices).encode()).digest()
    # Use the first 16 bytes of the seed as the IV for AES, which requires a 128-bit (16-byte) IV for CFB mode
    iv = seed[:16]
    return iv

def encrypt_message(key, iv, message):
    """Encrypt a message using AES with the derived key and provided IV."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return ciphertext
    except Exception as e:
        logging.error(f"Message encryption error: {e}")
        return None

def decrypt_message(key, iv, encrypted_message):
    """Decrypt a message using AES with the derived key and provided IV."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode()
    except Exception as e:
        logging.error(f"Message decryption error: {e}")
        return None

def assess_entropy(choices):
    """Assess the entropy of the choices string using statistical tests."""
    freqs = Counter(choices)
    total_chars = len(choices)
    _, p_value = chisquare(list(freqs.values()))  # Chi-squared test for randomness
    return p_value >= 0.01  # Threshold for statistical significance

# Unit tests for key functions
class TestPenroseFunctions(unittest.TestCase):
    def test_initialize_triangles(self):
        self.assertEqual(len(initialize_triangles(5)), 10)

    def test_subdivision_logic(self):
        triangles = initialize_triangles(5)
        shape, v1, v2, v3 = triangles[0]
        new_triangles = subdivision_logic(shape, v1, v2, v3, (1 + np.sqrt(5)) / 2, 'A')
        self.assertEqual(len(new_triangles), 2)

    def test_generate_seed(self):
        seed = generate_seed("A" * 256, 5)  # Generate a seed with enough entropy
        self.assertIsInstance(seed, bytes)
        self.assertEqual(len(seed), 32)

class TestEncryptionVulnerability(unittest.TestCase):
    def test_attack_on_weak_keys(self):
        """Simulate an attack that exploits weak keys generated from predictable Penrose tiling choices."""
        message = "This is a secret message"
        base = 5
        divisions = 2  # Reduced divisions for weaker keys
        phi = (1 + np.sqrt(5)) / 2
        salt = os.urandom(32)

        # Simulate weak key generation by using predictable choices
        predictable_choices = 'A' * divisions  # Assume an attacker knows or can guess this pattern
        weak_seed = generate_seed(predictable_choices, base)
        weak_key = derive_key(weak_seed, salt)

        # Encrypt the message with the weak key
        iv = generate_iv(base, divisions)
        encrypted_message = encrypt_message(attacker_key, iv, message)
        # When decrypting, use the same IV that was used for encryption

        # Simulate an attacker's attempt to recreate the weak key
        attacker_seed = generate_seed(predictable_choices, base)  # Attacker uses the same predictable choices
        attacker_key = derive_key(attacker_seed, salt)

        # Attempt decryption with the recreated weak key
        decrypted_message = decrypt_message(attacker_key, iv, encrypted_message)
        self.assertEqual(decrypted_message, message, "Attack failed, decryption with recreated weak key did not succeed")

def main(base, divisions, message, passphrase, use_kms=True):
    """Main function to execute the script's functionality."""
    phi = (1 + math.sqrt(5)) / 2
    salt = os.urandom(32)  # Increased salt size for better security

    try:
        # Initialize MockKMS with Penrose tiling parameters
        kms = MockKMS(base, divisions, passphrase)
        
        # Generate and encrypt a data key
        data_key = kms.generate_data_key()
        encrypted_key = kms.encrypt_data_key(data_key)

        if encrypted_key:
            logging.info(f"Encrypted Data Key: {base64.b64encode(encrypted_key).decode()}")

            # Decrypt the data key
            decrypted_key = kms.decrypt_data_key(encrypted_key)
            if decrypted_key:
                logging.info("Data key decrypted successfully.")
                
                # Encrypt the message using the decrypted data key
                iv = generate_iv(base, divisions)
                encrypted_message = encrypt_message(decrypted_key, iv, message)
                logging.info(f"Encrypted Message (Hex): {base64.b64encode(encrypted_message).decode()}")

                # Sign the original message using the ECDSA private key from MockKMS
                signature = kms.sign_message(message)
                logging.info(f"Signature: {base64.b64encode(signature).decode()}")

                # Verify the signature using the ECDSA public key from MockKMS
                verification_result = kms.verify_signature(message, signature)
                if verification_result:
                    logging.info("Signature verified successfully.")
                else:
                    logging.error("Failed to verify signature.")
            else:
                logging.error("Failed to decrypt data key.")
        else:
            logging.error("Failed to encrypt data key.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Penrose Tiling and Cryptography")
    parser.add_argument("--base", type=int, default=5, help="Base size for Penrose tiling")
    parser.add_argument("--divisions", type=int, default=4, help="Number of subdivisions for tiling")
    parser.add_argument("--message", type=str, required=True, help="Message to encrypt")
    parser.add_argument("--passphrase", type=str, required=True, help="Passphrase for key encryption")
    parser.add_argument("--use_kms", action="store_true", help="Use Key Management Service (KMS) simulation")
    args = parser.parse_args()

    main(args.base, args.divisions, args.message, args.passphrase, args.use_kms)