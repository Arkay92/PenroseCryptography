import numpy as np
import math
import hashlib
import secrets
import argparse
import base64
import os
import unittest
import logging
from collections import Counter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scipy.stats import chisquare

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MockKMS:
    def __init__(self, base, divisions):
        self.base = base
        self.divisions = divisions
        self.master_key = self._generate_master_key()

    def _generate_master_key(self):
        """Generate the master key using Penrose tiling-based entropy."""
        choices = self._generate_entropy()
        seed = self._generate_seed(choices)
        return self._derive_key(seed)

    def _generate_entropy(self):
        """Generate entropy based on Penrose tiling."""
        _, choices = subdivide_triangles(initialize_triangles(self.base), self.divisions, (1 + math.sqrt(5)) / 2)
        return ''.join(choices)

    def _generate_seed(self, choices):
        """Generate a seed from the choices."""
        return hashlib.sha256(choices.encode()).digest()

    def _derive_key(self, seed):
        """Derive a cryptographic key from the seed."""
        salt = secrets.token_bytes(16)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'penrose-tiling-key', backend=default_backend())
        return hkdf.derive(seed)

    def generate_data_key(self):
        """Generate a new data encryption key using Penrose tiling-based entropy."""
        choices = self._generate_entropy()
        return self._derive_key(self._generate_seed(choices))

    def encrypt_data_key(self, key):
        """Encrypt the data encryption key with the master key."""
        try:
            aesgcm = AESGCM(self.master_key)
            nonce = secrets.token_bytes(12)
            return nonce + aesgcm.encrypt(nonce, key, None)
        except Exception as e:
            logging.error(f"Data key encryption error: {e}")
            return None

    def decrypt_data_key(self, encrypted_key):
        """Decrypt the data encryption key with the master key."""
        try:
            aesgcm = AESGCM(self.master_key)
            nonce = encrypted_key[:12]
            return aesgcm.decrypt(nonce, encrypted_key[12:], None)
        except Exception as e:
            logging.error(f"Data key decryption error: {e}")
            return None

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

def main(base, divisions, message, use_kms=True):
    """Main function to execute the script's functionality."""
    phi = (1 + np.sqrt(5)) / 2
    salt = os.urandom(32)  # Increased salt size for better security

    try:
        if use_kms:
            kms = MockKMS(base, divisions)
            data_key = kms.generate_data_key()

            encrypted_key = kms.encrypt_data_key(data_key)
            if encrypted_key:
                logging.info(f"Encrypted Data Key: {base64.b64encode(encrypted_key).decode()}")

                decrypted_key = kms.decrypt_data_key(encrypted_key)
                if decrypted_key:
                    logging.info("Data key decrypted successfully.")
                    
                    # Encrypt the message using the data encryption key
                    iv = generate_iv(base, divisions)
                    encrypted_message = encrypt_message(data_key, iv, message)

                    logging.info(f"Encrypted Message (Hex): {base64.b64encode(encrypted_message).decode()}")
                else:
                    logging.error("Failed to decrypt data key.")
            else:
                logging.error("Failed to encrypt data key.")
        else:
            triangles, choices = subdivide_triangles(initialize_triangles(base), divisions, phi)
            entropy_ok = assess_entropy(choices)
            if not entropy_ok:
                raise ValueError("Insufficient entropy for key generation.")
            seed = generate_seed(choices, base)
            derived_key = derive_key(seed, salt)
                    
            # Encrypt the message using the data encryption key
            iv = generate_iv(base, divisions)
            encrypted_message = encrypt_message(derived_key, iv, message)

            # Decrypt and verify message
            decrypted_message = decrypt_message(derived_key, iv, encrypted_message)
            assert decrypted_message == message, "Decryption failed or message tampered"
            logging.info("Decryption successful.")

            # Print derived key, encrypted message, and entropy assessment
            logging.info(f"Derived Key (Base64): {base64.b64encode(derived_key).decode()}")
            logging.info(f"Encrypted Message (Hex): {base64.b64encode(encrypted_message).decode()}")
            logging.info(f"Entropy Assessment OK: {entropy_ok}")

            # Print common security information
            logging.info(f"Salt Value: {salt.hex()}")
            logging.info(f"Key Derivation Information: HKDF with SHA256, salt={salt}, info=b'penrose-tiling-key'")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Penrose Tiling and Cryptography")
    parser.add_argument("--base", type=int, default=5, help="Base size for Penrose tiling")
    parser.add_argument("--divisions", type=int, default=4, help="Number of subdivisions for tiling")
    parser.add_argument("--message", type=str, required=True, help="Message to encrypt")
    parser.add_argument("--use_kms", action="store_true", help="Use Key Management Service (KMS) simulation")
    args = parser.parse_args()

    main(args.base, args.divisions, args.message, args.use_kms)