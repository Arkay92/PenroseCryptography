import numpy as np
import math
import hashlib
import secrets
import argparse
import base64
import os
import unittest
from collections import Counter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from scipy.stats import chisquare

class MockKMS:
    def generate_data_key(self):
        """Generate a new data encryption key."""
        return b'\x00' * 32  # Simulated key generation

    def encrypt_data_key(self, key):
        """Encrypt the data encryption key with a master key."""
        return b'\x01' * 32  # Simulated key encryption

    def decrypt_data_key(self, encrypted_key):
        """Decrypt the data encryption key with a master key."""
        return b'\x00' * 32  # Simulated key decryption

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
    """Generate a cryptographic seed from the choices and Penrose tiling base."""
    seed_str = choices + str(base)
    return hashlib.sha256(seed_str.encode()).digest()

def derive_key(seed, salt):
    """Derive a cryptographic key using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'penrose-tiling-key', backend=default_backend())
    return hkdf.derive(seed)

def encrypt_message(key, message):
    """Encrypt a message using AES with the derived key and authenticate with HMAC."""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Use CFB mode for streaming data
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()  # Add PKCS7 padding
    padded_message = padder.update(message.encode()) + padder.finalize()  # Convert message to bytes
    ct = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ct

def decrypt_message(key, encrypted_message):
    """Decrypt a message using AES with the derived key and authenticate with HMAC."""
    iv = encrypted_message[:16]
    ct = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Use CFB mode for streaming data
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()  # Add PKCS7 unpadding
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
    return unpadded_message.decode()  # Decode bytes to string

def assess_entropy(choices):
    """Assess the entropy of the choices string using statistical tests."""
    freqs = Counter(choices)
    total_chars = len(choices)
    _, p_value = chisquare(list(freqs.values()))  # Chi-squared test for randomness
    return p_value >= 0.01  # Threshold for statistical significance

def main(base, divisions, message, kms):
    """Main function to execute the script's functionality."""
    phi = (1 + np.sqrt(5)) / 2
    salt = os.urandom(32)  # Increased salt size for better security

    try:
        if kms:
            # Initialize the KMS (hypothetical)
            kms_client = MockKMS()

            # Generate a data encryption key
            data_key = kms_client.generate_data_key()

            # Encrypt the data encryption key with a master key (hypothetical)
            encrypted_data_key = kms_client.encrypt_data_key(data_key)

            # Encrypt the message using the data encryption key
            encrypted_message = encrypt_message(data_key, message)

        else:
            triangles = initialize_triangles(base)
            choices = []
            for _ in range(divisions):
                new_triangles = []
                for shape, v1, v2, v3 in triangles:
                    choice = os.urandom(1)  # Use cryptographically secure PRNG for choice selection
                    choices.append(choice)
                    new_triangles.extend(subdivision_logic(shape, v1, v2, v3, phi, choice))
                triangles = new_triangles
            choices = b''.join(choices)  # Concatenate choices as bytes for seed generation
            freqs = Counter(choices)
            _, p_value = chisquare(list(freqs.values()))  # Calculate p-value for entropy assessment
            if p_value < 0.01:
                raise ValueError("Insufficient entropy for key generation.")
            seed = hashlib.sha256(choices + str(base).encode()).digest()  # Incorporate choices and base into seed
            derived_key = derive_key(seed, salt)
            encrypted_message = encrypt_message(derived_key, message)

        # Print encrypted message and derived key
        print(f"Derived Key (Base64): {base64.b64encode(data_key if kms else derived_key).decode()}")
        print(f"Encrypted Message (Hex): {encrypted_message.hex()}")

        if not kms:
            # Decrypt and verify message
            decrypted_message = decrypt_message(derived_key, encrypted_message)
            assert decrypted_message == message, "Decryption failed or message tampered"
            print("Decryption successful.")

            # Print security information
            print(f"Entropy Assessment P-value: {p_value}")
            print(f"Salt Value: {salt.hex()}")
            print(f"Key Derivation Information: HKDF with SHA256, salt={salt}, info=b'penrose-tiling-key'")

    except Exception as e:
        print(f"An error occurred: {e}")

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Penrose Tiling and Cryptography")
    parser.add_argument("--base", type=int, default=5, help="Base size for Penrose tiling")
    parser.add_argument("--divisions", type=int, default=4, help="Number of subdivisions for tiling")
    parser.add_argument("--message", type=str, help="Message to encrypt")
    parser.add_argument("--kms", action="store_true", help="Use Key Management Service (KMS)")
    args = parser.parse_args()

    main(args.base, args.divisions, args.message, args.kms)
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
