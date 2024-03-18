import numpy as np
import math
import hashlib
import secrets
import argparse
import base64
from collections import Counter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scipy.stats import chisquare
import os
import unittest

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

def generate_seed(choices):
    """Generate a cryptographic seed from the choices."""
    if len(choices) < 256:
        raise ValueError("Insufficient entropy for seed generation.")
    return hashlib.sha256(choices.encode()).digest()

def derive_key(seed, salt):
    """Derive a cryptographic key using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'penrose-tiling-key', backend=default_backend())
    return hkdf.derive(seed)

def encrypt_message(key, message):
    """Encrypt a message using AES with the derived key."""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv + ct

def assess_entropy(choices):
    """Assess the entropy of the choices string using statistical tests."""
    freqs = Counter(choices)
    total_chars = len(choices)
    freq_distribution = [freq / total_chars for freq in freqs.values()]
    _, p_value = chisquare(list(freqs.values()))  # Chi-squared test for randomness
    return p_value >= 0.01  # Threshold for statistical significance

def main(base, divisions):
    """Main function to execute the script's functionality."""
    phi = (1 + np.sqrt(5)) / 2
    salt = os.urandom(16)  # Generate a cryptographically secure salt

    try:
        triangles = initialize_triangles(base)
        triangles, choices = subdivide_triangles(triangles, divisions, phi)
        if not assess_entropy(choices):
            raise ValueError("Insufficient entropy for key generation.")
        seed = generate_seed(choices)
        derived_key = derive_key(seed, salt)
        encrypted_message = encrypt_message(derived_key, b"Secret Message")

        print(f"Derived Key (Base64): {base64.b64encode(derived_key).decode()}")
        print(f"Encrypted Message (Hex): {encrypted_message.hex()}")
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
        with self.assertRaises(ValueError):
            generate_seed("short")
        self.assertIsInstance(generate_seed("a" * 256), bytes)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Penrose Tiling and Cryptography")
    parser.add_argument("--base", type=int, default=5, help="Base size for Penrose tiling")
    parser.add_argument("--divisions", type=int, default=4, help="Number of subdivisions for tiling")
    args = parser.parse_args()
    
    main(args.base, args.divisions)
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
