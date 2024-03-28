import math, hashlib, secrets, argparse, base64, os, unittest, logging, subprocess, ssl, socket, csv
import numpy as np
import pandas as pd
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
from io import StringIO
from unittest.mock import patch
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

input_shape = None

class NeuralNetworkModel:
    def __init__(self, learning_rate=0.001):
        self.model = Sequential([
            Dense(128, activation='relu', input_shape=(input_shape,)),
            Dense(64, activation='relu'),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')  # Use 'sigmoid' for binary classification, 'softmax' for multi-class
        ])
        
        self.model.compile(optimizer=Adam(learning_rate=learning_rate), loss='binary_crossentropy', metrics=['accuracy'])  # Use 'binary_crossentropy' for binary classification, 'categorical_crossentropy' for multi-class

    def train(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=32):
        # Normalize the data
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_val_scaled = scaler.transform(X_val)

        # Train the model
        history = self.model.fit(X_train_scaled, y_train, validation_data=(X_val_scaled, y_val), epochs=epochs, batch_size=batch_size)
        return history

    def evaluate(self, X_test, y_test):
        # Normalize the test data
        scaler = StandardScaler()
        X_test_scaled = scaler.transform(X_test)

        # Evaluate the model
        evaluation_metrics = self.model.evaluate(X_test_scaled, y_test)
        accuracy = evaluation_metrics[1]  # Assuming accuracy is the second metric being evaluated
        
        # Log evaluation metrics
        logging.info(f"Model accuracy: {accuracy}")

class ModelTrainer:
    def __init__(self, data, target):
        self.data = data
        self.target = target

    def train_and_evaluate(self):
        # Check if dataset exists
        if not os.path.exists(entropy_dataset.filename):
            logging.info("Dataset not found. Starting to collect entropy data...")
            entropy_dataset.collect_entropy_data(num_entries=100)  # Collect 100 entries, adjust as needed
        
        # Proceed with loading and splitting the dataset
        train_df, validation_df, test_df = entropy_dataset.load_and_split_data()

        # Split the data into training, validation, and test sets
        X_train, X_temp, y_train, y_temp = train_test_split(self.data, self.target, test_size=0.4, random_state=42)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

        # Initialize the neural network model
        input_shape = X_train.shape[1]  # Number of features
        input_shape=input_shape
        model = NeuralNetworkModel()

        # Train the model and validate
        history = model.train(X_train, y_train, X_val, y_val, epochs=100, batch_size=32)

        # Evaluate the model on the test set
        model.evaluate(X_test, y_test)

        # Optionally, log the training process or plot the learning curves using 'history'
        logging.info(history.history['accuracy'], history.history['val_accuracy'])

def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem"):
    """Generates a self-signed certificate and key if they don't already exist."""
    try:
        with open(cert_path) as cert, open(key_path) as key:
            logging.info("Certificate and key already exist.")
    except FileNotFoundError:
        logging.info("Generating a new certificate and key...")
        subprocess.call([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-keyout', key_path, 
            '-out', cert_path, '-days', '365', '-nodes', '-subj', '/CN=localhost'
        ])
        logging.info("Certificate and key generated.")

class MockKMS:
    def __init__(self, base, divisions, passphrase, key_storage_path='key_storage.txt', input_shape=None):
        self.base = base
        self.divisions = divisions
        self.passphrase = passphrase.encode()
        self.key_storage_path = key_storage_path
        self.aes_key = None
        self.ecdsa_private_key = None
        self.ecdsa_public_key = None
        self.load_or_generate_keys()
        self.entropy_count = 0  # Counter for entropy generations
        if input_shape is not None:
            self.nn_model = NeuralNetworkModel(input_shape)  # Initialize the neural network model with the given input shape
        else:
            self.nn_model = None  # Defer initialization until the input shape is known

    def run_secure_service(self, cert_path="cert.pem", key_path="key.pem"):
        """Runs the KMS service with TLS support."""
        generate_self_signed_cert(cert_path, key_path)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('localhost', 8443))
            sock.listen(5)
            logging.info("Secure KMS service running on localhost:8443")
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    client_socket, address = ssock.accept()
                    logging.info(f"Secure connection established with {address}")
                    
                    # Handle the connection
                    try:
                        while True:
                            data = client_socket.recv(1024)
                            if not data:
                                break  # Client closed connection

                            # Decode the received data
                            message = data.decode('utf-8')
                            logging.info(f"Received message: {message}")

                            # Process the message
                            response = self.process_message(message)

                            # Send the response back to the client
                            client_socket.sendall(response.encode('utf-8'))
                    except Exception as e:
                        logging.error(f"Error handling client {address}: {e}")
                    finally:
                        client_socket.close()

    def process_message(self, message):
        """Process the message received from the client and perform operations based on it."""
        try:
            # For simplicity, let's assume the message format is "operation|data"
            operation, data = message.split("|", 1)

            if operation == "generate_vrf":
                vrf_output, proof = self.generate_vrf_proof(data)
                return f"VRF output: {vrf_output.hex()}, Proof: {proof.hex()}"
            elif operation == "verify_vrf":
                message, vrf_output, proof = data.split(",")
                result = self.verify_vrf_proof(message, bytes.fromhex(vrf_output), bytes.fromhex(proof))
                return "VRF verification result: " + ("Success" if result else "Failure")
            # Add more operations as needed

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            return "Error processing message"

        return "Operation not supported"

    def generate_vrf_proof(self, message):
        """Generate a VRF proof for a given message."""
        vrf_output = self._generate_vrf_output(message, self.ecdsa_private_key)
        proof = self.sign_message_with_private_key(vrf_output, self.ecdsa_private_key)
        return vrf_output, proof

    def verify_vrf_proof(self, message, vrf_output, proof):
        """Verify a VRF proof for a given message."""
        expected_vrf_output = self._generate_vrf_output(message, self.ecdsa_public_key)
        try:
            # Verify the proof against the expected VRF output
            self.verify_signature_with_public_key(vrf_output, proof, self.ecdsa_public_key)
            print("Proof verification succeeded.")
            return True  # Signature verification succeeded
        except InvalidSignature:
            print("Proof verification failed.")
            return False  # Signature verification failed

    def _generate_vrf_output(self, message, key):
        """Generate a deterministic 'random' value from a message and a key (private or public)."""
        # Ensure the message is in bytes
        message_bytes = message.encode() if isinstance(message, str) else message

        # Sign the message with the private key to generate a signature
        if isinstance(key, ec.EllipticCurvePrivateKey):
            signature = self.sign_message_with_private_key(message_bytes, key)
            data_to_hash = signature + message_bytes
        elif isinstance(key, ec.EllipticCurvePublicKey):
            hashed_message = hashlib.sha256(message_bytes).digest()
            data_to_hash = self.public_key_operation(hashed_message, key)
        else:
            raise ValueError("Key must be an ECDSA private or public key")

        # Hash the combination of the signature and message (for private key) or the "encrypted" hash (for public key)
        return hashlib.sha256(data_to_hash).digest()

    def sign_message_with_private_key(self, message, private_key):
        """Sign a message using the ECDSA private key."""
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature_with_public_key(self, message, signature, public_key):
        """Verify a message signature using the ECDSA public key."""
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

    def public_key_operation(self, data, public_key):
        """Perform a deterministic operation with the public key on the given data.
        This is a workaround to simulate 'using' the public key, as ECDSA doesn't support encryption.
        One approach is to hash the data concatenated with the serialized public key."""
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha256(data + public_key_bytes).digest()

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
        logging.info("Loading or generating keys...")
        try:
            with open(self.key_storage_path, 'rb') as key_file:
                salt, encrypted_data = key_file.read(16), key_file.read()
                encryption_key = self._get_encryption_key(salt)
                decrypted_data = self._decrypt_data(encrypted_data, encryption_key)
                aes_key_str, ecdsa_private_key_str, ecdsa_public_key_str = decrypted_data.decode().split('\n')

                self.aes_key = base64.b64decode(aes_key_str)
                self.ecdsa_private_key = serialization.load_pem_private_key(
                    base64.b64decode(ecdsa_private_key_str), password=None, backend=default_backend())
                self.ecdsa_public_key = serialization.load_pem_public_key(
                    base64.b64decode(ecdsa_public_key_str), backend=default_backend())

                logging.info("Keys successfully loaded from storage.")
        except Exception as e:
            logging.error(f"Failed to load keys from storage: {e}, generating new ones.")
            self.aes_key = self._generate_aes_key()
            self.ecdsa_private_key, self.ecdsa_public_key = self._generate_ecdsa_keys()
            self.store_keys()

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
        # Existing entropy generation logic remains until the dataset is large enough
        if entropy_dataset.is_large_enough():  # Define a method or condition to check dataset size
            # Use the neural network to generate entropy
            # Prepare input data for prediction
            # input_data = prepare_input_for_prediction()
            generated_entropy = self.nn_model.predict(input_data)
            choices_str = convert_generated_entropy_to_choices(generated_entropy)  # Convert generated entropy to a choices string
        else:
            # Existing Penrose tiling-based entropy generation logic
            _, choices = subdivide_triangles(initialize_triangles(self.base), self.divisions, (1 + math.sqrt(5)) / 2)
            choices_str = ''.join(choices)

        # The rest of the method remains unchanged
        seed = self._generate_seed(choices_str)
        randomness_score = assess_entropy(choices_str)
        entropy_dataset.add_entry(self.base, self.divisions, choices_str, seed, randomness_score)
        self.entropy_count += 1

        return choices_str
    
    def preprocess_dataset_for_nn(df):
        # Assuming 'df' is your dataframe and it contains both features and target
        # Let's say the target column is named 'target'
        X = df.drop('target', axis=1).values  # Features
        y = df['target'].values  # Target

        # Normalize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Split the dataset into training and validation sets
        X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
        
        # Reshape data if required by the model, especially for time-series models like LSTM
        X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
        X_val = X_val.reshape((X_val.shape[0], X_val.shape[1], 1))

        return X_train, X_val, y_train, y_val

    def invoke_training(self):
        logging.info("Invoking training process for neural network...")
        # Load the dataset
        df = pd.read_csv(entropy_dataset.filename)

        # Preprocess the dataset for neural network training
        X_train, X_val, y_train, y_val = preprocess_dataset_for_nn(df)

        # Train the neural network model
        # Ensure your nn_model has a method 'build_and_train_model' defined to accept these parameters
        self.nn_model.build_and_train_model(X_train, y_train, X_val, y_val)

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

class KMSClient:
    def __init__(self, server_address=('localhost', 8443), cert_path='cert.pem'):
        self.server_address = server_address
        self.cert_path = cert_path
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cert_path)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_REQUIRED

    def send_message(self, message):
        with socket.create_connection(self.server_address) as sock:
            with self.context.wrap_socket(sock, server_hostname='localhost') as ssock:
                logging.info(f"Securely connected to KMS service at {self.server_address}")
                ssock.sendall(message.encode('utf-8'))
                response = ssock.recv(4096).decode('utf-8')
                return response

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

class EntropyDataset:
    def __init__(self, filename='entropy_dataset.csv'):
        self.filename = filename
        self.headers = ['base', 'divisions', 'choices', 'entropy', 'randomness_score']

        # Initialize the CSV file with headers if it's new
        try:
            with open(self.filename, 'x', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.headers)
                writer.writeheader()
        except FileExistsError:
            pass  # File already exists, no need to add headers

    def add_entry(self, base, divisions, choices, entropy, randomness_score):
        with open(self.filename, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.headers)
            writer.writerow({
                'base': base,
                'divisions': divisions,
                'choices': choices,
                'entropy': base64.b64encode(entropy).decode(),
                'randomness_score': randomness_score
            })

    def collect_entropy_data(self, num_entries=100):
        """Collect and save entropy data."""
        # Check if file exists
        if not os.path.exists(self.filename):
            # Initialize CSV file with headers
            with open(self.filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.headers)
                writer.writeheader()

            # Collect entropy data
            for _ in range(num_entries):
                base, divisions = self._generate_random_parameters()
                choices_str, seed, randomness_score = self._generate_entropy_data(base, divisions)
                self.add_entry(base, divisions, choices_str, seed, randomness_score)
            logging.info(f"Collected {num_entries} entropy data entries.")

    def _generate_random_parameters(self):
        """Generate random parameters for entropy data collection."""
        # Example: generate random 'base' and 'divisions' parameters
        base = secrets.randbelow(10) + 5  # Random base between 5 and 14
        divisions = secrets.randbelow(5) + 1  # Random divisions between 1 and 5
        return base, divisions

    def _generate_entropy_data(self, base, divisions):
        """Generate a single entry of entropy data."""
        # Implement your entropy data generation logic here
        # For demonstration, this will be a placeholder returning random values
        choices_str = ''.join(secrets.choice(['A', 'B']) for _ in range(10))
        seed = hashlib.sha256(choices_str.encode()).digest()
        randomness_score = secrets.randbelow(100) / 100  # Random score between 0 and 1
        return choices_str, seed, randomness_score

    def load_and_split_data(self, test_size=0.2, validation_size=0.1):
        """Load the dataset from CSV and split into train, validation, and test sets."""
        # Load dataset
        df = pd.read_csv(self.filename)

        # Split dataset into train and temporary test
        train_df, temp_test_df = train_test_split(df, test_size=test_size + validation_size, random_state=42, shuffle=True)

        # Further split the temporary test set into validation and test sets
        validation_size_adjusted = validation_size / (test_size + validation_size)
        validation_df, test_df = train_test_split(temp_test_df, test_size=validation_size_adjusted, random_state=42, shuffle=True)

        return train_df, validation_df, test_df

entropy_dataset = EntropyDataset()

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

class TestRandomnessAndCryptography(unittest.TestCase):
    
    @patch.object(MockKMS, 'load_or_generate_keys')
    def setUp(self, mock_load_keys=None):
        # Initialize MockKMS without relying on external files
        self.kms = MockKMS(base=5, divisions=4, passphrase='test_passphrase')
        # Since load_or_generate_keys is mocked, manually generate the keys
        self.kms.aes_key = self.kms._generate_aes_key()
        self.kms.ecdsa_private_key, self.kms.ecdsa_public_key = self.kms._generate_ecdsa_keys()

    def test_entropy_generation(self):
        # Generate entropy multiple times and assess the diversity of output
        entropies = set()
        for _ in range(100):
            entropy = self.kms._generate_entropy()
            self.assertIsInstance(entropy, str)
            entropies.add(entropy)
        # Check if we have a reasonable diversity of outputs
        self.assertTrue(len(entropies) > 90)

    def test_key_generation(self):
        # Test AES key generation
        aes_key = self.kms._generate_aes_key()
        self.assertEqual(len(aes_key), 32)  # AES keys should be 32 bytes for AES-256

        # Test ECDSA key generation
        ecdsa_private, ecdsa_public = self.kms._generate_ecdsa_keys()
        self.assertTrue(ecdsa_private and ecdsa_public)

    def test_encryption_decryption_consistency(self):
        # Encrypt and decrypt a message and check for consistency
        message = b'This is a test message'
        aes_key = self.kms._generate_aes_key()
        encrypted_message = self.kms._encrypt_data(message, aes_key)
        decrypted_message = self.kms._decrypt_data(encrypted_message, aes_key)
        self.assertEqual(message, decrypted_message)

    def test_signature_verification(self):
        # Sign a message and verify the signature
        message = "Test message"
        signature = sign_message(self.kms.ecdsa_private_key, message)
        verification_result = verify_signature(self.kms.ecdsa_public_key, message, signature)
        self.assertTrue(verification_result)

        # Test verification with an incorrect signature
        incorrect_signature = b'wrong'
        verification_result = verify_signature(self.kms.ecdsa_public_key, message, incorrect_signature)
        self.assertFalse(verification_result)

def main(base, divisions, message, passphrase, use_kms=True):
    """Main function to execute the script's functionality."""
    phi = (1 + math.sqrt(5)) / 2
    salt = os.urandom(32)  # Increased salt size for better security

    try:
        # Initialize MockKMS with Penrose tiling parameters
        kms = MockKMS(base, divisions, passphrase)
        
        # Start the KMS service with TLS support
        kms.run_secure_service()

         # Create a KMS client and communicate with the KMS service
        client = KMSClient()
        response = client.send_message("generate_vrf|" + args.message)
        logging.info(f"Response from KMS: {response}")
        
        # Generate VRF proof for the message
        vrf_output, proof = kms.generate_vrf_proof(message)

        logging.info(f"VRF Output (Hex): {vrf_output.hex()}")
        logging.info(f"Proof (Hex): {proof.hex()}")

        # Verify VRF proof
        verification_result = kms.verify_vrf_proof(message, vrf_output, proof)
        if verification_result:
            logging.info("VRF proof verified successfully.")
        else:
            logging.error("Failed to verify VRF proof.")

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
        
        # Define the test suite for TestRandomnessAndCryptography
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestRandomnessAndCryptography)

        # Run the tests and output the results to the console
        runner = unittest.TextTestRunner(verbosity=2)  # Set verbosity to 2 for detailed output
        print("\nRunning TestRandomnessAndCryptography test suite:")
        result = runner.run(suite)  # Capture the result of the test run

        # Log the test results summary using the result variable
        logging.info(f"Ran {result.testsRun} tests.")
        if not result.wasSuccessful():
            logging.error("One or more tests failed.")
        if result.failures:
            logging.error(f"Failures: {len(result.failures)}")
            for test, traceback in result.failures:
                logging.error(f"Failure: {test.id()}\nTraceback: {traceback}")
        if result.errors:
            logging.error(f"Errors: {len(result.errors)}")
            for test, traceback in result.errors:
                logging.error(f"Error: {test.id()}\nTraceback: {traceback}")

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