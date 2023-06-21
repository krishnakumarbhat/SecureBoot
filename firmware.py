import hashlib
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def divide_into_chunks(file_path, chunk_size):
    chunks = []
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    return chunks

def calculate_sha256_hash(chunk):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def encrypt_hash(hash_value, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_hash = cipher.encrypt(hash_value.encode())
    return encrypted_hash.hex()

def store_encrypted_chunks(chunks, output_file):
    data = []
    for i, chunk in enumerate(chunks):
        hash_value = calculate_sha256_hash(chunk)
        encrypted_hash = encrypt_hash(hash_value, private_key)
        chunk_entry = {
            'sequence_number': i+1,
            'data': chunk.hex(),
            'encrypted_hash': encrypted_hash
        }
        data.append(chunk_entry)

    with open(output_file, 'w') as file:
        json.dump(data, file)

# Example usage
file_path = "firmware.uf2"
chunk_size = 1024
output_file = "encrypted_chunks.json"
private_key_file = "private_key.pem"
public_key_file = "public_key.pem"

# Generate a dummy private key for RSA 2048
private_key = RSA.generate(2048)

# Save the private key to a file
with open(private_key_file, "wb") as key_file:
    key_file.write(private_key.export_key())

# Extract the public key from the private key
public_key = private_key.publickey()

# Save the public key to a file
with open(public_key_file, "wb") as key_file:
    key_file.write(public_key.export_key())

# Divide the firmware file into chunks
chunks = divide_into_chunks(file_path, chunk_size)

# Store the encrypted chunks in JSON format with sequence numbers
store_encrypted_chunks(chunks, output_file)
