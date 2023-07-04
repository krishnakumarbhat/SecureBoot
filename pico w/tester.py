import hashlib
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import socket

# Helper function to read a file in chunks
def read_file_chunks(file_path, chunk_size):
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            yield chunk

# Calculate the SHA256 hash of a chunk
def calculate_sha256_hash(chunk):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

# Encrypt the hash value using the private key
def encrypt_hash(hash_value, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_hash = cipher.encrypt(hash_value.encode())
    return encrypted_hash.hex()

# Store the encrypted chunks in a JSON file
def store_encrypted_chunks(chunks, output_file):
    data = []
    for i, chunk in enumerate(chunks):
        hash_value = calculate_sha256_hash(chunk)
        encrypted_hash = encrypt_hash(hash_value, private_key)
        chunk_entry = {
            'sequence_number': i + 1,
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
chunks = read_file_chunks(file_path, chunk_size)

# Store the encrypted chunks in JSON format with sequence numbers
store_encrypted_chunks(chunks, output_file)

# Store the encrypted_chunks.json file in the Pico board
with open(output_file, 'r') as file:
    json_data = file.read()

with open('/path/to/destination/encrypted_chunks.json', 'w') as dest_file:
    dest_file.write(json_data)

# Establish a socket connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('10.10.10.10', 12345)  # Replace with the actual server IP
sock.connect(server_address)

# Send the JSON data to the server
sock.sendall(json_data.encode())

# Close the socket connection
sock.close()

