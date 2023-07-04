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

def encrypt_chunk(chunk, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_chunk = cipher.encrypt(chunk)
    return encrypted_chunk.hex()

def store_encrypted_chunks(chunks, output_file):
    data = []
    for i, chunk in enumerate(chunks):
        hash_value = calculate_sha256_hash(chunk)
        encrypted_chunk = {
            'sequence_number': i+1,
            'data': chunk.hex(),
            'encrypted_hash': hash_value
        }
        data.append(encrypted_chunk)

    with open(output_file, 'w') as file:
        json.dump(data, file)

def decrypt_hash(encrypted_hash, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_hash = cipher.decrypt(bytes.fromhex(encrypted_hash))
    return decrypted_hash.decode()

def check_integrity(chunk, decrypted_hash):
    calculated_hash = calculate_sha256_hash(chunk)
    return calculated_hash == decrypted_hash

def assemble_firmware(chunks, output_file):
    with open(output_file, "wb") as file:
        for chunk in chunks:
            file.write(chunk)

def verify_and_assemble_chunks(encrypted_chunks_file, private_key_file, output_file):
    with open(encrypted_chunks_file, "r") as file:
        encrypted_chunks = json.load(file)

    # Load the private key
    with open(private_key_file, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    valid_chunks = []
    for encrypted_chunk in encrypted_chunks:
        sequence_number = encrypted_chunk['sequence_number']
        data = bytes.fromhex(encrypted_chunk['data'])
        encrypted_hash = encrypted_chunk['encrypted_hash']

        # Decrypt the hash
        decrypted_hash = decrypt_hash(encrypted_hash, private_key)

        # Check integrity
        if check_integrity(data, decrypted_hash):
            valid_chunks.append(data)
            print(f"Chunk #{sequence_number}: Integrity verified.")
        else:
            print(f"Chunk #{sequence_number}: Integrity check failed. Skipping...")

    if len(valid_chunks) == len(encrypted_chunks):
        assemble_firmware(valid_chunks, output_file)
        print("Firmware reassembled successfully.")
    else:
        print("Integrity check failed. Cannot reassemble firmware.")

# Example usage
encrypted_chunks_file = "encrypted_chunks.json"
private_key_file = "private_key.pem"
output_file = "reassembled_firmware.uf2"

verify_and_assemble_chunks(encrypted_chunks_file, private_key_file, output_file)
