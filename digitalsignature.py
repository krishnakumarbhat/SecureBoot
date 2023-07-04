
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


########step1########## sending request for PKI for keys


private_key_file='private_key_file_in_pem.pem'

client_a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 48000)
client_a_socket.connect(server_address)

# Request private key from the server (Client B)
client_a_socket.send(b"private_key_request")
private_key = client_a_socket.recv(2048)
print(private_key)

# Write the received private key to a PEM file

# Convert the private key PEM to the desired format
private_key_pem = serialization.load_pem_private_key(private_key, password=None)
private_key_pem_formatted = private_key_pem.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
# Save the formatted PEM to a file
with open(private_key_file, 'wb') as file:
    file.write(private_key_pem_formatted)

#######step 2###########generate csr

# Create a certificate signing request (CSR)
subject = x509.Name([
    # Common Name (CN) - Typically the name of the entity
x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'tester'),

    # Organization (O) - The name of the organization
x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME,
                       u'AutomotiveCyberSecurityOrg'),

   # Organizational Unit (OU) - The department or division within the organization
x509.NameAttribute(
    x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'SecureBoot'),

    # Country (C) - The country code
x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'IN'),

    # State or Province (ST) - The state or province name
x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),

    # Locality (L) - The city or locality name
x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'Mysuru'),

    # Email Address (emailAddress) - The email address of the entity
x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u'email@tester.com')
])

# fake_file= 'C:/Users/Gururaj/Desktop/chat/onlycrypto/private_key.pem'
with open(private_key_file, 'rb') as key_file:
    private_key_1 = load_pem_private_key(
        key_file.read(), password=None, backend=default_backend())


csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key_1, hashes.SHA256(), default_backend()
        )

# Convert the CSR to PEM format
csr_pem = csr.public_bytes(serialization.Encoding.PEM)


# ###########step 3##### send csr in socket 
client_a_socket.send(csr_pem)
print("Certificate Signing Request sent to the server.....")
received_json_str = client_a_socket.recv(4096).decode('utf-8')
print(received_json_str)
# Parse the JSON string to a JSON object
certificate_json = json.loads(received_json_str)

print("Received signed certificate from the Certificate Authority....")
# Specify the file path to store the JSON data
certificate_file_path = 'certificate.json'

# Write the JSON object to the file
with open(certificate_file_path, 'w') as file:
    json.dump(certificate_json, file)

# # # Close the connection
client_a_socket.close()

#certificate is stored in the file.

######step 4############### dividing software blocks

file_path = "firmware.uf2"
chunk_size = 4096
#1
def divide_into_chunks(file_path, chunk_size):
    chunks = []
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    return chunks

chunks = divide_into_chunks(file_path, chunk_size)

#2
# Hash each chunk using SHA-256
def hash_chunk(chunk):
    hash_object = hashlib.sha256()
    hash_object.update(chunk)
    return hash_object.digest()

hashed_chunks = [hash_chunk(chunk) for chunk in chunks]

#3
# encrypt and store the blocks in a file
output_file = "encrypted_chunks.json"

def encrypt_hash(hash_value, private_key):
    encrypted_hash = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return encrypted_hash

def store_encrypted_chunks(chunks, output_file, private_key_file):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    data = [certificate_json]
    for i, chunk in enumerate(chunks):
        hash_value = hash_chunk(chunk)
        encrypted_hash = encrypt_hash(hash_value, private_key)
        
        chunk_entry = {
            'sequence_number': i+1,
            'chunk': chunk.hex(),
            'encrypted_hash': encrypted_hash.hex()
        }
        data.append(chunk_entry)

    with open(output_file, 'w') as file:
        json.dump(data, file)

store_encrypted_chunks(hashed_chunks, output_file, private_key_file)

# Create a new socket
client_socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set the server address
server_address1 = ('localhost', 50000)

# Connect to the server
client_socket1.connect(server_address1)

# Read the encrypted JSON file
encrypted_file = "encrypted_chunks.json"
with open(encrypted_file, 'rb') as file:
    data = file.read()

# Send the encrypted file to the server
client_socket1.sendall(data)

# Close the connection
client_socket1.close()



