import base64
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import time
import json
import re


def generationStorageDistributionOfKeys(clientAddress):
    # Generating key pair using RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    
    public_key = private_key.public_key()
    print(
        f"Keys generated successfully for the client with address-{clientAddress}")

    print("Keys generated:\n")
    print(private_key, "\n")
    print("\n", public_key, "\n")

    # Convert keys to Privacy-Enhanced Mail(PEM) format
    global private_pem
    global private_key_file
    private_key_file='private_key.pem'
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_file, 'wb') as file:
        file.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(private_pem, "\n")
    print(public_pem, "\n")

    # return (private_key, public_key)
    return private_key


def generationStorageDistributionCertificates(clientAddress, csr_pem):
    # Load the client's CSR
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Accessing private key of the server
    
    with open(private_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend())

    print("Generating Certificate....")
    time.sleep(1)

    # Create a certificate for the client
    subject = csr.subject
    issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,
                           u'JSS Certificate Authority'),
        x509.NameAttribute(
            x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'IN'),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'Mysuru')
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )

    # Create a hash of the client's information
    cert_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    cert_hash.update(csr_pem)
    hash_value = cert_hash.finalize()

    # Sign the hash with the private key
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Add the signature and algorithm information to the certificate
    cert = cert.add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.2.3.4.5'), signature
        ),
        critical=False
    ).add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.2.3.4.6'), b'SHA256'
        ),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    print(
        f"Certificate generated successfully for the client with address-{clientAddress}")

    # Convert the signed certificate to PEM format
    signed_cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # Return the signed certificate to the client
    return signed_cert_pem



def handleClientsRequest1(clientSocket, clientAddress):
    request = clientSocket.recv(2048).decode()
    if request == "private_key_request":
        private_key = generationStorageDistributionOfKeys(clientAddress)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        clientSocket.send(private_key_pem)

def handleClientsRequest(clientSocket, clientAddress):
    csr_pem = clientSocket.recv(4096)
    print("Received Certificate Signing Request from the client")
    signedCertificatePEM = generationStorageDistributionCertificates(
        clientAddress, csr_pem)
    print(signedCertificatePEM)
    certificate_json = {
        'certificate': signedCertificatePEM.decode('utf-8')
    }
    # Convert the dictionary to a JSON string
    certificate_json_str = json.dumps(certificate_json)

    # Send the JSON string to the client
    clientSocket.send(certificate_json_str.encode('utf-8'))
    print("Certificate sent successfully....!\n\n")


# Handle client requests
# Set up the server socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverAddress = ('localhost', 48000)
serverSocket.bind(serverAddress)
serverSocket.listen(1)
print(f"Server is listening...{serverAddress}")

# Wait for Client A to connect
clientAsocket, clientAaddress = serverSocket.accept()
print("Client A connected:", clientAaddress)

# Handle Client A's first request
handleClientsRequest1(clientAsocket, clientAaddress)

print("Client A connected again:", clientAaddress)

handleClientsRequest(clientAsocket, clientAaddress)


# Close the connection with Client A
clientAsocket.close()

# Close the server socket
serverSocket.close()

