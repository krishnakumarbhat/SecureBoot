import os
import socket
import json
import hashlib
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        port = int(request.form['port'])
        ip_address1 = request.form['ip_address1']
        port1 = int(request.form['port1'])
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join('uploads', filename))
        file_path = os.path.join('uploads', filename)

        private_key_file = 'private_key_file_in_pem.pem'

        client_a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ip_address, port)
        client_a_socket.connect(server_address)

        # Request private key from the server (Client B)
        client_a_socket.send(b"private_key_request")
        private_key = client_a_socket.recv(2048)

        # Write the received private key to a PEM file
        private_key_pem = serialization.load_pem_private_key(private_key, password=None)
        private_key_pem_formatted = private_key_pem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_file, 'wb') as file:
            file.write(private_key_pem_formatted)

        # Create a certificate signing request (CSR)
        subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'tester'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'AutomotiveCyberSecurityOrg'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'SecureBoot'),
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'IN'),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'Mysuru'),
            x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u'email@tester.com')
        ])

        with open(private_key_file, 'rb') as key_file:
            private_key_1 = load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            private_key_1, hashes.SHA256(), default_backend()
        )

        # Convert the CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # Send CSR in socket
        client_a_socket.send(csr_pem)

        received_json_str = client_a_socket.recv(4096).decode('utf-8')
        certificate_json = json.loads(received_json_str)

        # Specify the file path to store the JSON data
        certificate_file_path = 'certificate.json'

        # Write the JSON object to the file
        with open(certificate_file_path, 'w') as file:
            json.dump(certificate_json, file)

        client_a_socket.close()

        # Divide software blocks into chunks
        chunk_size = 4096

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

        # Hash each chunk using SHA-256
        def hash_chunk(chunk):
            hash_object = hashlib.sha256()
            hash_object.update(chunk)
            return hash_object.digest()

        hashed_chunks = [hash_chunk(chunk) for chunk in chunks]

        # Encrypt and store the blocks in a file
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

        def send_encrypted_hash(encrypted_hash, client_socket):
            client_socket.sendall(encrypted_hash)

        def store_encrypted_chunks(chunks, output_file, private_key_file, ip_address1, port1):
            client_a_socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address1 = (ip_address1, port1)
            client_a_socket1.connect(server_address1)

            with open(private_key_file, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)

            data = []
            for i, chunk in enumerate(chunks):
                hash_value = hash_chunk(chunk)
                encrypted_hash = encrypt_hash(hash_value, private_key)

                chunk_entry = {
                    'sequence_number': i + 1,
                    'chunk': chunk.hex(),
                    'encrypted_hash': encrypted_hash.hex()
                }
                data.append(chunk_entry)

                send_encrypted_hash(encrypted_hash, client_a_socket1)

            client_a_socket1.close()

            with open(output_file, 'w') as file:
                json.dump(data, file)

        store_encrypted_chunks(hashed_chunks, output_file, private_key_file, ip_address1, port1)

        return render_template("home.html", user=current_user, success=True)

    return render_template("home.html", user=current_user, success=False)
