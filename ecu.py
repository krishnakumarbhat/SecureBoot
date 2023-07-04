import socket
import json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def decrypt_hash(encrypted_hash, public_key):
    decrypted_hash = public_key.verify(
        encrypted_hash,
        encrypted_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return decrypted_hash


def verify_hash(original_hash, decrypted_hash):
    return original_hash == decrypted_hash


def main():
    # Load the public key from the file
    public_key_file = "public_key.pem"
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Create a new server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # host = socket.gethostbyname(socket.gethostname())
    host = 'localhost'
    # Set the server address and port
    server_address = (host, 50000)

    # Bind the socket to the server address
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)
    print('Receiver is listening on {}:{}'.format(*server_address))

    # Accept a connection from the sender
    client_socket, client_address = server_socket.accept()
    print('Connected to sender at {}:{}'.format(*client_address))

    # Receive the encrypted file
    received_file = "received_chunks.json"
    with open(received_file, 'wb') as file:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            file.write(data)

    print('File received successfully as {}'.format(received_file))

    # Close the connection
    client_socket.close()
    server_socket.close()

    # Load the received encrypted hashes from the file
    # Load the received encrypted hashes from the file
    with open(received_file, 'rb') as file:
        data = json.load(file)

if __name__ == '__main__':
    main()
