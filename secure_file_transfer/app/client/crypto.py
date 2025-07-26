
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def generate_keys(username):
    """Generate RSA key pair and save to files"""
    os.makedirs("client/client_keys", exist_ok=True)
    keys_folder = f"client/client_keys/{username}_keys"
    os.makedirs(keys_folder, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(f"{keys_folder}/private.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"{keys_folder}/public.pem", "wb") as f:
        f.write(pub_pem)

    return priv_pem, pub_pem

def handle_symmetric_key_receive(client_socket, username):
    """Receive and decrypt the symmetric key from the server"""
    try:
        import socket
        client_socket.settimeout(10)
        key_data = client_socket.recv(4096)
        client_socket.settimeout(None)

        if key_data.startswith(b"SYMMETRIC_KEY:"):
            encrypted_symkey = base64.b64decode(key_data.split(b":")[1])

            private_key_path = f"client/client_keys/{username}_keys/private.pem"
            if not os.path.exists(private_key_path):
                print(f"[CLIENT] Error: Private key not found at {private_key_path}")
                return None

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )

            symmetric_key = private_key.decrypt(
                encrypted_symkey,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            print(f"[CLIENT] Received and decrypted symmetric key successfully")
            return symmetric_key
        else:
            print("[CLIENT] Failed to receive symmetric key.")
            return None
    except socket.timeout:
        print("[CLIENT] Timeout waiting for symmetric key.")
        return None
    except Exception as e:
        print(f"[CLIENT] Error receiving symmetric key: {e}")
        return None