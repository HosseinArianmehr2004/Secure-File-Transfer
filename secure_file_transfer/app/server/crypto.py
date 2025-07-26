import base64
import os
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes


SERVER_KEY_PATH = "server/server_key.key"

# Generate or load server encryption key
if not os.path.exists(SERVER_KEY_PATH):
    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(Fernet.generate_key())
with open(SERVER_KEY_PATH, "rb") as f:
    SERVER_ENCRYPTION_KEY = f.read()
fernet = Fernet(SERVER_ENCRYPTION_KEY)


def send_symmetric_key(username, symmetric_key, client, db_path="server/server.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row:
        try:
            client_pubkey = fernet.decrypt(row[0])
            pubkey = serialization.load_pem_public_key(client_pubkey)

            encrypted_key = pubkey.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            client.send(b"SYMMETRIC_KEY:" + base64.b64encode(encrypted_key))
            print(f"[SERVER] Sent encrypted symmetric key to {username}")
        except Exception as e:
            print(f"[SERVER] Error sending symmetric key: {str(e)}")
            client.send(b"KEY_EXCHANGE_ERROR")


def regenerate_session_key(username, client, db_path="server/server.db"):
    new_key = Fernet.generate_key()
    send_symmetric_key(username, new_key, client, db_path)
    return new_key
