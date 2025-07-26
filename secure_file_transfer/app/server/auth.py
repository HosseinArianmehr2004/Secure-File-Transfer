import sqlite3
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from server.crypto import fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64


DB_PATH = "server/server.db"


def generate_salt():
    """Generate a random salt"""
    return os.urandom(16)


def hash_password(password: str, salt: bytes = None) -> tuple:
    """Hash a password with PBKDF2HMAC"""
    if salt is None:
        salt = generate_salt()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    hashed = kdf.derive(password.encode())
    return (salt + hashed, salt)


def verify_password(stored_hash: bytes, password: str) -> bool:
    """Verify a password against stored hash"""
    salt = stored_hash[:16]  # First 16 bytes are salt
    new_hash, _ = hash_password(password, salt)
    return new_hash == stored_hash


def create_initial_admin():
    """Create initial admin user if none exists"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE type='admin'")
    admin_count = c.fetchone()[0]

    if admin_count == 0:
        print("No admin users found. Creating initial admin...")
        print("Setting up initial admin account:")

        admin_username = input("Enter admin username: ")
        admin_password = input("Enter admin password: ")
        admin_email = input("Enter admin email (optional): ")

        # Hash the admin password
        hashed_password, _ = hash_password(admin_password)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        enc_pubkey = fernet.encrypt(pub_pem)

        try:
            c.execute(
                "INSERT INTO users (username, password, email, type, public_key) VALUES (?, ?, ?, ?, ?)",
                (admin_username, hashed_password, admin_email, "admin", enc_pubkey),
            )
            conn.commit()
            print(f"✅ Admin user '{admin_username}' created successfully!")

            os.makedirs("client/client_keys", exist_ok=True)
            keys_folder = f"client/client_keys/{admin_username}_keys"
            os.makedirs(keys_folder, exist_ok=True)

            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            with open(f"{keys_folder}/private.pem", "wb") as f:
                f.write(priv_pem)
            with open(f"{keys_folder}/public.pem", "wb") as f:
                f.write(pub_pem)

            print(f"🔑 Admin keys saved to {keys_folder}/")
            print("⚠️  IMPORTANT: Save these keys securely!")

        except sqlite3.IntegrityError:
            print("❌ Error: Username already exists!")
        except Exception as e:
            print(f"❌ Error creating admin user: {str(e)}")
    else:
        print(f"✅ Found {admin_count} admin user(s) in database.")

    conn.close()


def handle_register(client, data, db_path="server/server.db"):
    parts = data.strip().split()
    if len(parts) < 5:
        client.send(b"Invalid registration format.\n")
        return False

    _, username, password, email, b64_pubkey = (
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
    )

    try:
        # Hash the password before storing
        hashed_password, _ = hash_password(password)
        public_key = base64.b64decode(b64_pubkey.encode())
    except Exception:
        client.send(b"Invalid public key encoding.\n")
        return False

    enc_pubkey = fernet.encrypt(public_key)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password, email, public_key) VALUES (?, ?, ?, ?)",
            (username, hashed_password, email, enc_pubkey),
        )
        conn.commit()
        client.send(b"Registration successful.\n")
        conn.close()
        return True
    except sqlite3.IntegrityError:
        client.send(b"Username already exists.\n")
        conn.close()
        return False


def handle_login(client, data, db_path="server/server.db"):
    try:
        _, username, password = data.strip().split()
    except ValueError:
        client.send(b"Invalid login format.\n")
        return False

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()

    if row and verify_password(row[0], password):
        client.send(b"Login successful.\n")
        conn.close()
        return True
    else:
        client.send(b"Login failed.\n")
        conn.close()
        return False
