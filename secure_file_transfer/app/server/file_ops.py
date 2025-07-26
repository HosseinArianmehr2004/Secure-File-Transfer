import hashlib
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature
from server.crypto import fernet
from server.database import get_db_connection
from cryptography.hazmat.primitives import serialization, hashes


SERVER_FILES_DIR = "server/server_files_encrypted"


def handle_upload(client, data, symmetric_key, username):
    if not check_user_permissions(username, "upload"):
        client.send(b"Permission denied. Only admin and maintainer can upload files.\n")
        return

    parts = data.strip().split()
    if len(parts) < 4:
        client.send(b"Invalid upload command.\n")
        return

    _, username, filename, filesize = parts[0], parts[1], parts[2], int(parts[3])
    client.send(b"READY")

    encrypted_data = b""
    received = 0
    while received < filesize:
        chunk = client.recv(min(4096, filesize - received))
        if not chunk:
            break
        encrypted_data += chunk
        received += len(chunk)

    try:
        session_fernet = Fernet(symmetric_key)
        signed_data = session_fernet.decrypt(encrypted_data)

        sig_length = int.from_bytes(signed_data[:4], "big")
        signature = signed_data[4 : 4 + sig_length]
        filedata = signed_data[4 + sig_length :]

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        signature_valid = False
        if row:
            client_pubkey = fernet.decrypt(row[0])
            pubkey = serialization.load_pem_public_key(client_pubkey)

            try:
                pubkey.verify(
                    signature,
                    filedata,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                print(f"[SERVER] File signature verified for {username}")
                signature_valid = True
            except InvalidSignature:
                print(f"[SERVER] Warning: Invalid signature for file from {username}")
                signature_valid = False

        file_with_signature = sig_length.to_bytes(4, "big") + signature + filedata
        encrypted_file_data = fernet.encrypt(file_with_signature)

        user_dir = os.path.join(SERVER_FILES_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        existing_files = [
            f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))
        ]
        next_num = len(existing_files) + 1
        numbered_filename = f"{next_num}-{filename}"

        with open(os.path.join(user_dir, numbered_filename), "wb") as f:
            f.write(encrypted_file_data)

        status_msg = "verified" if signature_valid else "uploaded but signature invalid"
        client.send(
            f"File {status_msg} and encrypted successfully as {numbered_filename}.\n".encode()
        )

    except Exception as e:
        print(f"[SERVER] Detailed error: {str(e)}")
        client.send(b"Error processing file upload.\n")


def handle_list_files(client):
    root_dir = SERVER_FILES_DIR
    if not os.path.exists(root_dir):
        client.send(b"No files uploaded yet!")
        return

    users = [
        user
        for user in os.listdir(root_dir)
        if os.path.isdir(os.path.join(root_dir, user))
    ]
    if not users:
        client.send(b"No files uploaded yet!")
        return

    tree_lines = []
    has_files = False
    for user in users:
        user_path = os.path.join(root_dir, user)
        files = os.listdir(user_path)
        if files:
            has_files = True
            tree_lines.append(f"{user}/")
            for fname in files:
                tree_lines.append(f"  {user}/{fname}")

    if not has_files:
        client.send(b"No files uploaded yet!")
        return

    tree_str = "\n".join(tree_lines)
    client.send(tree_str.encode())


def handle_download(client, data, symmetric_key):
    """Secure file download with transport encryption and hash verification"""
    parts = data.strip().split(maxsplit=1)
    if len(parts) < 2:
        client.send(b"Invalid download command.")
        return

    rel_path = parts[1]
    file_path = os.path.join(SERVER_FILES_DIR, rel_path)

    if not os.path.isfile(file_path):
        client.send(b"NOT_FOUND")
        return

    try:
        # 1. Decrypt stored file with server key
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        signed_file_data = fernet.decrypt(encrypted_data)

        # 2. Extract components
        sig_length = int.from_bytes(signed_file_data[:4], "big")
        signature = signed_file_data[4 : 4 + sig_length]
        original_filedata = signed_file_data[4 + sig_length :]

        # 3. Generate file hash
        file_hash = hashlib.sha256(original_filedata).digest()

        # 4. Encrypt with session key (hash included in payload)
        session_fernet = Fernet(symmetric_key)
        payload = (
            sig_length.to_bytes(4, "big")
            + len(file_hash).to_bytes(4, "big")  # Hash length prefix
            + file_hash
            + signature
            + original_filedata
        )
        encrypted_payload = session_fernet.encrypt(payload)

        # 5. Send securely
        client.send(b"READY")
        client.send(str(len(encrypted_payload)).encode())
        client.sendall(encrypted_payload)

        print(f"[SERVER] Secure download completed for {rel_path}")

    except Exception as e:
        print(f"[SERVER] Download error: {str(e)}")
        client.send(b"DOWNLOAD_ERROR")


def handle_delete_file(client, data, username):
    parts = data.strip().split(maxsplit=1)
    if len(parts) < 2:
        client.send(b"Usage: DELETE_FILE filepath\n")
        return

    filepath = parts[1]
    file_owner = filepath.split("/")[0] if "/" in filepath else username

    if not check_user_permissions(username, "delete", file_owner):
        client.send(b"Permission denied.\n")
        return

    full_path = os.path.join(SERVER_FILES_DIR, filepath)
    if os.path.isfile(full_path):
        try:
            os.remove(full_path)
            client.send(f"File {filepath} deleted successfully.\n".encode())
        except Exception as e:
            client.send(f"Error deleting file: {str(e)}\n".encode())
    else:
        client.send(b"File not found.\n")


def handle_get_signature(client, data):
    filepath = data.strip().split()[1]
    full_path = os.path.join(SERVER_FILES_DIR, filepath)

    if not os.path.isfile(full_path):
        client.send(b"NOT_FOUND")
        return

    try:
        with open(full_path, "rb") as f:
            encrypted_data = f.read()

        signed_file_data = fernet.decrypt(encrypted_data)
        sig_length = int.from_bytes(signed_file_data[:4], "big")
        signature = signed_file_data[4 : 4 + sig_length]

        client.send(b"SIGNATURE:" + base64.b64encode(signature))
    except Exception as e:
        print(f"Error retrieving signature: {e}")
        client.send(b"ERROR")


def handle_rename(client, data, username):
    """Handle file renaming for maintainers"""
    try:
        parts = data.strip().split()
        if len(parts) != 3:
            client.send(b"Usage: RENAME old_path new_name")
            return

        old_path = parts[1]
        new_name = parts[2]

        # Security checks
        if not old_path.startswith(username + "/"):
            client.send(b"Can only rename your own files")
            return
        if "../" in new_name or "/" in new_name:
            client.send(b"Invalid new filename")
            return

        old_full = os.path.join(SERVER_FILES_DIR, old_path)
        new_full = os.path.join(SERVER_FILES_DIR, username, new_name)

        if not os.path.exists(old_full):
            client.send(b"File not found")
            return

        os.rename(old_full, new_full)
        client.send(b"File renamed successfully")

    except Exception as e:
        client.send(f"Error: {str(e)}".encode())


def handle_file_info(client, data):
    """Return file metadata"""
    try:
        path = data.strip().split()[1]
        full_path = os.path.join(SERVER_FILES_DIR, path)

        if not os.path.exists(full_path):
            client.send(b"NOT_FOUND")
            return

        info = {
            "owner": path.split("/")[0],
            "size": os.path.getsize(full_path),
            "modified": os.path.getmtime(full_path),
            "is_file": os.path.isfile(full_path),
        }
        client.send(json.dumps(info).encode())

    except Exception as e:
        client.send(f"ERROR: {str(e)}".encode())


def check_user_permissions(username, action, target_user=None):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT type FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return False

    user_type = row[0]
    if action == "upload":
        return user_type in ["admin", "maintainer"]
    elif action == "delete":
        return user_type == "admin" or (
            user_type == "maintainer" and target_user == username
        )
    elif action == "manage_users":
        return user_type == "admin"
    return False
