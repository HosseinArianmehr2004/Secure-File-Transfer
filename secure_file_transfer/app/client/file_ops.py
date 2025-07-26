from datetime import datetime
import hashlib
import json
import os
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes


def upload_file(client_socket, username, symmetric_key):
    """Upload a file to the server"""
    filepath = input("Enter path to file to upload: ")
    if not os.path.isfile(filepath):
        print("File does not exist.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        filedata = f.read()

    try:
        with open(f"client/client_keys/{username}_keys/private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            filedata,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        sig_length = len(signature)
        signed_data = sig_length.to_bytes(4, "big") + signature + filedata

        fernet = Fernet(symmetric_key)
        encrypted_data = fernet.encrypt(signed_data)

    except Exception as e:
        print(f"Error preparing file: {str(e)}")
        return

    client_socket.send(f"UPLOAD {username} {filename} {len(encrypted_data)}".encode())
    ack = client_socket.recv(1024)

    if ack != b"READY":
        print(f"Server response: {ack}")
        print("Server not ready for upload.")
        return

    client_socket.sendall(encrypted_data)
    resp = client_socket.recv(4096).decode()
    print(resp)


def download_file(client_socket, username, symmetric_key):
    """Secure file download with full verification and progress tracking"""
    client_socket.send(b"LIST_FILES")
    tree = client_socket.recv(16384).decode()

    print("\n--- Available Files ---")
    print(tree)
    if tree == "No files uploaded yet!":
        return

    filepath = input("\nEnter the relative path to download: ")
    uploader_username = filepath.split("/")[0] if "/" in filepath else None

    # 1. Request file
    client_socket.send(f"DOWNLOAD {filepath}".encode())
    ack = client_socket.recv(1024)
    if ack != b"READY":
        print("❌ Server not ready")
        return

    # 2. Receive file size
    filesize = int(client_socket.recv(32).decode())
    print(f"\n📦 Downloading {filesize} bytes...")

    # 3. Receive encrypted payload with progress
    encrypted_data = b""
    received = 0
    start_time = time.time()

    while received < filesize:
        chunk = client_socket.recv(min(4096, filesize - received))
        if not chunk:
            break
        encrypted_data += chunk
        received += len(chunk)

        # Progress tracking
        elapsed = time.time() - start_time
        speed = received / (elapsed + 0.0001) / 1024  # KB/s
        progress = received / filesize * 100
        print(
            f"\r⏳ {progress:.1f}% | {received}/{filesize} bytes | "
            f"{speed:.1f} KB/s | {elapsed:.1f}s",
            end="",
            flush=True,
        )

    print()  # New line after progress

    try:
        # 4. Decrypt with session key
        session_fernet = Fernet(symmetric_key)
        signed_data = session_fernet.decrypt(encrypted_data)

        # 5. Extract components (new format with hash)
        pos = 0
        sig_length = int.from_bytes(signed_data[pos : pos + 4], "big")
        pos += 4
        hash_length = int.from_bytes(signed_data[pos : pos + 4], "big")
        pos += 4
        expected_hash = signed_data[pos : pos + hash_length]
        pos += hash_length
        signature = signed_data[pos : pos + sig_length]
        pos += sig_length
        filedata = signed_data[pos:]

        # 6. Verify content hash
        actual_hash = hashlib.sha256(filedata).digest()
        hash_valid = actual_hash == expected_hash

        # 7. Verify signature (if available)
        signature_valid = True
        if uploader_username:
            signature_valid = verify_file_signature(
                uploader_username, filedata, signature, client_socket
            )

        # 8. Save file
        os.makedirs(f"client/client_downloaded_files/{username}", exist_ok=True)
        filename = os.path.basename(filepath)
        save_path = f"client/client_downloaded_files/{username}/{filename}"

        with open(save_path, "wb") as f:
            f.write(filedata)

        # 9. Display results
        print(f"\n✅ File saved to: {save_path}")
        print(f"📦 Size: {len(filedata)} bytes")
        print(f"📋 Uploaded by: {uploader_username or 'System'}")
        print(f"🔐 Content Hash: {'✅ Valid' if hash_valid else '❌ Invalid'}")
        print(
            f"🔏 Digital Signature: {'✅ Valid' if signature_valid else '❌ Invalid'}"
        )

        if not hash_valid or not signature_valid:
            print("\n❌ WARNING: File integrity verification failed!")
            if not hash_valid:
                print("   - File content has been modified")
            if not signature_valid:
                print("   - Signature verification failed")

    except Exception as e:
        print(f"\n❌ Download failed: {str(e)}")
        if os.path.exists(save_path):
            os.remove(save_path)


def delete_file(client_socket):
    """Delete a file from server"""
    client_socket.send(b"LIST_FILES")
    tree = client_socket.recv(16384).decode()
    print("--- Server Files ---")
    print(tree)

    if tree == "No files uploaded yet!":
        return

    filepath = input("Enter the relative path of the file to delete: ")
    client_socket.send(f"DELETE_FILE {filepath}".encode())
    response = client_socket.recv(4096).decode()
    print(response)


def rename_file(client_socket, username):
    """Handle file renaming"""
    list_files(client_socket)
    old_path = input("Enter file path to rename (e.g. your_username/filename): ")
    new_name = input("Enter new filename (without path): ")

    # Client-side validation
    if not old_path.startswith(username + "/"):
        print("❌ You can only rename your own files")
        return
    if "/" in new_name or "\\" in new_name:
        print("❌ New filename cannot contain path separators")
        return

    client_socket.send(f"RENAME {old_path} {new_name}".encode())
    print(client_socket.recv(4096).decode())


def list_files(client_socket):
    """Request and display a formatted list of available server files"""
    try:
        client_socket.send(b"LIST_FILES")
        response = client_socket.recv(16384).decode()

        if not response:
            print("\n❌ No response from server.")
            return

        print()
        print("╔══════════════════════════════════╗")
        print("║         AVAILABLE FILES          ║")
        print("╠══════════════════════════════════╣")

        if response == "No files uploaded yet!":
            print("║ No files found on the server.    ║")
        else:
            for line in response.split("\n"):
                if line.strip():
                    print(f"║ {line.ljust(30)}   ║")

        print("╚══════════════════════════════════╝")

    except Exception as e:
        print(f"\n❌ Failed to fetch files: {str(e)}")


def verify_file_signature(uploader_username, file_data, signature, client_socket):
    """Verify file signature using uploader's public key"""
    if not uploader_username:
        return True

    pubkey = get_user_public_key(uploader_username, client_socket)
    if not pubkey:
        print(
            f"⚠️ Warning: Could not verify file - missing public key for {uploader_username}"
        )
        return False

    try:
        pubkey.verify(
            signature,
            file_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def get_user_public_key(username, client_socket):
    """Fetch a specific user's public key from server"""
    client_socket.send(f"GET_PUBLIC_KEY {username}".encode())
    response = client_socket.recv(16384)

    if response == b"NOT_FOUND":
        return None

    try:
        pubkey = serialization.load_pem_public_key(base64.b64decode(response))
        return pubkey
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None


def view_file_info(client_socket):
    """View file metadata"""
    list_files(client_socket)
    path = input("Enter file path to inspect: ")
    client_socket.send(f"INFO {path}".encode())
    response = client_socket.recv(4096).decode()

    if response.startswith("{"):
        info = json.loads(response)
        print("\n📄 File Metadata:")
        print(f"Owner: {info['owner']}")
        print(f"Size: {info['size']} bytes")
        print(
            f"Last Modified: {datetime.fromtimestamp(info['modified']).strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"Type: {'File' if info['is_file'] else 'Directory'}")
    else:
        print(response)
