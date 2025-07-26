import base64
import shutil
import sqlite3
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from server.auth import hash_password
from server.crypto import fernet
from cryptography.hazmat.primitives import serialization, hashes


DB_PATH = "server/server.db"
SERVER_FILES_DIR = "server/server_files_encrypted"

def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        type TEXT DEFAULT 'guest',
        public_key BLOB
        )"""
    )
    conn.commit()
    conn.close()


def get_db_connection(db_path=DB_PATH):
    return sqlite3.connect(db_path)


def show_all_users(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id, username, password, email, public_key, type FROM users")
    users = c.fetchall()
    conn.close()
    print("All users:")
    for user in users:
        print(user)


def handle_set_user_role(client, data, requesting_username, db_path=DB_PATH):
    if not check_user_permissions(requesting_username, "manage_users"):
        client.send(b"Permission denied. Only admin can manage user roles.\n")
        return

    parts = data.strip().split()
    if len(parts) != 3:
        client.send(b"Usage: SET_ROLE username role\n")
        return

    _, target_username, new_role = parts
    if new_role not in ["admin", "maintainer", "guest"]:
        client.send(b"Invalid role. Must be admin, maintainer, or guest.\n")
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("UPDATE users SET type=? WHERE username=?", (new_role, target_username))
    if c.rowcount > 0:
        client.send(f"Role updated successfully for {target_username}.\n".encode())
    else:
        client.send(b"User not found.\n")
    conn.commit()
    conn.close()


def handle_get_user_role(client, username, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT type FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        client.send(f"USER_ROLE:{row[0]}".encode())
    else:
        client.send(b"USER_ROLE:unknown")


def handle_get_public_key(client, data, db_path=DB_PATH):
    username = data.strip().split()[1]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row:
        try:
            pubkey = fernet.decrypt(row[0])
            client.send(base64.b64encode(pubkey))
        except Exception as e:
            print(f"Error sending public key: {e}")
            client.send(b"ERROR")
    else:
        client.send(b"NOT_FOUND")


def handle_get_public_keys(client, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username, public_key FROM users")
    users = c.fetchall()
    conn.close()

    result = []
    for username, enc_pubkey in users:
        try:
            pubkey = fernet.decrypt(enc_pubkey)
            pubkey_b64 = base64.b64encode(pubkey).decode()
            result.append(f"{username}:{pubkey_b64}")
        except Exception:
            continue

    response = "|".join(result)
    client.send(response.encode() if response else b"NO_KEYS")


# def check_user_permissions(username, action, target_user=None, db_path=DB_PATH):
#     conn = sqlite3.connect(db_path)
#     c = conn.cursor()
#     c.execute("SELECT type FROM users WHERE username=?", (username,))
#     row = c.fetchone()
#     conn.close()

#     if not row:
#         return False


#     user_type = row[0]
#     if action == "upload":
#         return user_type in ["admin", "maintainer"]
#     elif action == "delete":
#         return user_type == "admin" or (
#             user_type == "maintainer" and target_user == username
#         )
#     elif action == "manage_users":
#         return user_type == "admin"
#     return False
def check_user_permissions(username, action, target_user=None, db_path=DB_PATH):
    """Complete permission verification with all cases"""
    if not username or not action:
        return False

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Get requesting user's info
            c.execute("SELECT type FROM users WHERE username=?", (username,))

            user = c.fetchone()

            if not user:
                return False

            user_type = user["type"]
            print(f"usertype: {user_type}")

            # Permission matrix
            if action == "upload":
                return user_type in ["admin", "maintainer"]

            elif action == "delete_file":
                return user_type == "admin" or (
                    user_type == "maintainer" and target_user == username
                )

            elif action == "manage_users":
                return user_type == "admin"

            elif action == "create_user":
                return user_type == "admin"

            elif action == "delete_user":
                # Only admins can delete users
                if user_type != "admin":
                    return False
                        
                # Can't delete yourself
                if target_user == username:
                    return False
                    
                # Check target exists and isn't admin
                c.execute("SELECT type FROM users WHERE username=?", (target_user,))
                target = c.fetchone()
                return target and target[0] != "admin"

            elif action == "list_users":
                return user_type == "admin"

            return False

    except sqlite3.Error as e:
        print(f"Permission check error: {e}")
        return False


def handle_admin_create_user(client, data, requesting_username, db_path=DB_PATH):
    """Complete admin user creation with full validation"""
    try:
        # Verify admin permissions
        if not check_user_permissions(requesting_username, "create_user"):
            client.send(b"ERROR:Permission denied. Only admin can create users.\n")
            return

        parts = data.strip().split(maxsplit=4)
        if len(parts) < 5:
            client.send(
                b"ERROR:Invalid format. Usage: CREATE_USER username password email role\n"
            )
            return

        _, username, password, email, role = parts
        role = role.lower()

        # Validate inputs
        if not username.isalnum():
            client.send(b"ERROR:Username must be alphanumeric.\n")
            return

        if role not in ["admin", "maintainer", "guest"]:
            client.send(b"ERROR:Invalid role. Must be admin/maintainer/guest.\n")
            return

        # Generate keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Hash password
        hashed_password, _ = hash_password(password)
        enc_pubkey = fernet.encrypt(pub_pem)

        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()

            try:
                c.execute(
                    """INSERT INTO users 
                    (username, password, email, type, public_key) 
                    VALUES (?, ?, ?, ?, ?)""",
                    (username, hashed_password, email, role, enc_pubkey),
                )
                conn.commit()

                # Save keys locally
                keys_dir = f"client/client_keys/{username}_keys"
                os.makedirs(keys_dir, exist_ok=True)

                priv_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                with open(f"{keys_dir}/private.pem", "wb") as f:
                    f.write(priv_pem)
                with open(f"{keys_dir}/public.pem", "wb") as f:
                    f.write(pub_pem)

                client.send(f"SUCCESS:User {username} created as {role}.\n".encode())

            except sqlite3.IntegrityError:
                client.send(b"ERROR:Username already exists.\n")
            except Exception as e:
                client.send(f"ERROR:Failed to create user: {str(e)}\n".encode())

    except Exception as e:
        client.send(f"ERROR:System error: {str(e)}\n".encode())


# def handle_delete_user(client, data, requesting_username, db_path=DB_PATH):
#     """Admin-only user deletion"""
#     if not check_user_permissions(requesting_username, "manage_users"):
#         client.send(b"Permission denied. Only admin can delete users.\n")
#         return

#     parts = data.strip().split()
#     if len(parts) != 2:
#         client.send(b"Usage: DELETE_USER username\n")
#         return

#     target_username = parts[1]

#     # Prevent self-deletion
#     if target_username == requesting_username:
#         client.send(b"Cannot delete your own account.\n")
#         return

#     conn = sqlite3.connect(db_path)
#     c = conn.cursor()
#     try:
#         # First delete user's files
#         user_files_dir = os.path.join("server/server_files_encrypted", target_username)
#         if os.path.exists(user_files_dir):
#             for filename in os.listdir(user_files_dir):
#                 file_path = os.path.join(user_files_dir, filename)
#                 try:
#                     os.unlink(file_path)
#                 except Exception as e:
#                     print(f"Error deleting file {file_path}: {e}")
#             os.rmdir(user_files_dir)

#         # Then delete user record
#         c.execute("DELETE FROM users WHERE username=?", (target_username,))
#         conn.commit()

#         # Delete keys (if exists)
#         keys_dir = f"client/client_keys/{target_username}_keys"
#         if os.path.exists(keys_dir):
#             for key_file in ["private.pem", "public.pem"]:
#                 try:
#                     os.remove(os.path.join(keys_dir, key_file))
#                 except FileNotFoundError:
#                     pass
#             os.rmdir(keys_dir)


#         client.send(f"User {target_username} deleted successfully.\n".encode())
#     except Exception as e:
#         client.send(f"Error deleting user: {str(e)}\n".encode())
#     finally:
#         conn.close()
def handle_delete_user(client, data, requesting_username, db_path=DB_PATH):
    """Complete user deletion with proper error handling"""
    try:
        parts = data.strip().split()
        if len(parts) != 2:
            client.send(b"ERROR:Usage: DELETE_USER username\n")
            return

        target_username = parts[1]

        # Verify admin permissions
        if not check_user_permissions(requesting_username, "delete_user", target_username):
            client.send(b"ERROR:Permission denied. Only admin can delete users.\n")
            return

        # Prevent self-deletion
        if target_username == requesting_username:
            client.send(b"ERROR:Cannot delete your own account.\n")
            return

        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()

            # Verify target user exists and isn't an admin
            c.execute("SELECT type FROM users WHERE username=?", (target_username,))
            target_user = c.fetchone()

            if not target_user:
                client.send(b"ERROR:User not found.\n")
                return

            if target_user[0] == "admin":
                client.send(b"ERROR:Cannot delete other admin users.\n")
                return

            # Delete user's files if directory exists
            user_files_dir = os.path.join(SERVER_FILES_DIR, target_username)
            try:
                if os.path.exists(user_files_dir):
                    shutil.rmtree(user_files_dir)
                    print(f"[SERVER] Deleted files for user {target_username}")
            except Exception as e:
                print(f"[SERVER] Warning: Could not delete user files: {e}")

            # Delete user's keys if directory exists
            keys_dir = f"client/client_keys/{target_username}_keys"
            try:
                if os.path.exists(keys_dir):
                    shutil.rmtree(keys_dir)
                    print(f"[SERVER] Deleted keys for user {target_username}")
            except Exception as e:
                print(f"[SERVER] Warning: Could not delete user keys: {e}")

            # Delete user record
            c.execute("DELETE FROM users WHERE username=?", (target_username,))
            conn.commit()

            client.send(f"SUCCESS:User {target_username} and all associated data deleted successfully.\n".encode())

    except Exception as e:
        client.send(f"ERROR:Failed to delete user: {str(e)}\n".encode())

def handle_list_users(client, requesting_username, db_path=DB_PATH):
    """List all users (admin only)"""
    if not check_user_permissions(requesting_username, "manage_users"):
        client.send(b"Permission denied. Only admin can list users.\n")
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username, email, type FROM users")
    users = c.fetchall()
    conn.close()

    if not users:
        client.send(b"No users found.\n")
        return

    response = "Username\tEmail\t\tRole\n" + "\n".join(
        [f"{u[0]}\t{u[1]}\t{u[2]}" for u in users]
    )
    client.send(response.encode())
