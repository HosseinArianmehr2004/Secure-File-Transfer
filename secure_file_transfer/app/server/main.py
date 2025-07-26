import socket
import threading
from server.database import handle_admin_create_user, handle_delete_user, handle_list_users, init_db, handle_get_public_keys, handle_set_user_role, handle_get_user_role, handle_get_public_key
from server.auth import create_initial_admin, handle_register, handle_login
from server.file_ops import handle_file_info, handle_rename, handle_upload, handle_list_files, handle_download, handle_delete_file, handle_get_signature
from server.crypto import send_symmetric_key, regenerate_session_key, fernet
from cryptography.fernet import Fernet


class Server:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def start(self):
        while True:
            client, addr = self.sock.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client,)).start()

    def handle_client(self, client):
        client.send(b"Welcome!")

        symmetric_key = Fernet.generate_key()
        print(f"[SERVER] Generated session symmetric key: {symmetric_key.decode()}")

        authenticated = False
        username = None

        while True:
            try:
                data = client.recv(16384)
                if not data:
                    break
                data = data.decode()

                if not authenticated:
                    if data.startswith("REGISTER"):
                        if handle_register(client, data):
                            username = data.split()[1]
                            authenticated = True
                            send_symmetric_key(username, symmetric_key, client)
                    elif data.startswith("LOGIN"):
                        if handle_login(client, data):
                            username = data.split()[1]
                            authenticated = True
                            send_symmetric_key(username, symmetric_key, client)
                        else:
                            continue
                    else:
                        client.send(b"Please authenticate first (REGISTER or LOGIN)\n")
                        continue

                elif data.startswith("GET_PUBLIC_KEYS"):
                    handle_get_public_keys(client)
                elif data.startswith("UPLOAD"):
                    handle_upload(client, data, symmetric_key, username)
                elif data.startswith("LIST_FILES"):
                    handle_list_files(client)
                elif data.startswith("DOWNLOAD"):
                    handle_download(client, data, symmetric_key)
                elif data.startswith("DELETE_FILE"):
                    handle_delete_file(client, data, username)
                elif data.startswith("SET_ROLE"):
                    handle_set_user_role(client, data, username)
                elif data.startswith("GET_USER_ROLE"):
                    handle_get_user_role(client, username)
                elif data.startswith("GET_PUBLIC_KEY"):
                    handle_get_public_key(client, data)
                elif data.startswith("GET_SIGNATURE"):
                    handle_get_signature(client, data)
                elif data.startswith("RENAME"):
                    handle_rename(client, data, username)
                elif data.startswith("INFO"):
                    handle_file_info(client, data)
                elif data.startswith("CREATE_USER"):
                    handle_admin_create_user(client, data, username)
                elif data.startswith("DELETE_USER"):
                    handle_delete_user(client, data, username)
                elif data.startswith("LIST_USERS"):
                    handle_list_users(client, username)
                elif data.strip().upper() == "EXIT":
                    client.send(b"Goodbye!\n")
                    break
                else:
                    client.send(b"Unknown command.\n")

            except Exception as e:
                client.send(f"Error: {str(e)}\n".encode())
                print(f"[SERVER] Client error: {str(e)}")
                break

        client.close()
        print(f"[SERVER] Client disconnected")

if __name__ == "__main__":
    init_db()
    create_initial_admin()
    print("🚀 Starting secure file transfer server...")
    server = Server()
    server.start()