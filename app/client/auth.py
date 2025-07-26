import os
import base64
from cryptography.hazmat.primitives import serialization
from client.crypto import generate_keys


def authenticate(client_socket):
    """Handle registration/login, reuse existing keys if already registered."""
    while True:
        print("\n--- Authentication ---")
        print("1. Register")
        print("2. Login")
        print("0. Exit")
        choice = input("Select an option: ")

        if choice == "1": # Register
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            email = input("Enter email (optional): ").strip()

            if not username or not password:
                print("❌ Username and password are required!")
                continue

            # Check if keys already exist for this user
            keys_folder = f"client/client_keys/{username}_keys"
            if os.path.exists(keys_folder):
                print(f"❌ User '{username}' already registered. Please login instead.")
                continue

            # Generate keys only for new users
            priv, pub = generate_keys(username)
            pub_b64 = base64.b64encode(pub).decode()

            try:
                client_socket.send(
                    f"REGISTER {username} {password} {email} {pub_b64}".encode()
                )
                response = client_socket.recv(4096).decode()
                print(response)

                if "successful" in response.lower():
                    return username
            except Exception as e:
                print(f"❌ Network error during registration: {str(e)}")
                continue

        elif choice == "2": # Login
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()

            private_key_path = f"client/client_keys/{username}_keys/private.pem"
            if not os.path.exists(private_key_path):
                print(f"❌ No keys found for '{username}'. Did you register first?")
                continue

            try:
                client_socket.send(f"LOGIN {username} {password}".encode())
                response = client_socket.recv(4096).decode()
                print(response)

                if "successful" in response.lower():
                    return username
            except Exception as e:
                print(f"❌ Network error during login: {str(e)}")
                continue

        elif choice == "0":
            client_socket.send(b"EXIT")
            client_socket.close()
            exit()
        else:
            print("Invalid option. Please try 1, 2, or 0.")
