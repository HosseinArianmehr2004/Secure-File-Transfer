import os
from client.file_ops import (
    rename_file,
    upload_file,
    download_file,
    delete_file,
    list_files,
    view_file_info,
)
from client.auth import authenticate


def get_public_keys(client_socket):
    """Request all public keys from server"""
    client_socket.send(b"GET_PUBLIC_KEYS")
    data = client_socket.recv(16384).decode()

    if data == "NO_KEYS":
        print("No public keys found.")
    else:
        print("All users and their public keys:")
        for entry in data.split("|"):
            uname, pubkey_b64 = entry.split(":", 1)
            print(f"User: {uname}\nPublic Key (base64): {pubkey_b64}\n")


def set_user_role(client_socket):
    """Set user role (admin only)"""
    username = input("Enter username: ")
    role = input("Enter role (admin/maintainer/guest): ")
    client_socket.send(f"SET_ROLE {username} {role}".encode())
    response = client_socket.recv(4096).decode()
    print(response)


def fetch_user_role(client_socket):
    """Fetch user's role from server and store it"""
    try:
        client_socket.send(b"GET_USER_ROLE")
        response = client_socket.recv(1024).decode()
        if response.startswith("USER_ROLE:"):
            return response.split(":")[1]
        else:
            return "guest"
    except Exception as e:
        print(f"⚠️  Warning: Could not fetch role ({str(e)}). Defaulting to 'guest'.")
        return "guest"


# def admin_menu(client_socket, username, symmetric_key):
#     """Menu for admin users"""
#     while True:
#         os.system("cls" if os.name == "nt" else "clear")
#         print(
#             f"""
# ╔══════════════════════════════════╗
# ║          ADMIN MENU              ║
# ╠══════════════════════════════════╣
# ║ 1. List All Public Keys          ║
# ║ 2. Upload File                   ║
# ║ 3. Download File                 ║
# ║ 4. Delete Any File               ║
# ║ 5. Manage User Roles             ║
# ║ 6. View All Files                ║
# ║ 7. Rename Files                  ║
# ║ 8. View File Metadata            ║
# ║                                  ║
# ║ 0. Exit                          ║
# ╚══════════════════════════════════╝
# Role: admin | User: {username}
#         """
#         )
#         choice = input("Select option (0-8): ")

#         if choice == "1":
#             get_public_keys(client_socket)
#         elif choice == "2":
#             upload_file(client_socket, username, symmetric_key)
#         elif choice == "3":
#             download_file(client_socket, username, symmetric_key)
#         elif choice == "4":
#             delete_file(client_socket)
#         elif choice == "5":
#             set_user_role(client_socket)
#         elif choice == "6":
#             list_files(client_socket)
#         elif choice == "7":
#             rename_file(client_socket, username)
#         elif choice == "8":
#             view_file_info(client_socket)
#         elif choice == "0":
#             client_socket.send(b"EXIT")
#             return
#         else:
#             print("Invalid option!")


#         input("\nPress Enter to continue...")
def admin_menu(client_socket, username, symmetric_key):
    """Complete admin menu with user management"""
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(
            f"""
╔══════════════════════════════════╗
║          ADMIN MENU              ║
╠══════════════════════════════════╣
║ 1. List All Public Keys          ║
║ 2. Upload File                   ║
║ 3. Download File                 ║
║ 4. Delete Any File               ║
║ 5. Manage User Roles             ║
║ 6. Create New User               ║
║ 7. Delete User                   ║
║ 8. List All Users                ║
║ 9. View All Files                ║
║ 10. Rename Files                 ║
║ 11. View File Metadata           ║
║                                  ║
║ 0. Exit                          ║
╚══════════════════════════════════╝
Role: admin | User: {username}
        """
        )
        choice = input("Select option (0-11): ").strip()

        if choice == "1":
            get_public_keys(client_socket)
        elif choice == "2":
            upload_file(client_socket, username, symmetric_key)
        elif choice == "3":
            download_file(client_socket, username, symmetric_key)
        elif choice == "4":
            delete_file(client_socket)
        elif choice == "5":
            target = input("Enter username to modify: ")
            new_role = input("Enter new role (admin/maintainer/guest): ")
            client_socket.send(f"SET_ROLE {target} {new_role}".encode())
            print(client_socket.recv(4096).decode())
        elif choice == "6":
            try:
                print("\n── Create New User ──")
                uname = input("Username: ").strip()
                pwd = input("Password: ").strip()
                email = input("Email (optional): ").strip()
                role = input("Role (admin/maintainer/guest): ").strip().lower()

                if not uname or not pwd:
                    print("❌ Username and password required!")
                    input("Press Enter to continue...")
                    continue

                client_socket.send(f"CREATE_USER {uname} {pwd} {email} {role}".encode())
                response = client_socket.recv(4096).decode()

                if response.startswith("SUCCESS:"):
                    print(f"✅ {response[8:]}", end="")
                else:
                    print(f"❌ {response[6:]}", end="")

            except Exception as e:
                print(f"❌ Error: {str(e)}")
            input("Press Enter to continue...")
        elif choice == "7":
            try:
                print("\n── Delete User ──")
                target = input("Username to delete: ").strip()
                if not target:
                    print("❌ Username cannot be empty!")
                elif target == username:
                    print("❌ You cannot delete your own account!")
                else:
                    # First confirm deletion
                    confirm = input(f"⚠️ WARNING: This will delete ALL of {target}'s files. Confirm? (y/n): ").lower()
                    if confirm == 'y':
                        client_socket.send(f"DELETE_USER {target}".encode())
                        response = client_socket.recv(4096).decode()
                        
                        if response.startswith("SUCCESS:"):
                            print(f"✅ {response}", end="")
                        else:
                            print(f"❌ {response}", end="")
            except Exception as e:
                print(f"❌ Error: {str(e)}")
            input("Press Enter to continue...")
        elif choice == "8":
            client_socket.send(b"LIST_USERS")
            response = client_socket.recv(4096).decode()
            print("\n╔══════════════════════════════════╗")
            print("║          USER LIST               ║")
            print("╠══════════════════════════════════╣")
            for line in response.splitlines():
                if line.strip():
                    print(f"║ {line.ljust(32)}║")
            print("╚══════════════════════════════════╝")
            input("Press Enter to continue...")
        elif choice == "9":
            list_files(client_socket)
            input("Press Enter to continue...")
        elif choice == "10":
            rename_file(client_socket, username)
            input("Press Enter to continue...")
        elif choice == "11":
            view_file_info(client_socket)
            input("Press Enter to continue...")
        elif choice == "0":
            client_socket.send(b"EXIT")
            return
        else:
            print("Invalid option!")
            input("Press Enter to continue...")


def maintainer_menu(client_socket, username, symmetric_key):
    """Menu for maintainer users"""
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(
            f"""
╔══════════════════════════════════╗
║        MAINTAINER MENU           ║
╠══════════════════════════════════╣
║ 1. List All Public Keys          ║
║ 2. Upload File                   ║
║ 3. Download File                 ║
║ 4. Delete My Files               ║
║ 5. View All Files                ║
║ 6. Rename My Files               ║
║ 7. View File Metadata            ║
║                                  ║
║ 0. Exit                          ║
╚══════════════════════════════════╝
Role: maintainer | User: {username}
        """
        )
        choice = input("Select option (0-7): ")

        if choice == "1":
            get_public_keys(client_socket)
        elif choice == "2":
            upload_file(client_socket, username, symmetric_key)
        elif choice == "3":
            download_file(client_socket, username, symmetric_key)
        elif choice == "4":
            delete_file(client_socket)
        elif choice == "5":
            list_files(client_socket)
        elif choice == "6":
            rename_file(client_socket, username)
        elif choice == "7":
            view_file_info(client_socket)
        elif choice == "0":
            client_socket.send(b"EXIT")
            return
        else:
            print("Invalid option!")

        input("\nPress Enter to continue...")


def guest_menu(client_socket, username):
    """Menu for guest users"""
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(
            f"""
╔══════════════════════════════════╗
║          GUEST MENU              ║
╠══════════════════════════════════╣
║ 1. List All Public Keys          ║
║ 2. Download File                 ║
║ 3. View Available Files          ║
║ 4. View File Metadata            ║
║                                  ║
║ 0. Exit                          ║
╚══════════════════════════════════╝
Role: guest | User: {username}
        """
        )
        choice = input("Select option (0-4): ")

        if choice == "1":
            get_public_keys(client_socket)
        elif choice == "2":
            download_file(client_socket, username)
        elif choice == "3":
            list_files(client_socket)
        elif choice == "4":
            view_file_info(client_socket)
        elif choice == "0":
            client_socket.send(b"EXIT")
            return
        else:
            print("Invalid option!")

        input("\nPress Enter to continue...")


def main_menu(client_socket, username, role, symmetric_key):
    """Main menu router"""
    if role == "admin":
        admin_menu(client_socket, username, symmetric_key)
    elif role == "maintainer":
        maintainer_menu(client_socket, username, symmetric_key)
    else:
        guest_menu(client_socket, username)
