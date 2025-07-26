import socket
from client.auth import authenticate
from client.crypto import handle_symmetric_key_receive
from client.menu import main_menu, fetch_user_role


class Client:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.symmetric_key = None
        self.role = None

    def connect(self):
        """Connect to the server"""
        self.socket.connect((self.host, self.port))
        print(self.socket.recv(4096).decode())

    def run(self):
        try:
            self.connect()
            self.username = authenticate(self.socket)
            if self.username:
                self.symmetric_key = handle_symmetric_key_receive(
                    self.socket, self.username
                )
                if self.symmetric_key:
                    self.role = fetch_user_role(self.socket)
                    main_menu(self.socket, self.username, self.role, self.symmetric_key)
        finally:
            self.socket.close()  # Always close the socket


if __name__ == "__main__":
    client = Client()
    client.run()
