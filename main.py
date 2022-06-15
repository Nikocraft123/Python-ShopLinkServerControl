# IMPORTS
import sys
import threading as th
from constants import *
import socket as so
from utils import file
from utils import time
from utils.crypt import rsa


# CLASSES

# Application
class App:

    # CONSTRUCTOR
    def __init__(self):

        # Load the client private and public rsa key
        print("Load server private rsa key ...")
        if file.exist(f"{KEY_PATH}/private_key.pem"):
            self.private_key = rsa.import_key_from_file(f"{KEY_PATH}/private_key.pem")
        else:
            print("No server private rsa key found! Generating new one ...")
            self.private_key = rsa.generate_private_key()
            rsa.export_key_to_file(f"{KEY_PATH}/private_key.pem", self.private_key)
        print("Load server public rsa key ...")
        if file.exist(f"{KEY_PATH}/public_key.pem"):
            self.public_key = rsa.import_key_from_file(f"{KEY_PATH}/public_key.pem")
        else:
            print("No server public rsa key found! Generating new one ...")
            self.public_key = rsa.generate_public_key(self.private_key)
            rsa.export_key_to_file(f"{KEY_PATH}/public_key.pem", self.public_key)

        self.socket = so.socket(so.AF_INET, so.SOCK_STREAM)


    # METHODS

    # Run
    def run(self):

        # print("IP:")
        # ip = input("> ")
        #
        # print("Port:")
        # port = int(input("> "))
        ip = "192.168.178.53"
        port = 44445

        try:
            self.socket.connect((ip, port))
        except so.error:
            print(f"Cannot connect to {ip}:{port}! No response ...")
            return self.run()

        print(f"New connection with {ip}:{port}! Initialize ...")

        # Send client information
        client_info = f"{NAME}-{VERSION}-{CONTROL_VER}" + " " * (128 - len(f"{NAME}-{VERSION}-{CONTROL_VER}"))
        self.socket.send(client_info.encode("utf-8"))

        # Receive server information
        try:
            server_info = self.socket.recv(128).decode("utf-8")
            name, version, control_ver = server_info.strip().split("-")
        except (so.error, UnicodeDecodeError):
            print(f"Server connection {ip}:{port} failed! Invalid response ...")
            self.socket.close()
            return self.run()

        # Check server information
        if name != "Shop Link Server":
            print(f"Server connection {ip}:{port} failed! Invalid server ...")
            self.socket.close()
            return self.run()
        if control_ver != CONTROL_VER:
            print(f"Server connection {ip}:{port} failed! Invalid version ...")
            self.socket.close()
            return self.run()

        # Send the client public rsa key
        self.socket.send(rsa.export_key_to_bytes(self.public_key))

        # Receive the server public rsa key
        try:
            server_key = rsa.import_key_from_bytes(self.socket.recv(2048))
        except so.error:
            print(f"Server connection {ip}:{port} failed! Invalid key ...")
            self.socket.close()
            return self.run()

        # Receive the aes password
        try:
            length = int(self.socket.recv(8).decode("utf-8"))
            password = rsa.decrypt_bytes(self.private_key, self.socket.recv(length)).decode("utf-8")
        except so.error:
            print(f"Server connection {ip}:{port} failed! Invalid password ...")
            self.socket.close()
            return self.run()

        # Send the aes password back
        encrypted_password = rsa.encrypt_bytes(server_key, password.encode("utf-8"))
        self.socket.send(str(len(encrypted_password)).zfill(8).encode("utf-8"))
        self.socket.send(encrypted_password)

        print(password)

        # Quit
        self.quit()

    # Quit
    def quit(self):

        # Close the socket
        self.socket.close()

        # Exit program
        print("Exit ...")
        sys.exit(0)


# FUNCTIONS

# Main
def main():

    # Print header
    print(f"{NAME}")
    print('-' * len(NAME))
    print("")
    print(f"Author: {AUTHOR}")
    print(f"Version: {VERSION}")
    print("")

    # Initialize application
    print("Initialize application ...")
    app = App()

    # Run application
    print("Run application ...")
    app.run()


# MAIN
if __name__ == '__main__':

    # Call main function
    main()
