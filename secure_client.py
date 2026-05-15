import socket
import os
import json
import crypto_utils

HOST = "127.0.0.1"  # server IP
PORT = 5000

# Mode
KEY_EVOLUTION_MODE = True


def start():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    print("Connected to server")

    # Receive server public key
    serialized_public = client_socket.recv(4096)
    public_key = crypto_utils.load_public_key(serialized_public)

    # Generate session key
    key = os.urandom(32)

    # Encrypt and send key
    key_enc = crypto_utils.rsa_encrypt(public_key, key)
    client_socket.sendall(key_enc)

    print("Secret key sent\n")

    counter = 0

    print("Enter commands (type 'exit' to quit):\n")

    while True:
        cmd = input("Command: ")
        if cmd.lower() == "exit":
            break

        counter += 1

        # Create message
        msg = f"{counter}|{cmd}".encode()

        # Generate HMAC
        shmac = crypto_utils.generate_hmac(key, msg)

        packet = {
            "counter": counter,
            "cmd": cmd,
            "hmac": shmac.hex()
        }

        client_socket.sendall((json.dumps(packet) + "\n").encode())
        print(f"Sent command: {cmd}")

        # Receive server response
        try:
            response = client_socket.recv(4096).decode()
            if response:
                print("Server:", response)
        except:
            pass

        # Key evolution
        if KEY_EVOLUTION_MODE:
            key = crypto_utils.generate_hmac(key, str(counter).encode())
            print(f"Key evolved: k{counter-1} → k{counter}")

    client_socket.close()


if __name__ == "__main__":
    start()
