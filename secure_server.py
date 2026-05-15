import socket
import json
import crypto_utils
import threading

HOST = "127.0.0.1"  # 0.0.0.0 for using two devices
PORT = 5000

# Modes
COUNTER_MODE = False
KEY_EVOLUTION_MODE = True

# Shared state
session_key = None
last_counter = 0


def handle_client(conn, addr, private_key, serialized_public):
    global session_key, last_counter
    print(f"Connection from: {addr}")

    if session_key is None:
        conn.sendall(serialized_public)
        key_enc = conn.recv(4096)
        session_key = crypto_utils.rsa_decrypt(private_key, key_enc)
        print("Secure channel established\n")
    else:
        print("Reusing existing session key\n")

    key = session_key
    buffer = ""

    while True:
        try:
            data = conn.recv(4096).decode(errors="ignore")
            if not data:
                break
        except:
            break

        buffer += data

        while "\n" in buffer:
            try:
                line, buffer = buffer.split("\n", 1)
                packet = json.loads(line)

                counter = packet["counter"]
                cmd = packet["cmd"]
                shmac = bytes.fromhex(packet["hmac"])
                msg = f"{counter}|{cmd}".encode()

            except:
                continue

            # If counter mode enabled, verify freshness
            if COUNTER_MODE and counter <= last_counter:
                print("Replay attack detected (old counter used)\n")
                continue

            # HMAC verification
            if not crypto_utils.verify_hmac(key, msg, shmac):
                if KEY_EVOLUTION_MODE:
                    print("Replay attack detected (old key used)\n")
                else:
                    print("Message authentication failed!\n")
                continue

            last_counter = counter

            print(f"Message received from {addr}")
            print(f"Executing command={cmd}")
            print(f"Command executed: {cmd}\n")

            response = f"Executed: {cmd}\n"
            conn.sendall(response.encode())

            # If adaptive key evolution enabled, k1 -> k2
            if KEY_EVOLUTION_MODE:
                key = crypto_utils.generate_hmac(key, str(counter).encode())
                session_key = key
                print(f"Key evolved: k{counter-1} → k{counter}")

    conn.close()


def start():
    global session_key, last_counter

    private_key, public_key = crypto_utils.rsa_key_gen()
    serialized_public = crypto_utils.serialize(public_key)

    # Starting the server
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print("Server listening...\n")
    print(f"Counter Mode: {COUNTER_MODE}")
    print(f"Key Evolution: {KEY_EVOLUTION_MODE}\n")

    try:
        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, private_key, serialized_public)
            )
            thread.start()

    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")

    finally:
        server_socket.close()


if __name__ == "__main__":
    start()
