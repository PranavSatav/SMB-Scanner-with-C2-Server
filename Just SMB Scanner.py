import socket
from impacket.smbconnection import SMBConnection, SessionError
import re
import os
from concurrent.futures import ThreadPoolExecutor

def scan_smb(ip):
    """
    Checks for open SMB port (445) and initiates detailed vulnerability analysis.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((ip, 445))
            if result == 0:
                print(f"[+] SMB service detected on: {ip}")
                test_anonymous_access(ip)
                banner_grab(ip)
            else:
                print(f"[-] No SMB service detected on: {ip}")
    except Exception as e:
        print(f"[-] Error scanning {ip}: {e}")

def banner_grab(ip):
    """
    Grabs SMB server banner for protocol version and details.
    """
    try:
        conn = SMBConnection(ip, ip)
        conn.login('', '')  # Attempt anonymous login for banner grabbing
        server_os = conn.getServerOS()
        print(f"  [*] SMB Server OS: {server_os}")
        save_to_log(ip, f"Banner: {server_os}")
    except SessionError as e:
        print(f"  [-] Banner grabbing failed on {ip}: {e}")
    finally:
        try:
            conn.logoff()
        except:
            pass

def test_anonymous_access(ip):
    """
    Tests SMB for anonymous login and enumerates shares.
    """
    try:
        conn = SMBConnection(ip, ip)
        conn.login('', '')  # Attempt anonymous login
        print(f"[!] Anonymous login successful on {ip}")
        shares = conn.listShares()
        for share in shares:
            share_name = share['shi1_netname']
            print(f"  [*] Found share: {share_name}")
            if not share_name.startswith("IPC$"):  # Ignore IPC$ shares
                check_share_permissions(ip, share_name, conn)
    except SessionError as e:
        print(f"[-] Anonymous login failed on {ip}: {e}")
    finally:
        try:
            conn.logoff()
        except:
            pass

def check_share_permissions(ip, share_name, conn):
    """
    Checks share for write permissions and sensitive files.
    """
    try:
        files = conn.listPath(share_name, '*.*')
        for file in files:
            if file.isDirectory:
                continue
            file_name = file.get_longname()
            print(f"    [+] Found file: {file_name}")
            if re.search(r"(config|\.env|\.ini|password|credentials|\.txt)", file_name, re.IGNORECASE):
                print(f"      [!] Potentially sensitive file found: {file_name}")
                save_to_log(ip, f"Sensitive file in {share_name}: {file_name}")
    except Exception as e:
        print(f"    [-] Could not access files in share {share_name}: {e}")

def save_to_log(ip, message):
    """
    Saves scan results to a log file.
    """
    log_file = "smb_vulnerability_report.txt"
    with open(log_file, "a") as f:
        f.write(f"IP: {ip}, {message}\n")
    print(f"      [+] Logged details to {log_file}")

def main():
    print("Multithreaded Advanced SMB Vulnerability Scanner")
    ip_range = input("Enter IP range (e.g., 192.168.1.1-192.168.1.10): ")
    start_ip, end_ip = ip_range.split('-')
    base_ip = '.'.join(start_ip.split('.')[:-1])
    start = int(start_ip.split('.')[-1])
    end = int(end_ip.split('.')[-1])

    # Create or clear log file
    if os.path.exists("smb_vulnerability_report.txt"):
        os.remove("smb_vulnerability_report.txt")
    open("smb_vulnerability_report.txt", "w").close()

    # Multithreading
    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in range(start, end + 1):
            ip = f"{base_ip}.{i}"
            executor.submit(scan_smb, ip)

if __name__ == "__main__":
    main()
