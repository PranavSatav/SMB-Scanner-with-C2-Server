# SMB-Scanner-with-C2-Server
SMB Scanner in Python with C2 Server to connect to remote host and scan for Vulnerabilities

O/P -->

Advanced SMB Vulnerability Scanner
Enter IP range (e.g., 192.168.1.1-192.168.1.10): 192.168.1.1-192.168.1.10
Scanning 192.168.1.1...
[+] SMB service detected on: 192.168.1.1
[!] Anonymous login successful on 192.168.1.1
  [*] Found share: PUBLIC
    [+] Found file: passwords.txt
      [!] Potentially sensitive file found: passwords.txt
      [+] Logged details to smb_vulnerability_report.txt
Scanning 192.168.1.2...
[-] No SMB service detected on: 192.168.1.2

