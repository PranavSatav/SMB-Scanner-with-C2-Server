# 🕵️ Advanced SMB Vulnerability Scanner

## Overview

This project is a sophisticated tool designed to scan a range of IP addresses for potential SMB (Server Message Block) vulnerabilities. It systematically detects available SMB services, attempts anonymous login, and identifies exposed sensitive files or shares. The scanner generates comprehensive reports to help security professionals and network administrators uncover potential risks.

## 🌟 Key Features

- **🌐 IP Range Scanning**: Efficiently scan multiple IP addresses (e.g., `192.168.1.1-192.168.1.10`)
- **🔓 Anonymous Login Detection**: Attempts anonymous access to SMB services
- **🔍 Sensitive File Discovery**: Searches for potentially sensitive files in SMB shares
- **📝 Detailed Vulnerability Reporting**: Logs findings in `smb_vulnerability_report.txt`

## 🛠 How it Works

The project consists of two primary components:

### 1. 🖥️ C2 Server (`c2_server.py`)
- Serves as the central control mechanism
- Manages agent connections and command processing
- Supports advanced commands:
  - `DIR`: Directory listing
  - `LS`: List files
  - `scan_range`: Scan IP address ranges

### 2. 🤖 Agent (`agent.py`)
- Deployed on target machines or scanning environments
- Receives and executes commands from the C2 server
- Performs detailed SMB vulnerability scans
- Reports scan results back to the C2 server

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.6+
- Required Python packages (install via pip):
  
  ```bash
  pip install pysmb socket threading
  ```

### Step 1: Start the C2 Server
Launch the central control server:
```bash
python c2_server.py
```

### Step 2: Start the Agent
Connect the agent to the C2 server:
```bash
python agent.py
```

### Step 3: Initiate SMB Scan
Use the `scan_range` command to scan specific IP ranges:
```bash
# In the C2 server console
scan_range 192.168.1.1 192.168.1.10
```

## 🎥 Demo Video
Check out the project demo:


https://github.com/user-attachments/assets/5079293a-b8f5-4db8-9a25-64da52a410df



## 🛡️ Scan Capabilities

The scanner provides in-depth analysis of:
- SMB service availability
- Anonymous login possibilities
- Accessible network shares
- Potential sensitive file exposures

## ⚠️ Ethical Use Disclaimer

🚨 **Important**: This tool is designed for:
- Authorized security testing
- Network administration
- Penetration testing with explicit permission

**Never use this tool on networks or systems you do not own or have explicit permission to test.

## 🔒 Security Considerations

- Always obtain proper authorization before scanning
- Use in controlled, legal, and ethical environments
- Respect privacy and legal boundaries

## 🤝 Contributing

Contributions are welcome! Please:
- Fork the repository
- Create a feature branch
- Submit a pull request
