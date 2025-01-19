# Network Packet Sniffer

## Overview
This project is a network packet sniffer built using Python. It allows you to:

Note: learning purposes only
1. Capture network packets in real-time.
2. Analyze HTTP, DNS, and sensitive unencrypted data.
3. Save captured packets to `.pcap` files for further analysis.
4. Detect potential issues, such as unencrypted credentials or DNS activity.

---

## Features
- **HTTP Analysis**:
  - Extracts GET and POST requests.
  - Logs headers and payloads.

- **DNS Analysis**:
  - Captures queried domains and their resolved IP addresses.

- **Sensitive Data Detection**:
  - Detects unencrypted logins/passwords in the payload.

- **Logging**:
  - Uses a JSON-formatted and color-coded logger.
  - Logs can be saved to `logs/`.

---

## Prerequisites
1. **Python 3.8+**
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run with elevated privileges (e.g., `sudo`) for packet capturing:
   ```bash
   sudo python3 network_sniffer.py
   ```

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/calypso-h97/network-packet-sniffer.git
   cd network-packet-sniffer
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   venv\Scripts\activate   # On Windows
   pip install -r requirements.txt
   ```

---

## Usage
### Real-Time Sniffing
To start sniffing packets in real-time:
```bash
sudo python3 network_sniffer.py
```
Select **1** to sniff traffic.

### Analyze Saved `.pcap` File
To analyze a previously captured `.pcap` file:
```bash
sudo python3 network_sniffer.py
```
Select **2** and provide the path to the `.pcap` file.

---

## Notes
- Ensure you have permissions to sniff packets on your machine.
- For DNS and HTTP traffic, ensure your network allows capturing.
- HTTPS traffic will not be decoded (encrypted payload).

---

## Contributing
Feel free to fork this repository, submit pull requests, or report issues. Contributions are welcome!

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author
[calypso-h97](https://github.com/calypso-h97)
