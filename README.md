# NetworkSniffer

## Overview
NetworkSniffer is lightweight yet powerful network packet analyzer designed for monitoring and analyzing real time network traffic. Built with simplicity in mind, this tool allows you to explore network communications, troubleshoot issues, and gain insights into your environment.

---

## Features
- **Device Discovery**: Quickly locate devices on your network, including their IP and MAC addresses.
- **Real Time Packet Capture**: Sniff and analyze network packets with detailed HTTP request and response information.
- **Man in the Middle Simulation**: Intercept and forward traffic between devices on the network.
- **Customizable Traffic Filtering**: Focus on specific HTTP methods or protocols..

---

## Environment Setup
For testing, I have used three VMs which were configured on the same subnet:

| **VM**        | **IP Address**       | **Purpose**                  |
|---------------|----------------------|------------------------------|
| Windows VM    | 192.168.56.101       | Target machine for traffic analysis. |
| Ubuntu VM     | 192.168.56.102       | Secondary test device.      |
| Kali Linux VM | 192.168.56.103       | Running Network Monitor Tool.|
| Gateway       | 192.168.56.2         | Network gateway.             |

Subnet Mask: `255.255.255.0`

---

## Installation

### Prerequisites
Ensure Python 3 is installed. The tool also requires certain Python libraries:

```bash
pip install -r requirements.txt
```

### Cloning the Repository
Clone the repository to your Kali Linux VM:
```bash
git clone https://github.com/<YourUsername>/NetworkSniffer.git
cd NetworkSniffer
```

---

## Getting Started

To get started with NetworkSniffer, use the following command line options:

```bash
root@rdx0120:/NetworkSniffer# python3 network_sniffer.py --help                          
usage: network_sniffer.py [-h] [-t TARGET_IP] [-g GATEWAY_IP] [-i INTERFACE] [-tf TARGET_FIND] [--ip-forward] [-m METHOD]

options:
  -h, --help            show this help message and exit
  -t TARGET_IP, --target TARGET_IP
                        Target IP address
  -g GATEWAY_IP, --gateway GATEWAY_IP
                        Gateway IP address
  -i INTERFACE, --interface INTERFACE
                        Interface name
  -tf TARGET_FIND, --targetfind TARGET_FIND
                        Target IP range to find
  --ip-forward, -if     Enable packet forwarding
  -m METHOD, --method METHOD
                        Limit sniffing to a specific HTTP method

```

## **Test Scenario:**

### 1. Identified active devices within my network:

```bash
python3 network_sniffer.py --tf 192.168.56.0/24 -i eth0

Device Discovery:
**************************************
    IP Address       MAC Address
**************************************
    192.168.56.101   08:00:27:AD:BE:CD
    192.168.56.102   08:00:27:DF:5A:FC
    192.168.56.103   08:00:27:GF:HA:2I
```

### 2. Simulated MITM Attack:

```bash
python3 network_sniffer.py --t 192.168.56.101 --g 192.168.56.2 -i eth0
```

**Output:**
```plaintext
HTTP Request:
    Method: b'POST'
    Host: b'testphp.vulnweb.com' 
    Path: b'/userinfo.php
    Source IP: 192.168.56.101
    Source MAC: 08:00:27:AD:BE:CD
    User-Agent: b'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'

Raw Payload:
b'user=admin&pass=mysecretpasswd1234'

HTTP Response:
    Status Code: b'302'
    Content Type: b'text/html; charset=UTF-8'
--------------------------------------------------

```

## Future Features:

- HTTPS Traffic Analysis: Currently, the tool cannot decrypt or analyze HTTPS traffic. Future updates aim to include support for SSL/TLS decryption with proper certificate handling.**

- Data Logging: Along with Real time analysis, I also plan to implement logging or exporting of captured packets for better review.

- Protocol Support: For now, the tool primarily focuses on HTTP and ARP-based traffic. Will address these limitations by expanding support for additional protocols like DNS, FTP, and SMTP.
