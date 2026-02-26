# Network Analyzer

A **Network Analyzer** implemented in C++ using the **libpcap** library.

This project captures and parses network traffic to help explore common protocol headers and packet structure. It’s designed as an educational tool to deepen understanding of how network protocols work at a low level.


## Features

- Capture live network traffic using `libpcap`
- Supports parsing of common protocols:
  - Ethernet
  - IPv4 & IPv6
  - TCP & UDP
  - ARP
  - ICMPv4 & ICMPv6
  - HTTP, DNS, DHCP
- Modular code structure for easier learning and extension


## Technologies Used

- **C++**
- **libpcap** (packet capture library)
- Header-based protocol definitions


## Prerequisites

Before building and running this project, install:

- A C++ compiler (e.g., `g++`)
- `libpcap` development headers

On Ubuntu/Debian systems:

```bash
sudo apt update
sudo apt install libpcap-dev
