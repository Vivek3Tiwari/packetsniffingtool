Sniffer Project Bundle
----------------------
Files:
  - sniffer_detector.py   : detection engine (Scapy-based)
  - snifferapi.py         : Flask API (receives PCAP and returns alerts)
  - index.html            : Web UI (upload PCAP, view alerts)
  - capture.pcap          : example pcap (optional)
  - alerts.csv            : sample alerts log (optional)
  - README.md             : this file
How to run:
  1) Install dependencies: pip install -r requirements.txt
  2) Start API: python snifferapi.py
  3) Open index.html in a browser (or use Live Server) and choose API URL -> Local.
Notes:
  - CORS is enabled in API. API runs on http://127.0.0.1:5000 by default.
  - Do not expose the API to the public without reviewing security implications.
Network Packet Sniffing Tool
Overview

A Python-based network packet sniffing tool designed to capture, analyze, and monitor real-time network traffic. This project demonstrates core concepts of network security, packet inspection, and protocol analysis.

Problem Statement

Modern networks generate massive amounts of traffic, making it difficult to monitor suspicious activities manually. There is a need for tools that can:

Capture packets in real time
Analyze protocol behavior
Help identify unusual or potentially malicious activity
 Solution

This tool captures live packets from the network interface and extracts key information such as:

Source and destination IP addresses
Protocol types (TCP, UDP, ICMP)
Port numbers
Packet-level insights

It provides a simplified way to understand network communication and security monitoring.

 Key Features
 Real-time packet capture
 Protocol analysis (TCP, UDP, ICMP)
 IP address tracking
 Port monitoring
 Lightweight and fast execution
 Command-line interface for efficient usage
 How It Works

The tool uses packet capturing libraries to intercept network traffic at the network interface level. Each packet is:

Captured from the network
Parsed into protocol layers
Extracted for useful information
Displayed in a readable format
 Tech Stack
Language: Python
Libraries: Scapy / Socket Programming / PyShark
Platform: Windows / Linux
