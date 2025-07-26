# 🕵️ Packet Sniffer using Scapy

A lightweight Python-based network packet sniffer that captures live traffic using the Scapy library.

---

## 📌 What It Does

- Captures live packets from a network interface (default: `eth0`)
- Prints source/destination IP addresses
- Shows protocol (TCP, UDP, ICMP, etc.)
- Displays port numbers (for TCP/UDP)
- Includes timestamps for each packet

---

## ⚙️ How It Works

- Uses Scapy’s `sniff()` function to monitor live traffic
- Extracts IP, TCP, and UDP headers from each packet
- Prints readable output with timestamps

---

## 🚀 How to Run

1. **Install Scapy**:
   ```bash
   pip install scapy

2.**To run the script in admin  (requires sudo for admin rights)**:
  ```bash
   sudo python3 sniffer.py
