# 🕵️ Packet Sniffer using Scapy

A lightweight Python-based network packet sniffer that captures live traffic using the Scapy library.

---

## 📌 What It Does

- Captures live packets from a network interface (default: `eth0`)
- Prints source/destination IP addresses
- Shows protocol names (e.g., TCP, UDP, ICMP) by decoding protocol numbers
- Displays port numbers (for TCP/UDP)

---

## ⚙️ How It Works

- Uses Scapy’s `sniff()` function to monitor live traffic
- Extracts IP, TCP, and UDP headers from each packet
- Decodes protocol numbers (6, 17, etc.) into readable names using a mapping dictionary

---

## 🚀 How to Run

1. **Install Scapy**:
   ```bash
   pip install scapy


2.**To run the script in admin  (requires sudo for admin rights)**:
  ```bash
   sudo python3 sniffer.py
