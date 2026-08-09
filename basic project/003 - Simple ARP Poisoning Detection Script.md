---
tags: [basic-project, cybersecurity, beginner-friendly]
category: "Basic Cybersecurity Projects"
difficulty: "Basic"
real_world_problem: "Detecting ARP spoofing attacks on local Ethernet/Wi-Fi networks that enable Man-in-the-Middle eavesdropping."
tools: [Python]
---

# 003 - Simple ARP Poisoning Detection Script

> **Category**: Basic Cybersecurity Projects | **Difficulty**: ⭐ Basic | **Duration**: 1-2 weeks

---

## Problem Statement and Real World Impact

Real-world applications me yeh problem kafi common hai. Detecting ARP spoofing attacks on local Ethernet/Wi-Fi networks that enable Man-in-the-Middle eavesdropping.

Jab hum beginner-level cybersecurity practicals ki baat karte hain, toh foundational concepts ko code ke zariye samajhna sabse effective tareeka hota hai. Yeh project ek simple Python script ke zariye is real-world problem ko directly solve karta hai.

---

## Textbook & Paper References

- **Book Reference**: Computer Networks by Andrew S. Tanenbaum (Chapter 4: Data Link Layer & ARP Protocol)
- **Research Paper**: Detection and Mitigation of ARP Cache Poisoning Attacks (IEEE Communications Surveys, 2016)

---

## System Architecture

Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project Basic-003: 003 - Simple ARP Poisoning Detection Script|Excalidraw Architecture Diagram]]

```mermaid
graph TD
    A[Input Data / Target] --> B[Processing Module]
    B --> C{Security Logic Check}
    C -- Matched / Anomaly --> D[Alert & Action]
    C -- Normal --> E[Pass / Complete]
```

---

## Technical Implementation Code

Python script using Scapy to monitor incoming ARP responses and trigger an alert if an IP is mapped to multiple MAC addresses.

```python
from scapy.all import sniff, ARP
import sys

ip_mac_table = {}

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2: # ARP Response
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc
        
        if sender_ip in ip_mac_table:
            if ip_mac_table[sender_ip] != sender_mac:
                print(f"[!] WARNING: Possible ARP Spoofing Attack!")
                print(f"    IP: {sender_ip} changed MAC from {ip_mac_table[sender_ip]} to {sender_mac}")
        else:
            ip_mac_table[sender_ip] = sender_mac
            print(f"[+] Recorded: {sender_ip} -> {sender_mac}")

if __name__ == "__main__":
    print("[*] Monitoring network for ARP Spoofing anomalies...")
    sniff(store=False, prn=process_packet, filter="arp")

```

---

## Expected Results & Outcomes

1. Clear understanding of underlying networking, hashing, or system security mechanics.
2. Functional, lightweight Python script ready to execute in a local lab.
3. Verification of security controls against common real-world misconfigurations.

---

## Legal and Ethical Notice

> [!WARNING] Educational Use Only
> Always run these basic projects in your own local testing environment or authorized laboratory network.

---

## Related Index
- [[00 - Basic Cybersecurity Projects Index]]
