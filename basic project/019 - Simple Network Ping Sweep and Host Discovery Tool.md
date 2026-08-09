---
tags: [basic-project, cybersecurity, beginner-friendly]
category: "Basic Cybersecurity Projects"
difficulty: "Basic"
real_world_problem: "Finding active live IP hosts on a local subnet to map out active network endpoints."
tools: [Python]
---

# 019 - Simple Network Ping Sweep and Host Discovery Tool

> **Category**: Basic Cybersecurity Projects | **Difficulty**: ⭐ Basic | **Duration**: 1-2 weeks

---

## Problem Statement and Real World Impact

Real-world applications me yeh problem kafi common hai. Finding active live IP hosts on a local subnet to map out active network endpoints.

Jab hum beginner-level cybersecurity practicals ki baat karte hain, toh foundational concepts ko code ke zariye samajhna sabse effective tareeka hota hai. Yeh project ek simple Python script ke zariye is real-world problem ko directly solve karta hai.

---

## Textbook & Paper References

- **Book Reference**: Computer Networking: A Top-Down Approach by Kurose & Ross (Chapter 4: Network Layer & ICMP Protocol)
- **Research Paper**: Analysis of Active Network Discovery Methods and Subnet Probing Efficiency (ACM SIGCOMM, 2015)

---

## System Architecture

Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project Basic-019: 019 - Simple Network Ping Sweep and Host Discovery Tool|Excalidraw Architecture Diagram]]

```mermaid
graph TD
    A[Input Data / Target] --> B[Processing Module]
    B --> C{Security Logic Check}
    C -- Matched / Anomaly --> D[Alert & Action]
    C -- Normal --> E[Pass / Complete]
```

---

## Technical Implementation Code

Python script issuing ICMP echo requests (or socket connections) across an IP range to output active live hosts.

```python
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "1000", ip]
    try:
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if output.returncode == 0:
            print(f"[+] Host ACTIVE: {ip}")
            return ip
    except:
        pass
    return None

def sweep_subnet(subnet_prefix):
    print(f"[*] Starting ICMP ping sweep on subnet: {subnet_prefix}.0/24")
    with ThreadPoolExecutor(max_workers=30) as executor:
        for host in range(1, 255):
            ip = f"{subnet_prefix}.{host}"
            executor.submit(ping_host, ip)

if __name__ == "__main__":
    sweep_subnet("192.168.1")

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
