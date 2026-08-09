---
tags: [basic-project, cybersecurity, beginner-friendly]
category: "Basic Cybersecurity Projects"
difficulty: "Basic"
real_world_problem: "Scanning web server access logs to automatically detect brute-force attempts and suspicious HTTP request patterns."
tools: [Python]
---

# 012 - Basic Log File Anomaly Scanner using Regex

> **Category**: Basic Cybersecurity Projects | **Difficulty**: ⭐ Basic | **Duration**: 1-2 weeks

---

## Problem Statement and Real World Impact

Real-world applications me yeh problem kafi common hai. Scanning web server access logs to automatically detect brute-force attempts and suspicious HTTP request patterns.

Jab hum beginner-level cybersecurity practicals ki baat karte hain, toh foundational concepts ko code ke zariye samajhna sabse effective tareeka hota hai. Yeh project ek simple Python script ke zariye is real-world problem ko directly solve karta hai.

---

## Textbook & Paper References

- **Book Reference**: Logging and Log Management by Anton Chuvakin (Chapter 5: Log Parsing & Pattern Detection)
- **Research Paper**: Automated Analysis of Web Server Access Logs for Security Auditing (IEEE Security & Privacy, 2016)

---

## System Architecture

Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project Basic-012: 012 - Basic Log File Anomaly Scanner using Regex|Excalidraw Architecture Diagram]]

```mermaid
graph TD
    A[Input Data / Target] --> B[Processing Module]
    B --> C{Security Logic Check}
    C -- Matched / Anomaly --> D[Alert & Action]
    C -- Normal --> E[Pass / Complete]
```

---

## Technical Implementation Code

Python log scanner evaluating Nginx/Apache log files using regular expressions to flag 401/403 status bursts and malicious GET parameters.

```python
import re
from collections import defaultdict

log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d{3})')

def analyze_logs(log_filepath):
    failed_logins = defaultdict(int)
    suspicious_queries = []
    
    with open(log_filepath, "r") as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                ip, timestamp, request, status = match.groups()
                if status in ["401", "403"]:
                    failed_logins[ip] += 1
                if any(x in request for x in ["../", "' OR ", "SELECT ", "<script>"]):
                    suspicious_queries.append((ip, request))
                    
    print("=== SUSPICIOUS IP SUMMARY (Failed Attempts > 5) ===")
    for ip, count in failed_logins.items():
        if count > 5:
            print(f"[!] IP: {ip} | Failed Attempts: {count}")
            
    print("
=== POTENTIAL EXPLOIT PAYLOAD LOGS ===")
    for ip, req in suspicious_queries:
        print(f"[!] IP: {ip} | Request: {req}")

if __name__ == "__main__":
    print("[*] Log Scanner Module Loaded.")

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
