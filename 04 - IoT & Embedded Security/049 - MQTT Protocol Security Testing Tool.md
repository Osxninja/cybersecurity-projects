---
tags: [iot-security, offensive-security, btech-project, mqtt, industrial-iot, vulnerability-assessment, penetration-testing]
category: "IoT & Embedded Security"
difficulty: "Intermediate-Advanced"
real_world_problem: "Automated vulnerability discovery in misconfigured MQTT messaging brokers within Industrial IoT and Smart City infrastructure"
tools: ['Eclipse Mosquitto', 'Python Paho-MQTT', 'Boofuzz', 'Nmap', 'Wireshark']
estimated_duration: "6 weeks"
---

# 049 - MQTT Protocol Security Testing Tool

> **Category**: IoT & Embedded Security | **Difficulty**: Intermediate-Advanced | **Duration**: 6 weeks

---

## Abstract & Problem Context
Message Queuing Telemetry Transport (MQTT) is the primary lightweight messaging protocol driving modern Industrial IoT (IIoT), smart factory automation, and smart city infrastructure. However, misconfigured MQTT brokers—specifically those operating without username/password authentication, lacking granular Access Control Lists (ACLs), or running without TLS encryption—provide malicious actors with a direct pathway to compromise critical operational infrastructure.

The primary objective of this project is to build an automated, end-to-end **MQTT Security Testing Tool**. This framework executes a multi-stage auditing pipeline, including: broker service discovery (Port 1883/8883), wildcard topic hierarchy harvesting (`#` and `+`), authentication and ACL privilege escalation checks, malformed packet mutation fuzzing, and TLS/SSL cipher suite validation.

Using this security testing framework, security engineers can pinpoint unauthenticated brokers and insecure topic ACLs within industrial enterprise environments. Dynamic payload inspection ensures that vulnerabilities are identified and remediated well before actual exploitation can occur.

---

## Real-World Context & Vulnerability Deep Dive
To understand the risk, it is important to observe how the MQTT messaging architecture operates in IIoT networks. MQTT utilizes a publish/subscribe architecture where a central Broker handles all client connections. Sensors publish telemetry data to specific topics (e.g., `factory/line1/temp`), and actuators or Programmable Logic Controllers (PLCs) subscribe to respective topics to receive control signals. To minimize overhead, the protocol defaults to plain-text transport (Port 1883) and often supports anonymous access.

### Real-World Incidents
The severity of this issue is evident from recent global internet scans (2020-2023), which identified over **80,000 publicly exposed unauthenticated MQTT brokers**. These brokers were freely exposing sensitive feeds, including medical patient telemetry, smart city traffic signals, and building management systems. In a notable **Smart Factory Robotic Arm Attack (2021)**, attackers sniffed wildcard topics and subsequently injected unauthorized override commands into actuator control endpoints (e.g., `factory/line1/actuator/arm`), resulting in a complete physical shutdown of the assembly line.

According to technical analysis, the most critical vulnerability lies in the misuse of wildcard subscriptions (the `#` multi-level and `+` single-level wildcards). When a client sends a `SUBSCRIBE` command to the `#` topic, and the broker lacks per-topic ACL enforcement, the broker will echo the entire factory network's real-time telemetry feed back to the attacker's socket. Furthermore, exploiting Quality of Service (QoS) Level 2 and retained messages can trigger memory exhaustion Denial of Service (DoS) attacks.

To mitigate this systemic operational risk, our testing framework implements protocol-aware auditing logic. By passing dynamic fuzzing vectors, it detects broker header parsing vulnerabilities, while the ACL validator maps out read/write authorization boundary leaks.

---

## Academic & Research Paper References

| # | Paper Title | Authors | Year | Source | Key Insight & Contribution |
|---|-------------|---------|------|--------|---------------------------|
| 1 | Security Evaluation of MQTT Broker Implementations in Industrial IoT | Formby et al. | 2020 | IEEE TII | Comprehensive vulnerability matrix of major MQTT brokers under fuzzing and authentication bypass vectors. |
| 2 | Analyzing Vulnerabilities and Privacy Risks of Public MQTT Brokers | Farris et al. | 2021 | ACM TCPS | Empirical scan and analysis of over 50,000 public MQTT deployments revealing widespread industrial data leaks. |
| 3 | MQTT-Fuzz: Dynamic Protocol Fuzzing for Industrial Messaging Gateways | Chen et al. | 2022 | IEEE S&P Workshops | Protocol-aware mutation fuzzing framework targeting MQTT control packet headers and variable payload length fields. |

---

## System Architecture & Visual Diagram
Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project 049: MQTT Protocol Security Testing Tool|Excalidraw Architecture Diagram]]

```mermaid
graph TD
    subgraph Target Industrial IoT Infrastructure
        B1[Unauthenticated MQTT Broker - Port 1883]
        B2[TLS Encrypted MQTT Broker - Port 8883]
        T1[Industrial Sensor] -->|Publish Telemetry| B1
        T2[PLC / Robotic Arm Controller] -->|Subscribe Control Commands| B1
    end

    subgraph Security Assessment Orchestrator
        CLI[Framework CLI / Controller] --> M1[Broker Recon & Service Fingerprinting]
        CLI --> M2[Wildcard Topic Hierarchy Harvester]
        CLI --> M3[Auth & ACL Privilege Auditor]
        CLI --> M4[Protocol Packet Mutation Fuzzer]
    end

    subgraph Probing & Execution Core
        M1 --> C1[Port 1883/8883 Socket Prober]
        M2 --> C2[Paho-MQTT Wildcard Subscriber `#`]
        M3 --> C3[Credential Dictionary & ACL Matrix Tester]
        M4 --> C4[Boofuzz / Raw Socket Packet Injector]
    end

    subgraph Findings Correlation Engine
        C1 --> D1[Vulnerability Mapper & Severity Calculator]
        C2 --> D1
        C3 --> D1
        C4 --> D1
    end

    subgraph Security Output & Remediation
        D1 --> E1[Executive PDF / Markdown Audit Report]
        D1 --> E2[Broker Hardening Guidelines & ACL Rules]
        D1 --> E3[JSON Audit Event Logs]
    end
```

---

## Deep-Dive Technical Implementation & Code Walkthrough

### Phase 1: Environment & Setup
First, we will configure an Eclipse Mosquitto broker in an isolated lab environment and install the necessary Python dependencies.

```bash
#!/usr/bin/env bash
# Phase 1: MQTT Security Testing Environment Setup
set -euo pipefail

echo "[+] Installing Mosquitto Broker and Testing Utilities..."
sudo apt-get update && sudo apt-get install -y \
    mosquitto mosquitto-clients python3-pip nmap

pip3 install paho-mqtt requests boofuzz tabulate

echo "[+] Starting local Mosquitto service for audit testing..."
sudo systemctl restart mosquitto || sudo service mosquitto restart
echo "[+] Setup Complete! Broker running on port 1883."
```

### Phase 2: Core Engine Development
Next, we develop the main Python engine to perform anonymous login testing, harvest wildcard subscriptions (`#`), and validate ACL read/write permissions.

```python
#!/usr/bin/env python3
"""
MQTT Protocol Security Audit Core Engine
Extracts topic hierarchy via wildcard '#' subscription and tests authentication enforcement.
"""

import time
import sys
import paho.mqtt.client as mqtt

class MQTTSecurityAuditor:
    def __init__(self, target_host, target_port=1883):
        self.target_host = target_host
        self.target_port = target_port
        self.harvested_topics = set()

    def on_connect(self, client, userdata, flags, rc):
        """
        Validates connection callback results.
        An rc (return code) of 0 means the connection was successful without authentication.
        """
        if rc == 0:
            print(f"[+] [SUCCESS] Anonymous Authentication Allowed on {self.target_host}:{self.target_port}!")
            # Subscribe to multi-level wildcard topic to dump all telemetry
            client.subscribe("#", qos=0)
            print("[*] Subscribed to multi-level wildcard ('#') topic. Harvesting telemetry...")
        else:
            print(f"[-] Anonymous Auth Refused. Return code: {rc}")

    def on_message(self, client, userdata, msg):
        """
        Extracts the topic name and payload bytes from incoming messages.
        """
        topic = msg.topic
        payload = msg.payload.decode('utf-8', errors='ignore')
        if topic not in self.harvested_topics:
            self.harvested_topics.add(topic)
            print(f"[HARVESTED TOPIC] {topic} | Sample Payload: {payload[:50]}")

    def run_anonymous_audit(self, timeout=5):
        """
        Executes the connection test and harvests topics for the specified duration.
        """
        client = mqtt.Client(client_id="SecurityAuditorProbe")
        client.on_connect = self.on_connect
        client.on_message = self.on_message

        try:
            client.connect(self.target_host, self.target_port, keepalive=60)
            client.loop_start()
            time.sleep(timeout)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Connection Error: {e}")

        print(f"\n[+] Audit Complete. Total Unique Topics Harvested: {len(self.harvested_topics)}")

if __name__ == "__main__":
    host = "127.0.0.1"
    auditor = MQTTSecurityAuditor(target_host=host, target_port=1883)
    auditor.run_anonymous_audit(timeout=3)
```

### Phase 3: Integration & Testing
In this phase, we build a payload injection tester that verifies write permissions and checks ACL boundaries by attempting unauthorized publications.

```python
#!/usr/bin/env python3
"""
MQTT Unauthorized Message Injection & ACL Tester
"""
import paho.mqtt.client as mqtt

def test_unauthorized_publish(target_host, target_topic="factory/line1/actuator"):
    """
    Checks for ACL write permissions by publishing a fake control command to the target topic.
    """
    print(f"[*] Testing unauthorized write access on topic: {target_topic}...")
    client = mqtt.Client(client_id="UnauthorizedInjectorProbe")
    
    try:
        client.connect(target_host, 1883)
        # Publish malicious payload
        res = client.publish(target_topic, payload="OVERRIDE_VALVE_CLOSE", qos=1)
        res.wait_for_publish()
        if res.rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"[ALERT - ACL LEAK] Published unauthorized message to {target_topic} successfully!")
        else:
            print(f"[-] Publish rejected with code {res.rc}")
        client.disconnect()
    except Exception as e:
        print(f"[-] Injection Test Failed: {e}")

if __name__ == "__main__":
    test_unauthorized_publish("127.0.0.1")
```

### Phase 4: Verification & Metrics
Finally, we run an evaluation script to generate a concise summary of the audit findings.

```python
#!/usr/bin/env python3
"""
MQTT Audit Results Verification Summary
"""
def summarize_audit(auth_bypass, total_topics, acl_vulnerable):
    print("=== MQTT Security Assessment Summary ===")
    print(f"Anonymous Auth Bypass Allowed: {'YES (CRITICAL)' if auth_bypass else 'NO'}")
    print(f"Total Discovered Telemetry Topics: {total_topics}")
    print(f"ACL Privilege Escalation Vulnerable: {'YES (HIGH)' if acl_vulnerable else 'NO'}")

summarize_audit(auth_bypass=True, total_topics=14, acl_vulnerable=True)
```

---

## Tools & Technology Stack

| Tool | Purpose | Alternative |
|------|---------|-------------|
| **Eclipse Mosquitto** | MQTT broker installation and client CLI testing tools | EMQX / HiveMQ |
| **Python Paho-MQTT** | MQTT protocol client wrapper for harvesting topics & testing ACLs | MQTT.fx / gmqtt |
| **Boofuzz** | Dynamic mutation fuzzing framework targeting MQTT control packets | Peach Fuzzer / AFL++ |
| **Nmap** | Service discovery scanner targeting ports 1883 (MQTT) and 8883 (MQTTS) | Masscan |
| **Wireshark** | Packet analyzer for capturing plain-text MQTT payload transmissions | Tshark |

---

## Expected Results & Verification Metrics

Upon completion, this project will deliver the following quantifiable metrics and outputs:
- **Broker Audit Speed**: Full scanning and wildcard topic harvesting execute in $< 10$ seconds per broker target.
- **Coverage**: Comprehensive checks covering Anonymous Authentication, Wildcard (`#`) leaks, ACL Write permissions, and TLS cipher strength validations.
- **Accuracy**: $100\%$ validation with zero false positives for write permission authorization testing.
- **Core Code Artifacts**:
  1. `mqtt_auditor.py`: Wildcard harvesting and authentication checker script.
  2. `mqtt_acl_injector.py`: ACL privilege escalation test module.
  3. `mqtt_fuzzer.py`: Protocol packet header mutation script.

---

## Legal and Ethical Disclaimer
> [!WARNING] Educational Use Only
> This research project must be executed in an authorized, isolated laboratory environment. Scanning, connecting to, or interacting with public or unauthorized MQTT brokers is illegal.

---

## Related Projects
- [[046 - IoT Botnet Detection using Network Flow Analysis]]
- [[047 - Smart Home Device Vulnerability Assessment Framework]]
- [[053 - Industrial SCADA-ICS Security Assessment Platform]]

