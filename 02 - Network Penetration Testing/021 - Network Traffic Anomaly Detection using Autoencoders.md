---
tags: [offensive-security, network-pentesting, btech-project, autoencoders, deep-learning, network-anomaly, py-torch]
category: "Network Penetration Testing"
difficulty: "Advanced"
real_world_problem: "Anomaly detection for insider threats"
tools: [PyTorch, Python, Scapy, Pandas, Wireshark, FlowContainer]
estimated_duration: "6 weeks"
---

# 🎯 021 - Network Traffic Anomaly Detection using Autoencoders

> **Category**: [[Network Penetration Testing]] | **Difficulty**: ⭐⭐⭐ | **Duration**: 6 weeks

---

## 📋 Problem Statement

> [!CAUTION] Real-World Impact
> Insider threats, zero-day exploits, and lateral movement by advanced adversaries often slip past traditional signature-based security systems (such as legacy Snort/Suricata IDS) because their traffic patterns do not match known attack signatures. Malicious activity disguised as standard network operations can remain undetected for months, leading to catastrophic data exfiltration and network destruction.

Signature-based Network Intrusion Detection Systems (NIDS) are fundamentally reactive—they depend on static rules created after a vulnerability or attack vector is publicly disclosed. In contrast, anomaly-based NIDS establish a statistical or deep learning baseline of "normal" network operational behavior, triggering alerts when live traffic deviates significantly from expected patterns.

This project implements a Deep Autoencoder Neural Network architecture to perform unsupervised network traffic anomaly detection. By capturing raw packet flows and converting them into statistical flow metrics (e.g., packet arrival time intervals, byte distributions, flow duration, port entropy, and flag ratios), the Autoencoder learns a compressed latent representation of normal baseline network behavior. When uncompressed reconstruction error spikes above a statistically derived threshold, the system flags the flow as anomalous—enabling real-time detection of stealthy insider threats, covert port scans, zero-day C2 communication, and data exfiltration.

### 🌍 Real-World Incidents
- **Tesla Insider Data Leak (2023)**: Former employees utilized legitimate access privileges to exfiltrate over 75 gigabytes of sensitive corporate data over standard internal protocols without triggering signature alerts.
- **Capital One Cloud Intrusion (2019)**: An insider exploited a misconfigured SSRF vulnerability to move laterally and exfiltrate 100 million customer records via legitimate AWS S3 sync commands.
- **Stuxnet Worm Propagation (2010)**: Stuxnet moved stealthily through isolated industrial control networks using custom zero-day RPC vulnerabilities that bypassed all traditional static firewall rules.

---

## 🔬 Research Paper References

| # | Paper Title | Authors | Year | Source | Key Contribution |
|---|-------------|---------|------|--------|-----------------|
| 1 | Kitsune: An Ensemble of Autoencoders for Network Intrusion Detection | Mirsky et al. | 2018 | NDSS | Demonstrated online, unsupervised anomaly detection on edge devices using feature-grouped autoencoders. |
| 2 | Deep Learning for Cyber Security Intrusion Detection | Ring et al. | 2019 | Computers & Security | Comprehensive survey evaluating autoencoders, GANs, and LSTMs for network flow anomaly detection. |
| 3 | N-BaIoT: Network-based Detection of IoT Botnet Attacks Using Autoencoders | Meidan et al. | 2018 | IEEE Pervasive | Evaluated deep autoencoders for detecting Mirai botnet propagation across local network traffic. |

---

## 🏗️ System Architecture
Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project 021: 021 - Network Traffic Anomaly Detection using Autoencoders|Excalidraw Architecture Diagram]]


```mermaid
graph TD
    subgraph Data_Ingestion ["1. Live Packet Ingestion & Flow Assembly"]
        NIC[Network Interface Card / PCAP Dump] --> ScapySniffer[PyPcap / Scapy Flow Aggregator]
        ScapySniffer --> FlowEngine[5-Tuple Flow Extractor: SrcIP, DstIP, SrcPort, DstPort, Proto]
    end

    subgraph Feature_Processing ["2. Statistical Feature Extraction"]
        FlowEngine --> StatEngine[Compute Flow Duration, Packet Sizes, IAT, Flags]
        StatEngine --> Scaler[Standardization & MinMaxScaler Normalization]
    end

    subgraph Deep_Learning_Core ["3. PyTorch Autoencoder Model"]
        Scaler --> InputLayer[Input Layer: 32 Continuous Flow Features]
        InputLayer --> Encoder[Deep Encoder Layers: 32 -> 16 -> 8 Nodes]
        Encoder --> LatentSpace[Latent Representation: 4 Dimensions]
        LatentSpace --> Decoder[Deep Decoder Layers: 8 -> 16 -> 32 Nodes]
        Decoder --> OutputLayer[Reconstructed Feature Vector]
    end

    subgraph Anomaly_Scoring ["4. Reconstruction Error & Thresholding"]
        OutputLayer --> MSE[Compute Mean Squared Error: MSE = 1/N * Σ(X - X_hat)^2]
        MSE --> ThresholdCheck{MSE > Baseline Anomaly Threshold?}
        ThresholdCheck -- Yes --> Anomaly[FLAG ANOMALY: Zero-Day / Insider Threat]
        ThresholdCheck -- No --> Normal[BENIGN TRAFFIC: Pass]
    end

    subgraph Response_Layer ["5. Dashboard & SIEM Alerting"]
        Anomaly --> Dashboard[Real-Time Grafana / Streamlit Monitoring]
        Anomaly --> SIEM[Generate JSON Alert for SIEM Ingestion]
    end

    style Data_Ingestion fill:#1e1e2e,stroke:#89b4fa,stroke-width:2px;
    style Feature_Processing fill:#181825,stroke:#fab387,stroke-width:2px;
    style Deep_Learning_Core fill:#11111b,stroke:#a6e3a1,stroke-width:2px;
    style Anomaly_Scoring fill:#313244,stroke:#f38ba8,stroke-width:2px;
    style Response_Layer fill:#2a2a3c,stroke:#cba6f7,stroke-width:2px;
```

---

## 📐 Technical Implementation

### Phase 1: Research & Environment Setup (Week 1)
- Set up a virtualized network environment with multiple active endpoints generating background traffic (HTTP, SSH, DNS, SMB).
- Collect a 24-hour dataset of purely benign enterprise traffic (or leverage public benchmark datasets like CIC-IDS2017 / UNSW-NB15).
- Configure a Python 3.11 environment with PyTorch, Scikit-learn, Pandas, NumPy, and Scapy.

### Phase 2: Core Module Development (Weeks 2-3)
- **Flow Feature Extraction Pipeline (`flow_extractor.py`)**:
  - Group packets by 5-tuple key `(Src IP, Dst IP, Src Port, Dst Port, Protocol)` within sliding time windows (e.g., 10 seconds).
  - Extract 32 statistical features per flow: packet count, total bytes, mean/std-dev of Inter-Arrival Times (IAT), packet size mean/variance, TCP flag frequencies (SYN, ACK, FIN, RST, PSH), and port entropy.
- **PyTorch Autoencoder Architecture (`autoencoder_model.py`)**:
  - Implement a symmetric fully connected deep autoencoder in PyTorch:
    - *Encoder*: Linear(32, 16) -> ReLU -> Linear(16, 8) -> ReLU -> Linear(8, 4).
    - *Decoder*: Linear(4, 8) -> ReLU -> Linear(8, 16) -> ReLU -> Linear(16, 32).
  - Train exclusively on clean, benign baseline flow features using MSE loss and Adam optimizer.

### Phase 3: Integration & Real-Time Engine (Week 4-5)
- Determine optimal anomaly reconstruction threshold:
  $$\text{Threshold} = \mu_{\text{train\_loss}} + 3 \times \sigma_{\text{train\_loss}}$$
- Construct a real-time live sniffing daemon that feeds network flow features directly into the trained PyTorch model for real-time inference.
- Inject simulated attack scenarios:
  1. Stealthy low-and-slow port scans (`nmap -sS -T1`).
  2. Data exfiltration over non-standard ports.
  3. Internal lateral movement via SMB credential dumping.
  4. Encrypted Command & Control heartbeats.

### Phase 4: Analysis & Documentation (Week 6)
- Evaluate detection ROC-AUC scores, precision, recall, and false positive rates.
- Build an interactive web dashboard (Streamlit) displaying live network traffic MSE reconstruction errors and anomaly alerts.
- Finalize BTech dissertation report.

---

## 🔧 Tools & Technologies

| Tool | Purpose | Alternative |
|------|---------|-------------|
| PyTorch | Deep learning model development and inference | TensorFlow / Keras |
| Python Scapy / Pyshark | Network packet capture and flow extraction | FlowContainer / GoPacket |
| Pandas / NumPy | Data processing and numerical calculations | Polars |
| Streamlit | Real-time security dashboard visualization | Grafana + Prometheus |
| CIC-IDS2017 Dataset | Benchmark dataset for baseline model validation | UNSW-NB15 |

---

## 💡 Key Features
- ✅ **Unsupervised Deep Learning**: Requires zero labeled attack data; learns solely from normal baseline network traffic.
- ✅ **32-Dimensional Flow Feature Extractor**: Captures rich statistical, temporal, and protocol-level flow attributes.
- ✅ **Sub-Millisecond Inference**: Evaluates network flow anomalies in < 2 milliseconds per flow using optimized PyTorch tensors.
- ✅ **Zero-Day Attack Resilience**: Detects unknown, novel threat patterns based purely on statistical deviation from baseline behavior.
- ✅ **Interactive Anomaly Dashboard**: Displays real-time reconstruction error graphs, highlighting anomalous IP pairs instantly.

---

## 📊 Expected Results

> [!NOTE] Deliverables
> Complete PyTorch autoencoder source code, feature extraction pipeline, pre-trained baseline model weights, interactive Streamlit dashboard, and research project thesis.

### Performance Metrics
- **Anomaly Detection AUC-ROC**: > 0.96 on benchmark evaluation datasets.
- **False Positive Rate**: < 1.5% in stable enterprise baseline environments.
- **Processing Throughput**: > 5,000 network flows analyzed per second on single CPU core.

### Output Artifacts
1. Network Flow Extractor Module (`network_flow_miner.py`).
2. PyTorch Autoencoder Trainer & Evaluator (`autoencoder_nids.py`).
3. Streamlit Real-time Monitoring Dashboard (`nids_dashboard.py`).

---

## 🎓 Learning Outcomes
1. 📚 **Deep Learning for Security**: Deep understanding of autoencoders, representation learning, and reconstruction loss dynamics.
2. 📚 **Network Traffic Profiling**: Expertise in 5-tuple flow aggregation, statistical feature extraction, and temporal analysis.
3. 📚 **Anomaly-Based Threat Detection**: Ability to design NIDS solutions capable of uncovering insider threats and zero-day exploits.
4. 📚 **Real-Time Data Pipelines**: Experience building low-latency Python data ingestion pipelines linking raw sockets to ML models.

---

## ⚠️ Ethical Considerations
> [!WARNING] Legal & Ethical Notice
> Capturing deep packet flows on corporate or public networks records private user activity and payload metadata, potentially violating user privacy acts (e.g., GDPR, CCPA). Network monitoring tools must only be deployed on authorized infrastructure with explicit administrative consent.

---

## 🔗 Related Projects
- [[016 - Automated Network Reconnaissance Framework]]
- [[018 - DNS Tunneling Detection Using ML Classifiers]]
- [[030 - Honeypot Deployment & Attack Analysis Platform]]

---
*📅 Created: 2026-07-30 | 🏷️ Category: Network Penetration Testing | 🔐 Offensive Security Research*
