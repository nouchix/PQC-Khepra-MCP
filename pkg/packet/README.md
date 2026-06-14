# Khepra Packet Auditor (`pkg/packet`)

## Overview
The `pkg/packet` module is designed to perform **Automated Cryptographic Auditing** on network traffic. 

**IMPORTANT:** This module is **NOT** a packet sniffer (like Wireshark or tcpdump). It does not capture live traffic from the network interface. 

Instead, it acts as a **Strategic Analyzer** that consumes packet captures exported by industry-standard tools.

## Why this approach?
1.  **Security & Stability:** Running a live packet capture tool requires Root/Admin privileges and kernel drivers (libpcap/npcap). Embedding this into the Khepra binary would make it flagged by Antivirus and difficult to deploy in sensitive client environments.
2.  **Industry Standard:** Clients already trust Wireshark/Tshark. We leverage that trust for collection, and use Khepra for **Intelligence**.
3.  **Focus:** Wireshark shows you the *data*. Khepra tells you the *risk* (e.g., "SNDL Attack Vector" or "Legacy TLS").

## Workflow

### 1. Capture (Client Side)
The client (or consultant) captures traffic using TShark (command-line Wireshark).
```bash
# Capture 60 seconds of traffic and output to JSON
tshark -i eth0 -a duration:60 -T json > capture.json
```

### 2. Audit (Khepra Side)
Khepra consumes the JSON artifact and applies military-grade heuristic analysis.
```bash
khepra audit ingest snapshot.json -pcap capture.json
```

## Insights Generated
*   **Cleartext Exposure:** Detects HTTP or other unencrypted protocols.
*   **Legacy Crypto:** Identifies TLS 1.0/1.1 usage (violates NIST 800-53).
*   **PQC Risk (SNDL):** Flags standard RSA/ECDH key exchanges as "Store-Now-Decrypt-Later" risks, driving the case for Post-Quantum Migration.
