# 🛡️ Ghulam Mustafa 

### Cybersecurity Student | SOC Analyst | Blue Team | Defensive Security

<p align="center">

**🎯 Building toward a career in Security Operations & Defensive Cybersecurity**

</p>

---

## 🔗 Connect With Me
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ghulam-mustafa-khan-6771753b8/)
] 


<a href="https://app.letsdefend.io/profile/ghulamsarwar05647">
  <img src="https://img.shields.io/badge/🛡️_LetsDefend-My_Profile-111827?style=for-the-badge" alt="LetsDefend Profile">
</a>


[View TryHackMe Profile]([![TryHackMe](https://img.shields.io/badge/TryHackMe-Profile-red?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/ghulamsarwar05647)
</p>

---

# 👨‍💻 About Me

I am a cybersecurity student focused on **defensive security, Security Operations, SOC analysis, incident response, threat detection, SIEM and threat hunting**.

Currently developing practical skills through hands-on cybersecurity labs, projects and continuous learning.

### 🎯 Career Goal

**SOC Analyst → SOC Level 2 → Security Operations / Defensive Security**

My long-term goal is to work in a high-level cybersecurity environment and specialize in defensive security operations.

---

# 🛡️ Cybersecurity Focus

<p align="center">

🛡️ SOC Operations
🔎 Threat Detection
🚨 Incident Response
📊 SIEM Analysis
🔍 Threat Hunting
💻 Endpoint Security
🌐 Network Security
☁️ Cloud Security
🐍 Security Automation
🦠 Malware Analysis

</p>

---

# 🧰 Technical Skills

### 🛡️ Security Operations

* SOC Monitoring
* Alert Triage
* Incident Investigation
* Incident Response
* Threat Detection
* Threat Hunting
* Log Analysis
* Security Monitoring

### 📊 SIEM

* Microsoft Sentinel
* Splunk
* Sentinel
* Elastic Security
* Log Analysis
* Detection Rules
* Security Event Correlation

### 💻 Endpoint Security

* Microsoft Defender
* Windows Event Logs
* Endpoint Investigation
* Endpoint Detection & Response
* Velociraptor

### 🌐 Networking

* TCP/IP
* DNS
* HTTP/HTTPS
* Firewalls
* VPN
* Network Monitoring
* Packet Analysis

### 🐧 Operating Systems

* Linux
* Windows
* Kali Linux

### 🐍 Programming & Automation

* Python
* Bash
* PowerShell
* Security Automation
* Log Processing

### ☁️ Cloud Security

* Cloud Security Fundamentals
* Identity & Access Management
* Cloud Monitoring
* Cloud Security Operations

---

# 🧪 Security Tools

<p align="center">








\

</p>

---



# Enterprise SIEM Log Analysis Lab (Splunk)

## 📌 Project Overview
This project demonstrates the deployment and configuration of an enterprise-grade Security Information and Event Management (SIEM) environment using **Splunk**. The core objective of this lab is to ingest multi-source infrastructure logs, construct optimized Search Processing Language (SPL) queries, and engineer automated correlation rules to detect real-world cyber threats such as Brute Force attacks and data exfiltration.

---

## 📊 Security Operations Center (SOC) Dashboard

### 🔎 Dashboard Description
The analytical dashboard engineered below serves as a centralized pane of glass for a Level 2 SOC Analyst. It translates raw, unstructured log volumes into structured, actionable security intelligence in real-time. 

The visual layout prioritizes high-fidelity indicators of compromise (IoCs). The top row tracks volatile volumetric anomalies, such as sudden spikes in failed authentication attempts or firewall drops, which instantly flag active brute-force or scanning campaigns. The central matrix displays automated statistical distributions tracking top active users and internal-to-external data transfer ratios to expose malicious insider data staging. The final layer correlates live inbound traffic against external threat intelligence lists, instantly isolating malicious external IP addresses interacting with critical network components.

### 🖼️ Dashboard Architecture Screenshots

#### 🔹 Panel 1: Real-Time Authentication Failures & Volumetric Spikes
*This panel monitors authentication logs (EventCode 4625) using mathematical aggregation via the `stats` command to isolate brute force trends before a network breach occurs.*
<img width="1566" height="682" alt="Brute-Force_tracker   png" src="https://github.com/user-attachments/assets/23ada842-a161-454f-b5a2-71a1eae822ff" />



#### 🔹 Panel 2: Network Infrastructure Data Outflow (Data Exfiltration Tracker)
*This panel visualizes data throughput by calculating bytes-to-megabytes transformations using the `eval` command, tracking anomalies where an internal host exceeds baseline transfer thresholds.*

<img width="1561" height="535" alt="Data-Exfiltration-Tracker   png" src="https://github.com/user-attachments/assets/6506a430-4718-4b07-866b-3a8240110045" />


#### 🔹 Panel 3: Threat Intelligence Inbound Log Correlation Matrix
*This component displays live traffic matching against known malicious indicators using active `lookup` schemas, highlighting high-priority alerts for analytical review.*
<img width="1585" height="677" alt="Threat_Intel_Matrix   png" src="https://github.com/user-attachments/assets/dd199c3a-51c4-4b62-8e2e-516e14151a47" />


---

## 🛠️ Core SPL Hunting Signatures Employed

### 1. Brute Force Detection Signature
```splunk
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as Failed_Attempts, count(eval(EventCode=4624)) as Successful_Attempts by user
| where Failed_Attempts > 5 AND Successful_Attempts > 0
```

### 2. High-Volume Outbound Exfiltration Signature
```splunk
index=network_logs
| stats avg(bytes_sent) as normal_average, max(bytes_sent) as current_transfer by user
| eval danger_line = normal_average * 3
| where current_transfer > danger_line
```




# 📊 My Top 5 Essential Security SPL Commands

This section documents my core competency in **Search Processing Language (SPL)**. These commands are engineered to parse raw infrastructure data, calculate volumetric traffic, and hunt for hidden security anomalies.

---

### 1. The Threat Aggregator (`STATS`)
* **Objective:** Group network event signatures to identify high-frequency threat clusters.
* **What it proves:** You know how to aggregate data and count risk occurrences by signature types.
```spl
index=_internal
| stats count by component
| sort - count
```

### 2. High-Frequency Vector Isolation (`TOP`)
* **Objective:** Instantly isolate top talkers or aggressive log noise channels.
* **What it proves:** You can isolate chatterboxes and high-frequency anomaly vectors automatically.
```spl
index=_internal
| top limit=10 log_level
```

### 3. Anomaly & Threat Hunting (`RARE`)
* **Objective:** Find the "needle in the haystack." In security, attackers hide in low-frequency system events.
* **What it proves:** Threat hunting capability. This query flags structural anomalies by finding the rarest 5 executed code modules.
```spl
index=_internal
| rare limit=5 group
```

### 4. Volumetric Bandwidth Engineering (`EVAL`)
* **Objective:** Calculate exact network packet transmission weights in human-readable Megabytes.
* **What it proves:** You can manipulate strings, calculate byte metrics, and build custom calculated fields on the fly.
```spl
index=_internal
| eval Megabytes = round(len(_raw) / 1024 / 1024, 4)
| table _time, component, log_level, Megabytes
| sort - Megabytes
```

### 5. Threat Intelligence Enrichment (`LOOKUP`)
* **Objective:** Match live infrastructure traffic tables against a signature watchlist database.
* **What it proves:** You understand how to enrich raw data using lookup table matrices to append context dynamically.
```spl
index=_internal
| lookup alert_actions.csv action OUTPUT label
| table _time, component, action, label
```
MY FRIST SEARCH OF MY CYBER SECURITY CARRER.

<img width="1911" height="982" alt="image" src="https://github.com/user-attachments/assets/86d3e43f-3058-43b4-88c2-16f1c7dae11a" />





# ====================================================================
# [RULE-01] DETECTION VECTOR: BRUTE FORCE & IDENTITY THREATS
# ====================================================================
[Authentication_Brute_Force_Detected]
search = index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, user | where count > 10
cron_schedule = */5 * * * *
dispatch.earliest_time = -5m
dispatch.latest_time = now
action.email = 1
action.email.to = soc-alerts@company.com
action.email.subject = [CRITICAL ALERT] Threat Actor Brute Force Loop In Progress
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
description = Triggers when a unique IP exceeds 10 authentication failures within a rolling 5-minute window.

# ====================================================================
# [RULE-02] DETECTION VECTOR: PERIMETER DATA EXFILTRATION RADAR
# ====================================================================
[Network_Data_Exfiltration_Anomalous_Egress]
search = index=network sourcetype=pan:traffic | eval payload_mb = bytes_out/1024/1024 | stats sum(payload_mb) as total_outbound by src_ip | where total_outbound > 5000
cron_schedule = */15 * * * *
dispatch.earliest_time = -15m
dispatch.latest_time = now
action.webhook = 1
action.webhook.uri = https://company.com
description = Alerts when an internal host pushes more than 5GB of raw outbound data over network parameters in 15 minutes.

# ====================================================================
# [RULE-03] DETECTION VECTOR: CRITICAL THREAT INTEL MATRIX STRIKE
# ====================================================================
[Threat_Intel_Malicious_IP_Correlation]
search = index=firewall log_level=ERROR component="Threat Signature Vector"
cron_schedule = * * * * *
dispatch.earliest_time = -1m
dispatch.latest_time = now
action.slack = 1
action.slack.channel = #soc-emergency-response
description = Real-time instantaneous alert firing when a structural log signature flags a critical severity vector block.




index=_internal


# 🚨 SOC / Blue Team Projects

## 01 — Enterprise SIEM Log Analysis Lab

**Status:** 🔵 Planned

### Objective

Build a realistic SOC environment for investigating suspicious activity through centralized security logs.

### Tools

* Microsoft Sentinel
* Windows Event Logs
* KQL
* MITRE ATT&CK

### Skills Demonstrated

* Log ingestion
* Alert investigation
* Event correlation
* Detection engineering
* Incident investigation

### 📂 Project

[View Project](PROJECT-LINK)

### 🖼️ Screenshots

---

# 02 — Intrusion Detection System

**Status:** 🔵 Planned

### Objective

Build and configure an intrusion detection environment capable of identifying suspicious network activity.

### Tools

* Suricata / Snort
* Wireshark
* Linux
* Python

### Skills Demonstrated

* Network monitoring
* Packet analysis
* IDS rules
* Threat detection
* Alert investigation

### 📂 Project

[View Project](PROJECT-LINK)

### 🖼️ Screenshots

---

# 03 — Python File Integrity Monitor

**Status:** 🔵 Planned

### Objective

Develop a Python-based tool that detects unauthorized changes to files.

### Tools

* Python
* SHA-256
* Linux

### Skills Demonstrated

* Python
* Hashing
* File monitoring
* Security automation

### 📂 Project

[View Project](PROJECT-LINK)

### 🖼️ Screenshots

---

# 04 — Isolated Malware Analysis Sandbox

**Status:** 🔵 Planned

### Objective

Create an isolated environment for safely analyzing suspicious files and observing malicious behavior.

### Tools

* Windows Sandbox / Virtual Machine
* Sysmon
* Procmon
* Wireshark
* Velociraptor

### Skills Demonstrated

* Malware analysis
* Process investigation
* Network analysis
* IOC extraction
* Threat intelligence

### 📂 Project

[View Project](PROJECT-LINK)

### 🖼️ Screenshots

---

# 05 — Enterprise SIEM Investigation

**Status:** 🔵 Planned

### Objective

Investigate simulated enterprise security incidents using SIEM data.

### Investigation Areas

* Brute-force attacks
* Suspicious authentication
* Impossible travel
* Malicious PowerShell
* Suspicious processes
* Data exfiltration indicators

### Tools

* Microsoft Sentinel
* KQL
* MITRE ATT&CK

### 📂 Project

[View Project](PROJECT-LINK)

---

# 06 — AI Malware Classification Tool

**Status:** 🔵 Planned

### Objective

Develop a machine-learning based system capable of classifying potentially malicious files.

### Tools

* Python
* Machine Learning
* Pandas
* Scikit-learn

### Skills Demonstrated

* Malware analysis
* Feature engineering
* Machine learning
* Security automation

### 📂 Project

[View Project](PROJECT-LINK)


# 📚 TryHackMe

### SOC Level 1 Learning Path

Currently developing practical skills through hands-on defensive-security labs.

### Areas Covered

* SOC Fundamentals
* Networking
* Linux
* Windows
* SIEM
* Log Analysis
* Threat Detection
* Incident Response
* Phishing Analysis
* Digital Forensics
* Threat Hunting

### 🏆 Progress

**Current:** SOC Level 1 Learning Path

**Profile:** [View TryHackMe Profile]([![TryHackMe](https://img.shields.io/badge/TryHackMe-Profile-red?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/ghulamsarwar05647)

---

# 🎓 Education

## Bachelor / Top-Up Degree — Cybersecurity

**Institution:** [UNIVERSITY NAME]

**Program:** Cybersecurity

**Status:** [IN PROGRESS ]

**Expected Completion:** [3]

### 📜 Certificate

[CERTIFICATE LINK]

---

## BTEC Level 5 — Cybersecurity

**Institution:** [WOOLWHICH INSTITUTE DUBAI]

**Qualification:** BTEC Level 5

**Field:** Cybersecurity

**Status:** [IN PROGRESS]

### 📜 Certificate

[CERTIFICATE LINK]

---

# 🏆 Certifications

| Certification     | Provider   | Status     | Certificate              |
| ----------------- | ---------- | ---------- | ------------------------ |
| CompTIA Security+ | CompTIA    | 🔵 Planned | [View](CERTIFICATE-LINK) |
| CompTIA CySA+     | CompTIA    | 🔵 Planned | [View](CERTIFICATE-LINK) |
| CompTIA Network+  | CompTIA    | 🔵 Planned | [View](CERTIFICATE-LINK) |


---

# 📊 Cybersecurity Learning Roadmap

```text
2026
│
├── SOC Fundamentals
├── Networking
├── Linux
├── Windows
├── TryHackMe SOC Level 1
├── Python
└── GitHub Portfolio
        │
        ▼
2027
│
├── SIEM
├── Microsoft Sentinel
├── Splunk
├── Incident Response
├── Threat Hunting
├── Security+
└── Security Projects
        │
        ▼
2028
│
├── Advanced SOC
├── EDR
├── Cloud Security
├── CySA+
├── Malware Analysis
└── Advanced Projects
        │
        ▼
2029
│
├── SOC Experience
├── SOC Level 2 Skills
├── Incident Response
├── Threat Hunting
├── Detection Engineering
└── Security Operations Career
```

---

# 📈 Experience

## SOC Analyst — [COMPANY NAME]

**[START DATE] – [END DATE]**

### Responsibilities

* Monitored security alerts
* Investigated suspicious activity
* Performed SIEM investigations
* Analyzed security logs
* Investigated endpoint alerts
* Performed incident triage
* Escalated security incidents
* Documented incidents
* Supported threat detection

### Tools

* [SIEM]
* [EDR]
* [Ticketing System]
* [Threat Intelligence Platform]


# 📸 Project Evidence

All projects include:

* 📋 Project documentation
* 🧠 Methodology
* 🛠️ Tools used
* 📊 Results
* 🖼️ Screenshots
* 🔎 Investigation findings
* 🚨 Detection logic
* 🛡️ Mitigation
* 🎯 MITRE ATT&CK mapping
* 📚 References

---

# 📜 Certifications & Credentials

### Security+

[Certificate / Verification](CERTIFICATE-LINK)

### CySA+

[Certificate / Verification](CERTIFICATE-LINK)

### Network+

[Certificate / Verification](CERTIFICATE-LINK)

### Cybersecurity Degree

[Degree / Verification](DEGREE-LINK)

---

# 📫 Contact

<p align="center">

**Interested in cybersecurity, SOC operations, defensive security and collaboration?**

</p>

📧 Email: [ghulamsarwar05647@gmail.com
]

💼 LinkedIn: [www.linkedin.com/in/
ghulam-mustafa-khan-6771753b8
]


---

# ⭐ My Cybersecurity Philosophy

> **Learn → Build → Document → Share → Improve**

I believe cybersecurity skills are developed through continuous hands-on practice, realistic projects and constant learning.

---

<p align="center">

### 🛡️ Building the skills today for the security operations of tomorrow.

</p>
