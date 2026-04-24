# 🛡️ Mahmoud Hussein | SOC Analyst Portfolio

SOC Analyst passionate about threat detection, incident response, and digital forensics, with hands-on experience in SIEM, network traffic analysis, and memory forensics.

---

## 🚀 My Cyber Security Journey

Welcome to my cybersecurity portfolio.

This repository showcases **real-world SOC investigations, hands-on labs, and threat detection scenarios**, demonstrating practical experience in:

* 🔍 Threat Hunting & Log Analysis
* 🛡️ Incident Response & DFIR
* 🧠 Memory Forensics & Malware Analysis

---

## 🔥 Featured Investigations

Start here 👇 (Highlighted real-world case studies)

* 🧩 [Boogeyman 1 – Initial Access Investigation](./investigations/Boogeyman1.md)

* 🧠 [Boogeyman 2 – Memory Forensics Analysis](./investigations/Boogeyman2.md)

* 🔥 [Boogeyman 3 – Enterprise SOC Investigation](./investigations/Boogeyman3.md)

* 🛡️ [Volt Typhoon – APT Attack Chain Investigation](./investigations/Volt-Typhoon.md)

* 🕸️ [DeceptiTech – Honeypot Initial Access Investigation](./investigations/Initial-Access-Pot.md)

* 🎭 [Masquerade – Malware Analysis & C2 Communication Investigation](./investigations/Masquerade.md)

* 🔍 [Windows Backdoor & PowerShell – Splunk Log Investigation](./investigations/Windows-Backdoor-Splunk.md)

* 🌐 [Directory Curiosity – PCAP Network & Malware Investigation](./investigations/TShark-Challenge-II:Directory.md)

* ⚡ [Tempest Incident Response Investigation](./investigations/Tempest.md)

* 🌐 [Slingshot – Web Attack & Kill Chain Investigation](./investigations/Slingshot.md)

* 🧠 [BOTSv2 – Advanced Threat Hunting & APT Investigation](./investigations/BOTSv2.md)

* 🧠 [Memory Forensics – Volatility Analysis](./investigations/Memory-Forensics-Volatility.md)

* 🛡️ [IronShade APT – Linux Compromise Investigation](./investigations/IronShade.md)

* 🛡️ [Swiftspend – Wazuh & Sysmon Threat Detection Investigation](./investigations/Swiftspend.md)

* 🛡️ [Axios Supply Chain Attack – Dependency Injection & RAT Analysis](./investigations/Axios-Supply-Chain.md)

* 🐢 [Tardigrade – Linux Server Compromise Investigation](./investigations/Tardigrade.md)

* 🔍 [Windows Process Execution – HR Compromise Investigation](./investigations/HR-Compromise.md)

---

## 🔧 Tools & Technologies

* **SIEM/SOAR:** Splunk, ELK Stack (Kibana)
* **Network Analysis:** Wireshark, TShark, Zeek (Bro), Snort
* **Endpoint & Forensics:** EDR Solutions, Volatility 3, Autopsy, Sysmon
* **Frameworks:** MITRE ATT&CK, Unified Kill Chain, Pyramid of Pain
* **OS:** Ubuntu Linux (Primary), Windows

---

## 🔍 Specialized Security Investigations

### 🛡️ Boogeyman Series (Full Attack Chain)

A complete attack lifecycle investigation from initial access to persistence:

* **Boogeyman 1:** Phishing & Initial Access
* **Boogeyman 2:** Memory Forensics & Process Injection
* **Boogeyman 3:** Enterprise Detection & Log Correlation

---

### 🛡️ Volt Typhoon APT Investigation

* Full attack chain analysis of a real-world APT scenario
* Initial access via account takeover and privilege escalation
* Persistence through web shell deployment on compromised server
* Credential dumping using Mimikatz and registry enumeration
* Lateral movement across internal servers
* Data collection and staging using PowerShell
* Command & Control (C2) via proxy configuration (netsh)
* Defense evasion through log clearing and artifact removal
* Multi-source log correlation using Splunk

---

### 🕸️ DeceptiTech – Honeypot Initial Access Investigation

* DFIR investigation of a ransomware attack originating from a misconfigured Linux honeypot
* Exploitation of exposed WordPress service via brute-force attack (`/wp-login.php`)
* Web shell deployment through a backdoored theme file
* Privilege escalation using exposed SSH key backup file
* Internal network reconnaissance after root access
* Malware persistence established on compromised host
* Reconstruction of the initial attack vector leading to full network compromise

---

### 🎭 Masquerade Investigation (Malware & C2 Analysis)

* Phishing-based initial access via malicious script execution
* Detection of external C2 communication (`api-edgecloud.xyz`)
* Analysis of staged payload delivery and decryption (RC4)
* Extraction and hashing of second-stage malware
* Identification of covert communication channel with remote server
* AES-encrypted command-and-control traffic analysis
* Decryption of attacker commands and full compromise validation

---

### 🌐 Directory Curiosity Investigation (PCAP & Threat Analysis)

* Network traffic analysis using PCAP and TShark
* Detection of malicious domain communication (`jx2-bavuong[.]com`)
* DNS and HTTP traffic correlation with suspicious IP
* Identification of file indexing exposure and attacker interaction
* Extraction of malicious executable from network traffic
* Malware hash analysis and verification via VirusTotal
* Detection of trojan activity and packed .NET executable

---

### 🔍 Windows Backdoor Investigation (Splunk Log Analysis)

* Log analysis using Splunk (index=main) across Windows hosts
* Detection of backdoor user creation (`A1berto`)
* Registry persistence identification under SAM database
* Discovery of impersonation technique targeting legitimate user
* Remote command execution via WMIC for user creation
* Analysis of malicious PowerShell activity (79 events)
* Detection of encoded PowerShell web request to external server
* Full compromise validation on infected host

---

### 🌐 Slingshot Investigation

* Web attack detection using Kibana (ELK Stack)
* Reconnaissance & directory enumeration detection
* Brute-force attack identification (Hydra)
* Web shell upload and command execution
* LFI exploitation and database credential access
* Data exfiltration tracking (customer_credit_cards)

---

### 🧠 BOTSv2 Investigation (Advanced Threat Hunting)

* Multi-source log analysis using Splunk (botsv2 dataset)
* Insider threat detection (Amber Turing activity)
* Web attack detection (SQL Injection & XSS)
* Malware delivery via USB and ransomware execution
* Command & Control (C2) detection using DNS analysis
* Spear phishing and data exfiltration tracking
* Full attack chain reconstruction across endpoints and network

---

### 🛡️ Axios Supply Chain Investigation

* Supply chain attack via malicious npm dependency injection
* Compromise of developer account باستخدام Social Engineering
* Execution of malicious post-install scripts (node postinst.js)
* Deployment of cross-platform RAT (Linux / Windows / macOS)
* C2 communication over HTTP with hardcoded endpoints
* Detection of malicious Python payload execution on Linux
* Persistence via event-triggered execution (MITRE T1546.004)
* Analysis of obfuscated JavaScript using custom encryption key
* Identification of attacker-controlled package (typing-coreutils)

---

### 🌀 Tempest Investigation

* DFIR analysis & attacker tracking
* Reverse proxy detection & privilege escalation

---

### 🛡️ IronShade APT Investigation

* Linux system compromise via exposed SSH service
* Persistence through backdoor user and cronjob
* Detection of hidden processes and malicious services
* Identification of attacker IP and brute-force attempts
* Malware deployment and post-exploitation activity analysis

---

### 🛡️ Swiftspend Investigation (Wazuh & Sysmon)

* Endpoint monitoring using Wazuh and Sysmon logs
* Detection of malicious macro-based initial access
* Persistence via scheduled task creation
* PowerShell execution with Base64 obfuscation
* Credential dumping using custom tooling
* Detection of account creation for persistence
* Data exfiltration identification and analysis

---

### 🔍 Windows Process Execution Investigation (HR Compromise)

* Detection using Windows Event Logs (Event ID 4688)
* Identification of compromised HR user and attacker activity
* Abuse of LOLBins (certutil.exe) for payload download
* Detection of persistence via scheduled tasks
* Analysis of payload delivery from external hosting (controlc.com)
* Extraction of Indicators of Compromise (IOC)
* Reconstruction of attack timeline using process logs
