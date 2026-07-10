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

* 🛡️ [Volt Typhoon – APT Attack Chain Investigation](./investigations/Volt-Typhoon.md)

* 🕸️ [DeceptiTech – Honeypot Initial Access Investigation](./investigations/Initial-Access-Pot.md)

* 💀 [Conti Ransomware – Exchange Compromise & DFIR Investigation](./investigations/Conti.md)

* ☀️ [BlackSun Ransomware – Endpoint Compromise & Persistence Investigation](./investigations/BlackSun.md)

* 🎭 [Masquerade – Malware Analysis & C2 Communication Investigation](./investigations/Masquerade.md)

* 🔍 [Windows Backdoor & PowerShell – Splunk Log Investigation](./investigations/Windows-Backdoor-Splunk.md)

* 🛡️ [IronShade APT – Linux Persistence & Honeypot Compromise Investigation](./investigations/IronShade.md)

* 🧩 [Boogeyman 1 – Phishing, PowerShell & DNS Exfiltration Investigation](./investigations/Boogeyman1.md)

* 🧠 [Boogeyman 2 – Memory Forensics & Fileless Persistence Investigation](./investigations/Boogeyman2.md)

* 🔥 [Boogeyman 3 – Enterprise SOC Investigation & Active Directory Compromise](./investigations/Boogeyman3.md)

* 🔥 [BOTSv2 – Enterprise Threat Hunting & APT Investigation](./investigations/BOTSv2-Investigation.md)

* 🔥 [Slingshot - Web Server Compromise & Attack Chain Investigation](./investigations/Slingshot.md)

* 🔥 [Carnage – Malware Traffic Analysis & C2 Investigation](./investigations/Carnage.md)

* 🔥 [BookWorld Web Server Compromise Investigation](./investigations/BookWorld-Web-Investigation.md)

* 🔥 [DanaBot Malware Delivery & Network Forensics Investigation](./investigations/DanaBot.md)

* 🔥 [Lockdown Lab - IIS Web Shell & AgentTesla DFIR Investigation](./investigations/Lockdown-Lab.md)

* 🌐 [Directory Curiosity – PCAP Network & Malware Investigation](./investigations/TShark-Challenge-II:Directory.md)


* 🛡️ [Swiftspend – Wazuh & Sysmon Threat Detection Investigation](./investigations/Swiftspend.md)

* 🛡️ [Axios Supply Chain Attack – Dependency Injection & RAT Analysis](./investigations/Axios-Supply-Chain.md)

* 🐢 [Tardigrade – Linux Server Compromise Investigation](./investigations/Tardigrade.md)

* 🔍 [Windows Process Execution – HR Compromise Investigation](./investigations/HR-Compromise.md)

---

## 🔧 Tools & Technologies

* **SIEM/SOAR:** Splunk, ELK Stack (Kibana)
* **Network Analysis:** Wireshark, TShark, Zeek (Bro), Snort, Brim
* **Endpoint & Forensics:** EDR Solutions, Volatility 3, Autopsy, Sysmon
* **Frameworks:** MITRE ATT&CK, Unified Kill Chain, Pyramid of Pain
* **OS:** Ubuntu Linux (Primary), Windows

---

## 🔍 Specialized Security Investigations

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

### 💀 Conti Ransomware Investigation (Exchange & DFIR)

* DFIR investigation of Conti ransomware attack targeting Microsoft Exchange
* Initial access via exploitation of multiple CVEs (Proxy-like attack chain)
* Web shell deployment for remote command execution and persistence
* Backdoor account creation with administrative privileges
* Process migration to `lsass.exe` for credential dumping
* Detection of privilege escalation and lateral movement techniques
* Identification of ransomware payload execution and file encryption
* Mass distribution of ransom notes across user directories
* Full attack chain reconstruction from exploitation to impact

---

### ☀️ BlackSun Ransomware Investigation (Endpoint & Splunk Analysis)

* Endpoint compromise investigation using Splunk log analysis
* Detection of malicious binary download via PowerShell
* Analysis of persistence mechanism using scheduled tasks
* Execution of payload with SYSTEM-level privileges
* Identification of C2 communication via ngrok tunneling
* Detection of staged PowerShell malware (`BlackSun.ps1`)
* Ransomware behavior analysis and note creation
* Identification of desktop defacement via malicious wallpaper

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

### 🛡️ IronShade APT Investigation

* Linux compromise assessment and DFIR analysis
* Detection of malicious SSH activity and backdoor account creation
* Persistence via cronjobs and malicious systemd services
* Identification of hidden processes and masqueraded binaries
* Threat actor tracking through authentication logs and SSH sessions
* Unauthorized package installation and metadata analysis
* Root privilege escalation and post-exploitation activity investigation

---

### 🧩 Boogeyman 1 Investigation

* Spear-phishing analysis targeting the finance department
* Malicious LNK shortcut and obfuscated PowerShell execution
* Payload delivery through attacker-controlled Python HTTP server
* Host reconnaissance using Seatbelt and SQLite tooling
* Credential harvesting from Windows Sticky Notes database
* KeePass database theft through DNS tunneling exfiltration
* C2 beaconing analysis and financial data compromise investigation

---

### 🧠 Boogeyman 2 Investigation

* Spear-phishing investigation targeting the HR department
* Malicious VBA macro and staged payload delivery analysis
* Memory forensics investigation using Volatility 3
* Process tree reconstruction from WINWORD.exe to updater.exe
* JavaScript-based malware execution through wscript.exe
* C2 communication analysis and malicious network connection tracing
* Fileless persistence via PowerShell, registry payloads, and scheduled tasks
* Outlook cache artifact recovery and malicious document tracking

---

### 🔥 Boogeyman 3 Investigation

* Multi-stage spear-phishing investigation targeting the company CEO
* ISO, HTA, and DLL-based malware execution chain analysis
* Persistence establishment through malicious scheduled tasks
* Command & Control (C2) beaconing and network communication tracing
* UAC bypass investigation using fodhelper.exe
* Credential dumping and Pass-the-Hash attack analysis with Mimikatz
* PowerView-based network share enumeration and credential harvesting
* Lateral movement investigation via WinRM and wsmprovhost.exe
* Active Directory compromise and DCSync attack analysis
* LockBit ransomware staging and enterprise attack chain reconstruction

---

### 🔥 BOTSv2 Investigation

* Executive targeting and spear-phishing campaign investigation
* Email header, attachment, and threat actor attribution analysis
* TOR browser activity and anonymous infrastructure tracking
* Web application attack investigation including SQL injection and XSS activity
* Network-based threat hunting using firewall, proxy, IDS, and packet telemetry
* Malicious account creation and web application compromise analysis
* Ransomware impact assessment and encrypted file investigation
* USB-delivered malware execution and persistence analysis
* Malware attribution through dynamic DNS and C2 infrastructure tracking
* APT campaign investigation involving PowerShell Empire and scheduled task persistence
* SSL-encrypted command-and-control traffic analysis
* Enterprise-wide attack chain reconstruction using Splunk, Sysmon, Suricata, and endpoint logs

---

### 🔥 Slingshot Investigation

* Investigated web server compromise through Apache log analysis using Elastic Stack
* Traced attacker reconnaissance activities including Nmap NSE scanning and Gobuster directory enumeration
* Analyzed brute-force authentication attacks against administrative login portals using Hydra
* Investigated unauthorized administrative access and malicious file upload activity
* Performed web shell execution analysis and post-exploitation command tracking
* Identified Local File Inclusion (LFI) exploitation used to access sensitive configuration files
* Traced database access, credential exposure, and customer data compromise activities
* Reconstructed the complete attack timeline from initial reconnaissance to database manipulation
* Extracted web-based indicators of compromise (IOCs) including attacker IPs, tools, credentials, and malicious artifacts

---

### 🔥 Carnage Investigation

* Investigated a phishing-driven malware infection through full packet capture (PCAP) analysis
* Traced malicious ZIP payload delivery and extracted staged malware distribution infrastructure
* Identified multiple attacker-controlled domains involved in payload hosting and malware delivery
* Analyzed Cobalt Strike command-and-control infrastructure, beacon traffic, and callback communications
* Investigated DNS activity, including external IP discovery requests via public API services
* Performed SSL certificate and web server fingerprinting to profile attacker infrastructure
* Reconstructed post-infection network activity and malware communication patterns
* Analyzed SMTP traffic to identify malicious spam activity and email transmission artifacts
* Extracted network-based indicators of compromise (IOCs) including domains, IP addresses, and C2 infrastructure

---

### 🔥 BookWorld Web Investigation

* Investigated a web server compromise through SQL injection and administrative account abuse
* Identified attacker infrastructure, geolocation, and malicious activity originating from an external IP address
* Analyzed SQL injection attacks used to enumerate databases, extract schema information, and access customer records
* Traced attacker discovery of hidden administrative functionality and unauthorized access to the web management portal
* Investigated authentication abuse involving weak default administrative credentials
* Analyzed malicious file upload activity resulting in remote code execution (RCE) on the web server
* Examined a PHP web shell containing a reverse shell payload used for persistent remote access
* Reconstructed the complete attack timeline from initial exploitation through post-compromise persistence
* Extracted web application Indicators of Compromise (IOCs) including attacker IPs, session artifacts, uploaded malware, and callback infrastructure

---

### 🔥 DanaBot Malware Investigation

* Investigated a multi-stage DanaBot malware infection using PCAP analysis and threat intelligence correlation
* Traced initial access activity to a malicious JavaScript downloader delivered from attacker-controlled infrastructure
* Analyzed execution of the malware chain through Windows Script Host (wscript.exe) and subsequent payload deployment
* Performed JavaScript deobfuscation to uncover malware functionality, network communications, and payload retrieval mechanisms
* Identified secondary-stage DLL payload delivery and analyzed malware staging behavior
* Investigated attacker-controlled domains, delivery servers, and command-and-control infrastructure involved in the infection chain
* Reconstructed the complete attack timeline from initial compromise through payload execution
* Extracted host and network Indicators of Compromise (IOCs), including malicious domains, IP addresses, file hashes, and execution artifacts
* Mapped observed attacker behavior to MITRE ATT&CK techniques including obfuscated files, registry modification, DLL execution, and ingress tool transfer

---

### 🔥 Lockdown Lab Investigation

* Investigated a multi-stage intrusion targeting a public-facing IIS web server
* Analyzed reconnaissance activity including Nmap HTTP enumeration and SMB share discovery
* Traced malicious ASP.NET web shell deployment and reverse shell establishment
* Performed Windows memory forensics using Volatility to reconstruct attacker activity
* Identified persistence through Startup folder implants and malicious process execution
* Analyzed w3wp.exe child processes and outbound command-and-control communications
* Conducted static malware analysis, identifying UPX packing and AgentTesla RAT characteristics
* Correlated network, memory, and threat intelligence artifacts to reconstruct the complete attack timeline
* Extracted indicators of compromise (IOCs) including attacker infrastructure, malware artifacts, and C2 domains

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
