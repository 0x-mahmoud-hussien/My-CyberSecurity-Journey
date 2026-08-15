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

* 🕵️ [New Hire Old Artifacts - Splunk Threat Hunting & Endpoint Investigation](./investigations/New-Hire-Old-Artifacts.md)

* 🔍 [Windows Backdoor & PowerShell – Splunk Log Investigation](./investigations/Windows-Backdoor-Splunk.md)

* 🧠 [BlueSky Ransomware Lab - Network Forensics & Ransomware Attack Investigation](./investigations/BlueSky-Ransomware-Lab.md)

* 🛡️ [IronShade APT – Linux Persistence & Honeypot Compromise Investigation](./investigations/IronShade.md)

* 🧩 [Boogeyman 1 – Phishing, PowerShell & DNS Exfiltration Investigation](./investigations/Boogeyman1.md)

* 🧠 [Boogeyman 2 – Memory Forensics & Fileless Persistence Investigation](./investigations/Boogeyman2.md)

* 🔥 [Boogeyman 3 – Enterprise SOC Investigation & Active Directory Compromise](./investigations/Boogeyman3.md)

* 🔥 [BOTSv2 – Enterprise Threat Hunting & APT Investigation](./investigations/BOTSv2-Investigation.md)

* 🧠 [Brave Lab - Windows Memory Forensics & User Activity Investigation with Volatility](./investigations/Brave-Lab.md)

* ☕ [OpenWire Lab - Apache ActiveMQ RCE & Java Deserialization Investigation](./investigations/OpenWire-Lab.md)

* 🌐 [WireDive Lab - Multi-Protocol Network Forensics & Traffic Analysis](./investigations/WireDive-Lab.md)

* 🕵️ [XLMRat Lab - Network Forensics & Malware Analysis Investigation](./investigations/XLMRat-Lab.md)

* 🔥 [Slingshot - Web Server Compromise & Attack Chain Investigation](./investigations/Slingshot.md)

* 🕵️ [The Silent Transfer - Network Forensics & Threat Hunting](./investigations/The-Silent-Transfer.md)

* 🔥 [Carnage – Malware Traffic Analysis & C2 Investigation](./investigations/Carnage.md)

* 🧩 [PacketMaze Lab - Multi-Protocol Network Forensics Investigation](./investigations/PacketMaze-Lab.md)

* 🦅 [HawkEye Lab - Network Forensics & Keylogger Data Exfiltration Investigation](./investigations/HawkEye-Lab.md)

* 🔥 [BookWorld Web Server Compromise Investigation](./investigations/BookWorld-Web-Investigation.md)

* 🔥 [DanaBot Malware Delivery & Network Forensics Investigation](./investigations/DanaBot.md)

* 🔥 [Lockdown Lab - IIS Web Shell & AgentTesla DFIR Investigation](./investigations/Lockdown-Lab.md)

* 🔥 [Ramnit - Memory Forensics & Malware IOC Investigation](./investigations/Ramnit.md)

* 🤖 [FakeGPT Lab - Malicious Chrome Extension & Credential Theft Investigation](./investigations/FakeGPT-Lab.md)

* 🔥 [PsExec Hunt - SMB Lateral Movement & PsExec Investigation](./investigations/PsExec-Hunt.md)

* 🔥 [Tomcat Takeover - Apache Tomcat Compromise & Web Shell Investigation](./investigations/Tomcat-Takeover.md)

* 🔥 [Masterminds - Multi-Host Malware Traffic Investigation with Brim](./investigations/Masterminds.md)

* 🧠 [RedLine Lab - Memory Forensics & Malware Investigation with Volatility](./investigations/RedLine.md)

* 🧠 [Reveal Lab - Memory Forensics & Multi-Stage Attack Investigation with Volatility](./investigations/Reveal-Lab.md)

* 🩸 [MangoBleed — MongoDB CVE-2025-14847 Intrusion Investigation](./investigations/MangoBleed-MongoDB-CVE-2025-14847.md)

* 🕵️ [Noxious — LLMNR Poisoning & NTLMv2 Credential Capture](./investigations/Noxious.md)

* 🌐 [Directory Curiosity – PCAP Network & Malware Investigation](./investigations/TShark-Challenge-II:Directory.md)


* 🛡️ [Swiftspend – Wazuh & Sysmon Threat Detection Investigation](./investigations/Swiftspend.md)

* 🛡️ [Axios Supply Chain Attack – Dependency Injection & RAT Analysis](./investigations/Axios-Supply-Chain.md)

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

### 🕵️ New Hire Old Artifacts Investigation

* Investigated a December 2021 endpoint security incident at Widget LLC using Splunk and Windows Sysmon telemetry.
* Identified the execution of NirSoft Web Browser Password Viewer from the user's temporary directory and confirmed browser credential access activity.
* Detected a suspicious binary masquerading as `PalitExplorer.exe` while executing under the name `IonicLarge.exe`.
* Traced outbound C2 communications from the malicious binary to `2[.]56[.]59[.]42` and identified two external connections.
* Investigated registry modifications targeting Windows Defender under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.
* Reconstructed attacker anti-forensics activity involving process termination and deletion of malicious binaries and dropped DLL artifacts.
* Analyzed PowerShell and WMIC activity used to suppress four Windows Defender Threat IDs through repeated `MSFT_MpPreference` modifications.
* Identified the four suppressed Threat IDs in execution order: `2147735503`, `2147737010`, `2147737007`, and `2147737394`.
* Discovered the execution of `C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe` from the user's Roaming AppData directory.
* Identified the NW.js dependencies loaded by `EasyCalc.exe`: `ffmpeg.dll`, `nw.dll`, and `nw_elf.dll`.

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

### 🧠 BlueSky Ransomware Investigation

* Investigated a multi-stage ransomware intrusion through network traffic analysis and PowerShell script deobfuscation
* Identified SQL Server compromise via brute-force authentication and abuse of `xp_cmdshell` for remote command execution
* Traced privilege escalation through C2 process injection into `winlogon.exe`
* Analyzed malicious PowerShell payloads used to disable Microsoft Defender and evade endpoint security controls
* Investigated persistence mechanisms through scheduled task creation (`\Microsoft\Windows\MUI\LPupdate`)
* Analyzed credential dumping activity using `Invoke-PowerDump.ps1` and identified harvested credential artifacts
* Reconstructed lateral movement across the network using SMBExec and attacker-discovered host inventories
* Investigated ransomware deployment workflow, including payload delivery, execution chain, and ransom note creation
* Extracted Indicators of Compromise (IOCs) including attacker IP addresses, malicious URLs, registry modifications, scheduled tasks, and ransomware artifacts
* Correlated attacker behavior with MITRE ATT&CK techniques covering Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Command and Control, and Impact

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

### 🧠 Brave Lab Investigation

* Performed Windows memory forensics using Volatility 3 to analyze a suspected compromised workstation
* Verified forensic evidence integrity through SHA-256 hashing and reconstructed the system acquisition timeline
* Investigated active process execution, including Brave Browser, PowerShell, Chrome, Notepad, and OneDrive
* Analyzed established network connections to identify external communications with ProtonMail infrastructure
* Correlated browser activity, process execution, and registry artifacts to reconstruct user behavior prior to acquisition
* Extracted process artifacts, executable hashes, and memory-resident evidence for forensic validation
* Performed low-level memory carving using hexadecimal analysis to recover hidden strings and memory artifacts
* Traced PowerShell process lineage through parent-child process relationships and execution timestamps
* Reconstructed recently opened documents by analyzing command-line arguments and application execution history
* Leveraged UserAssist registry artifacts to determine application usage patterns and Brave Browser execution duration

---

### ☕ OpenWire Lab Investigation

* Investigated remote code execution (RCE) through Apache ActiveMQ OpenWire protocol exploitation (CVE-2023-46604)
* Analyzed malicious Java deserialization traffic targeting the ActiveMQ service over TCP port 61616
* Traced outbound command-and-control (C2) communications across multiple attacker-controlled servers
* Examined malicious XML payloads leveraging Spring Framework to instantiate `java.lang.ProcessBuilder`
* Reconstructed the complete exploitation chain from XML payload retrieval to arbitrary operating system command execution
* Investigated secondary payload delivery and execution of a dropped reverse shell binary (`/tmp/docker`)
* Identified attacker infrastructure including primary and secondary C2 servers, malicious payload hosting, and HTTP staging activity
* Performed root cause analysis of the Java deserialization vulnerability and reviewed the vendor patch validating `Throwable` class instantiation
* Extracted Indicators of Compromise (IOCs) including attacker IP addresses, dropped malware, exploited service, malicious Java classes, and network artifacts
* Documented the full attack lifecycle covering Initial Access, Remote Code Execution, Command and Control, and post-exploitation payload deployment

---

### 🌐 WireDive Network Forensics Investigation

* Analyzed diverse network traffic using Wireshark across DHCP, DNS, SMB, shell, HTTP/S, NTP, STP, CDP, HSRP, SNMP, and RADIUS protocols.
* Investigated DHCP transactions to identify requested IP addresses, client MAC addresses, and DHCP release transaction identifiers.
* Analyzed DNS traffic to extract TXT record data, identify root DNS infrastructure, and trace authoritative name servers.
* Investigated SMB authentication failures, remote share access, file paths, and extracted sensitive data from transferred files.
* Reconstructed reverse shell activity and identified listening ports, privilege escalation attempts, Netcat usage, and sensitive file access.
* Analyzed attacker commands to identify the installed Netcat version, exposed `/etc/passwd` data, and the password used for sudo privilege escalation.
* Investigated network infrastructure protocols including NTP, DHCP, STP, CDP, HSRP, ICMPv6, SNMP, and RADIUS to extract critical network configuration artifacts.
* Decrypted and analyzed HTTPS traffic to recover credentials, authentication data, web interaction artifacts, and sensitive user information.
* Extracted and analyzed TLS, OCSP, HTTP/2, and encrypted web traffic artifacts to identify certificate status and compromised account details.
* Reconstructed the complete investigation across multiple packet captures to identify authentication failures, sensitive data exposure, suspicious shell activity, and network configuration artifacts.

---

### 🕵️ XLMRat Lab Investigation

* Investigated a multi-stage malware infection affecting host `10.1.9.101` through network traffic analysis of the provided PCAP.
* Reconstructed the initial infection chain from the HTTP delivery of `xlm.txt` to the second-stage PowerShell payload `mdm.jpg`.
* Identified the attacker infrastructure at `45.126.209.4` and traced malware delivery over the non-standard HTTP port `222/TCP`.
* Analyzed the VBScript stager and reconstructed the obfuscated PowerShell execution using `-NOP`, hidden window execution, and `-ExecutionPolicy Bypass`.
* Identified `mdm.jpg` as a disguised PowerShell script that dropped `Conted.vbs`, `Conted.bat`, and `Conted.ps1` into `C:\Users\Public\`.
* Reconstructed the persistence mechanism through the scheduled task `Update Edge`, configured to execute every two minutes.
* Deobfuscated the PowerShell payload and identified `RegSvcs.exe` as the legitimate .NET LOLBin targeted for Process Hollowing.
* Extracted and analyzed the embedded AsyncRAT payload, identifying the malware family as `AsyncRAT` with SHA256 `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`.
* Traced encrypted TLS C2 communication between the compromised host and the attacker infrastructure and mapped the observed activity to relevant MITRE ATT&CK techniques.

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

### 🕵️ The Silent Transfer Network Investigation

* Investigated suspicious encrypted outbound traffic from a compromised developer workstation using Wireshark, TShark, Zeek, and Zui.
* Identified the compromised workstation `10.14.30.88` and confirmed repeated C2 communication with external infrastructure.
* Traced the initial compromise to the malicious delivery domain `cdn-updates.microsoftservice.net` and identified the downloaded dropper `winservice-patch-4891.exe`.
* Analyzed C2 TLS activity and identified the JA4 fingerprint `t13d190900_9dc949149365_97f8aa674fd9` associated with the C2 client.
* Reconstructed attacker activity following C2 establishment, including SMB discovery across 23 unique internal destination hosts.
* Identified lateral movement through RDP from the compromised workstation to internal server `10.14.0.12`.
* Investigated DNS activity from the pivoted server and identified `backup.corpfiles-sync.com` as the infrastructure resolved before the outbound transfer.
* Identified the exfiltrated archive `Q4-Finance-Backup-2025.zip` and extracted its SHA256 hash as an investigation IOC.
* Inspected application-layer C2 traffic and decoded the Base64 command `d2hvYW1p` to recover the attacker-issued `whoami` command.
* Reconstructed the attack lifecycle from initial payload delivery and C2 establishment through internal reconnaissance, lateral movement, and data exfiltration.

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

### 🧩 PacketMaze Network Forensics Investigation

* Investigated suspicious multi-protocol network activity using Wireshark to reconstruct the complete attack sequence.
* Recovered plaintext FTP authentication credentials after analyzing protocol downgrade from encrypted to cleartext communication.
* Identified unauthorized file transfers, FTP artifacts, and attacker access to sensitive data stored on the internal server.
* Analyzed DNS, HTTP, UDP, FTP, and TLS traffic to uncover attacker infrastructure and external communications.
* Investigated encrypted TLS sessions by extracting Client Random values and Ephemeral Public Keys for forensic correlation.
* Detected periodic UDP beaconing behavior consistent with command-and-control (C2) communications.
* Performed metadata analysis on transferred images using ExifTool to identify the originating device and supporting forensic evidence.
* Extracted Indicators of Compromise (IOCs) including compromised credentials, malicious IP addresses, domains, cryptographic artifacts, and exfiltrated files.
* Reconstructed the complete compromise timeline from initial authentication through data exfiltration and external communications.

---

### 🦅 HawkEye Keylogger Investigation

* Investigated a phishing-driven malware infection through comprehensive network traffic analysis using Wireshark
* Traced malicious DNS resolution, HTTP payload delivery, and execution of the HawkEye Keylogger malware
* Identified malware hosting infrastructure, delivery server technologies, and attacker-controlled domains
* Reconstructed SMTP-based data exfiltration sessions and recovered stolen credentials through traffic decoding
* Decoded Base64-encoded authentication data using CyberChef to recover attacker email credentials
* Analyzed periodic exfiltration behavior and identified the malware's automated 10-minute data theft interval
* Identified compromised browser, banking, email, and corporate account credentials extracted by the keylogger
* Correlated malware behavior with HawkEye Reborn v9 through threat intelligence and infrastructure analysis
* Extracted Indicators of Compromise (IOCs) including malicious domains, IP addresses, file hashes, SMTP accounts, and persistence artifacts
* Reconstructed the complete attack lifecycle from initial phishing download through credential theft and outbound data exfiltration

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

### 🔥 Ramnit Investigation

* Performed Windows memory forensics using Volatility to identify active malicious processes
* Traced malware execution chain and extracted executable path from volatile memory
* Analyzed network connections to identify outbound command-and-control (C2) communication
* Correlated network indicators with threat intelligence to identify attacker infrastructure
* Extracted malware artifacts including SHA1 hash and PE compilation timestamp
* Investigated malicious domains and associated command-and-control infrastructure
* Reconstructed malware activity timeline from memory artifacts and network evidence
* Extracted memory-based indicators of compromise (IOCs) including processes, IP addresses, domains, and file hashes

---

### 🤖 FakeGPT Lab Investigation

* Investigated a malicious Chrome extension masquerading as "ChatGPT" that was designed to steal credentials, session cookies, and user keystrokes.
* Analyzed the extension structure and identified `manifest.json`, `loader.js`, `app.js`, and `crypto.js` as the key components of the malicious extension.
* Identified excessive browser permissions including `cookies`, `webRequest`, `webRequestBlocking`, `<all_urls>`, and access to HTTP/HTTPS traffic.
* Deobfuscated the Base64-encoded target domain and identified `www.facebook.com` as the website monitored for credential theft.
* Analyzed anti-analysis mechanisms in `loader.js` that detect headless and virtualized browser environments using `navigator.plugins.length` and `HeadlessChrome` checks.
* Reconstructed credential harvesting through the `submit` event, capturing usernames and passwords from login forms.
* Identified real-time keylogging through the browser `keydown` event listener.
* Analyzed the `exfiltrateCredentials()` function used to package and encrypt stolen credentials before transmission.
* Identified AES encryption using the hardcoded key `SuperSecretKey123` and a randomly generated 16-byte IV.
* Reconstructed covert data exfiltration through dynamically created `<img>` requests to `https://Mo.Elshaheedy.com/collect`.
* Identified `Mo.Elshaheedy.com` as the attacker-controlled exfiltration server and extracted the associated URL as an IOC.
* Mapped the observed malware behavior to MITRE ATT&CK techniques including T1027, T1497.001, T1555.003, T1539, T1056.001, T1056.004, T1041, and T1573.001.

---

### 🔥 PsExec Hunt Investigation

* Investigated SMB-based lateral movement across multiple Windows workstations
* Traced attacker authentication and credential reuse using compromised domain accounts
* Analyzed PsExec remote service deployment and execution (PSEXESVC.exe)
* Identified administrative share abuse through ADMIN$ and IPC$ network shares
* Examined SMB protocol activity including NTLM authentication and Tree Connect requests
* Tracked attacker pivoting from the initial compromised host to additional systems
* Reconstructed lateral movement timeline using PCAP and network forensic analysis
* Extracted indicators of compromise (IOCs) including compromised hosts, user accounts, network shares, and PsExec artifacts

---

### 🔥 Tomcat Takeover Investigation

* Investigated Apache Tomcat server compromise through network traffic and web log analysis
* Analyzed attacker reconnaissance including Nmap scanning and Gobuster directory enumeration
* Identified unauthorized access to the Tomcat Manager administrative interface
* Investigated brute-force authentication resulting in administrative account compromise
* Traced malicious WAR file deployment for remote code execution and web shell access
* Reconstructed post-exploitation activities including interactive reverse shell execution
* Analyzed Linux persistence established through scheduled cron job execution
* Extracted indicators of compromise (IOCs) including attacker infrastructure, compromised credentials, malicious payloads, and persistence mechanisms

---

### 🔥 Masterminds Investigation

* Investigated multi-host malware infections through comprehensive PCAP analysis using Brim
* Traced phishing-initiated compromise and malicious payload delivery across multiple endpoints
* Analyzed DNS, HTTP, and POST traffic to reconstruct malware execution and command-and-control communications
* Identified malware families including Emotet, RedLine Stealer, and Phorpiex through threat intelligence correlation
* Extracted malicious domains, downloaded payloads, C2 infrastructure, and network-based indicators of compromise (IOCs)
* Investigated Suricata IDS alerts to validate malicious network activity and endpoint compromise
* Correlated multi-stage malware download chains and victim-to-C2 communications across infected systems
* Performed OSINT-based threat attribution using VirusTotal and URLhaus to classify malware infrastructure

---

### 🧠 RedLine Memory Forensics Investigation

* Performed Windows memory forensics using Volatility to identify malicious processes and process lineage
* Investigated process injection through RWX memory regions and detected malicious in-memory execution techniques
* Traced malware execution from dropped payload to child process creation using process tree analysis
* Identified command-and-control (C2) infrastructure through network socket and memory artifact analysis
* Analyzed VPN-related processes to uncover attacker network evasion techniques and NIDS bypass behavior
* Extracted malware file paths, malicious URLs, attacker IP addresses, and process-based indicators of compromise (IOCs)
* Correlated volatile memory artifacts with network activity to reconstruct the complete attack timeline
* Documented attacker persistence, execution flow, and memory-based forensic evidence for incident response

---

### 🧠 Reveal Lab Investigation

* Analyzed Windows memory dump using Volatility 3 to investigate a multi-stage malware attack
* Identified malicious PowerShell execution and traced the process hierarchy to the initial compromise
* Investigated Living-off-the-Land (LotL) techniques involving PowerShell, WebDAV, and Rundll32
* Traced remote WebDAV share access (\\45.9.74.32@8888\davwwwroot\) used for staging the second-stage payload
* Identified second-stage DLL execution through Rundll32 using the malicious file `3435.dll`
* Mapped attacker behavior to MITRE ATT&CK T1218.011 (System Binary Proxy Execution: Rundll32)
* Determined the compromised user context and reconstructed the execution workflow
* Attributed the intrusion to the StrelaStealer malware family through threat intelligence correlation
* Extracted memory-based indicators of compromise (IOCs) including malicious processes, remote infrastructure, and payload artifacts
* Reconstructed the complete attack chain from initial PowerShell execution through credential-stealing malware deployment

---

### 🩸 MongoBleed — MongoDB CVE-2025-14847 Intrusion Investigation

* Investigated the compromise of a secondary MongoDB server (`mongodbsync`) following exploitation of the **MongoBleed vulnerability (CVE-2025-14847)**.
* Identified the vulnerable MongoDB version as **8.0.16** and confirmed exploitation through **75,260 rapid heap-memory scraping connections**.
* Traced the exploitation activity to the external attacker IP **65.0.76.43**, with the first malicious connection observed at **2025-12-29 05:25:52 UTC**.
* Determined that the heap disclosure activity was used to extract credentials from MongoDB process memory, followed by successful SSH authentication as **`mongoadmin`**.
* Reconstructed the attacker's interactive SSH session and identified post-compromise discovery commands including `whoami` and `ls -la`.
* Analyzed attacker activity involving **LinPEAS**, executed through `curl -L ... | sh`, enabling privilege-escalation enumeration directly in memory without writing the tool to disk.
* Identified `/var/lib/mongodb/` as the targeted staging directory containing the MongoDB database files.
* Detected installation of the `zip` utility and subsequent use of `python3 -m http.server 6969` to establish an HTTP-based file transfer mechanism.
* Reconstructed the intrusion chain from **CVE exploitation → credential extraction → SSH access → discovery → privilege-escalation enumeration → database staging → potential HTTP exfiltration**.
* Mapped observed attacker techniques to **MITRE ATT&CK**, including T1190, T1021.004, T1033, T1083, T1059.004, T1005, T1560.001, and T1048.003.

---

### 🕵️ Noxious — LLMNR Poisoning & NTLMv2 Credential Capture

* Investigated an **LLMNR poisoning attack** against the `Forela-WKstn002` workstation after a mistyped hostname (`DCC01`) triggered LLMNR fallback.
* Identified the rogue Kali machine at `172.17.79.135`, running as hostname `kali`, which responded to the victim's LLMNR request and impersonated the requested host.
* Reconstructed the **NTLMv2 credential capture** process and recovered the compromised account `FORELA\john.deacon`.
* Extracted the NTLM Server Challenge and NTProofStr from the SMB authentication exchange and reconstructed the captured NetNTLMv2 material for offline analysis.
* Cracked the captured NTLMv2 credential using **Hashcat (mode 5600)**, recovering the plaintext password `NotMyPassword0K?`.
* Traced the victim's original intended network resource to the sensitive SMB share `\\DC01\DC-Confidential`.
* Correlated DHCP, LLMNR, SMB2, and NTLMSSP traffic to reconstruct the complete attack chain from the initial hostname typo through credential capture.
* Identified the rogue system's VMware MAC address `00:0c:29:36:18:82` and correlated it with the attacker IP and Kali hostname.
* Mapped the investigation to **MITRE ATT&CK**, including LLMNR/NBT-NS Poisoning (`T1557.001`), Password Cracking (`T1110.002`), Network Sniffing (`T1040`), and Network Share Discovery (`T1135`).

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
