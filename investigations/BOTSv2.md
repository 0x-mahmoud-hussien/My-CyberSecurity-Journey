# 🧠 BOTSv2 – Advanced Threat Hunting & APT Investigation (Splunk)

---

## 📌 Scenario

A simulated enterprise environment was compromised by advanced threat actors, including insider activity and external APT groups. Logs from multiple sources (Windows endpoints, network traffic, IDS, and web proxy) were ingested into Splunk (index=botsv2) for analysis.

As a SOC Analyst, the objective was to perform deep threat hunting, identify attacker behavior, trace communications, and uncover multiple stages of compromise across the environment.

---

## 🎯 Investigation Objectives

* Identify suspicious user activity and insider threats
* Detect external attacker behavior and reconnaissance
* Analyze web, email, and endpoint activity
* Investigate persistence, exploitation, and C2 communication
* Correlate events across multiple data sources

---

## 🌐 Initial Reconnaissance & Web Activity

### 👤 Suspicious User Activity (Amber Turing)

* Initial search:

```
index="botsv2" amber
```

* Identify IP from firewall logs:

```
index="botsv2" sourcetype="pan:traffic"
```

---

### 🌍 Competitor Website Visited

```
www.berkbeer.com
```
![Competitor Website Visited](../images/botsv2_1.png)

➡️ Amber accessed competitor website to gather executive contact information

---

### 🖼️ Extracted Sensitive Information

```
/images/ceoberk.png
```
![Extracted Sensitive Information](../images/botsv2_2.png)

➡️ Image contained CEO contact details

---

### 👨‍💼 Targeted Executive

```
Martin Berk
mberk@berkbeer.com
```
![Targeted Executive](../images/botsv2_3.png)
![Targeted Executive](../images/botsv2_4.png)

---

### 📧 Additional Contact

```
hbernhard@berkbeer.com
```
![Additional Contact](../images/botsv2_5.png)

---

### 📎 Data Exfiltration

```
Saccharomyces_cerevisiae_patent.docx
```
![Data Exfiltration](../images/botsv2_6.png)

➡️ Sensitive file sent externally

---

### 🕵️ Personal Email Usage

```
ambersthebest@yeastiebeastie.com
```
![Personal Email Usage](../images/botsv2_7.png)

➡️ Possible insider threat behavior

---

## 🧅 Defense Evasion

### TOR Usage

```
7.0.4
```
![TOR Usage](../images/botsv2_8.png)

➡️ Used to anonymize activity

---

## 🌐 External Attack Activity

### 🎯 Target Server

```
www.brewertalk.com → 52.42.208.228
```
![Target Server](../images/botsv2_9.png)


---

### ⚠️ Attacker IP

```
45.77.65.211
```
![Attacker IP](../images/botsv2_10.png)

---

### 🧨 Exploited Endpoint

```
/member.php
```
![Exploited Endpoint](../images/botsv2_11.png)

---

### 💣 SQL Injection

```
updatexml
```
![SQL Injection](../images/botsv2_12.png)

---

## 🍪 XSS Attack

### 🔓 Cookie Value

```
1502408189
```
![Cookie Value](../images/botsv2_13.png)

---

### 👤 Victim

```
Kevin Lagerfield
```

---

### 🎭 Malicious Account

```
kIagerfield
```
![Malicious Account](../images/botsv2_14.png)

➡️ Username impersonation for persistence

---

## 💻 Endpoint Compromise (Mallory)

### 🗂️ Encrypted File

```
Frothly_marketing_campaign_Q317.pptx.crypt
```
![Encrypted File](../images/botsv2_15.png)

---

### 🎬 Additional File

```
S07E02
```
![Additional File](../images/botsv2_16.png)

---

### 🔌 Infection Vector

```
USB – Alcor Micro Corp.
```

---

### 🧠 Malware Details

Language:

```
Perl
```

First Seen:

```
2017-01-17
```

---

### 🌐 C2 Servers

```
eidk.duckdns.org
eidk.hopto.org
```

---

## 📧 Spear Phishing

### 📎 Attachment

```
invoice.zip
```
![Attachment](../images/botsv2_17.png)

---

### 🔐 Password

```
912345678
```
![Password](../images/botsv2_18.png)

---

### 🔒 SSL Issuer

```
C = US
```
![SSL Issuer](../images/botsv2_19.png)

---

## 📥 Malware Activity

### ⚠️ Suspicious File

```
나는_데이비드를_사랑한다.hwp
```
![Suspicious File](../images/botsv2_20.png)

---

### 🧬 Metadata Attribution

```
Ryan Kovar
```

---

### 🧠 Marker

```
CyberEastEgg
```

---

## 🔁 Persistence

### ⚙️ Scheduled Task Beaconing

```
process.php
```

---

## 🚨 Attack Summary

* Insider threat activity (Amber Turing)
* Reconnaissance against competitor
* Data exfiltration via email
* TOR anonymization
* External scanning and exploitation
* SQL Injection & XSS
* Session hijacking
* Malware via USB
* Ransomware execution
* C2 via dynamic DNS
* Spear phishing campaign
* Persistence via tasks and fake users

---

## 🧠 Skills Demonstrated

* Splunk Threat Hunting
* Log Correlation
* Web Attack Detection
* Insider Threat Analysis
* Malware Investigation
* Network Analysis
* Endpoint Forensics
* C2 Detection

---

## 🏁 Conclusion

This investigation demonstrates a full attack lifecycle involving insider threats, web exploitation, malware delivery, and persistence techniques.

By correlating logs across multiple sources, the complete attack chain was reconstructed, revealing how attackers gained access, moved laterally, and maintained persistence.

This lab reflects real-world SOC operations and highlights the importance of visibility, detection, and threat hunting capabilities in modern security environments.
