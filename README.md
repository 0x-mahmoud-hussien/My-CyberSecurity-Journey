# 🛡️ Mahmoud Hussein | SOC Analyst Portfolio
### My Cyber Security Journey 🚀

Welcome to my cybersecurity repository. This project documents my technical progress, hands-on labs, and real-world investigations in the field of Security Operations and Threat Hunting.

---

## 🔧 Tools & Technologies

* **SIEM/SOAR:** Splunk, ELK Stack (Kibana), Tines.
* **Network Analysis:** Wireshark, TShark, Zeek (Bro), Snort, NetworkMiner.
* **Endpoint & Forensics:** FlareVM, EDR Solutions, Volatility 3, Autopsy, Sysmon.
* **Frameworks:** MITRE ATT&CK, Unified Kill Chain, Pyramid of Pain.
* **OS:** Ubuntu Linux (Primary), Windows.

---

## 🏆 Certifications & Professional Path
* [🎓 **Professional Certifications** (SOC Level 1, CS 101, Pre-Security)](./certifications/completed_paths.md)

---

## 🧪 Hands-on Labs & Technical Writeups
Click on any of the sections below to view detailed writeups:

* [🌐 **Network Analysis & IDS** (Wireshark, Snort, Zeek, NetworkMiner, TShark, Brim)](./labs/network/network_security.md)
* [🛡️ **Cyber Frameworks & Threat Intel** (MITRE, CTI, Threat Hunting)](./labs/frameworks/cyber_frameworks.md)
* [📊 **SIEM & SOAR Operations** (Splunk, ELK, Alert Triage)](./labs/siem-soar/siem_mastery.md)
* [🖥️ **Windows Endpoint Security** (Logging, Sysmon, Threat Detection, Defender)](./labs/endpoint-security/windows_security.md)
* [🐧 **Linux Endpoint Security** (Auditd, Threat Detection, Defender)](./labs/os-security/linux_security.md)
* [🦠 **Malware Analysis & Concepts** (Static/Dynamic, LotL, Defender)](./labs/endpoint-security/malware_analysis.md)
* [📧 **Email Security & Phishing Analysis** (PhishTool, SPF/DKIM/DMARC)](./labs/email-security/phishing_analysis.md)
* [🐝 **Web Application Security** (OWASP Top 10, Web Defender)](./labs/web-security/web_vulnerabilities.md)
* [🐧 **Linux Fundamentals Walkthrough**](./labs/os-security/linux_fundamentals.md)


---

#### 42. Windows Event Logs
<p align="center">
  <img src="./images/windows_event_logs_badge.png" width="45%" />
  <img src="./images/windows_event_logs_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم بنية سجلات أحداث ويندوز (System, Security, Application) وكيفية التعامل معها.
    * استخدام أداة **Event Viewer** و **Get-WinEvent** عبر PowerShell للبحث عن الأحداث وتصفيتها.
    * التعرف على الـ **Event IDs** الهامة للتحقيق الأمني (مثل 4624 للـ Logon و 4688 لإنشاء العمليات).
    * تحليل سجلات الـ **XPath Queries** لكتابة فلاتر مخصصة ودقيقة لاستخراج الأدلة الرقمية.
    * مراقبة سلوك المستخدمين وكشف محاولات الدخول غير المصرح بها أو التلاعب بالنظام.



---

#### 37. Tempest (Investigation Challenge)
<p align="center">
  <img src="./images/tempest_badge.png" width="45%" />
  <img src="./images/tempest_tasks.png" width="45%" />
</p>

* **ما تم إنجازه (Accomplishments):**
    * حل تحدي عملي متكامل يتطلب مهارات التحقيق الرقمي والاستجابة للحوادث (**DFIR**).
    * تحليل الأدلة الرقمية ومطاردة التهديدات داخل بيئة مصابة لكشف جدول المهاجم الزمني.
    * استخدام أدوات التحليل المتنوعة لفك شفرة الهجوم واستخراج الـ Flags المطلوبة.
    * تعزيز القدرة على ربط الأحداث ببعضها للوصول إلى كيفية حدوث الاختراق (Root Cause Analysis).


---


#### 43. Boogeyman 1 (Case Study)
<p align="center">
  <img src="./images/boogeyman1_badge.png" width="45%" />
  <img src="./images/boogeyman1_tasks.png" width="45%" />
</p>

*#### 43. Boogeyman 1 (Case Study) - [📖 View Detailed Technical Investigation Report](./investigations/Boogeyman1.md).


---

#### 44. Core Windows Processes
<p align="center">
  <img src="./images/core_windows_processes_badge.png" width="45%" />
  <img src="./images/core_windows_processes_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم العمليات الأساسية لنظام التشغيل ويندوز (مثل System, Smss.exe, Csrss.exe, Wininit.exe, Services.exe).
    * التعرف على الـ **Parent Process** والمسار الصحيح (Path) لكل عملية أساسية لتمييز أي تلاعب.
    * فهم كيفية عمل الـ **Session 0** والـ **Session 1** وكيفية توزيع العمليات عليهما.
    * تعلم كيفية استخدام أدوات مثل **Process Explorer** و **Task Manager** لتحليل سلوك العمليات بشكل معمق.
    * اكتشاف تقنيات التمويه التي يستخدمها المهاجمون من خلال انتحال أسماء العمليات الأساسية (Process Mimicking).



---

#### 45. Volatility (Memory Forensics - Volatility 3)
<p align="center">
  <img src="./images/volatility_badge.png" width="30%" />
  <img src="./images/volatility_tasks.png" width="32%" />
  <img src="./images/volatility_scenarios.png" width="32%" />
</p>

*#### 39. Volatility - [📖 View Detailed Memory Forensics Report](./investigations/Volatility.md)


---

#### 46. Boogeyman 2 (Phishing & Memory Analysis)
<p align="center">
  <img src="./images/boogeyman2_badge.png" width="45%" />
  <img src="./images/boogeyman2_tasks.png" width="45%" />
</p>

*#### 46. Boogeyman 2 (Phishing & Memory Analysis) - [📖 View Detailed Investigation Report](./investigations/Boogeyman2.md)



#### 47. Boogeyman 3 (Full Attack Chain Analysis)
<p align="center">
  <img src="./images/boogeyman3_badge.png" width="45%" />
  <img src="./images/boogeyman3_chart.png" width="45%" />
</p>

*> 📝 **[Technical Investigation Report (Detailed Write-up)](./investigations/Boogeyman3.md)**


 ---

### 🏆 Special Achievement: Boogeyman Slayer
<p align="center">
  <img src="./images/boogeyman_slayer_badge.png" width="30%" />
</p>

> **تم الحصول على هذه البادج بعد إتمام سلسلة تحديات Boogeyman الثلاثة (Capstone Challenges).

 ---

#### 48. Hacking with PowerShell
<p align="center">
  <img src="./images/powershell_hacking_badge.png" width="45%" />
  <img src="./images/powershell_hacking_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم أساسيات الـ **PowerShell Scripting** وكيفية أتمتة مهام الفحص.
    * ممارسة تقنيات الـ **Enumeration** لجمع معلومات النظام والشبكة.
