#### 44. Boogeyman 2 (Memory Forensics Challenge)
<p align="center">
  <img src="../images/boogeyman2_badge.png" width="45%" />
  <img src="../images/boogeyman2_tasks.png" width="45%" />
</p>

---

# 🕵️‍♂️ Technical Investigation Report: Case Boogeyman 2 (The Return)

## 📋 Scenario Overview
رغم تحسين الدفاعات الأمنية في شركة "Quick Logistics LLC"، عاد تهديد الـ **Boogeyman** بأساليب (TTPs) أكثر تطوراً. استهدف المهاجم موظفة الموارد البشرية "Maxine" عبر بريد إلكتروني ينتحل صفة متقدم لوظيفة "Junior IT Analyst". بمجرد فتح السيرة الذاتية المرفقة، تم اختراق محطة العمل وبدأ المهاجم في تنفيذ عمليات خفية داخل الذاكرة (**RAM**).

---

## 🛠️ Toolset
تم استخدام أدوات تحليل متقدمة للتعامل مع الأدلة الرقمية والذاكرة:
* **Volatility 3:** الأداة الرئيسية لتحليل الـ Memory Dump واستخراج العمليات والاتصالات.
* **Olevba (Oletools):** لتحليل الـ Macros الخبيثة داخل ملفات الـ Microsoft Office.
* **Thunderbird:** لتحليل ترويسات البريد الإلكتروني (Phishing Header).

---

## 🔍 Deep Dive Investigation

### 1. Phishing & Macro Analysis
* **The Bait:** رسالة من `westaylor23@outlook.com` موجهة إلى `maxine.beck@quicklogisticsorg.onmicrosoft.com`.
* **The Document:** ملف باسم `Resume_WesleyTaylor.doc` بـ Hash: `52c4384a0b9e248b95804352ebec6c5b`.
* **The Trigger:** باستخدام **Olevba**، تم اكتشاف Macro خبيث يقوم بتحميل المرحلة الثانية من الرابط: 
  `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`

### 2. Memory Forensics (Volatility Analysis)
من خلال تحليل ملف الذاكرة، تم اكتشاف سلسلة التنفيذ التالية:
* **Execution Chain:** الـ Word Macro قام بتشغيل أداة `wscript.exe` (PID: 4260) لتنفيذ ملف JavaScript خبيث تم تخزينه في: `C:\ProgramData\update.js`.
* **Stage 2 Loader:** ملف `update.js` قام بتحميل ملف تنفيذي خبيث `updater.exe` وتخزينه في مسار المهام: `C:\Windows\Tasks\updater.exe`.
* **C2 Establishment:** عملية `updater.exe` (PID: 6216) أنشأت اتصالاً بخادم المهاجم عبر: `128.199.95.189:8080`.

### 3. Persistence Mechanism
لضمان البقاء داخل النظام حتى بعد إعادة التشغيل، قام المهاجم بإنشاء **Scheduled Task** يومية:
* **Command:** استخدام `schtasks` لإنشاء مهمة باسم `Updater` تقوم بتشغيل كود PowerShell مخفي كل يوم في تمام الساعة 09:00 صباحاً.
* **Hidden Trace:** تم العثور على أثر الملف الأصلي في مسار الـ Outlook Cache داخل الذاكرة: 
  `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\...`

---

## 📊 Attack Timeline
1. **Initial Access:** استقبال وفتح ملف `Resume_WesleyTaylor.doc`.
2. **Dropper Stage:** تفعيل الماكرو وتحميل `update.js` عبر `wscript.exe`.
3. **Payload Delivery:** تحميل وتشغيل `updater.exe` من نطاق `boogeymanisback.lol`.
4. **C2 Callback:** إنشاء اتصال عكسي (Reverse Shell) مع IP المهاجم.
5. **Persistence:** جدولة مهمة (Scheduled Task) لتنفيذ PowerShell Payload يومياً.

---

## 🛡️ Indicators of Compromise (IOCs)
| Type | Value |
| :--- | :--- |
| **Domain** | `files.boogeymanisback.lol` |
| **IP Address** | `128.199.95.189` |
| **File Paths** | `C:\ProgramData\update.js`, `C:\Windows\Tasks\updater.exe` |
| **Processes** | `wscript.exe` (4260), `updater.exe` (6216) |
| **Malicious Hash** | `52c4384a0b9e248b95804352ebec6c5b` (MD5) |
