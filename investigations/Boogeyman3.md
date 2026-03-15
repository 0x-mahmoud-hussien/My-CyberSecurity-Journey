# 🕵️‍♂️ Investigation Report: Case Boogeyman 3 (The Slayer)

## 📋 Scenario Overview
تحليل هجمة **APT Simulation** متكاملة استهدفت شركة Quick Logistics LLC. بدأت الهجمة بملف ISO ملغم وانتهت باختراق الـ **Domain Controller** وتشفير البيانات.

## 🛠️ Technical Findings & Evidence (IOCs)

### 1. Initial Access & Execution
* **Initial Payload PID:** تم تنفيذ الـ **Initial Payload** عبر الـ **PID**: `6392`.
* **Implantation Command:** قام المهاجم بزرع ملف `review.dat` باستخدام الأمر التالي:
  `"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat`
* **Execution of Implant:** تم تشغيل الـ **Implanted File** عبر:
  `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer`
* **Persistence:** المهاجم ثبت نفسه في النظام عبر **Scheduled Task** باسم: `Review`.

### 2. Command & Control (C2)
* **C2 Infrastructure:** تم رصد اتصال مع الـ **C2 Server** على العنوان: `165.232.170.151:80`.

### 3. Privilege Escalation & Credential Dumping
* **UAC Bypass:** استخدم المهاجم الـ **Process** المدعو `fodhelper.exe` لتخطي الـ **UAC** ورفع الصلاحيات.
* **Credential Dumping Tool:** تم تحميل أداة **Mimikatz** من الرابط: 
  `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`
* **Exfiltrated Credentials:** تم استخراج حساب `itadmin` والـ **NTLM Hash** الخاص به: `itadmin:F84769D250EB95EB2D7D8B4A1C5613F2`.

### 4. Lateral Movement
* **Remote File Access:** المهاجم وصل لملف سكريبت حساس باسم `IT_Automation.ps1` عبر الـ **Remote Share**.
* **Target Host:** الجهاز المستهدف للـ **Lateral Movement** كان `WKSTN-1327`.
* **New Credentials:** تم كشف حساب الموظف `allan.smith` بكلمة مرور: `Tr!ckyP@ssw0rd987`.

### 5. Domain Compromise & Ransomware
* **DCSync Attack:** المهاجم نفذ هجوم **DCSync** لسحب الـ **Hash** الخاص بحساب `backupda` من الـ **Domain Controller**.
* **Ransomware Execution:** المرحلة النهائية بدأت بتحميل الـ **Ransomware Binary** من الرابط:
  `http://ff.sillytechninja.io/ransomboogey.exe`

---
💡 *هذا التقرير يوثق تسلسل الهجمة (**Attack Chain**) بناءً على تحليل السجلات الرقمية داخل بيئة العمل.*
