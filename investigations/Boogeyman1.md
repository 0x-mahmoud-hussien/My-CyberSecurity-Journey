#### 43. Boogeyman 1 (Case Study)
<p align="center">
  <img src="../images/boogeyman1_badge.png" width="45%" />
  <img src="../images/boogeyman1_tasks.png" width="45%" />
</p>

---

# 🕵️‍♂️ Investigation Report: Case Boogeyman 1 (The Initial Threat)

## 📋 Scenario Overview
محاكاة لتحقيق جنائي رقمي يبدأ برسالة بريد إلكتروني احتيالية (**Phishing Email**) استهدفت الموظفة "Julianne" في قسم الحسابات. الهجمة اعتمدت على ملف مرفق مشفر يحتوي على **LNK Shortcut** لتنفيذ أوامر **PowerShell** خبيثة، وانتهت بسحب بيانات حساسة عبر بروتوكول الـ **DNS**.

---

## 🛠️ Technical Findings & Evidence (Artifacts)

### 1. Phishing & Attachment Analysis
* **Attacker Email:** تم إرسال البريد من العنوان: `agriffin@bpakcaging.xyz`.
* **Victim Email:** الموظفة المستهدفة هي `julianne.westcott@hotmail.com`.
* **Mail Relay Service:** استخدم المهاجم خدمة `elasticemail` لإرسال البريد.
* **Malicious Attachment:** المرفق كان ملف مضغوط بكلمة مرور `Invoice2023!` ويحتوي داخله على ملف `Invoice_20230103.lnk`.

### 2. Payload & Execution (LNK Analysis)
* **Encoded Payload:** باستخدام أداة `lnkparse` تم استخراج كود **Base64** مخفي داخل الـ Command Line Arguments الخاص بالملف.
* **Initial Execution:** فك تشفير الكود أظهر بداية تنفيذ سلسلة أوامر خبيثة على جهاز الضحية.

### 3. Endpoint Investigation (PowerShell Logs)
* **C2 Domains:** تم رصد نطاقات التواصل مع المهاجم وهي: `cdn.bpakcaging.xyz` و `files.bpakcaging.xyz`.
* **Enumeration Tool:** قام المهاجم بتحميل أداة `seatbelt` لجمع معلومات عن النظام.
* **Sensitive Data Discovery:** وصل المهاجم لملف قاعدة بيانات `protected_data.kdbx` الخاص ببرنامج `KeePass`.
* **Targeted Files:** تم رصد الوصول لملف `plum.sqlite` التابع لبرنامج **Microsoft Sticky Notes**.

### 4. Network Analysis & Exfiltration
* **Exfiltration Tool:** استخدم المهاجم أداة `nslookup` لتهريب البيانات عبر طلبات الـ **DNS**.
* **Protocol & Method:** تمت عملية الـ Exfiltration باستخدام بروتوكول `dns`، بينما استخدم المهاجم طريقة `POST` في بروتوكول الـ HTTP لإرسال نتائج الأوامر المنفذة.
* **Exfiltrated Content:** تم استخراج كلمة مرور الملف المسرب وهي `%p9^3!IL^Mz47E2GaT^y` ورقم بطاقة ائتمان مخزن داخله: `4024007128269551`.

---
💡 *تم تحليل هذه الهجمة من خلال دمج سجلات الـ PowerShell (JSON) مع تحليل حركة الشبكة (PCAP) باستخدام أدوات jq و Wireshark.*
