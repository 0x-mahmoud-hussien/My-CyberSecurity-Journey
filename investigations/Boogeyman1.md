#### 43. Boogeyman 1 (Case Study)
<p align="center">
  <img src="../images/boogeyman1_badge.png" width="45%" />
  <img src="../images/boogeyman1_tasks.png" width="45%" />
</p>

---

# 🕵️‍♂️ Technical Investigation Report: Case Boogeyman 1 (The Initial Threat)

## 📋 Scenario Overview
بدأت الحادثة برسالة بريد إلكتروني احتيالية (**Phishing**) استهدفت قسم الحسابات في شركة "Quick Logistics LLC". الهجمة انتحلت صفة شريك تجاري باسم "B Packaging Inc" بخصوص فاتورة غير مدفوعة. الموظفة "Julianne" قامت بفتح المرفق الخبيث، مما أدى إلى اختراق كامل لمحطة العمل الخاصة بها من قبل مجموعة تهديد ناشئة تُعرف باسم **Boogeyman**.

---

## 🛠️ Tools Used
خلال عملية التحقيق، تم استخدام مجموعة من الأدوات المتقدمة لتحليل الأدلة الرقمية:
* **Thunderbird:** لتحليل ترويسات البريد الإلكتروني استخراج المرفقات.
* **LNKParse3:** لتحليل ملفات الـ Shortcut (LNK) واستخراج الأوامر المخفية.
* **jq:** لمعالجة وتحليل سجلات PowerShell بصيغة JSON.
* **Wireshark & Tshark:** لتحليل حركة الشبكة واستعادة الملفات المسربة.

---

## 🔍 Investigation Steps & Findings

### 1. Phishing & Attachment Analysis
* **Email Source:** تم إرسال البريد من العنوان `agriffin@bpakcaging.xyz` مستخدماً خدمة `elasticemail` للتخفي.
* **Malicious Payload:** المرفق كان ملف ZIP محمي بكلمة مرور `Invoice2023!` ويحتوي على ملف `Invoice_20230103.lnk`.
* **LNK Analysis:** باستخدام `lnkparse`، تم اكتشاف كود **Base64** طويل مخفي داخل حقل الـ Arguments لبدء تنفيذ أوامر PowerShell.

### 2. Endpoint Investigation (PowerShell Analysis)
باستخدام أداة `jq` لتحليل `powershell.json`، تم رصد الأنشطة التالية:
* **C2 Channels:** تواصل المهاجم مع نطاقات خبيثة وهي `cdn.bpakcaging.xyz` و `files.bpakcaging.xyz`.
* **Reconnaissance:** تحميل أداة `seatbelt` لجمع معلومات حساسة عن النظام.
* **Data Discovery:** تم الوصول لملف قاعدة بيانات KeePass باسم `protected_data.kdbx` وملف ملاحظات ملصقة `plum.sqlite`.

### 3. Network Exfiltration Analysis
* **The Method:** استخدم المهاجم أداة `nslookup` لتهريب البيانات عبر بروتوكول **DNS** لضمان عدم اكتشافه من قبل أنظمة الحماية التقليدية.
* **Staging Server:** استضافة الملفات المسربة تمت باستخدام خادم محلي يعتمد على **Python**.
* **Recovered Content:** تم استعادة كلمة مرور الملف المسرب وهي `%p9^3!IL^Mz47E2GaT^y` ورقم بطاقة ائتمان كان مخزناً بالداخل: `4024007128269551`.

---

## 📊 Attack Timeline
1. **00:00:** وصول بريد Phishing من نطاق منتحل `bpakcaging.xyz`.
2. **+5m:** فتح ملف الـ LNK وبدء تنفيذ PowerShell Payload.
3. **+15m:** تحميل أدوات الاستطلاع (`seatbelt`) وتحديد الملفات الحساسة.
4. **+30m:** تهريب (Exfiltration) ملفات KeePass و Sticky Notes عبر نفق DNS.
5. **+45m:** نجاح المهاجم في فك تشفير البيانات واستخراج أرقام بطاقات الائتمان.

---

## 🛡️ Indicators of Compromise (IOCs)
* **Domains:** `cdn.bpakcaging.xyz`, `files.bpakcaging.xyz`.
* **Sender:** `agriffin@bpakcaging.xyz`.
* **Files:** `Invoice_20230103.lnk`, `protected_data.kdbx`, `seatbelt.exe`.
* **Technique:** DNS Exfiltration, LNK Base64 Obfuscation.
