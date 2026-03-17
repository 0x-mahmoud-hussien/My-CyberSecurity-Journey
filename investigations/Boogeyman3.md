#### 45. Boogeyman 3 (The Final Chapter - ELK Stack Investigation)
<p align="center">
  <img src="../images/boogeyman3_badge.png" width="45%" />
  <img src="../images/boogeyman3_chart.png" width="45%" />
</p>

---

# 🕵️‍♂️ Technical Investigation Report: Case Boogeyman 3 (Lurking in the Dark)

## 📋 Scenario Overview
في هذا الجزء، استهدف المهاجم المدير التنفيذي للشركة "Evan Hutchinson" مستخدماً وصوله السابق لبريد أحد الموظفين. الهجمة كانت تعتمد على خداع المستخدم لفتح ملف **ISO** يحتوي على ملفات مخفية لبدء عملية الاختراق. تم التحقيق في هذه الحادثة باستخدام سجلات نظام **Sysmon** المركزية داخل منصة **Kibana (ELK Stack)** للوقوف على كامل تفاصيل الهجمة وتوسيع نطاق المهاجم داخل الشبكة.

---

## 🛠️ Toolset & Platform
* **ELK Stack (Elasticsearch, Logstash, Kibana):** المنصة الرئيسية لتحليل ملايين السجلات والبحث عن الأنماط المشبوهة.
* **Sysmon Logs:** المصدر الأساسي للبيانات لرصد إنشاء العمليات (Event ID 1) والاتصالات الشبكية (Event ID 3).
* **Kibana Discovery:** لعمل Filtering وتحديد النطاق الزمني للهجمة (29-30 أغسطس 2023).

---

## 🔍 Investigation Steps & Findings

### 1. Initial Access (Phishing ISO)
* **Email Source:** تم إرسال البريد من `p.mclane@quicklogisticsorg.onmicrosoft.com` (حساب مخترق سابقاً).
* **The Payload:** ملف ISO باسم `Meeting_Notes.iso` تم تحميله في مجلد الـ Downloads الخاص بالضحية.
* **The Bait:** داخل الـ ISO، وجد الضحية ملف اختصار (LNK) باسم `Meeting_Notes.lnk` يقوم بتشغيل ملف مخفي.

### 2. Execution & Persistence (DLL Sideloading)
من خلال تحليل سجلات **Sysmon**، تم اكتشاف تقنية التخفي المستخدمة:
* **The Trick:** ملف الـ LNK يقوم بتشغيل عملية `cmd.exe` التي بدورها تُشغل `calc.exe`.
* **Malicious DLL:** المهاجم استخدم تقنية **DLL Sideloading** حيث قام بوضع ملف `WinUpdate.dll` خبيث في نفس مسار البرنامج، مما أدى لتحميل الكود الخبيث بمجرد تشغيل الآلة الحاسبة.
* **Persistence:** تم إنشاء مفتاح في الـ Registry تحت مسار `Run` لضمان تشغيل البرنامج الخبيث مع كل بداية تشغيل للنظام.

### 3. Lateral Movement & C2 Activity
* **C2 Communication:** تم رصد اتصال خارجي من عملية `calc.exe` إلى IP المهاجم `167.71.199.191` عبر المنفذ `8080`.
* **Internal Recon:** المهاجم قام بتحميل أداة `mimikatz.exe` بـ Hash محدد لاستخراج بيانات الاعتماد من الذاكرة.
* **Targeting Servers:** تم رصد محاولة الوصول لخادم ملفات داخلي (`Fileserver.quicklogistics.local`) باستخدام بروتوكول **SMB**.

---

## 📊 Attack Timeline
1. **Aug 29, 09:20:** وصول بريد الـ Phishing للمدير التنفيذي.
2. **Aug 29, 10:05:** فتح ملف الـ ISO وتشغيل ملف الـ LNK الخبيث.
3. **Aug 29, 10:10:** تشغيل `calc.exe` وتحميل الـ DLL الخبيث (`WinUpdate.dll`).
4. **Aug 29, 11:30:** بدء عمليات الاستطلاع الداخلي وتحميل أدوات استخراج الهويات (Mimikatz).
5. **Aug 30, 08:45:** محاولة التحرك العرضي (Lateral Movement) تجاه الخوادم الحساسة.

---

## 🛡️ Indicators of Compromise (IOCs)
* **IP Address:** `167.71.199.191`.
* **Filenames:** `Meeting_Notes.iso`, `WinUpdate.dll`, `mimikatz.exe`.
* **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`.
* **Hashes:** * ISO Hash: `CB3A1E6ACFB246F256FBEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6`.
    * Mimikatz Hash: `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`.
