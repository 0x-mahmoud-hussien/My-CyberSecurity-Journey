#### 44. Core Windows Processes
<p align="center">
  <img src="../../images/core_windows_processes_badge.png" width="45%" />
  <img src="../../images/core_windows_processes_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم العمليات الأساسية لنظام التشغيل ويندوز (مثل System, Smss.exe, Csrss.exe, Wininit.exe, Services.exe).
    * التعرف على الـ **Parent Process** والمسار الصحيح (Path) لكل عملية أساسية لتمييز أي تلاعب.
    * فهم كيفية عمل الـ **Session 0** والـ **Session 1** وكيفية توزيع العمليات عليهما.
    * تعلم كيفية استخدام أدوات مثل **Process Explorer** و **Task Manager** لتحليل سلوك العمليات بشكل معمق.
    * اكتشاف تقنيات التمويه التي يستخدمها المهاجمون من خلال انتحال أسماء العمليات الأساسية (Process Mimicking).

---

#### 29. Sysmon
<p align="center">
  <img src="../../images/sysmon_badge.png" width="45%" />
  <img src="../../images/sysmon_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم دور أداة **Sysmon** كجزء من مجموعة أدوات **Sysinternals** في مراقبة الأنظمة.
    * تعلم كيفية تثبيت وإعداد الـ **Configuration Files** لتصفية الأحداث الهامة وتقليل الضجيج (Noise).
    * تحليل أحداث النظام الهامة مثل إنشاء العمليات (**Process Creation**)، اتصالات الشبكة، وتعديل الـ Registry.
    * اكتشاف الهجمات المتقدمة (مثل الـ الـ Process Injection) التي لا تستطيع سجلات ويندوز العادية كشفها.
    * كتابة واستخدام الـ **Rules** (باستخدام لغة XML) لتخصيص عملية الرصد بناءً على احتياجات المؤسسة.


    ---

#### 42. Windows Event Logs
<p align="center">
  <img src="../../images/windows_event_logs_badge.png" width="45%" />
  <img src="../../images/windows_event_logs_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم بنية سجلات أحداث ويندوز (System, Security, Application) وكيفية التعامل معها.
    * استخدام أداة **Event Viewer** و **Get-WinEvent** عبر PowerShell للبحث عن الأحداث وتصفيتها.
    * التعرف على الـ **Event IDs** الهامة للتحقيق الأمني (مثل 4624 للـ Logon و 4688 لإنشاء العمليات).
    * تحليل سجلات الـ **XPath Queries** لكتابة فلاتر مخصصة ودقيقة لاستخراج الأدلة الرقمية.
    * مراقبة سلوك المستخدمين وكشف محاولات الدخول غير المصرح بها أو التلاعب بالنظام.

    ---


#### 48. Hacking with PowerShell
<p align="center">
  <img src="../../images/powershell_hacking_badge.png" width="45%" />
  <img src="../../images/powershell_hacking_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم أساسيات الـ **PowerShell Scripting** وكيفية أتمتة مهام الفحص.
    * ممارسة تقنيات الـ **Enumeration** لجمع معلومات النظام والشبكة.

  ---
  
#### 15. Windows Threat Detection 2
<p align="center">
  <img src="../../images/win_threat_detection_2_badge.png" width="45%" />
  <img src="../../images/win_threat_detection_2_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * اكتشاف تقنيات الاستكشاف (Discovery) الشائعة باستخدام سجلات أحداث ويندوز.
    * تعلم كيفية تتبع أصل الهجوم من خلال إعادة بناء شجرة العمليات (**Process Tree Reconstruction**).
    * التعرف على البيانات التي يبحث عنها المهاجمون وكيفية تنفيذ عمليات تسريبها (Exfiltration).
    * فهم كيفية تسجيل الأوامر الخبيثة في السجلات من خلال تنفيذها عملياً ومراقبة النتائج.

---