#### 31. Alert Triage With Splunk
<p align="center">
  <img src="../../images/splunk_triage_badge.png" width="45%" />
  <img src="../../images/splunk_triage_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * تعلم الكيفية الصحيحة للتحقيق في التنبيهات (Alerts) داخل بيئة عمل الـ SOC.
    * فهم كيفية تتبع وتحليل هجمات التخمين (**Brute-force Attacks**) على أنظمة لينكس عبر Splunk.
    * اكتشاف آليات البقاء (**Persistence Mechanisms**) التي يزرعها المهاجمون داخل أنظمة ويندوز.
    * تحليل الـ **Web Shells** وكشف الثغرات في خوادم الويب المصابة.
    * الممارسة العملية على التحقيق في 3 سيناريوهات واقعية لمواجهة التهديدات باستخدام منصة **Splunk**.

---

#### 32. Alert Triage With Elastic
<p align="center">
  <img src="../../images/elastic_triage_badge.png" width="45%" />
  <img src="../../images/elastic_triage_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * استخدام منصة **Kibana** لتحليل سجلات الأمان الشائعة بكفاءة عالية.
    * تعلم كيفية تحديد مؤشرات الاختراق الرئيسية (**Key IOCs**) من خلال البيانات الضخمة.
    * ربط الأحداث (**Event Correlation**) عبر مصادر سجلات متعددة لرسم صورة كاملة للهجوم.
    * كشف تفاصيل الاختراقات الأمنية من خلال تتبع وتحليل سلسلة من تنبيهات الـ SOC.

---

#### 33. ItsyBitsy (Investigation Case Study)
<p align="center">
  <img src="../../images/itsybitsy_badge.png" width="45%" />
  <img src="../../images/itsybitsy_tasks.png" width="45%" />
</p>

> **السيناريو والتحقيق (Scenario & Investigation):**
> محاكاة دور محلل SOC (Analyst John) للتحقيق في تنبيه IDS يشير لاتصال **C2** مشبوه من قسم الـ HR. تم تحليل سجلات **HTTP** لمدة أسبوع كامل داخل **Kibana** (index: connection_logs).

* **المهارات المكتسبة (Skills Applied):**
    * استخدام **KQL** لتحليل آلاف الأحداث وتحديد الـ IP الخاص بالمستخدم المصاب.
    * كشف استخدام أدوات ويندوز الشرعية (**Legit Windows Binaries**) في عمليات تحميل ملفات خبيثة.
    * التعرف على تقنيات المهاجمين في استغلال مواقع مشاركة الملفات المشهورة كمنصات **C2 Server**.
    * تتبع الـ **Full URL** للوصول للملف المشبوه واستخراج الـ Secret Code (Flag) من داخل محتواه.

---

#### 34. Incident Handling With Splunk
<p align="center">
  <img src="../../images/incident_handling_splunk_badge.png" width="45%" />
  <img src="../../images/incident_handling_splunk_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * تعلم كيفية الاستفادة من مواقع الاستخبارات المفتوحة المصدر (**OSINT**) لتعزيز عملية التحقيق.
    * ربط ورسم خريطة لأنشطة المهاجم بمراحل سلسلة القتل السيبراني (**Cyber Kill Chain Phases**).
    * إتقان استخدام استعلامات **Splunk** الفعالة للبحث في السجلات (Logs) وتتبع التهديدات.
    * فهم الأهمية التكاملية لمصادر السجلات المرتكزة على المضيف (**Host-centric**) والمرتكزة على الشبكة (**Network-centric**).

---

#### 35. Benign (SOC Investigation – Splunk & LOLBins)

---

### 📌 Scenario

An IDS alert indicated suspicious process execution on a host within the HR department. Due to limited resources, only **Windows process creation logs (Event ID 4688)** were collected and ingested into Splunk (`index=win_eventlogs`) for investigation.

---

### 🎯 Investigation Focus

* Identify compromised host
* Detect misuse of legitimate system tools (LOLBins)
* Trace attacker activity and payload delivery

---

### 🔍 Key Findings

* 📊 Total logs analyzed (March 2022):

  ```
  13959
  ```

* 🕵️ Imposter account detected:

  ```
  Amel1a
  ```

* 👤 Suspicious HR user activity:

  ```
  Chris.fort (Scheduled Tasks Execution)
  ```
![schtasks](../../images/schtasks.png)

* ⚠️ Confirmed compromised user:

  ```
  haroon
  ```

---

### 🚨 Attack Details

* 🛠️ LOLBin used:

  ```
  certutil.exe
  ```

* 📅 Execution date:

  ```
  2022-03-04
  ```

* 🌐 Payload source:

  ```
  controlc.com
  ```

* 🔗 Full URL:

  ```
  https://controlc.com/e4d11035
  ```
  ![lolbin](../../images/lolbin.png)

---

### 📦 Post-Exploitation

* 📁 File dropped on host:

  ```
  benign.exe
  ```

* 🧬 Malicious pattern identified:

  ```
  THM{KJ&*H^B0}
  ```

---

### 🧠 Skills Demonstrated

* Splunk log analysis (Event ID 4688)
* Detection of LOLBins abuse
* Threat hunting & anomaly detection
* Identifying compromised accounts
* Tracing attacker activity & payload delivery

---

### 🏁 Conclusion

The investigation revealed a compromised HR host where the attacker leveraged **certutil.exe** (a legitimate Windows binary) to download a malicious payload from an external file-sharing service. The activity highlights common attacker techniques to bypass security controls using trusted system tools.

This scenario reflects real-world SOC investigations involving limited visibility and emphasizes the importance of process-level monitoring and behavioral analysis.
