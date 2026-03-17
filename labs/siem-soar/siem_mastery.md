# 📊 SIEM & SOAR Operations

## 🛠️ Security Information and Event Management (SIEM)
**Description:** Learning how to centralize, search, and analyze logs using industry-standard tools like Splunk and Elastic Stack.

<p align="center">
  <img src="../../images/splunk-badge.png" width="45%" />
  <img src="../../images/splunk-tasks.png" width="45%" />
</p>

### 🔍 Splunk Proficiency:
* **Architecture:** فهم الـ Indexer, Search Head, والـ Forwarder.
* **Data Ingestion:** تعلم كيفية إضافة البيانات والبحث فيها باستخدام الـ SPL.
* **Log Investigation:** ممارسة التحقيق في السجلات لاكتشاف النشاطات المشبوهة.

---

## 📊 Elastic Stack (ELK)
<p align="center">
  <img src="../../images/elk-badge.png" width="45%" />
  <img src="../../images/elk-tasks.png" width="45%" />
</p>

### 🛠️ Elastic Stack Key Learning Outcomes:
* **ELK Architecture:** فهم كيفية عمل Elasticsearch و Logstash و Kibana معاً.
* **KQL Proficiency:** كتابة استعلامات معقدة باستخدام Kibana Query Language.
* **Visualizing Data:** بناء Dashboards لمراقبة التهديدات الأمنية لحظياً.

---

## ⚙️ Security Orchestration, Automation, and Response (SOAR)
**Description:** Learning how to automate repetitive tasks and orchestrate incident response workflows.

<p align="center">
  <img src="../../images/soar-badge.png" width="45%" />
  <img src="../../images/soar-tasks.png" width="45%" />
</p>

### 🛠️ Key Learning Outcomes:
* **Automation Playbooks:** فهم كيفية بناء الـ Playbooks لأتمتة الرد على التنبيهات.
* **Efficiency Boost:** كيفية تقليل الـ Mean Time to Respond (MTTR).


---

#### 30. Log Analysis with SIEM
<p align="center">
  <img src="../../images/siem_analysis_badge.png" width="45%" />
  <img src="../../images/siem_analysis_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * استكشاف مصادر البيانات المتنوعة التي يتم سحبها (**Ingestion**) إلى أنظمة الـ SIEM.
    * فهم أهمية ربط البيانات (**Data Correlation**) لتحويل السجلات المنفصلة إلى قصة هجوم متكاملة.
    * تعلم القيمة التحليلية لسجلات الويندوز، لينكس، الويب، والشبكة أثناء التحقيقات.
    * الممارسة العملية على تحليل السلوكيات الخبيثة واكتشاف الأنماط المشبوهة داخل منصة الـ SIEM.

---

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

#### 35. Benign (Scenario-Based Investigation)
<p align="center">
  <img src="../../images/benign_badge.png" width="30%" />
  <img src="../../images/benign_tasks.png" width="32%" />
  <img src="../../images/benign_progress.png" width="32%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * تحليل سجلات الـ **Splunk** للتمييز بين العمليات النظامية والأنشطة المشبوهة.
    * التحقيق في سيناريوهات واقعية تتضمن استخدام أدوات ويندوز (LOLBins) في سياق سليم وخبيث.
    * إتقان مهارات البحث المتقدمة لتحديد الـ **Root Cause** لأي تنبيه أمني.
    * تقليل الـ False Positives عبر فهم السلوك الطبيعي للمستخدمين والأنظمة داخل الشبكة.