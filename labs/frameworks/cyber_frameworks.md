# 🛡️ Cybersecurity Frameworks & Methodologies

## 🛡️ Frameworks: MITRE ATT&CK Mastery
**Description:** Deep understanding of adversary tactics and techniques based on real-world observations.

<p align="center">
  <img src="../../images/mitre-badge.png" width="45%" />
  <img src="../../images/mitre-tasks.png" width="45%" />
</p>

### 🛠️ Key Learning Outcomes:
* **Tactics vs. Techniques:** فهم الفرق بين "ماذا" يحاول المهاجم تحقيقه و"كيف" يقوم بذلك فعلياً.
* **Matrix Navigation:** استخدام مصفوفة MITRE لتحليل الهجمات وتحديد الفجوات الدفاعية.
* **Detection & Mitigation:** تحسين قدرات الكشف والرد على التهديدات بناءً على الإطار.

---

## 🛠️ Practical Investigation: MITRE ATT&CK Navigator
**Scenario:** Adversary Mapping & Defensive Analysis (APT28 Case Study)

<p align="center">
  <img src="../../images/mitre-navigator-badge.png" width="45%" />
  <img src="../../images/apt28-scenario-task.png" width="45%" />
</p>

### 🛠️ Hands-on Skills Applied:
* **APT Profiling:** تحليل سلوك مجموعة **APT28** وتحديد الـ Techniques اللي بيستخدموها.
* **Navigator Mapping:** استخدام أداة **MITRE Navigator** لعمل Visualization للفجوات الدفاعية (Defensive Gaps).
* **Detection Engineering:** تحديد الـ TTPs اللي محتاجة مراقبة مكثفة بناءً على السيناريو العملي.

---

## 🔺 Threat Hunting: The Pyramid Of Pain
**Description:** Understanding the relationship between IOCs and the "pain" they cause an adversary.

<p align="center">
  <img src="../../images/pyramid-of-pain.png" width="45%" />
  <img src="../../images/pyramid-tasks.png" width="45%" />
</p>

### 🧠 Key Learning Outcomes:
* **Detection Strategy:** بناء استراتيجيات كشف تركز على سلوك المهاجم (TTPs) وليس فقط الأدوات.
* **Raising Attack Cost:** تعلم كيفية رفع تكلفة الهجوم على المخترق من خلال استهداف المستويات العليا للهرم.

---

## ⛓️ Strategic Defense: Unified Kill Chain
**Description:** Mastering the end-to-end framework that describes the phases of a cyberattack.

<p align="center">
  <img src="../../images/unified-kill-chain.png" width="45%" />
  <img src="../../images/ukc-tasks.png" width="45%" />
</p>

### 🛠️ Key Learning Outcomes:
* **Framework Integration:** دمج الـ Kill Chain التقليدي مع مصفوفة الـ MITRE ATT&CK.
* **Attack Phases:** دراسة الـ 18 مرحلة للهجوم من الـ Reconnaissance وحتى الـ Objectives.


# 🛡️ Cyber Frameworks & Threat Intelligence

---

#### 25. Intro to Cyber Threat Intel
<p align="center">
  <img src="../../images/cti_intro_badge.png" width="45%" />
  <img src="../../images/cti_intro_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم ماهية الاستخبارات المتعلقة بالتهديدات السيبرانية (CTI) وأهميتها القصوى لمحللي الـ SOC.
    * دراسة دورة حياة استخبارات التهديدات (**Threat Intelligence Lifecycle**) والمؤشرات التي يجب البحث عنها.
    * التعرف على كيفية مشاركة المعلومات الاستخباراتية باستخدام الـ Feeds والمنصات المتخصصة (Platforms).

---

#### 26. File and Hash Threat Intel
<p align="center">
  <img src="../../images/file_hash_intel_badge.png" width="45%" />
  <img src="../../images/file_hash_intel_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * تفسير مسارات وأسماء الملفات المشبوهة باستخدام القواعد الاستدلالية (**Heuristics**).
    * إنشاء والتحقق من بصمات الملفات (**File Hashes**) لضمان سلامتها وتحديد هويتها.
    * الاستفادة من منصات **VirusTotal** و **MalwareBazaar** لإثراء المعلومات حول الملفات المكتشفة حديثاً.
    * استخراج وتحليل سلوك الملفات من تقارير الـ **Sandbox** وربطها بإطار عمل **MITRE ATT&CK**.

---

#### 27. IP and Domain Threat Intel
<p align="center">
  <img src="../../images/ip_domain_intel_badge.png" width="45%" />
  <img src="../../images/ip_domain_intel_tasks.png" width="45%" />
</p>

* **ما تم تعلمه (Learning Objectives):**
    * فهم أهمية استخبارات التهديدات المتعلقة بالعناوين (IPs) والنطاقات (Domains) لعمل الـ SOC.
    * تحديد الموقع الجغرافي للـ IPs وتفسير أرقام الأنظمة المستقلة (**ASNs**) التابعة لها.
    * اكتشاف البنية التحتية المشبوهة باستخدام محركات **Shodan** و **Censys** وتحليل الـ Service Banners.
    * تقييم سمعة العناوين والنطاقات (Reputation Assessment) باستخدام أدوات متنوعة.
    * إثراء بيانات النطاقات (Domain Enrichment) عبر فحص عمر الـ WHOIS، سجلات الـ DNS، وشفافية الشهادات الرقمية (Certificates).

---

#### 28. Invite Only (Challenge Room)
<p align="center">
  <img src="../../images/invite_only_badge.png" width="45%" />
  <img src="../../images/invite_only_tasks.png" width="45%" />
</p>

* **ما تم إنجازه (Accomplishments):**
    * حل تحدي عملي يحاكي سيناريوهات اختراق واقعية تتطلب مهارات تحليلية متقدمة.
    * استخدام تقنيات البحث والتقصي الرقمي للوصول إلى المعلومات المطلوبة (Flags).
    * تطبيق أدوات الـ OSINT والتحليل الفني لفك شفرة التحدي والوصول للحل النهائي.
    * تعزيز مهارات حل المشكلات (Problem Solving) تحت ظروف تحاكي بيئة عمل الـ SOC.

---

### 🏆 Special Achievement: Threat Intel Defender
<p align="center">
  <img src="../../images/threat_intel_defender_path_badge.png" width="30%" />
</p>

> **تم الحصول على هذه البادج بعد إتمام مسار Cyber Threat Intelligence، وإتقان مهارات تتبع التهديدات عبر الـ IPs والـ Domains، وتحليل الـ Malware Bazaar، وربط الأنشطة المشبوهة بإطار عمل MITRE ATT&CK لتوقع ومنع الهجمات قبل حدوثها.**