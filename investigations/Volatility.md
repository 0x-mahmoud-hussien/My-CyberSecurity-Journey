# 🕵️‍♂️ Memory Forensics Report: Volatility Investigations

## 📋 Overview
تقرير فني يغطي تحليل ملفات الذاكرة (**Memory Dumps**) لسيناريوهين مختلفين: الأول يتعلق بـ **Banking Trojan** متنكر في هيئة ملف Adobe، والثاني يتعلق بهجمة **Ransomware** دولية. تم استخدام أداة **Volatility** لاستخراج الأدلة الرقمية.

---

## 🛠️ Case 001: BOB! THIS ISN'T A HORSE! (Banking Trojan)

### 1. System & Process Identification
* **Suggested Profile:** تم تحديد البروفايل المناسب للتحليل وهو `Win7SP1x64`.
* **Malicious Process:** تم رصد بروسيس مشبوهة باسم `reader_sl.exe` بـ **PID:** `1640`.
* **Parent Process:** البروسيس الأب (Parent) لها كانت `explorer.exe` بـ **PID:** `1484`.

### 2. Network & Persistence
* **C2 Connection:** البروسيس المشبوهة حاولت الاتصال بالعنوان `41.168.5.140` عبر بورت `8080`.
* **Memory Offset:** تم تحديد مكان وجود البروسيس في الذاكرة عند الـ Offset: `0x000000003fa39ca0`.

---

## 🛠️ Case 002: That Kind of Hurt my Feelings (Ransomware Analysis)

### 1. Process & Memory Analysis
* **Suggested Profile:** البروفايل المستخدم هو `Win7SP1x64`.
* **Suspicious Process:** تم تحديد بروسيس مشبوهة باسم `@WanaDecryptor@` بـ **PID:** `2732`.
* **VAD Analysis:** تم فحص الـ **VAD Tag** المرتبط بالبروسيس ووجد أنه `VadS`.
* **DLL Analysis:** تم العثور على ملف **DLL** مشبوه محمل في الذاكرة باسم `mmsystem.dll` عند الـ Offset: `0xfffff8a0011501f0`.

### 2. File & Command Forensics
* **Injected Process:** تم رصد عملية حقن كود (Code Injection) في بروسيس `lsass.exe`.
* **Referenced File:** تم العثور على مسار ملف مشبوه داخل الذاكرة: `C:\Users\John\Downloads\thisistotallynotatrap.exe`.
* **Command Line:** المهاجم حاول تنفيذ أوامر عبر الـ CMD لإيقاف خدمات الحماية أو تشفير البيانات.

---
💡 *تم إعداد هذا التحقيق باستخدام تقنيات تحليل الـ VAD والـ DLL Modules وربط الاتصالات الشبكية بالبروسيس المصابة.*
