# 🕵️‍♂️ Technical Investigation Report: Case Boogeyman 3 (Lurking in the Dark)

## 1. Executive Summary
تم الكشف عن هجوم معقد استهدف شركة Quick Logistics LLC، وتحديداً الحساب الخاص بالمدير التنفيذي (CEO) Evan Hutchinson. بدأ الهجوم عبر رسالة بريد إلكتروني احتيالية (Phishing) تحتوي على ملف ISO ملغوم. نجح المهاجم في تجاوز الدفاعات الأولية، وقام بعمليات تحرك جانبي (Lateral Movement) وتصعيد صلاحيات (Privilege Escalation)، وصولاً إلى سحب بيانات الاعتماد ونشر برمجية فدية (Ransomware).

## 2. Scenario
بعد تعرض الشركة لهجمات سابقة، استمر المهاجم المعروف بـ Boogeyman في التخفي داخل الشبكة. استغل المهاجم وصوله المبدئي لبريد أحد الموظفين لإرسال رسالة "عاجلة" للمدير التنفيذي لإغرائه بفتح ملف مالي مفترض، مما أدى إلى سلسلة من العمليات التخريبية داخل بيئة العمل.

## 3. Investigation Steps
* تحليل البريد الإلكتروني: فحص الرسالة القادمة من allie.sierra[at]quicklogistics[.]org.
* تحليل المرفقات: فحص ملف ProjectFinancialSummary_Q3.pdf المكتشف في مجلد التحميلات.
* تتبع العمليات (Process Tracking): استخدام سجلات التحقيق لتحديد الـ PID الخاص بالملفات المنفذة وتتبع الأوامر.
* تحليل التحرك الجانبي: مراقبة استخدام بروتوكولات مثل WinRM (عبر wsmprovhost.exe) للانتقال بين الأجهزة.
* تحليل استخراج البيانات: رصد محاولات تحميل أدوات خارجية (مثل Mimikatz) وسحب الـ Hashes.

## 4. Tools Used
* ELK Stack (Kibana): للبحث في السجلات وتحليل الأحداث.
* Sysmon: لمراقبة سجلات النظام والعمليات بدقة.

## 5. Findings (النتائج)
* خداع الامتداد: الملف المرفق يظهر كـ PDF ولكنه في الحقيقة ISO (Disc Image File). وبداخله ملف HTA (HTML Application) هو المسؤول عن بدء الهجوم.
* تنفيذ المرحلة الأولى: تم تنفيذ Payload المرحلة الأولى بواسطة عملية تحمل PID رقم 6392.
* الزرع والاستمرارية: قام المهاجم بنسخ ملف review.dat إلى مجلد Temp باستخدام أداة xcopy.exe وإنشاء مهمة مجدولة (Scheduled Task) باسم Review لضمان البقاء في النظام.
* تجاوز صلاحيات المستخدم (UAC Bypass): تم استخدام عملية fodhelper.exe لتجاوز نظام التحكم في حساب المستخدم والحصول على صلاحيات إدارية.
* استخراج الـ Hashes: تم استخدام أداة Mimikatz (محملة من GitHub) لسحب بيانات الاعتماد.
* التحرك الجانبي: تم اختراق جهاز WKSTN-1327 باستخدام حساب itadmin المكتشف.
* الهجوم النهائي: الوصول إلى الـ Domain Controller وتنفيذ هجوم DCSync لسحب بيانات حساب backupda.

## 6. Attack Timeline
* 29/08/2023 - 10:51: تحميل ملف الـ ISO الملغوم ProjectFinancialSummary_Q3.pdf.
* تنفيذ المرحلة الأولى: تشغيل ملف الـ HTA وتواصله مع C2 IP 165.232.170.151.
* تثبيت الأقدام: إنشاء ملف review.dat وتشغيله عبر rundll32.exe مع DllRegisterServer.
* تصعيد الصلاحيات: تنفيذ UAC Bypass عبر fodhelper.exe.
* التحرك الجانبي: اكتشاف ملف IT_Automation.ps1 على مشاركة شبكية، مما أدى للحصول على كلمات مرور جديدة.
* تشفير البيانات: تحميل وتشغيل برمجية الفدية ransomboogey.exe.

## 7. Indicators of Compromise (IOCs)

| Type | Value |
| :--- | :--- |
| C2 IP:Port | 165[.]232[.]170[.]151:80 |
| Malicious File | ProjectFinancialSummary_Q3.pdf (Actual: ISO/HTA) |
| Persistence File | C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat |
| Ransomware URL | http[:]//ff[.]sillytechninja[.]io/ransomboogey[.]exe |
| Mimikatz Tool | https://github.com/gentilkiwi/mimikatz/releases/download/... |
| Scheduled Task | Review |
