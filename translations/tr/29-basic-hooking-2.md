\newpage
\subsection{29. windows API hooking bölüm 2. Basit C++ örneği}

﷽

![api hooking](./images/42/2022-03-09_11-38.png){width="80%"}    

### API hooking nedir?

API hooking, API çağrılarının davranışını ve akışını enstrüman etmek ve değiştirmek için kullanılan bir tekniktir. Bu teknik, zararlı kodun algılanıp algılanmadığını belirlemek için birçok antivirüs çözümü tarafından da kullanılır.     

Hooking'in en kolay yolu, bir atlama (`jump`) talimatı eklemektir. Bu bölümde, başka bir tekniği göstereceğim.     

Bu yöntem toplamda altı bayttan oluşur ve şu şekilde görünür.      

`push` talimatı, bir `32-bit` değeri yığına iter ve `retn` talimatı, yığının tepesindeki `32-bit` adresi Instruction Pointer’a (Komut İşaretçisine) çıkarır (başka bir deyişle, yığının en üstünde bulunan adreste yürütmeyi başlatır).    

### örnek 1

Bir örneğe bakalım. Bu durumda, `kernel32.dll` içindeki `WinExec` işlevini hooklayabilirim (`hooking.cpp`):    

```cpp
/*
hooking.cpp
basic hooking example with push/retn method
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/03/08/basic-hooking-2.html
*/
#include <windows.h>

// buffer for saving original bytes
char originalBytes[6];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCSTR lpCmdLine, UINT uCmdShow) {
  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, originalBytes, 6, NULL);
  return WinExec("mspaint", uCmdShow);
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD *hookAddress;
  DWORD src;
  DWORD dst;
  CHAR patch[6]= {0};

  // get memory address of function WinExec
  hLib = LoadLibraryA("kernel32.dll");
  hookedAddress = GetProcAddress(hLib, "WinExec");

  // save the first 6 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), 
  (LPCVOID) hookedAddress, 
  originalBytes, 6, NULL);

  // overwrite the first 6 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // create a patch "push <addr>, retn"
  memcpy_s(patch, 1, "\x68", 1); // 0x68 opcode for push
  memcpy_s(patch + 1, 4, &myFuncAddress, 4);
  memcpy_s(patch + 5, 1, "\xC3", 1); // opcode for retn

  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, patch, 6, NULL);
}

int main() {

  // call original
  WinExec("notepad", SW_SHOWDEFAULT);

  // install hook
  setMySuperHook();

  // call after install hook
  WinExec("notepad", SW_SHOWDEFAULT);

}
```

Gördüğünüz gibi, kaynak kod ilk bölümdeki hooking örneğiyle aynıdır. Tek fark şudur:     

![api hooking 2](./images/42/2022-03-09_12-08.png){width="80%"}    

Bu, aşağıdaki assembly talimatlarına çevrilecektir:     

```nasm
// push myFunc memory address onto the stack
push myFunc

// jump to myFunc
retn
```

Haydi,şunu bir derleyelim:    

```bash
i686-w64-mingw32-g++ -O2 hooking.cpp -o hooking.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive >/dev/null 2>&1
```

![api hooking 3](./images/42/2022-03-09_11-41.png){width="80%"}    

Ve `Windows 7 x64`'te çalıştıralım:    

```powershell
.\hooking.exe
```

![api hooking 4](./images/42/2022-03-09_12-26.png){width="80%"}    

Gördüğünüz gibi her şey mükemmel çalışıyor :)    

[x86 API Hooking Demystified](http://jbremer.org/x86-api-hooking-demystified/)    
[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)    
[Github'taki kaynak kod:](https://github.com/cocomelonc/2022-03-08-basic-hooking-2)    
