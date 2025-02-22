\newpage
\subsection{19.  windows api hooking. Basit C++ örneği}

﷽

![api hooking](./images/27/2021-11-30_17-00.png){width="80%"}    

### API hooking nedir?

API hooking, API çağrılarının davranışını ve akışını enstrüman etmek ve değiştirmek için kullanılan bir tekniktir. Bu teknik, zararlı kodun algılanıp algılanmadığını belirlemek için birçok antivirüs çözümü tarafından da kullanılır.     

### example 1

Windows API işlevlerini hooklamadan önce, bir DLL'den dışa aktarılan bir işlevle bunu nasıl yapacağımızı ele alacağım.     
Örneğin, şu mantığa sahip bir DLL'imiz var (`pet.cpp`):    

```cpp
/*
pet.dll - DLL example for basic hooking
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, 
DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
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

extern "C" {
  __declspec(dllexport) int _cdecl Cat(LPCTSTR say) {
    MessageBox(NULL, say, "=^..^=", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Mouse(LPCTSTR say) {
    MessageBox(NULL, say, "<:3()~~", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Frog(LPCTSTR say) {
    MessageBox(NULL, say, "8)~", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Bird(LPCTSTR say) {
    MessageBox(NULL, say, "<(-)", MB_OK);
	  return 1;
	}
}
```

Gördüğünüz gibi, bu DLL en basit dışa aktarılan işlevlere sahip: `Cat`, `Mouse`, `Frog`, `Bird`, her biri bir sayparametresi alıyor. Bu işlevlerin mantığı oldukça basittir; sadece bir başlıkla birlikte bir mesaj açarlar.

Şimdi bunu derleyelim:     

```bash
x86_64-w64-mingw32-gcc -shared -o pet.dll pet.cpp -fpermissive
```

![api hooking 2](./images/27/2021-11-30_17-30.png){width="80%"}    

Daha sonra, bu DLL'i doğrulamak için basit bir kod oluşturuyoruz (`cat.cpp`):     

```cpp
#include <windows.h>

typedef int (__cdecl *CatProc)(LPCTSTR say);
typedef int (__cdecl *BirdProc)(LPCTSTR say);

int main(void) {
  HINSTANCE petDll;
  CatProc catFunc;
  BirdProc birdFunc;
  BOOL freeRes;

  petDll = LoadLibrary("pet.dll");

  if (petDll != NULL) {
    catFunc = (CatProc) GetProcAddress(petDll, "Cat");
    birdFunc = (BirdProc) GetProcAddress(petDll, "Bird");
    if ((catFunc != NULL) && (birdFunc != NULL)) {
      (catFunc) ("meow-meow");
      (catFunc) ("mmmmeow");
      (birdFunc) ("tweet-tweet");
    }
    freeRes = FreeLibrary(petDll);
  }

  return 0;
}

```

Haydi şunu derleyelim:    

```bash
x86_64-w64-mingw32-g++ -O2 cat.cpp -o cat.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
```

![api hooking 3](./images/27/2021-11-30_17-34.png){width="80%"}    

ve, `Windows 7 x64`'te başlatalım:

```powershell
.\cat.exe
```

![api hooking 4](./images/27/2021-11-30_17-37.png){width="80%"}    

![api hooking 5](./images/27/2021-11-30_17-38.png){width="80%"}    

![api hooking 6](./images/27/2021-11-30_18-02.png){width="80%"}    

Ve gördüğünüz gibi, her şey beklendiği gibi çalışıyor.      

Bu senaryoda, örneğin `Cat` işlevi hooklanacak, ancak bu herhangi bir işlev olabilir.      

Bu tekniğin iş akışı şu şekildedir:      

Öncelikle, `Cat` işlevinin bellek adresini alın.      

![api hooking 7](./images/27/2021-11-30_18-05.png){width="80%"}    

sonra, `Cat` işlevinin ilk `5` baytını kaydedin. Bu baytları daha sonra kullanacağız:    

![api hooking 8](./images/27/2021-11-30_18-07.png){width="80%"}    

daha sonra, orijinal `Cat` işlevi çağrıldığında çalıştırılacak bir `myFunc` işlevi oluşturun:     

![api hooking 9](./images/27/2021-11-30_18-08.png){width="80%"}    

i̇lk 5 baytı `myFunc` işlevine bir atlama (`jmp`) ile değiştirin:     

![api hooking 10](./images/27/2021-11-30_18-11.png){width="80%"}    

Sonrasında, bir "patch" oluşturun:     

![api hooking 11](./images/27/2021-11-30_18-17.png){width="80%"}    

bir sonraki adımda, `Cat` işlevimizi yamalayın (`Cat` işlevini `myFunc` işlevine yönlendirin):     

![api hooking 12](./images/27/2021-11-30_18-19.png){width="80%"}    

Burada ne yaptık? Bu numara **"klasik 5-bayt hook"** tekniğidir. Eğer işlevi ayrıştırırsak:   

![api hooking disas](./images/27/2021-11-30_21-05.png){width="80%"}    

Vurgulanan `5` bayt, birçok API işlevinde bulunan oldukça tipik bir başlangıçtır. Bu ilk `5` baytı bir `jmp` talimatıyla değiştirerek, yürütmeyi tanımladığımız kendi işlevimize yönlendiriyoruz. Orijinal baytları daha sonra, yürütmeyi tekrar hooklanan işlevimize geçirmek istediğimizde başvurabilmek için saklıyoruz.    

Bu nedenle, önce orijinal `Cat` işlevini çağırırız, hookumuzu ayarlarız ve ardından tekrar `Cat`'i çağırırız:    

![api hooking 13](./images/27/2021-11-30_18-21.png){width="80%"}    

Tam kaynak kodu şu şekilde:    
```cpp
/*
hooking.cpp
basic hooking example
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/30/basic-hooking-1.html
*/
#include <windows.h>

typedef int (__cdecl *CatProc)(LPCTSTR say);

// buffer for saving original bytes
char originalBytes[5];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCTSTR say) {
  HINSTANCE petDll;
  CatProc catFunc;

  // unhook the function: rewrite original bytes
  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, 
  originalBytes, 5, NULL);

  // return to the original function and modify the text
  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  return (catFunc) ("meow-squeak-tweet!!!");
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD src;
  DWORD dst;
  CHAR patch[5]= {0};

  // get memory address of function Cat
  hLib = LoadLibraryA("pet.dll");
  hookedAddress = GetProcAddress(hLib, "Cat");

  // save the first 5 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), 
  (LPCVOID) hookedAddress, 
  originalBytes, 5, NULL);

  // overwrite the first 5 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // will jump from the next instruction 
  // (after our 5 byte jmp instruction)
  src = (DWORD)hookedAddress + 5;
  dst = (DWORD)myFuncAddress;
  rOffset = (DWORD *)(dst-src);

  // \xE9 - jump instruction
  memcpy(patch, "\xE9", 1);
  memcpy(patch + 1, &rOffset, 4);

  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, patch, 
  5, NULL);

}

int main() {
  HINSTANCE petDll;
  CatProc catFunc;

  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  // call original Cat function
  (catFunc)("meow-meow");

  // install hook
  setMySuperHook();

  // call Cat function after install hook
  (catFunc)("meow-meow");

}

```

Haydi bunu derleyelim:   

```bash
x86_64-w64-mingw32-g++ -O2 hooking.cpp -o hooking.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
```

![api hooking 14](./images/27/2021-11-30_18-22.png){width="80%"}    

Ve bunu eylemde görelim (bu durumda `Windows 7 x64` üzerinde):

```powershell
.\hooking.exe
```

![api hooking 15](./images/27/2021-11-30_18-25.png){width="80%"}    

![api hooking 16](./images/27/2021-11-30_18-25_1.png){width="80%"}    

Gördüğünüz gibi, hookumuz mükemmel bir şekilde çalıştı!! Cat artık `meow-meow` yerine `meow-squeak-tweet` yapıyor!!!

### örnek 2

Benzer şekilde, `kernel32.dll` içindeki `WinExec` gibi bir işlevi hooklayabilirsiniz (`hooking2.cpp`):        

```cpp
#include <windows.h>

// buffer for saving original bytes
char originalBytes[5];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCSTR lpCmdLine, UINT uCmdShow) {

  // unhook the function: rewrite original bytes
  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, originalBytes, 5, NULL);

  // return to the original function and modify the text
  return WinExec("calc", uCmdShow);
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD src;
  DWORD dst;
  CHAR patch[5]= {0};

  // get memory address of function MessageBoxA
  hLib = LoadLibraryA("kernel32.dll");
  hookedAddress = GetProcAddress(hLib, "WinExec");

  // save the first 5 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), 
  (LPCVOID) hookedAddress, originalBytes, 5, NULL);

  // overwrite the first 5 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // will jump from the next instruction 
  // (after our 5 byte jmp instruction)
  src = (DWORD)hookedAddress + 5;
  dst = (DWORD)myFuncAddress;
  rOffset = (DWORD *)(dst-src);

  // \xE9 - jump instruction
  memcpy(patch, "\xE9", 1);
  memcpy(patch + 1, &rOffset, 4);

  WriteProcessMemory(GetCurrentProcess(), 
  (LPVOID)hookedAddress, patch, 5, NULL);

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

Şunu derleyelim:     

```bash
x86_64-w64-mingw32-g++ -O2 hooking2.cpp -o hooking2.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
```

![api hooking 17](./images/27/2021-11-30_18-35.png){width="80%"}    

ve çalıştıralım:    

```powershell
.\hooking2.exe
```

![api hooking 18](./images/27/2021-11-30_18-38.png){width="80%"}    

Yani her şey umduğumuz gibi gitti.     

[Github'ki kaynak kod](https://github.com/cocomelonc/2021-11-30-basic-hooking-1)   
[MessageBox](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox)    
[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)    
[Exporting from DLL using __declspec](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport?view=msvc-170)    
