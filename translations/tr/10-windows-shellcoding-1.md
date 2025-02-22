\newpage
\subsection{10. windows shellcoding - bölüm 1. basit bir örnek}

﷽

![win32 shellcoding](./images/16/2021-10-27_19-24.png){width="80%"}          

Kabuk kodu hakkında önceki bölümlerde, Linux örnekleriyle çalıştık. Bu bölümdeki amacım, Windows makinesi için kabuk kodu yazmak olacak.      

### kabuk kodunu test etme

Kabuk kodunu test ederken, onu bir programa yerleştirip çalıştırmak oldukça kullanışlıdır. İlk yazıda kullandığımız aynı kodu kullanacağız (`run.c`):    

```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "my shellcode here";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1, 
  // so our shellcode worked
  return 1;
}
```

### i̇lk örnek.calc.exe’yi çalıştır

Öncelikle, kabuk kodunun bir prototipini C dilinde yazacağız. Basitlik açısından, aşağıdaki kaynak kodunu yazalım (`exit.c`):

```cpp
/*
exit.c - run calc.exe and exit
*/
#include <windows.h>

int main(void) {
  WinExec("calc.exe", 0);
  ExitProcess(0);
}
```

Gördüğünüz gibi, bu programın mantığı basit: hesap makinesini (`calc.exe`) başlat ve çık. Kodumuzun gerçekten çalıştığından emin olalım. Derleyelim:      

```bash
i686-w64-mingw32-gcc -o exit.exe exit.c -mconsole -lkernel32
```

![compile exit.c](./images/16/2021-10-27_19-42.png){width="80%"}          

Sonra Windows makinesinde çalıştır(`Windows 7 x86 SP1`):              

```powershell
.\exit.exe
```

![run exit.exe](./images/16/2021-10-27_19-46.png){width="80%"}          

Her şey mükemmel bir şekilde çalıştı.       

Let's now try to write this logic in assembly language. The Windows kernel is completely different from the Linux kernel. At the very beginning of our program, we have `#include <windows.h>`, which in turn means that the windows library will be included in the code and this will dynamically link dependencies by default. However, we cannot do the same with ASM. In the case of ASM, we need to find the location of the [WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) function, load the arguments onto the stack, and call the register that has a pointer to the function. Likewise for the [ExitProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess) function. It is important to know that most windows functions are available from three main libraries: `ntdll.dll`, `Kernel32.DLL` and `KernelBase.dll`. If you run our example in a debugger (`x32dbg` in my case), you can make sure of this:          


Şimdi bu mantığı assembly dilinde yazmayı deneyelim. Windows çekirdeği, Linux çekirdeğinden tamamen farklıdır. Programımızın başında `#include <windows.h>` ifadesi yer alıyor, bu da Windows kütüphanesinin koda dahil edileceği ve bağımlılıkların varsayılan olarak dinamik bir şekilde bağlanacağı anlamına gelir. Ancak, aynı şeyi ASM ile yapamayız. ASM'de, [WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) işlevinin konumunu bulmamız, argümanları yığına yüklememiz ve işlevin işaretçisine sahip olan kaydı çağırmamız gerekir. [ExitProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess) işlevi için de aynı şey geçerlidir. Çoğu Windows işlevinin üç ana kütüphanede bulunduğunu bilmek önemlidir: `ntdll.dll`, `Kernel32.DLL` ve `KernelBase.dll`. Örneğimizi bir hata ayıklayıcıda (benim durumumda `x32dbg`) çalıştırırsanız, bunu doğrulayabilirsiniz:

![debug exit.exe](./images/16/2021-10-27_20-06.png){width="80%"}          

### fonksiyonun adresini bulma

Yani, bellekteki `WinExec` adresini bilmemiz gerekiyor. Haydi bulalım!    

```cpp
/*
getaddr.c - get addresses of functions 
(ExitProcess, WinExec) in memory
*/
#include <windows.h>
#include <stdio.h>

int main() {
  unsigned long Kernel32Addr;      // kernel32.dll address
  unsigned long ExitProcessAddr;   // ExitProcess address
  unsigned long WinExecAddr;       // WinExec address

  Kernel32Addr = GetModuleHandle("kernel32.dll");
  printf("KERNEL32 address in memory: 0x%08p\n", Kernel32Addr);

  ExitProcessAddr = GetProcAddress(Kernel32Addr, "ExitProcess");
  printf("ExitProcess address in memory is: 0x%08p\n", ExitProcessAddr);

  WinExecAddr = GetProcAddress(Kernel32Addr, "WinExec");
  printf("WinExec address in memory is: 0x%08p\n", WinExecAddr);

  getchar();
  return 0;
}
```

Bu program size çekirdek adresini ve `kernel32.dll` içindeki `WinExec` adresini söyleyecek. Şimdi bunu derleyelim:       

```bash
i686-w64-mingw32-gcc -O2 getaddr.c -o getaddr.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wall \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc >/dev/null 2>&1
```

![compile getaddr.exe](./images/16/2021-10-27_20-22.png){width="80%"}          

ve bizim hedef makinemizde çalıştıralım:    
```cmd
.\getaddr.exe
```

![run getaddr.exe](./images/16/2021-10-27_20-26.png){width="80%"}          

Artık işlevlerimizin adreslerini biliyoruz. Programımızın kernel32 adresini doğru bir şekilde bulduğuna dikkat edin.     

### assembly zamanı

`Kernel32.dll` içindeki `WinExec()` işlevi, süreci çalıştıran kullanıcının erişebileceği herhangi bir programı başlatmak için kullanılabilir:    

```cpp
UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);
```

Bizim durumumuzda, `lpCmdLine` `calc.exe`'ye, `uCmdShow` ise 1'e (`SW_NORMAL`) eşit olacak.     

Öncelikle, `calc.exe`'yi bir python betiği (`conv.py`) aracılığıyla hex'e dönüştürelim:

```python
# convert string to reversed hex
import sys

input = sys.argv[1]
chunks = [input[i:i+4] for i in range(0, len(input), 4)]
for chunk in chunks[::-1]:
    print (chunk[::-1].encode("utf-8").hex())
```

![calc.exe to hex](./images/16/2021-10-27_21-10.png){width="80%"}          

Then, create our assembly code:
```nasm
xor  ecx, ecx         ; zero out ecx
push ecx              ; string terminator 0x00 for 
                      ; "calc.exe" string
push 0x6578652e       ; exe. : 6578652e
push 0x636c6163       ; clac : 636c6163

mov  eax, esp         ; save pointer to "calc.exe" 
                      ; string in ebx

; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT uCmdShow);
inc  ecx              ; uCmdShow = 1
push ecx              ; uCmdShow *ptr to stack in 
                      ; 2nd position - LIFO
push eax              ; lpcmdLine *ptr to stack in 
                      ; 1st position
mov  ebx, 0x76f0e5fd  ; call WinExec() function 
                      ; addr in kernel32.dll
call ebx
```

> Bir şeyi Little Endian formatına koymak için, baytların hex değerlerini ters çevirerek yazmanız yeterlidir.

Peki ya `ExitProcess` işlevi?     
```cpp
void ExitProcess(UINT uExitCode);
```

Bu işlev, `WinExec` işlevi kullanılarak `calc.exe` süreci başlatıldıktan sonra ana süreci düzgün bir şekilde kapatmak için kullanılır:     

```nasm
; void ExitProcess([in] UINT uExitCode);
xor  eax, eax         ; zero out eax
push eax              ; push NULL
mov  eax, 0x76ed214f  ; call ExitProcess 
                      ; function addr in kernel32.dll
jmp  eax              ; execute the ExitProcess function
```

Final kodumuz:     

```nasm
; run calc.exe and normal exit
; author @cocomelonc
; nasm -f elf32 -o example1.o example1.asm
; ld -m elf_i386 -o example1 example1.o
; 32-bit linux (work in windows as shellcode)

section .data

section .bss

section .text
  global _start   ; must be declared for linker

_start:
  xor  ecx, ecx         ; zero out ecx
  push ecx              ; string terminator 0x00 
                        ; for "calc.exe" string
  push 0x6578652e       ; exe. : 6578652e
  push 0x636c6163       ; clac : 636c6163

  mov  eax, esp         ; save pointer to "calc.exe" 
                        ; string in ebx

  ; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT   uCmdShow);
  inc  ecx              ; uCmdShow = 1
  push ecx              ; uCmdShow *ptr to stack in 
                        ; 2nd position - LIFO
  push eax              ; lpcmdLine *ptr to stack in 
                        ; 1st position
  mov  ebx, 0x76f0e5fd  ; call WinExec() function 
                        ; addr in kernel32.dll
  call ebx

  ; void ExitProcess([in] UINT uExitCode);
  xor  eax, eax         ; zero out eax
  push eax              ; push NULL
  mov  eax, 0x76ed214f  ; call ExitProcess function 
                        ; addr in kernel32.dll
  jmp  eax              ; execute the ExitProcess function
```

Derleyelim:    

```bash
nasm -f elf32 -o example1.o example1.asm
ld -m elf_i386 -o example1 example1.o
objdump -M intel -d example1
```

![compile asm](./images/16/2021-10-27_21-17.png){width="80%"}          

O zaman, tekrar bash ile biraz kodlama yaparak ve `objdump` kullanarak bayt kodunu çıkaralım:     

```bash
objdump -M intel -d example1 | grep '[0-9a-f]:'|grep -v 
'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|
sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|
sed 's/$/"/g'
```

![bytecode](./images/16/2021-10-27_21-19.png){width="80%"}          

Bizim byte kodumuz:     

```bash
"\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c
\x63\x89\xe0\x41\x51\x50\xbb\xfd\xe5\xf0\x76\xff
\xd3\x31\xc0\x50\xb8\x4f\x21\xed\x76\xff\xe0"
```

> yalnızca opkodları bizim için çevirmesi amacıyla nasm kullandığımız için, ELF dosyası olarak 32-bit Linux için derlenmiştir.

Daha sonra, yukarıdaki kodu (`run.c`) şu kod ile değiştirin:   

```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61"
"\x6c\x63\x89\xe0\x41\x51\x50\xbb\xfd\xe5\xf0"
"\x76\xff\xd3\x31\xc0\x50\xb8\x4f\x21\xed\x76"
"\xff\xe0";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1,
  // so our shellcode worked
  return 1;
}
```

Çalıştır:

```bash
i686-w64-mingw32-gcc run.c -o run.exe
```

![compile run.c](./images/16/2021-10-27_23-11.png){width="80%"}          

ve çalıştıralım:

```powershell
.\run.exe
```

![run run.exe](./images/16/2021-10-27_23-14.png){width="80%"}          

> Hesap makinesi (`calc.exe`) süreci, ana süreç sona erdikten sonra bile çalışmaya devam eder, çünkü bu, kendi başına bir süreçtir.

Yani, kabuk kodumuz mükemmel bir şekilde çalıştı :) 

Örneğin, Windows için kendi kabuk kodunuzu bu şekilde oluşturabilirsiniz.    

Ancak, bir sorun var. Bu kabuk kodu yalnızca bu makinede çalışacaktır. Çünkü, tüm DLL'lerin ve işlevlerinin adresleri yeniden başlatıldığında değişir ve her sistemde farklıdır. Bu kodun herhangi bir Windows 7 x86 SP1 sisteminde çalışabilmesi için, ASM'in işlevlerin adreslerini kendisinin bulması gerekir. Bunu bir sonraki bölümde yapacağım.     

[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)                 
[ExitProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)               
[The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)              
[my intro to x86 assembly](https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)          
[my nasm tutorial](https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)           
[linux shellcoding part 1](https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html)                
[linux shellcoding part 2](https://cocomelonc.github.io/tutorial/2021/10/17/linux-shellcoding-2.html)                
[Github'taki kaynak kod](https://github.com/cocomelonc/2021-10-26-windows-shellcoding-1)        
