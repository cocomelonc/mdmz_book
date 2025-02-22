\newpage
\subsection{11. windows shellcoding - bölüm 2. Kernel32 adresini bulma}

﷽

![win32 shellcoding](./images/17/2021-10-30_16-30.png){width="80%"}         

Windows shellcoding hakkındaki yazımın [ilk](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html) bölümünde, aşağıdaki mantığı kullanarak `kernel32` ve işlevlerin adreslerini bulmuştuk:

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
  printf("ExitProcess address in memory is: 0x%08p\n", 
  ExitProcessAddr);

  WinExecAddr = GetProcAddress(Kernel32Addr, "WinExec");
  printf("WinExec address in memory is: 0x%08p\n", WinExecAddr);

  getchar();
  return 0;
}
```

Daha sonra, bulduğumuz adresi kabuk kodumuza girdik:    

```nasm
; void ExitProcess([in] UINT uExitCode);
xor  eax, eax         ; zero out eax
push eax              ; push NULL
mov  eax, 0x76ed214f  ; call ExitProcess function 
                      ; addr in kernel32.dll
jmp  eax              ; execute the ExitProcess function
```

Sorun şu ki, tüm DLL'lerin ve işlevlerinin adresleri yeniden başlatıldığında değişir ve her sistemde farklıdır. Bu nedenle, ASM kodumuza herhangi bir adresi sabit olarak yazamayız:     

![win32 shellcoding 2](./images/17/2021-10-30_16-50.png){width="80%"}        

Öncelikle, `kernel32.dll` adresini nasıl buluruz?

### TEB ve PEB yapıları

Herhangi bir exe dosyasını çalıştırdığımızda, işletim sisteminde (bildiğim kadarıyla) ilk oluşturulan şeylerden biri [PEB](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)'dir:     

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

ve [TEB](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) için:

```cpp
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

`PEB` - Windows'ta süreç oluşturma aşamasında yükleyici tarafından doldurulan bir süreç yapısıdır ve sürecin çalışması için gerekli bilgileri içerir.     

`TEB`, mevcut süreçteki iş parçacıkları hakkında bilgi depolamak için kullanılan bir yapıdır ve her iş parçacığının kendi TEB'si vardır.     

Şimdi, `windbg` hata ayıklayıcısında bir program açalım ve şu komutu çalıştıralım:    

```cmd
dt _teb
```

![win32 shellcoding 3](./images/17/2021-10-30_17-20.png){width="80%"}        

Gördüğümüz gibi, PEB'in `0x030` ofseti bulunmaktadır. Benzer şekilde, PEB yapısının içeriğini şu komutla görebiliriz:    

```powershell
dt _peb
```

![win32 shellcoding 4](./images/17/2021-10-30_17-27.png){width="80%"}        

Şimdi, PEB yapısının başlangıcından `0x00c` ofsetinde bulunan üyeye, yani `PEB_LDR_DATA`'ya bakmamız gerekiyor. [PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), sürecin yüklü modülleri hakkında bilgi içerir.    

Daha sonra, `windbg` kullanarak `PEB_LDR_DATA` yapısını da inceleyebiliriz:    

```cmd
dt _PEB_LDR_DATA
```

![win32 shellcoding 5](./images/17/2021-10-30_17-32.png){width="80%"}        

Burada, `InLoadOrderModuleList`'in ofsetinin `0x00c`, `InMemoryOrderModuleList`'in `0x014` ve `InInitializationOrderModuleList`'in `0x01c` olduğunu görebiliriz.

`InMemoryOrderModuleList`, her liste öğesinin bir `LDR_DATA_TABLE_ENTRY` yapısına işaret ettiği çift bağlantılı bir listedir, bu nedenle windbg bu yapının türünü `LIST_ENTRY` olarak belirtiyor.    

Devam etmeden önce şu komutu çalıştıralım:             

```cmd
!peb
```

![win32 shellcoding 6](./images/17/2021-10-30_17-46.png){width="80%"}        

Gördüğümüz gibi, LDR (`PEB` yapısı) adresi - `77328880`.   

Şimdi `InLoadOrderModuleList`, `InMemoryOrderModuleList` ve `InInitializationOrderModuleList` adreslerini görmek için şu komutu çalıştıralım:

```cmd
dt _PEB_LDR_DATA 77328880
```

Bu, bağlantılı listelerin ilgili başlangıç ve bitiş adreslerini gösterecektir:        

![win32 shellcoding 7](./images/17/2021-10-30_17-51.png){width="80%"}        

`LDR_DATA_TABLE_ENTRY` yapısına yüklenmiş modülleri görüntülemeyi deneyelim ve yüklü modüllerin temel adreslerini görebilmemiz için bu yapının başlangıç adresini `0x5119f8` olarak belirteceğiz. Unutmayın ki, `0x5119f8` bu yapının adresidir, bu yüzden ilk giriş bu adresten `8-byte` daha az olacaktır:     

```cmd
dt _LDR_DATA_TABLE_ENTRY 0x5119f8-8
```

![win32 shellcoding 8](./images/17/2021-10-30_18-54.png){width="80%"}        

Gördüğünüz gibi, `BaseDllName` bizim `exit.exe`'miz. Bu, benim çalıştırdığım exe dosyasıdır. Ayrıca, `InMemoryOrderLinks` adresinin şimdi `0x511a88` olduğunu görebilirsiniz. `0x018` ofsetindeki `DllBase`, `BaseDllName`'in temel adresini içerir. Şimdi, bir sonraki yüklü modülümüz `0x511a88`'den 8 byte uzaklıkta olmalıdır, yani `0x5119f8-8`:      

```cmd
dt _LDR_DATA_TABLE_ENTRY 0x5119f8-8
```

![win32 shellcoding 8](./images/17/2021-10-30_18-58.png){width="80%"}        

Gördüğünüz gibi, `BaseDllName` `ntdll.dll`'dir. Adresi `0x77250000`'dir ve bir sonraki modül `0x511e58`'den 8 byte sonra bulunur. Sonra:    

```cmd
dt _LDR_DATA_TABLE_ENTRY 0x511e58-8
```

![win32 shellcoding 8](./images/17/2021-10-30_19-02.png){width="80%"}        

Gördüğünüz gibi, üçüncü modülümüz `kernel32.dll`'dir ve adresi `0x76fd0000`, ofseti ise `0x018`'dir. Bunun doğru olduğundan emin olmak için `getaddr.exe` programımızı çalıştırabiliriz:    

![win32 shellcoding 8](./images/17/2021-10-30_19-03.png){width="80%"}        

Bu modül yükleme sırası, en azından bildiğim kadarıyla, Windows 10 ve 7 için her zaman sabit kalacaktır. Bu nedenle, ASM ile yazarken, tüm PEB LDR yapısını tarayarak `kernel32.dll` adresini bulabilir ve kabuk kodumuza yükleyebiliriz.    

[İlk](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html) bölümde yazdığım gibi, bir sonraki modül `kernelbase.dll` olmalıdır. Sadece bir deney yapmak ve bunun doğru olduğundan emin olmak için şu komutu çalıştırabiliriz:    

```cmd
dt _LDR_DATA_TABLE_ENTRY 0x511f70-8
```

![win32 shellcoding 9](./images/17/2021-10-30_19-12.png){width="80%"}        

Böylece aşağıdaki bilgiler elde edilir:    
1. `PEB` yapısına olan ofset: `0x030`    
2. `PEB` içindeki `LDR`'ye olan ofset: `0x00c`    
3. `InMemoryOrderModuleList`'e olan ofset: `0x014`    
4. İlk yüklü modül bizim `.exe` dosyamızdır.    
5. İkinci yüklü modül `ntdll.dll`'dir.     
6. Üçüncü yüklü modül `kernel32.dll`'dir.    
7. Dördüncü yüklü modül `kernelbase.dll`'dir.     

Son zamanlardaki tüm Windows OS sürümlerinde (bildiğim kadarıyla), FS kaydı `TEB`'i işaret eder. Dolayısıyla, `kernel32.dll`'imizin temel adresini almak için (`kernel.asm`):     

```nasm
; find kernel32
; author @cocomelonc
; nasm -f win32 -o kernel.o kernel.asm
; ld -m i386pe -o kernel.exe kernel.o
; 32-bit windows

section .data

section .bss

section .text
  global _start               ; must be declared for linker

_start:
  mov eax, [fs:ecx + 0x30]    ; offset to the PEB struct
  mov eax, [eax + 0xc]        ; offset to LDR within PEB
  mov eax, [eax + 0x14]       ; offset to 
                              ; InMemoryOrderModuleList
  mov eax, [eax]              ; kernel.exe address loaded 
                              ; in eax (1st module)
  mov eax, [eax]              ; ntdll.dll address loaded
                              ; (2nd module)
  mov eax, [eax + 0x10]       ; kernel32.dll address 
                              ; loaded (3rd module)
```

Bu assembly kodu ile `kernel32.dll` adresini bulabilir ve `EAX` kaydında depolayabiliriz. Şimdi bunu derleyelim:    

```bash
nasm -f win32 -o kernel.o kernel.asm
ld -m i386pe -o kernel.exe kernel.o
```

![win32 shellcoding 10](./images/17/2021-10-30_19-26.png){width="80%"}        

Bunu kopyalayıp ve hata ayıklayıcıyı kullanarak Windows 7’de çalıştıralım:         

![win32 shellcoding 11](./images/17/2021-10-30_19-29.png){width="80%"}       

Çalıştır:

![win32 shellcoding 12](./images/17/2021-10-30_19-31.png){width="80%"}       

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı =^..^=!    

Bir sonraki adım, `LoadLibraryA` kullanarak bir işlevin (örneğin, `ExitProcess`) adresini bulmak ve bu işlevi çağırmak olacak. Bu konu bir sonraki bölümde ele alınacak.     

[History and Advances in Windows Shellcode](http://www.phrack.org/archives/issues/62/7.txt)       
[PEB structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)        
[TEB structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)       
[PEB_LDR_DATA structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)            
[The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)              
[windows shellcoding part 1](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html)             
[Github'taki kaynak kod](https://github.com/cocomelonc/2021-10-30-windows-shellcoding-2)         
