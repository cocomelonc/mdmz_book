\newpage
\subsection{99. linux kötü amaçlı yazılım geliştirme 2: işlemi ID’ye göre bulma. Basit C örneği.}

﷽

![linux](./images/134/2024-09-17_12-29.png){width="80%"}     

Linux için kötü amaçlı yazılım programlarken rootkitler ve diğer ilginç ve kötü şeyler hakkında ışık tutacağımı söz verdim, ancak başlamadan önce basit şeyler yapmayı deneyelim.   

Bazı okuyucularım, örneğin, Linux süreçlerine kod enjeksiyonu yapmanın nasıl olduğunu bilmiyorlar.   

Beni çok uzun süredir okuyanlar, enjeksiyon amaçları için Windows'ta process ID bulmaya yönelik böyle ilginç ve basit bir [örneği](https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html) hatırlarlar.

### pratik örnek

Hadi Linux için benzer bir mantık uygulayalım. Her şey çok basit:   

```cpp
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
    return -1;
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
```

Kodum, Linux'ta `/proc` dizinini tarayarak çalışan bir işlemi ismiyle nasıl arayacağınızı göstermektedir. `/proc/[pid]/comm` içinde saklanan işlem adlarını okur ve bir eşleşme bulursa, hedef işlemin İşlem Kimliğini (`PID`) alır.      

Gördüğünüz gibi burada sadece iki fonksiyon bulunmaktadır. İlk olarak, `find_process_by_name` fonksiyonunu uyguladık. Bu fonksiyon, `/proc` dizini içinde işlem adını aramaktan sorumludur.     

Bu fonksiyon, bir işlem adı (`proc_name`) alır ve bulunan işlemin `PID` değerini döndürür veya işlem bulunamazsa `-1` değerini döndürür.    

Fonksiyon, `opendir()` fonksiyonunu kullanarak `/proc` dizinini açar. Bu dizin, çalışan işlemler hakkında bilgiler içerir ve her alt dizin bir işlem kimliği (`PID`) ile adlandırılmıştır.    

Ardından, `/proc` içindeki girişleri döngüyle tarar:    

```cpp
while ((entry = readdir(dir)) != NULL) {
```

`readdir()` fonksiyonu, `/proc` dizinindeki tüm girişleri taramak için kullanılır. Her giriş ya bir çalışan işlemi (eğer giriş adı bir sayıysa) ya da diğer sistem dosyalarını temsil eder.    

Daha sonra, giriş adının bir sayı olup olmadığını kontrol eder. Yalnızca sadece rakamlardan oluşan dizin adları, `/proc` içinde geçerli işlem dizinleridir:    

```cpp
if (isdigit(*entry->d_name)) {
```

Dikkat edilmesi gereken nokta, her `/proc/[pid]` dizini içindeki `comm` dosyası, ilgili işlemle ilişkili çalıştırılabilir dosyanın adını içerir:    

```cpp
snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
```

Bu, `comm` dosyasının tam yolunu oluşturduğumuz anlamına gelir: `/proc/`, işlem kimliği (`d_name`) ve `/comm` birleştirilir.    

Son olarak, `comm` dosyasını açar, işlem adını okur ve karşılaştırır:    

```cpp
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
```

Ardından, elbette dizini kapatın ve fonksiyondan çıkın.    

İkinci fonksiyon `main` fonksiyonudur:

```cpp
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
```

Sadece komut satırı argümanlarını kontrol eder ve işlem bulma mantığını çalıştırır.    

### demo

Hadi her şeyi aksiyonda görelim. Derleyelim:     

```bash
gcc -z execstack hack.c -o hack
```

![linux](./images/134/2024-09-16_17-19.png){width="80%"}     

Daha sonra Linux makinesinde çalıştırın:     

```bash
./hack [process_name]
```

![linux](./images/134/2024-09-16_17-35.png){width="80%"}     

![linux](./images/134/2024-09-16_17-36.png){width="80%"}     

Gördüğünüz gibi, her şey mükemmel çalıştı. Telegram ID'sini bulduk (`75678`) benim durumumda! =^..^=    

Her şey oldukça kolay görünüyor, değil mi?     

Ancak bir durum var. Eğer firefox gibi bir işlem için çalıştırmayı denersek:

```bash
./hack firefox
```

şunu alıyoruz:    

![linux](./images/134/2024-09-16_18-56.png){width="80%"}     

Karşılaştığımız sorun, bazı işlemlerin (örneğin `firefox`) alt süreçler veya çoklu iş parçacıkları oluşturması nedeniyle olabilir. Bunların hepsi `comm` dosyasını kullanarak işlem adını saklamayabilir.      

`/proc/[pid]/comm` dosyası, çalıştırılabilir dosyanın tam yolunu içermez ve özellikle birden fazla iş parçacığı veya alt süreç varsa, tüm işlem örneklerini yansıtmayabilir.     

Bu nedenle olası sorunlar şunlar olabilir:    
- `/proc/[pid]/comm` içinde farklı işlem adları: Alt süreçler veya iş parçacıkları, farklı adlandırma kuralları kullanabilir veya `/proc/[pid]/comm` altında `firefox` olarak listelenmeyebilir.       
- zombi veya yetim işlemler: Bazı işlemler, eğer zombi veya yetim işlem (orphan process) durumundaysa doğru şekilde görüntülenmeyebilir.     

### pratik örnek 2

comm dosyasını okumak yerine, `/proc/[pid]/cmdline` dosyasını kontrol edebiliriz. Bu dosya, işlemi başlatmak için kullanılan tam komutu içerir (işlem adı, tam yol ve argümanlar dahil). Birden fazla örneği çalışan işlemler için (`firefox` gibi) daha güvenilir bir kaynaktır.     

Bu nedenle, başka bir versiyon oluşturdum (`hack2.c`):    

```cpp
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
```

Gördüğünüz gibi, bu kodun güncellenmiş bir versiyonudur ve bunun yerine `/proc/[pid]/cmdline` dosyasını okur.    

Ancak `/proc/[pid]/cmdline` veya `/proc/[pid]/status` dosyası her zaman tüm alt işlemleri veya iş parçacıklarını doğru şekilde göstermeyebilir.     

### demo 2

İkinci örneği çalıştırarak kontrol edelim. Derleyin:     

```bash
gcc -z execstack hack2.c -o hack2
```

![linux](./images/134/2024-09-17_08-23.png){width="80%"}     

Daha sonra Linux makinesinde çalıştırın:     

```bash
.\hack [process_name]
```

![linux](./images/134/2024-09-17_08-24.png){width="80%"}     

Gördüğünüz gibi, doğru.   

Umarım bu pratik örnek içeren gönderi, malware araştırmacıları, Linux programcıları ve Linux çekirdek programlama ile kod enjeksiyon teknikleriyle ilgilenen herkes için faydalıdır.    

[Find process ID by name. Windows version](https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html)      
[github'taki kaynak kod](https://github.com/cocomelonc/meow/tree/master/2024-09-16-linux-hacking-2)    
