\newpage
\subsection{98. linux malware development 1: Intro to kernel hacking. Simple C example.}

﷽

![kötü amaçlı yazılım](./images/125/2024-06-21_00-30.png){width="80%"}      

Aslında, bu gönderiye başka bir isim de verilebilirdi, örneğin *"Kötü amaçlı yazılım geliştirme teknikleri - 41. bölüm"*, ancak burada yine okuyucularımın bana sorduğu birçok soruya yanıt veriyorum. *Linux için nasıl kötü amaçlı yazılım geliştirebilirim?*     

Belki de bu gönderi, bir dizi yazının başlangıcı ve aynı zamanda çıkış noktası olacaktır (beni uzun süredir takip edenler, başladığım ancak henüz mantıksal sonuca ulaştırmadığım birçok farklı yazı serim olduğunu fark etmişlerdir).      

Dürüst olmak gerekirse, Linux çekirdeği için programlama konusundaki son deneyimim üniversitede yaklaşık 10+ yıl önceydi, o zamandan beri çok şey değişti. Bu yüzden, Linux rootkit, stealer vb. gibi ilginç bir kötü amaçlı yazılım yazmayı denemeye karar verdim.    

İlk olarak, sistemimi bozmamak için bir Linux sanal makinesi kurdum - [xubuntu 20.04](https://xubuntu.org/). Daha yeni bir `Ubuntu (Xubuntu, Lubuntu)` sürümü de yükleyebilirsiniz, ancak 20.04 sürümü deneyler için oldukça uygundur:          

![kötü amaçlı yazılım](./images/125/2024-06-21_00-51.png){width="80%"}

### pratik örnek

Örneğin, bir kernel rootkit gibi bir kötü amaçlı yazılım oluşturmak istiyorsak, geliştirdiğimiz kod, oluşturduğumuz çekirdek modüllerini kullanarak çekirdek seviyesinde ayrıcalıklarla (`ring 0`) çalıştırılabilir. Bu rolde çalışmak bazı zorluklar barındırır. Bir yandan, çalışmalarımız kullanıcı ve kullanıcı alanı araçları tarafından fark edilmez. Ancak, bir hata yaparsak ciddi sonuçları olabilir. Çekirdek, kendi kusurlarına karşı bizi koruyamaz, bu da tüm sistemi çökertme riski taşıdığımız anlamına gelir. Sanal makine kullanımı, Xubuntu ortamımızda geliştirme sürecini daha yönetilebilir hale getirecektir.    

Hadi modülleri içe aktarmakla başlayalım:    

```cpp
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
```

Bu `#include` ifadeleri, çekirdek modülü programlaması için gerekli başlık dosyalarını içerir:
- `linux/init.h` - Modül başlatma ve temizleme için gerekli makro ve fonksiyonları içerir.    
- `linux/module.h` - Modül programlaması için gerekli makro ve fonksiyonları içerir.     
- `linux/kernel.h` - Çekirdek geliştirme için çeşitli fonksiyonlar ve makrolar sağlar**.    

```cpp
MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");
```

Bu makrolar, modül hakkında meta verileri tanımlar:    

- `MODULE_LICENSE("GPL")` - Modülün hangi lisans altında yayınlandığını belirtir. Burada **GNU Genel Kamu Lisansı (GPL)** kullanılmıştır.    
- `MODULE_AUTHOR("cocomelonc")` - Modülün yazarını belirtir.     
- `MODULE_DESCRIPTION("kernel-test-01")` - Modül hakkında kısa bir açıklama sağlar.     
- `MODULE_VERSION("0.001")` - Modülün sürümünü belirtir.      

Sonraki birkaç satırda, **başlatma (init) fonksiyonunu** tanımlıyoruz:     

```cpp
static int __init hack_init(void) {
  printk(KERN_INFO "Meow-meow!\n");
  return 0;
}
```

Bu fonksiyon, modül için başlatma fonksiyonudur:
- `static int __init hack_init(void)` - Fonksiyonun bu dosyaya özel (`static`) olduğunu tanımlar ve `__init` makrosu ile başlatma fonksiyonu olduğunu belirtir.      
- `printk(KERN_INFO "Meow-meow!\n")` - Çekirdek loguna "Meow-meow!" mesajını INFO seviyesinde yazdırır.    
- `return 0` - Başarılı başlatmayı belirtmek için `0` döndürür.    

Sonraki adım, `hack_exit` fonksiyonudur:    

```cpp
static void __exit hack_exit(void) {
  printk(KERN_INFO "Meow-bow!\n");
}
```

Bu fonksiyon, modül için temizleme (çıkış) fonksiyonudur:

- `static void __exit hack_exit(void)` - Fonksiyonun bu dosyaya özel (`static`) olduğunu tanımlar ve `__exit` makrosu ile çıkış (temizleme) fonksiyonu olduğunu belirtir.
- `printk(KERN_INFO "Meow-bow!\n")` - Çekirdek loguna "Meow-bow!" mesajını INFO seviyesinde yazdırır.    

Daha sonra, başlatma ve temizleme fonksiyonlarını kaydediyoruz:    

```cpp
module_init(hack_init);
module_exit(hack_exit);
```

Böylece, tam kaynak kodu şu şekilde görünüyor: `hack.c`:    

```cpp
/*
 * hack.c
 * introduction to linux kernel hacking
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2024/06/20/kernel-hacking-1.html
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");

static int __init hack_init(void) {
  printk(KERN_INFO "Meow-meow!\n");
  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "Meow-bow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
```

Bu kod, bir Linux çekirdek modülünün temel yapısını, başlatma ve temizleme fonksiyonlarının nasıl tanımlanacağını ve modül hakkında meta verilerin nasıl sağlanacağını göstermektedir.

### demo

Bu modülü çalışırken görelim. Derlemeden önce şu paketleri yüklemeniz gerekir:    

```bash
$ apt update
$ apt install build-essential linux-headers-$(uname -r)
```

Derleme için aşağıdaki içeriğe sahip `Makefile` dosyasını oluşturun:     

```makefile
obj-m += hack.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Bu `Makefile`, Linux çekirdek modülünü derlemek ve temizlemek için kullanılır.     
- `obj-m` değişkeni, çekirdek modülleri olarak derlenecek nesne dosyalarını listeler. `hack.o`, `hack.c` kaynak dosyasından derlenecek nesne dosyasıdır.
- `+=` operatörü, `hack.o` dosyasını modül olarak derlenecek nesne dosyaları listesine ekler.   

Aşağıdaki komut, modülü derlemek için `Makefile` içinde kullanılır:   

```makefile
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```

Bu komut, `make` aracılığıyla modülü derler. `-C /lib/modules/$(shell uname -r)/build`, çalışan çekirdeğin derleme dizinine geçiş yapar. `$(shell uname -r)`, şu anda çalışan çekirdeğin sürümünü alır ve `/lib/modules/$(shell uname -r)/build`, çekirdek derleme dizininin bulunduğu yerdir.     

`M=$(PWD)`, `M` değişkenini geçerli çalışma dizinine `$(PWD)` ayarlar, yani modül kaynak kodlarının bulunduğu dizin. Bu, çekirdek derleme sistemine mevcut dizinde modül kaynak dosyalarını aramasını söyler.     

`modules` hedefi, `obj-m` içinde listelenen modülleri derler.    

`make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean` - bu komut, modül derleme dosyalarını temizler.     

Bir terminal açın, `hack.c` ve `Makefile` içeren dizine gidin:    

![kötü amaçlı yazılım](./images/125/2024-06-21_00-25.png){width="80%"}      

ve aşağıdaki komutu çalıştırarak modülü derleyin:    

```bash
make
```

![kötü amaçlı yazılım](./images/125/2024-06-21_00-26.png){width="80%"}      

Sonuç olarak, `make` komutunu çalıştırdıktan sonra birkaç yeni ara ikili dosya (binary) oluşacaktır. Ancak en önemli ekleme, `hack.ko` dosyasının oluşmasıdır.      

Peki, sırada ne var? Yeni bir terminalde `dmesg` komutunu çalıştırın:    

```bash
dmesg
```

![kötü amaçlı yazılım](./images/125/2024-06-21_00-27.png){width="80%"}      

Daha sonra, şu komutu kullanarak modülü çalışan çekirdeğe yükleyin:     

```bash
sudo insmod hack.ko
```

Şimdi, yeni bir terminalde `dmesg` komutunu tekrar çalıştırırsanız `Meow-meow!` mesajını görmelisiniz:     

![kötü amaçlı yazılım](./images/125/2024-06-21_00-27_1.png){width="80%"}      

Çalışan çekirdekten modülü kaldırmak için şu komutu kullanın:      

```bash
sudo rmmod hack
```

![kötü amaçlı yazılım](./images/125/2024-06-21_00-28.png){width="80%"}      

![kötü amaçlı yazılım](./images/125/2024-06-21_00-29.png){width="80%"}      

Gördüğünüz gibi, çekirdek tamponunda `Meow-bow!` mesajı belirdi, yani her şey beklendiği gibi mükemmel çalıştı! =^..^=     

Bununla birlikte, bir önemli husus daha var. Bir Linux çekirdek modülü oluşturduğunuzda, onun yalnızca oluşturulduğu belirli çekirdek sürümüne ait olduğunu unutmamak önemlidir. Farklı bir çekirdeğe modül yüklemeye çalışırsanız, yükleme işleminin başarısız olması olasıdır.        

Sanırım burada bir mola vereceğiz. Gelecek yazılarda rootkit ve stealer konularına bakacağız.      

Bu yazının pratik bir örnekle birlikte, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama teknikleriyle ilgilenen herkes için faydalı olacağını umuyorum.    

[GitHub'taki kaynak kod](https://github.com/cocomelonc/meow/tree/master/2024-06-20-linux-kernel-hacking-1)
