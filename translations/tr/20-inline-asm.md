\newpage
\subsection{20. inline ASM ile shellcode çalıştırma. Basit C++ örneği.}

﷽

![inline asm](./images/28/2021-12-03_11-41.png){width="80%"}    

Bu bölüm oldukça kısa ve zararlı yazılımda shellcode çalıştırmak için inline assembly kullanımını açıklayan bir örneği tanımlamaktadır.      

Hadi zararlı yazılımımızın C++ kaynak kodu örneğine bakalım:    

```cpp
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
  asm(".byte 0x90,0x90,0x90,0x90\n\t"
          "ret \n\t");
  return 0;
}

```

Gördüğünüz gibi, mantık oldukça basit. 4 adet `NOP` talimatı ekliyorum ve öncesinde `meow-meow` dizgisini yazdırıyorum. Bu `meow` dizgisini temel alarak debugger'da shellcode'u kolayca bulabiliyorum.     

![inline asm 2](./images/28/2021-12-03_11-52.png){width="80%"}    

Hadi derleyelim:    

```bash
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe \
-mconsole -fpermissive
```

![inline asm 3](./images/28/2021-12-03_11-51.png){width="80%"}    

Ve bunu `x96dbg`'de çalıştıralım (benim durumumda `Windows 7 x64` üzerinde):        

![inline asm 4](./images/28/2021-12-03_12-09.png){width="80%"}    

Gördüğünüz gibi, vurgulanan talimatlar benim `NOP` talimatlarım, bu yüzden her şey beklendiği gibi mükemmel bir şekilde çalışıyor.     

Bu tekniği cephaneliğinizde bulundurmanın iyi bir nedeni, `VirtualAlloc` kullanarak shellcode'u kopyalamak için yeni `RWX` bellek tahsis etmenizi gerektirmemesidir. Bu yöntem daha popüler ve şüpheli olup, mavi takım üyeleri tarafından daha fazla araştırılmaktadır.     

Umarım bu yazı, bu ilginç teknik hakkında mavi takım üyelerine farkındalık kazandırır ve kırmızı takım üyelerinin cephaneliğine bir silah daha ekler.     

[inline assembly](https://docs.microsoft.com/en-us/cpp/assembler/inline/inline-assembler?view=msvc-170)    
[Github'taki kaynak kod:](https://github.com/cocomelonc/2021-12-03-inline-asm-1)    
