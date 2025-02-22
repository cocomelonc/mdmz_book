\newpage
\subsection{12. windows shellcoding - bölüm 3. PE dosya formatı}

﷽

![pe file](./images/18/2021-10-31_21-19.png){width="80%"}         

Bu bölüm, önceki bölümlerin bir devamı olarak okunabileceği gibi, aynı zamanda bağımsız bir materyal olarak da okunabilir. Bu, PE dosya formatının genel bir incelemesidir.      

### PE dosyası (PE file)

PE dosya formatı nedir? Win32'nin yerel dosya formatıdır. Spesifikasyonu, bir anlamda Unix Coff (Common Object File Format) formatından türetilmiştir. "Portable Executable" (Taşınabilir Çalıştırılabilir) terimi, dosya formatının Win32 platformu genelinde evrensel olduğu anlamına gelir: Her Win32 platformunun PE yükleyicisi bu dosya formatını tanır ve kullanır, hatta Windows Intel dışındaki CPU platformlarında çalışıyor olsa bile. Ancak, PE yürütülebilir dosyalarınızın değişiklik yapmadan diğer CPU platformlarına taşınabileceği anlamına gelmez. Dolayısıyla, PE dosya formatını incelemek, Windows'un yapısına dair değerli bilgiler sağlar.     

Temelde, PE dosya yapısı şu şekilde görünür:                     

![pe file struct](./images/18/pefile.png){width="80%"}         

PE dosya formatı esasen PE başlığı tarafından tanımlanır, bu nedenle öncelikle bu başlık hakkında bilgi edinmek isteyebilirsiniz. Her bir parçasını anlamanıza gerek yok, ancak yapısı hakkında bir fikir edinmeli ve en önemli bölümleri tanıyabilmelisiniz.    

### DOS başlığı (DOS header)

DOS başlığı, PE dosyasını yüklemek için gerekli bilgileri saklar. Bu nedenle, bir PE dosyasını yüklemek için bu başlık zorunludur.            

DOS başlığı yapısı:          

```cpp
typedef struct _IMAGE_DOS_HEADER {// DOS .EXE header
    WORD   e_magic;       // Magic number
    WORD   e_cblp;        // Bytes on last page of file
    WORD   e_cp;          // Pages in file
    WORD   e_crlc;        // Relocations
    WORD   e_cparhdr;     // Size of header in paragraphs
    WORD   e_minalloc;    // Minimum extra paragraphs needed
    WORD   e_maxalloc;    // Maximum extra paragraphs needed
    WORD   e_ss;          // Initial (relative) SS value
    WORD   e_sp;          // Initial SP value
    WORD   e_csum;        // Checksum
    WORD   e_ip;          // Initial IP value
    WORD   e_cs;          // Initial (relative) CS value
    WORD   e_lfarlc;      // File address of relocation table
    WORD   e_ovno;        // Overlay number
    WORD   e_res[4];      // Reserved words
    WORD   e_oemid;       // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;     // OEM information; e_oemid specific
    WORD   e_res2[10];    // Reserved words
    LONG   e_lfanew;      // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

ve bu `64` baytlık bir boyuta sahiptir. Bu yapıda en önemli alanlar `e_magic` ve `e_lfanew`'dir. Başlığın ilk iki byte'ı, dosya türünü tanımlayan sihirli byte'lardır: `4D 5A` veya "MZ", Microsoft'ta DOS üzerinde çalışan Mark Zbikowski'nin baş harfleridir. Bu sihirli byte'lar, dosyayı bir PE dosyası olarak tanımlar:     

![pe file 1](./images/18/2021-10-31_22-24.png){width="80%"}         

`e_lfanew` - is at offset `0x3c` of the DOS HEADER and contains the offset to the PE header:

![pe file 2](./images/18/2021-10-31_22-40.png){width="80%"}         

### DOS stub

Dosyanın ilk `64` baytından sonra bir `DOS` stub başlar. Bu alan bellekte çoğunlukla sıfırlarla doldurulur:     

![pe file 3](./images/18/2021-10-31_22-57.png){width="80%"}         

### PE başlığı (PE header)

Bu kısım küçüktür ve yalnızca sihirli baytlar olan `PE\0\0` veya `50 45 00 00` şeklinde bir dosya imzasını içerir:

![pe file 4](./images/18/2021-10-31_23-03.png){width="80%"}         

Yapısı:        
```cpp
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

Bu yapıya daha yakından bakalım.        

**Dosya Başlığı** (veya COFF Başlığı) - dosyanın temel özelliklerini tanımlayan bir alan kümesidir:    

```cpp
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

![pe file 5](./images/18/2021-10-31_23-18.png){width="80%"}         

**Opsiyonel Başlık (Optional Header)** - COFF nesne dosyaları bağlamında isteğe bağlıdır, ancak PE dosyaları için değildir. Bu başlık `AddressOfEntryPoint`, `ImageBase`, `Section Alignment`, `SizeOfImage`, `SizeOfHeaders` ve `DataDirectory` gibi birçok önemli değişkeni içerir. Bu yapının `32-bit` ve `64-bit` versiyonları vardır:    

```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY 
    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

![pe file 6](./images/18/2021-10-31_23-29.png){width="80%"}         

Burada, dikkat çekmek istediğim şey `IMAGE_DATA_DIRECTORY`'dir:

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

Bu bir veri dizinidir. Basitçe, her biri 2 `DWORD` değerinden oluşan bir yapıya sahip `16` elemanlık bir dizidir.    

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

### Section Tablosu (Section Table)

Bu, PE dosyasının `.text` ve `.data` gibi bölümlerini tanımlayan `IMAGE_SECTION_HEADER` yapılarını içeren bir dizidir.     

`IMAGE_SECTION_HEADER` yapısı:

```cpp
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

ve `0x28` bayttan oluşur.     

### Bölümler (Sections)

Bölüm tablosundan sonra, gerçek bölümler gelir:                  

![pe file 7](./images/18/2021-11-01_00-00.png){width="80%"}         

Uygulamalar fiziksel belleğe doğrudan erişmez, yalnızca sanal belleğe erişir. Bölümler, sanal belleğe aktarılmış bir alanı temsil eder ve tüm işlem bu verilerle doğrudan yapılır. Sanal bellekteki ofsetler olmayan bir adres, **Sanal Adres (Virtual adress)** olarak adlandırılır. Başka bir deyişle, Sanal adresler, bir uygulamanın başvurduğu bellek adresleridir. **ImageBase** alanında ayarlanan uygulama için tercih edilen indirme konumu, sanal bellekte bir uygulama alanının başladığı noktaya benzer. Ve **RVA (Relative Virtual Address)** ofsetleri bu noktaya göre ölçülür. RVA'yı şu formülle hesaplayabiliriz: `RVA = VA - ImageBase`. `ImageBase` her zaman bilinir ve VA veya RVA'ya sahip olduğumuzda, biri diğerinden türetilebilir.    

Her bölümün boyutu bölüm tablosunda sabittir, bu nedenle bölümler belirli bir boyutta olmalı ve bunun için `NULL` baytlarla (`00`) doldurulurlar.     

Bir Windows NT uygulaması genellikle `.text`, `.bss`, `.rdata`, `.data`, `.rsrc` gibi farklı önceden tanımlanmış bölümlere sahiptir. Uygulamaya bağlı olarak, bu bölümlerin bazıları kullanılır, ancak hepsi kullanılmaz.      

##### .text

Windows'ta, tüm kod segmentleri `.text` adlı bir bölümde bulunur.

##### .rdata

Salt okunur veriler, dosya sistemindeki dizgiler ve sabitler gibi, `.rdata` adlı bir  bölümde bulunur.

##### .rsrc

Bu, bir kaynak bölümüdür ve kaynak bilgilerini içerir. Çoğu durumda, dosyanın kaynaklarının bir parçası olan simgeleri ve görüntüleri gösterir. Diğer bölümlerin çoğu gibi, bu bölüm bir kaynak dizin yapısıyla başlar, ancak bu bölümün verileri bir kaynak ağacında daha fazla yapılandırılır.

```cpp
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
```

##### .edata

Bu bölüm, bir uygulama veya DLL için dışa aktarma verilerini içerir. Bulunduğunda, dışa aktarma bilgilerine erişmek için bir dışa aktarma dizini içerir.`IMAGE_EXPORT_DIRECTORY` yapısı şunları içerir:                

```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    PULONG  *AddressOfFunctions;
    PULONG  *AddressOfNames;
    PUSHORT *AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Dışa aktarılan semboller genellikle DLL'lerde bulunur, ancak DLL'ler sembolleri de içe aktarabilir. Dışa aktarma tablosunun temel amacı, dışa aktarılan işlevlerin adlarını ve/veya numaralarını RVA ile ilişkilendirmektir, yani süreç bellek haritasındaki konumlarıyla.       

### İçe Aktarma Adres Tablosu (Import Address Table)
İçe Aktarma Adres Tablosu, işlev işaretçileri içerir ve DLL'ler yüklendiğinde işlevlerin adreslerini almak için kullanılır. Derlenmiş bir uygulama, tüm API çağrılarının doğrudan kodlanmış adresler yerine bir işlev işaretçisi aracılığıyla çalışması için tasarlanmıştır.       

### Sonuç

PE dosya formatı, burada yazdığımdan daha karmaşıktır. Örneğin, Windows yürütülebilir dosyalar hakkında ilginç bir görsel örnek, Ange Albertini'nin Github projesi [corkami](https://github.com/corkami/pics/blob/master/binary/pe101/README.md)'de bulunabilir:     

![pe file poster](./images/18/pe101l.png){width="80%"}         

[PE bear](https://github.com/hasherezade/pe-bear-releases)                  
[MSDN PE format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)                
[corkami](https://github.com/corkami/pics/blob/master/binary/pe101/README.md)                    
[An In-Depth Look into the Win32 Portable Executable File Format](https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail)            
[An In-Depth Look into the Win32 Portable Executable File Format, Part 2](https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2)                 
[MSDN IMAGE_NT_HEADERS](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)                
[MSDN IMAGE_FILE_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)               
[MSDN IMAGE_OPTIONAL_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)             
[MSDN IMAGE_DATA_DIRECTORY](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)           
