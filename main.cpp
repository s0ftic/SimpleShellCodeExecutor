#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <comdef.h>
#include <map>

using namespace std;

HANDLE hProc;

HANDLE GetProcess(DWORD pID)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,0, pID);

	if (hProc == NULL)
		return 0;

	return hProc;
}

uint64_t GetModuleBaseAdress(const char* moduleName,DWORD pId)
{
	HANDLE module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do 
	{
		if (!strcmp(_bstr_t(mEntry.szModule), moduleName)) 
		{
			CloseHandle(module);
			return (uint64_t)(mEntry.hModule);
		}

	} while (Module32Next(module, &mEntry));

	
	return 0;
}

DWORD GetProcessId(const char* name)
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);

	do
	{
		if (strcmp(_bstr_t(entry.szExeFile), name) == 0)
		{
			CloseHandle(handle);
			return entry.th32ProcessID;
		}
	}
	while (Process32Next(handle, &entry));

	CloseHandle(handle);
	return 0;
}

void read_memory(uintptr_t src, uintptr_t dst, size_t size)
{
	ReadProcessMemory(hProc, (LPCVOID)src, (LPVOID)dst, size, NULL);
}


template <typename type>
type read_memory(uint64_t src, uint64_t size = sizeof(type)) 
{
	type ret;
	read_memory(src, (uintptr_t)&ret, size);
	return ret;
}

std::map<std::string, uint64_t> imports;

uintptr_t GetFuncAddress(uint64_t hModuleAdress)
{
	if (!hModuleAdress)
		return 0;

	IMAGE_DOS_HEADER dos_header = read_memory< IMAGE_DOS_HEADER >(hModuleAdress);
	IMAGE_NT_HEADERS nt_headers = read_memory< IMAGE_NT_HEADERS >(hModuleAdress + dos_header.e_lfanew);
	IMAGE_IMPORT_DESCRIPTOR descriptor = read_memory< IMAGE_IMPORT_DESCRIPTOR >(hModuleAdress + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress);

	int descriptor_count = 0;
	int thunk_count = 0;

	while (descriptor.Name)
	{
		auto first_thunk = read_memory< IMAGE_THUNK_DATA >(hModuleAdress + descriptor.FirstThunk);
		auto original_first_thunk{ read_memory< IMAGE_THUNK_DATA >(hModuleAdress + descriptor.OriginalFirstThunk) };
		thunk_count = 0;

		while (original_first_thunk.u1.AddressOfData) 
		{
			char name[256];
			read_memory(hModuleAdress + original_first_thunk.u1.AddressOfData + 0x2, (uintptr_t)name, 256);

			std::string str_name(name);
			auto thunk_offset = thunk_count * sizeof(uintptr_t);

			if (str_name.length() > 0)
				imports[str_name] = hModuleAdress + descriptor.FirstThunk + thunk_offset;


			++thunk_count;
			first_thunk = read_memory< IMAGE_THUNK_DATA >(hModuleAdress + descriptor.FirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
			original_first_thunk = read_memory< IMAGE_THUNK_DATA >(hModuleAdress + descriptor.OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
		}

		++descriptor_count;
		descriptor = read_memory< IMAGE_IMPORT_DESCRIPTOR >(hModuleAdress + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptor_count);
	}

	return (imports.size() > 0);
}

int main()
{
	SetConsoleCP(65001);
	SetConsoleOutputCP(65001);

	printf(u8" ▄▀▀▀▀▄  ▄▀▀▄ ▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▀▀▄    ▄▀▀▀▀▄      ▄▀▄▄▄▄   ▄▀▀▀▀▄   ▄▀▀█▄▄   ▄▀▀█▄▄▄▄ \n");
	printf(u8"█ █   ▐ █  █   ▄▀ ▐  ▄▀   ▐ █    █    █    █      █ █    ▌ █      █ █ ▄▀   █ ▐  ▄▀   ▐ \n");
	printf(u8"   ▀▄   ▐  █▄▄▄█    █▄▄▄▄▄  ▐    █    ▐    █      ▐ █      █      █ ▐ █    █   █▄▄▄▄▄  \n");
	printf(u8"▀▄   █     █   █    █    ▌      █         █         █      ▀▄    ▄▀   █    █   █    ▌  \n");
	printf(u8" █▀▀▀     ▄▀  ▄▀   ▄▀▄▄▄▄     ▄▀▄▄▄▄▄▄▀ ▄▀▄▄▄▄▄▄▀  ▄▀▄▄▄▄▀   ▀▀▀▀    ▄▀▄▄▄▄▀  ▄▀▄▄▄▄   \n");
	printf(u8" ▐       █   █     █    ▐     █         █         █     ▐           █     ▐   █    ▐   \n");
	printf(u8"         ▐   ▐     ▐          ▐         ▐         ▐                 ▐         ▐        \n");

	
	DWORD pId = GetProcessId("notepad.exe");

	printf("pId -> %i\n",pId);

	if (pId == 0)
	{
		printf("process not found!\n");
		return 0;
	}

	hProc = GetProcess(pId);

	printf("hProc -> 0x%x\n", hProc);

	if (hProc == 0)
	{
		printf("filed to open process!\n");
		return 0;
	}

	uint64_t ModuleBase = GetModuleBaseAdress("notepad.exe", pId);

	printf("ModuleBase -> 0x%x\n", ModuleBase);

	DWORD Adress = GetFuncAddress(ModuleBase);

	printf("Import Found At (TranslateMessage -> 0x%x)\n", imports["TranslateMessage"]);

	uint64_t iat_func = imports["TranslateMessage"];
	uint64_t orginal_function_addr = read_memory<uint64_t>(iat_func);

	uint8_t sheall_code[] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };
	
	LPCVOID stub_base = VirtualAllocEx(hProc, 0, sizeof(sheall_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	*(uint64_t*)(sheall_code + 0x18) = iat_func;
	*(uint64_t*)(sheall_code + 0x22) = orginal_function_addr;


	uint64_t entry_point = 0x0; //ShealCode Adress
	*(uint64_t*)(sheall_code + 0x39) = (uint64_t)ModuleBase;
	*(uint64_t*)(sheall_code + 0x4a) = entry_point;

	WriteProcessMemory(hProc, (LPVOID)stub_base, (LPVOID)sheall_code, sizeof(sheall_code), NULL);

	getchar();
}
