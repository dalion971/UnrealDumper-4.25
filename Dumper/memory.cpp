#include <Windows.h>
#include <winternl.h>
#include "memory.h"
#ifdef DRV
#include "Driver.h"
#endif
HANDLE hProcess;
uint64 Base;

bool Read(void* address, void* buffer, uint64 size) {
#ifdef DRV
	return driver->ReadMemory(address, buffer, size);
#endif
	uint64 read;
	return ReadProcessMemory(hProcess, address, buffer, size, &read) && read == size;
}

bool ReaderInit(uint32 pid, wchar_t* module_name) {
#ifdef DRV
	driver->AttachByID(pid);
	if(!driver->Init())
	{
		MessageBoxA(NULL, "Error Driver Installed", "", MB_OK);
		return false;
	}
	Base = driver->GetModuleBase(module_name).addr;
	if (!Base) 		return false;
	return true;
#else
	PROCESS_BASIC_INFORMATION pbi;
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
	if (!hProcess) return false;
	if (0 > NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0)) goto failed;
	Base = Read<uint64>((uint8*)pbi.PebBaseAddress + 0x10);
	if (!Base) goto failed;
	return true;
failed:
	CloseHandle(hProcess);
	return false;
#endif

}

uint64 GetImageSize() {
	char buffer[0x400];
	if (!Read((void*)Base, buffer, 0x400)) return 0;
	auto nt = (PIMAGE_NT_HEADERS)(buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
	return nt->OptionalHeader.SizeOfImage;
}
