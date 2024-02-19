#include <windows.h>
#include <winternl.h>
#include "memory.h"
#include "utils.h"
#include <TlHelp32.h>

bool Compare(uint8* data, uint8 *sig, uint32 size) {
  for (uint32 i = 0; i < size; i++) {
    if (data[i] != sig[i] && sig[i] != 0x00) {
      return false;
    }
  }
  return true;
}

uint8* FindSignature(void* start, void* end, const char* sig, uint32 size) {
  for (uint8* it = (uint8*)start; it < (uint8*)end - size; it++) {
    if (Compare(it, (uint8*)sig, size)) {
      return it;
    };
  }
  return 0;
}

void* FindPointer(void* start, void* end, const char* sig, uint32 size, int32 addition) {
  uint8* address = FindSignature(start, end, sig, size);
  if (!address) return nullptr;
  int32 k;
  for (k = 0; sig[k]; k++);
  int32 offset = *(int32*)(address + k);
  return address + k + 4 + offset + addition;
}

void IterateExSections(void* data, std::function<bool(void*, void*)> callback) {
  auto dos = (PIMAGE_DOS_HEADER)data;
  auto nt = (PIMAGE_NT_HEADERS)((uint8*)data + dos->e_lfanew);
  auto s = IMAGE_FIRST_SECTION(nt);
  for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
    if (s->Characteristics & IMAGE_SCN_CNT_CODE) {
      auto start = (uint8*)data + s->VirtualAddress;
      auto end = start + s->SizeOfRawData;
      if (callback(start, end)) break;
    }
  }
}

uint32 GetProccessPath(uint32 pid, wchar_t* processName, uint32 size) {
#ifdef DRV
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Failed to create process snapshot. Error code: %u\n", GetLastError());
		return 1;
	}

	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnapshot, &processEntry)) {
		do {
			if (processEntry.th32ProcessID == pid) {
				processName = processEntry.szExeFile;
				size = processEntry.dwSize;
				break;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}

	CloseHandle(hSnapshot);
	return size;
#else
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
  if (!QueryFullProcessImageNameW(hProcess, 0, processName, (DWORD*)(&size))) size = 0;
  CloseHandle(hProcess);
  return size;
#endif
}

uint64 GetTime() {
  LARGE_INTEGER ret;
  NtQuerySystemTime(&ret);
  return ret.QuadPart;
}
