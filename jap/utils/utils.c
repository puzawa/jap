#include "utils.h"
#include "ntdef.h"

bool CreateFileFromMemory(const wchar_t* file_path, const char* src, size_t size) {
	FILE* file = _wfopen(file_path, L"wb");
	if (!file)
		return false;

	size_t written = fwrite(src, 1, size, file);
	fclose(file);

	return written == size;
}

bool RemoveFileFromDisk(const wchar_t* file_path) {
	return _wremove(file_path) == 0;
}

uintptr_t GetKernelModuleAddress(const char* module_name) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll)
		return 0;

	NtQuerySystemInformation_t NtQuerySystemInformation =
		(NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
		return 0;


	PVOID buffer = NULL;
	ULONG buffer_size = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer)
			return 0;

		status = NtQuerySystemInformation(SystemModuleInformation, buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	PSYSTEM_MODULE_INFORMATION_2 modules = (PSYSTEM_MODULE_INFORMATION_2)buffer;
	if (!modules) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		const char* current_name = (const char*)(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);

		if (_stricmp(current_name, module_name) == 0) {
			uintptr_t result = modules->Modules[i].ImageBase;
			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

//char win32k_path[MAX_PATH];
bool GetWin32kPath(char* win32k_path_out) {
	char systemRootEnv[MAX_PATH];
	UINT len = GetSystemDirectoryA(systemRootEnv, MAX_PATH);
	if (len == 0 || len >= MAX_PATH) {
		log_error("GetSystemDirectoryA failed or buffer too small");
		return false;
	}

	if (snprintf(win32k_path_out, MAX_PATH, "%s\\win32k.sys", systemRootEnv) >= MAX_PATH) {
		return false;
	}
	return true;
}

bool bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask) {
		if (*szMask == 'x' && *pData != *bMask)
			return false;
	}
	return (*szMask) == 0;
}

uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++) {
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	}
	return 0;
}