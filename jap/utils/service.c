#include "utils.h"

#include <winreg.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING);


bool RegisterAndStartService(const wchar_t* driver_name, const wchar_t* driver_path) {
	if (!driver_name || !driver_path)
		return false;

	const DWORD ServiceTypeKernel = 1;
	bool result = false;

	size_t services_len = wcslen(L"SYSTEM\\CurrentControlSet\\Services\\") + wcslen(driver_name) + 1;
	wchar_t* servicesPath = malloc(services_len * sizeof(wchar_t));
	if (!servicesPath) return false;
	wcscpy_s(servicesPath, services_len, L"SYSTEM\\CurrentControlSet\\Services\\");
	wcscat_s(servicesPath, services_len, driver_name);

	size_t npath_len = wcslen(L"\\??\\") + wcslen(driver_path) + 1;
	wchar_t* nPath = malloc(npath_len * sizeof(wchar_t));
	if (!nPath) { free(servicesPath); return false; }
	wcscpy_s(nPath, npath_len, L"\\??\\");
	wcscat_s(nPath, npath_len, driver_path);

	HKEY key;
	LSTATUS reg_status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath, &key);
	if (reg_status != ERROR_SUCCESS) {
		log_error("Failed to create service registry key: 0x%lX", (unsigned long)reg_status);
		goto cleanup;
	}

	DWORD imagePathSize = (DWORD)((wcslen(nPath) + 1) * sizeof(wchar_t));
	reg_status = RegSetKeyValueW(key, NULL, L"ImagePath", REG_EXPAND_SZ, nPath, imagePathSize);
	if (reg_status != ERROR_SUCCESS) {
		log_error("Failed to set ImagePath value: 0x%lX", (unsigned long)reg_status);
		RegCloseKey(key);
		goto cleanup;
	}

	reg_status = RegSetKeyValueW(key, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (reg_status != ERROR_SUCCESS) {
		log_error("Failed to set Type value: 0x%lX", (unsigned long)reg_status);
		RegCloseKey(key);
		goto cleanup;
	}

	RegCloseKey(key);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		log_error("Failed to get ntdll handle.");
		goto cleanup;
	}

	RtlAdjustPrivilege_t RtlAdjustPrivilege =
		(RtlAdjustPrivilege_t)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	NtLoadDriver_t NtLoadDriver =
		(NtLoadDriver_t)GetProcAddress(ntdll, "NtLoadDriver");

	if (!RtlAdjustPrivilege || !NtLoadDriver) {
		log_error("Failed to get required functions from ntdll.");
		goto cleanup;
	}

	BOOLEAN wasEnabled;
	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10;
	NTSTATUS status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &wasEnabled);
	if (!NT_SUCCESS(status)) {
		log_error("Failed to acquire SeLoadDriverPrivilege: 0x%lX", (unsigned long)status);
		goto cleanup;
	}

	size_t reg_len = wcslen(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + wcslen(driver_name) + 1;
	wchar_t* regPath = malloc(reg_len * sizeof(wchar_t));
	if (!regPath) goto cleanup;
	wcscpy_s(regPath, reg_len, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscat_s(regPath, reg_len, driver_name);

	UNICODE_STRING us;
	RtlInitUnicodeString(&us, regPath);
	status = NtLoadDriver(&us);

	log_info("NtLoadDriver Status: 0x%08lX", (unsigned long)status);

	if (status == 0xC0000603) {
		log_warn("STATUS_IMAGE_CERT_REVOKED: Vulnerable driver blocklist active.");
	}

	result = NT_SUCCESS(status) || (status == 0xC000010E);
	free(regPath);

cleanup:
	free(servicesPath);
	free(nPath);
	return result;
}

bool StopAndRemoveService(const wchar_t* driver_name) {
	if (!driver_name)
		return false;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		log_error("Failed to get ntdll handle.");
		return false;
	}

	NtUnloadDriver_t NtUnloadDriver =
		(NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");
	if (!NtUnloadDriver) {
		log_error("NtUnloadDriver not found.");
		return false;
	}

	size_t reg_len = wcslen(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + wcslen(driver_name) + 1;
	wchar_t* regPath = malloc(reg_len * sizeof(wchar_t));
	if (!regPath) return false;
	wcscpy_s(regPath, reg_len, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscat_s(regPath, reg_len, driver_name);

	UNICODE_STRING us;
	RtlInitUnicodeString(&us, regPath);

	NTSTATUS st = NtUnloadDriver(&us);

	log_info("NtUnloadDriver Status: 0x%08lX", (unsigned long)st);

	size_t svc_len = wcslen(L"SYSTEM\\CurrentControlSet\\Services\\") + wcslen(driver_name) + 1;
	wchar_t* svcPath = malloc(svc_len * sizeof(wchar_t));
	if (svcPath) {
		wcscpy_s(svcPath, svc_len, L"SYSTEM\\CurrentControlSet\\Services\\");
		wcscat_s(svcPath, svc_len, driver_name);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, svcPath);
		free(svcPath);
	}

	free(regPath);
	return (st == 0 || NT_SUCCESS(st));
}
