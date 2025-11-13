#pragma once

#include <Windows.h>
#include <wchar.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
	bool file_created;
	bool service_created;

	HANDLE hDevice;

	uintptr_t win32k_base;
	int NtUserSetGestureConfig_rva;
	uintptr_t NtUserSetGestureConfig_ref;

	const wchar_t* vuln_driver_path;
	const wchar_t* vuln_driver_name;
} DriverState;