#pragma once

#include <Windows.h>
#include <wchar.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
	bool file_created;
	bool service_created;
	bool vuln_fine;

	HANDLE hDevice;

	uintptr_t swap_module_base;
	int swap_rva;
	uintptr_t swap_ref;
	uintptr_t swap_u;

	const wchar_t* vuln_driver_path;
	const wchar_t* vuln_driver_name;
} DriverState;