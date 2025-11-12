#pragma once

#include <Windows.h>
#include <wchar.h>
#include <stdbool.h>

typedef struct {
	bool file_created;
	bool service_created;

	HANDLE hDevice;

	const wchar_t* vuln_driver_path;
	const wchar_t* vuln_driver_name;
} DriverState;