#pragma once
#include <wchar.h>
#include <stdbool.h>

typedef struct {
	bool file_created;
	bool service_created;

	const wchar_t* vuln_driver_path;
	const wchar_t* vuln_driver_name;
} DriverState;