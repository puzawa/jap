#pragma once
#include "driver/driver_state.h"

#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

bool TryLoadVuln(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** pDriverState);
bool UnloadVuln(DriverState* driverState);

bool CallKernelFunction(
	DriverState* driverState,
	uintptr_t faddress,
	uintptr_t* return_out, size_t args_count, uintptr_t* args
);

PVOID MMapKernelPeImage(DriverState* driverState, BYTE* image_in);