#pragma once
#include "driver_state.h"

#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>


bool OpenDriverConnection(DriverState* driverState);
bool CloseDriverConnection(DriverState* driverState);

bool ReadMemory(DriverState* driverState, uintptr_t address, void* buffer, size_t size);
bool WriteMemory(DriverState* driverState, uintptr_t address, const void* buffer, size_t size);

uintptr_t FindPatternAtKernel(DriverState* driverState, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
uintptr_t GetKernelModuleExport(DriverState* driverState, uint64_t kernel_module_base, const char* function_name);