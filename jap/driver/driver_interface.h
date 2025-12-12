#pragma once
#include "driver_state.h"

#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>


// Opens a handle to the RTCore64 driver device
bool OpenDriverConnection(DriverState* driverState);

// Closes the driver device handle
bool CloseDriverConnection(DriverState* driverState);

// Reads arbitrary memory using the driver (supports kernel memory)
bool ReadMemory(DriverState* driverState, uintptr_t address, void* buffer, size_t size);

// Writes data to arbitrary memory using the driver
bool WriteMemory(DriverState* driverState, uintptr_t address, const void* buffer, size_t size);

// Scans a kernel memory region for a byte pattern using a mask
uintptr_t FindPatternAtKernel(
    DriverState* driverState,
    uintptr_t dwAddress,
    uintptr_t dwLen,
    BYTE* bMask,
    const char* szMask
);

// Resolves the address of an exported kernel function by name
uintptr_t GetKernelModuleExport(
    DriverState* driverState,
    uint64_t kernel_module_base,
    const char* function_name
);
