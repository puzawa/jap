#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include "rxi/log.h"

#include <windows.h>
#include <winternl.h>

#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <stdbool.h>

// Writes a binary blob from memory to disk as a file
bool CreateFileFromMemory(const wchar_t* desired_file_path, const char* address, size_t size);

// Deletes a file from disk
bool RemoveFileFromDisk(const wchar_t* file_path);

// Registers a kernel driver as a system service and starts it
bool RegisterAndStartService(const wchar_t* driver_name, const wchar_t* driver_path);

// Stops a driver service and removes it from the system
bool StopAndRemoveService(const wchar_t* driver_name);

// Retrieves the full path to the win32k kernel module
bool GetWin32kPath(char* win32k_path_out);

// Returns the base address of a loaded kernel module by name
uintptr_t GetKernelModuleAddress(const char* module_name);

// Scans a memory region for a byte pattern using a mask
uintptr_t FindPattern(
    uintptr_t dwAddress,
    uintptr_t dwLen,
    BYTE* bMask,
    const char* szMask
);
