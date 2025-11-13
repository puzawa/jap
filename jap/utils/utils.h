#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include "rxi/log.h"

#include <windows.h>
#include <winternl.h>

#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <stdbool.h>

bool CreateFileFromMemory(const wchar_t* desired_file_path, const char* address, size_t size);
bool RemoveFileFromDisk(const wchar_t* file_path);

bool RegisterAndStartService(const wchar_t* driver_name, const wchar_t* driver_path);
bool StopAndRemoveService(const wchar_t* driver_name);

bool GetWin32kPath(char* win32k_path_out);
uintptr_t GetKernelModuleAddress(const char* module_name);

uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);