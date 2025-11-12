#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include "logging/log.h"

#include <windows.h>

#include <stdio.h>
#include <wchar.h>
#include <stdbool.h>

bool CreateFileFromMemory(const wchar_t* desired_file_path, const char* address, size_t size);
bool RemoveFileFromDisk(const wchar_t* file_path);