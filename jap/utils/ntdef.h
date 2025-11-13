#pragma once
#include <windows.h>
#include <winternl.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef enum _SYSTEM_INFORMATION_CLASS_2 {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS_2;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY_2 {
	HANDLE Section;
	PVOID  MappedBase;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY_2, * PSYSTEM_MODULE_INFORMATION_ENTRY_2;

typedef struct _SYSTEM_MODULE_INFORMATION_2 {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY_2 Modules[1];
} SYSTEM_MODULE_INFORMATION_2, * PSYSTEM_MODULE_INFORMATION_2;

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS_2 SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING);