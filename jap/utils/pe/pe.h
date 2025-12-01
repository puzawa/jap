#pragma once
#include <Windows.h>

typedef struct 
{
	ULONG64 address;
	USHORT* item;
	ULONG32 count;
} PeRelocInfo;

typedef struct 
{
	char* name;
	ULONG64* address;
}PeImportFunctionInfo;

typedef struct 
{
	char* module_name;
	PeImportFunctionInfo* function_datas;
	ULONG32 function_count;
	ULONG32 function_capacity;
}PeImportInfo;

typedef struct
{
	PeRelocInfo* relocs;
	ULONG32 count;
	ULONG32 capacity;
} PeRelocVec;

typedef struct
{
	PeImportInfo* imports;
	ULONG32 count;
	ULONG32 capacity;
} PeImportVec;


PIMAGE_NT_HEADERS64 PeGetNtHeaders(void* image_base);

PeRelocVec PeGetRelocs(void* image_base);

PeImportVec PeGetImports(void* image_base);

void PeFreeRelocs(PeRelocVec* reloc_vec);

void PeFreeImports(PeImportVec* import_vec);
