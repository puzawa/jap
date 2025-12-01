#pragma once
#include <Windows.h>

struct PeRelocInfo
{
	ULONG64 address;
	USHORT* item;
	ULONG32 count;
};

struct PeImportFunctionInfo
{
	char* name;
	ULONG64* address;
};

struct PeImportInfo
{
	char* module_name; 
	struct PeImportFunctionInfo* function_datas;
	ULONG32 function_count;
	ULONG32 function_capacity;
};

typedef struct
{
	struct PeRelocInfo* relocs;
	ULONG32 count;
	ULONG32 capacity;
} PeRelocVec;

typedef struct
{
	struct PeImportInfo* imports;
	ULONG32 count;
	ULONG32 capacity;
} PeImportVec;


PIMAGE_NT_HEADERS64 PeGetNtHeaders(void* image_base);

PeRelocVec PeGetRelocs(void* image_base);

PeImportVec PeGetImports(void* image_base);

void PeFreeRelocs(PeRelocVec* reloc_vec);

void PeFreeImports(PeImportVec* import_vec);
