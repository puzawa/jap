#include "pe.h"
#include <stdlib.h>
#include <string.h>

#define PE_INITIAL_CAPACITY 8

PIMAGE_NT_HEADERS64 PeGetNtHeaders(void* image_base) {
	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	const PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((ULONG64)image_base + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return nt_headers;
}

PeRelocVec PeGetRelocs(void* image_base) {
	PeRelocVec relocs = { 0 };
	const PIMAGE_NT_HEADERS64 nt_headers = PeGetNtHeaders(image_base);

	if (!nt_headers)
		return relocs;

	DWORD reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (!reloc_va)
		return relocs;

	relocs.capacity = PE_INITIAL_CAPACITY;
	relocs.relocs = (struct PeRelocInfo*)malloc(relocs.capacity * sizeof(struct PeRelocInfo));
	if (!relocs.relocs)
		return relocs;

	PIMAGE_BASE_RELOCATION current_base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG64)image_base + reloc_va);
	const PIMAGE_BASE_RELOCATION reloc_end = (PIMAGE_BASE_RELOCATION)((ULONG64)current_base_relocation + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
		if (relocs.count == relocs.capacity) {
			relocs.capacity *= 2;
			void* new_mem = realloc(relocs.relocs, relocs.capacity * sizeof(struct PeRelocInfo));
			if (!new_mem) {
				PeFreeRelocs(&relocs);
				return (PeRelocVec) { 0 };
			}
			relocs.relocs = (struct PeRelocInfo*)new_mem;
		}

		struct PeRelocInfo* reloc_info = &relocs.relocs[relocs.count];

		reloc_info->address = (ULONG64)image_base + current_base_relocation->VirtualAddress;
		reloc_info->item = (USHORT*)((ULONG64)current_base_relocation + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info->count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

		relocs.count++;

		current_base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG64)current_base_relocation + current_base_relocation->SizeOfBlock);
	}

	return relocs;
}

PeImportVec PeGetImports(void* image_base) {
	PeImportVec imports = { 0 };
	const PIMAGE_NT_HEADERS64 nt_headers = PeGetNtHeaders(image_base);

	if (!nt_headers)
		return imports;

	DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!import_va)
		return imports;

	imports.capacity = PE_INITIAL_CAPACITY;
	imports.imports = (struct PeImportInfo*)malloc(imports.capacity * sizeof(struct PeImportInfo));
	if (!imports.imports)
		return imports;

	memset(imports.imports, 0, imports.capacity * sizeof(struct PeImportInfo));

	PIMAGE_IMPORT_DESCRIPTOR current_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)image_base + import_va);

	while (current_import_descriptor->FirstThunk) {
		if (imports.count == imports.capacity) {
			imports.capacity *= 2;
			void* new_mem = realloc(imports.imports, imports.capacity * sizeof(struct PeImportInfo));
			if (!new_mem) {
				PeFreeImports(&imports);
				return (PeImportVec) { 0 };
			}
			imports.imports = (struct PeImportInfo*)new_mem;
			memset(&imports.imports[imports.count], 0, (imports.capacity / 2) * sizeof(struct PeImportInfo));
		}

		struct PeImportInfo* import_info = &imports.imports[imports.count];

		const char* module_name_src = (char*)((ULONG64)image_base + current_import_descriptor->Name);
		size_t module_name_len = strlen(module_name_src) + 1;
		import_info->module_name = (char*)malloc(module_name_len);
		if (!import_info->module_name) {
			PeFreeImports(&imports);
			return (PeImportVec) { 0 };
		}
		strcpy_s(import_info->module_name, module_name_len, module_name_src);

		import_info->function_capacity = PE_INITIAL_CAPACITY;
		import_info->function_datas = (struct PeImportFunctionInfo*)malloc(import_info->function_capacity * sizeof(struct PeImportFunctionInfo));
		if (!import_info->function_datas) {
			PeFreeImports(&imports);
			return (PeImportVec) { 0 };
		}
		memset(import_info->function_datas, 0, import_info->function_capacity * sizeof(struct PeImportFunctionInfo));

		PIMAGE_THUNK_DATA64 current_first_thunk = (PIMAGE_THUNK_DATA64)((ULONG64)image_base + current_import_descriptor->FirstThunk);
		PIMAGE_THUNK_DATA64 current_originalFirstThunk = (PIMAGE_THUNK_DATA64)((ULONG64)image_base + current_import_descriptor->OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function) {
			if (import_info->function_count == import_info->function_capacity) {
				import_info->function_capacity *= 2;
				void* new_mem = realloc(import_info->function_datas, import_info->function_capacity * sizeof(struct PeImportFunctionInfo));
				if (!new_mem) {
					PeFreeImports(&imports);
					return (PeImportVec) { 0 };
				}
				import_info->function_datas = (struct PeImportFunctionInfo*)new_mem;
				memset(&import_info->function_datas[import_info->function_count], 0, (import_info->function_capacity / 2) * sizeof(struct PeImportFunctionInfo));
			}

			struct PeImportFunctionInfo* func_data = &import_info->function_datas[import_info->function_count];

			PIMAGE_IMPORT_BY_NAME thunk_data = (PIMAGE_IMPORT_BY_NAME)((ULONG64)image_base + current_originalFirstThunk->u1.AddressOfData);

			const char* func_name_src = (const char*)thunk_data->Name;
			size_t func_name_len = strlen(func_name_src) + 1;
			func_data->name = (char*)malloc(func_name_len);
			if (!func_data->name) {
				PeFreeImports(&imports);
				return (PeImportVec) { 0 };
			}
			strcpy_s(func_data->name, func_name_len, func_name_src);

			func_data->address = &current_first_thunk->u1.Function;

			import_info->function_count++;
			++current_originalFirstThunk;
			++current_first_thunk;
		}

		imports.count++;
		++current_import_descriptor;
	}

	return imports;
}

void PeFreeRelocs(PeRelocVec* reloc_vec) {
	if (!reloc_vec) return;

	free(reloc_vec->relocs);
	reloc_vec->relocs = NULL;
	reloc_vec->count = 0;
	reloc_vec->capacity = 0;
}

void PeFreeImports(PeImportVec* import_vec) {
	if (!import_vec) return;

	for (ULONG32 i = 0; i < import_vec->count; ++i) {
		struct PeImportInfo* info = &import_vec->imports[i];

		free(info->module_name);

		for (ULONG32 j = 0; j < info->function_count; ++j) {
			free(info->function_datas[j].name);
		}
		free(info->function_datas);
	}

	free(import_vec->imports);

	import_vec->imports = NULL;
	import_vec->count = 0;
	import_vec->capacity = 0;
}