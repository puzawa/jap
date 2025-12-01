#include "vuln.h"

#include "utils/pe/pe.h"
#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_interface.h"

void RelocateImageByDelta(PeRelocVec relocs, const ULONG64 delta) {
	for(int ri =0; ri < relocs.count; ri++)
	{
		PeRelocInfo current_reloc = relocs.relocs[ri];

		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*(ULONG64*)(current_reloc.address + offset) += delta;
		}
	}
}

bool ResolveImports(DriverState* driverState,PeImportVec imports) {
	for (int ii = 0; ii < imports.count; ii++) {
		PeImportInfo current_import = imports.imports[ii];
		ULONG64 Module = GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
			return false;
		}

		for (int fi = 0; fi < current_import.function_count; fi++) {
			PeImportFunctionInfo current_function_data =current_import.function_datas[fi];
			ULONG64 function_address = GetKernelModuleExport(driverState, Module, current_function_data.name);

			if (!function_address) {
				static uintptr_t ntoskrnlAddr = 0;
				if (Module != ntoskrnlAddr) {
					function_address = GetKernelModuleExport(driverState, ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
		
	}

	return true;
}


bool FixSecurityCookie(BYTE* local_image, ULONG64 kernel_image_base)
{
	PIMAGE_NT_HEADERS64 headers = PeGetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
		return true;

	PIMAGE_LOAD_CONFIG_DIRECTORY load_config_struct = local_image + load_config_directory;
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
		return true;


	stack_cookie = stack_cookie - kernel_image_base + local_image;

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232)
		return false;


	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId();
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie;
	return true;
}

bool ResolveKernelPeImage(DriverState* driverState, BYTE* data, uintptr_t kernel_image_base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = PeGetNtHeaders(data);

	if (!nt_headers) {
		log_error("invalid format of PE image");
		return false;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		log_error("image is not 64 bit");
		return false;
	}
	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	BYTE* local_image_base = malloc(image_size);
	if (!local_image_base)
		return 0;

	memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
			continue;
		void* local_section = local_image_base + current_image_section[i].VirtualAddress;
		memcpy(local_section, (void*)(data + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
	}

	ULONG64 realBase = kernel_image_base;
	RelocateImageByDelta(PeGetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);
	if (!FixSecurityCookie(local_image_base, kernel_image_base)){
		return 0;
	}

	if (!ResolveImports(driverState, PeGetImports(local_image_base))) {	
		return 0;
	}
}