#include "vuln.h"
#include "utils/pe/pe.h"
#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_interface.h"


void RelocateImageByDelta(PeRelocVec relocs, const ULONG64 delta) {
	for (int ri = 0; ri < relocs.count; ri++)
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

bool ResolveImports(DriverState* driverState, PeImportVec imports) {
	for (int ii = 0; ii < imports.count; ii++) {
		PeImportInfo current_import = imports.imports[ii];
		ULONG64 Module = GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
			return false;
		}

		for (int fi = 0; fi < current_import.function_count; fi++) {
			PeImportFunctionInfo current_function_data = current_import.function_datas[fi];
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

			log_info("in %s resolved %s ptr: %p", current_import.module_name, current_function_data.name, function_address);
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

PVOID ExAllocatePoolWithTag_ptr = 0;
PVOID ExAllocatePoolWithTag(DriverState* driverState, int PoolType, SIZE_T NumberOfBytes, ULONG Tag) {

	if (!ExAllocatePoolWithTag_ptr) {
		uintptr_t ntosbase = GetKernelModuleAddress("ntoskrnl.exe");
		ExAllocatePoolWithTag_ptr = GetKernelModuleExport(driverState, ntosbase, "ExAllocatePoolWithTag");
	}

	if (!ExAllocatePoolWithTag_ptr)
		return 0;

	uintptr_t args[3] = { PoolType, NumberOfBytes, Tag};
	uintptr_t out = ExAllocatePoolWithTag_ptr;
	CallKernelFunction(driverState, ExAllocatePoolWithTag_ptr, &out, 3, args);
	return out;
}

PVOID MMapKernelPeImage(DriverState* driverState, BYTE* image_in)
{
	const PIMAGE_NT_HEADERS64 nt_headers = PeGetNtHeaders(image_in);

	if (!nt_headers) {
		log_error("invalid format of PE image");
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		log_error("image is not 64 bit");
		return 0;
	}
	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	BYTE* local_image_base = malloc(image_size);
	if (!local_image_base)
		return 0;

	memcpy(local_image_base, image_in, nt_headers->OptionalHeader.SizeOfHeaders);

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
			continue;

		void* local_section = local_image_base + current_image_section[i].VirtualAddress;
		memcpy(local_section, (void*)(image_in + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
	}

	
	uintptr_t kernel_image_base = ExAllocatePoolWithTag(driverState,0, image_size, 'enoN');
	RelocateImageByDelta(PeGetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);
	
	//if (!FixSecurityCookie(local_image_base, kernel_image_base)) {
	//	return 0;
	//}

	if (!ResolveImports(driverState, PeGetImports(local_image_base))) {
		return 0;
	}

	if (!WriteMemory(driverState, kernel_image_base, local_image_base, image_size)) {
		return 0;
	}

	const uintptr_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

	free(local_image_base);
	return address_of_entry_point;

}