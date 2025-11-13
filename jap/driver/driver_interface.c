#include "driver_interface.h"
#include "utils/utils.h"


typedef struct
{
	unsigned char gap1[8];
	unsigned long long address;
	unsigned char gap2[4];
	unsigned int offset;
	unsigned int size;
	unsigned int data;
	unsigned char gap3[16];
} ComPacket;

bool OpenDriverConnection(DriverState* driverState) {
	driverState->hDevice = CreateFile(
		L"\\\\.\\RTCore64",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (driverState->hDevice == INVALID_HANDLE_VALUE) {
		log_error("Failed to open driver connection");
		return false;
	}
	log_info("Driver connection openned handle: %p", driverState->hDevice);

	return true;
}

bool CloseDriverConnection(DriverState* driverState) {
	if (driverState->hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(driverState->hDevice);
		driverState->hDevice = INVALID_HANDLE_VALUE;
		return true;
	}
	return false;
}


bool ReadMemory(DriverState* driverState, uintptr_t address, void* buffer, size_t size)
{
	unsigned char* dst = (unsigned char*)buffer;
	size_t remaining = size;

	while (remaining > 0)
	{
		ComPacket packet = { 0 };
		packet.address = address;
		packet.size = (remaining > 4) ? 4 : (unsigned int)remaining;

		if (!DeviceIoControl(driverState->hDevice, 0x80002048, &packet, sizeof(packet),
			&packet, sizeof(packet), NULL, NULL))
		{
			return false;
		}

		for (unsigned int i = 0; i < packet.size; i++)
		{
			dst[i] = (packet.data >> (i * 8)) & 0xFF;
		}

		dst += packet.size;
		address += packet.size;
		remaining -= packet.size;
	}

	return true;
}

bool WriteMemory(DriverState* driverState, uintptr_t address, const void* buffer, size_t size)
{
	const unsigned char* src = (const unsigned char*)buffer;
	size_t remaining = size;

	while (remaining > 0)
	{
		ComPacket packet = { 0 };
		packet.address = address;
		packet.size = (remaining > 4) ? 4 : (unsigned int)remaining;

		packet.data = 0;
		for (unsigned int i = 0; i < packet.size; i++)
		{
			packet.data |= ((unsigned int)src[i]) << (i * 8);
		}

		if (!DeviceIoControl(driverState->hDevice, 0x8000204C, &packet, sizeof(packet),
			&packet, sizeof(packet), NULL, NULL))
		{
			return false;
		}

		src += packet.size;
		address += packet.size;
		remaining -= packet.size;
	}

	return true;
}

uintptr_t FindPatternAtKernel(DriverState* driverState, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		log_error("No module address to find pattern");
		return 0;
	}

	if (dwLen > 1024ULL * 1024ULL * 1024ULL) { // > 1 GB
		log_error("Can't find pattern, too big section");
		return 0;
	}

	BYTE* sectionData = (BYTE*)malloc(dwLen);
	if (!sectionData) {
		log_error(L"Memory allocation failed");
		return 0;
	}

	if (!ReadMemory(driverState, dwAddress, sectionData, dwLen)) {
		log_error(L"Read failed in FindPatternAtKernel");
		free(sectionData);
		return 0;
	}

	uintptr_t result = FindPattern((uintptr_t)sectionData, dwLen, bMask, szMask);
	if (result == 0) {
		log_error(L"Can't find pattern");
		free(sectionData);
		return 0;
	}

	result = dwAddress - (uintptr_t)sectionData + result;
	free(sectionData);
	return result;
}

uintptr_t GetKernelModuleExport(DriverState* driverState, uint64_t kernel_module_base, const char* function_name)
{
	if (!kernel_module_base || !function_name)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(driverState, (void*)kernel_module_base, &dos_header, sizeof(dos_header)) ||
		dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	if (!ReadMemory(driverState, (void*)(kernel_module_base + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers)) ||
		nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const DWORD export_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const DWORD export_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_rva || !export_size)
		return 0;

	PIMAGE_EXPORT_DIRECTORY export_data = (PIMAGE_EXPORT_DIRECTORY)VirtualAlloc(NULL, export_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!export_data)
		return 0;

	if (!ReadMemory(driverState, (void*)(kernel_module_base + export_rva), export_data, export_size)) {
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	uint64_t delta = (uint64_t)export_data - export_rva;

	uint32_t* name_table = (uint32_t*)(export_data->AddressOfNames + delta);
	uint16_t* ordinal_table = (uint16_t*)(export_data->AddressOfNameOrdinals + delta);
	uint32_t* function_table = (uint32_t*)(export_data->AddressOfFunctions + delta);

	for (DWORD i = 0; i < export_data->NumberOfNames; i++) {
		char* current_function_name = (char*)(name_table[i] + delta);

		if (_stricmp(current_function_name, function_name) == 0) {
			uint16_t function_ordinal = ordinal_table[i];

			if (function_table[function_ordinal] <= 0x1000) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0;
			}

			uint64_t function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_rva &&
				function_address <= kernel_module_base + export_rva + export_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0;
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}
