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
