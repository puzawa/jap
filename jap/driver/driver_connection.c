#include "driver_connection.h"
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