#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_interface.h"

#include "EasyPdb.h"

int main() {
	log_set_level(LOG_TRACE);

	char win32k_path[MAX_PATH];
	GetWin32kPath(win32k_path);

	log_info("win32k path: %s", win32k_path);

	int NtUserSetGestureConfig_rva = EzPdbGetRva(win32k_path, "NtUserSetGestureConfig");
	log_info("rva: %d", NtUserSetGestureConfig_rva);

	LoadLibraryA("user32.dll");
	LoadLibraryA("win32u.dll");
	uintptr_t win32k = GetKernelModuleAddress("win32k.sys");
	log_info("win32k base: %p\n", win32k);


	const wchar_t* vuln_driver_path = L"C:\\temp\\temp.sys";
	const wchar_t* vuln_driver_name = L"tempdrv";

	DriverState* driverState = malloc(sizeof(DriverState));
	driverState->vuln_driver_name = vuln_driver_name;
	driverState->vuln_driver_path = vuln_driver_path;

	CreateAndStartDriver(driverState);
	OpenDriverConnection(driverState);


	uintptr_t NtUserSetGestureConfig = win32k + NtUserSetGestureConfig_rva;

	uintptr_t nt_qword = FindPatternAtKernel(driverState, NtUserSetGestureConfig, 0x100, "\x48\x8B\x05", "xxx");
	log_info("nt_qword: %p\n", nt_qword);

	int  nt_qword_offset = 0;
	ReadMemory(driverState, nt_qword + 3, &nt_qword_offset, sizeof(int));
	log_info("nt_qword_offset: %d\n", nt_qword_offset);

	uintptr_t NtUserSetGestureConfig_ref = nt_qword + nt_qword_offset + 7;
	log_info("NtUserSetGestureConfig_ref: %p\n", NtUserSetGestureConfig_ref);

	CloseDriverConnection(driverState);
	TryStopAndRemoveDriver(driverState);

	return 0;
}