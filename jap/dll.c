#include "utils/utils.h"
#include "vuln/vuln.h"
#include "driver/driver_interface.h"

#define DLL_EXPORT __declspec(dllexport)

DLL_EXPORT
bool eTryLoadVuln(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** pDriverState) {
	if (!pDriverState) {
		log_error("pDriverState cant be empty");
		return false;
	}

	return TryLoadVuln(vuln_driver_path, vuln_driver_name, pDriverState);
}

DLL_EXPORT
bool eUnloadVuln(DriverState* driverState) {
	return UnloadVuln(driverState);
}

DLL_EXPORT
uintptr_t eGetKernelModuleAddress(const char* module_name) {
	return GetKernelModuleAddress(module_name);
}

DLL_EXPORT
uintptr_t eGetKernelModuleExport(DriverState* driverState, uint64_t kernel_module_base, const char* function_name) {
	if (!driverState || !driverState->vuln_fine) {
		log_error("eGetKernelModuleExport wrong driverState");
		return 0;
	}
	return GetKernelModuleExport(driverState, kernel_module_base, function_name);
}

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		log_set_level(LOG_TRACE);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}