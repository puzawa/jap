#include "utils/utils.h"
#include "utils/pe/pe.h"

#include "vuln/vuln.h"
#include "driver/driver_interface.h"

#define DLL_EXPORT __declspec(dllexport)

DLL_EXPORT
bool eCallKernelFunction(
	DriverState* driverState,
	uintptr_t faddress,
	uintptr_t* return_out, size_t args_count, uintptr_t* args
)
{
	if (!driverState || !faddress) {
		log_error("driverState/faddress cant be empty");
		return false;
	}
	if ((args_count > 0) && !args)
	{
		log_error("invalid args");
		return false;
	}

	return CallKernelFunction(driverState, faddress, return_out, args_count, args);
}

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

DLL_EXPORT
PIMAGE_NT_HEADERS64 ePeGetNtHeaders(void* image_base) {
	if (!image_base) {
		log_error("ePeGetNtHeaders: image_base is NULL");
		return NULL;
	}
	return PeGetNtHeaders(image_base);
}

DLL_EXPORT
PeRelocVec ePeGetRelocs(void* image_base) {
	PeRelocVec empty = { 0 };

	if (!image_base) {
		log_error("ePeGetRelocs: image_base is NULL");
		return empty;
	}
	return PeGetRelocs(image_base);
}

DLL_EXPORT
PeImportVec ePeGetImports(void* image_base) {
	PeImportVec empty = { 0 };

	if (!image_base) {
		log_error("ePeGetImports: image_base is NULL");
		return empty;
	}
	return PeGetImports(image_base);
}

DLL_EXPORT
void ePeFreeImports(PeImportVec* imports) {
	if (!imports) {
		log_error("ePeFreeImports: imports pointer is NULL");
		return;
	}
	PeFreeImports(imports);
}

DLL_EXPORT
void ePeFreeRelocs(PeRelocVec* imports) {
	if (!imports) {
		log_error("ePeFreeRelocs: imports pointer is NULL");
		return;
	}
	PeFreeRelocs(imports);
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