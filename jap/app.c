#include "utils/utils.h"
#include "vuln/vuln.h"
#include "driver/driver_interface.h"


int main() {
	log_set_level(LOG_TRACE);

	const wchar_t* vuln_driver_path = L"C:\\temp\\temp.sys";
	const wchar_t* vuln_driver_name = L"tempdrv";

	DriverState* driverState = NULL;
	if (!TryLoadVuln(vuln_driver_path, vuln_driver_name, &driverState))
		return 1;

	uintptr_t ntos = GetKernelModuleAddress("ntoskrnl.exe");
	if (ntos) {
		log_info("ntos: %p", ntos);
		uintptr_t test_export = GetKernelModuleExport(driverState, ntos, "ExAllocatePoolWithTag");
		log_info("test_export: %p", test_export);

	}
	UnloadVuln(driverState);

	return 0;
}