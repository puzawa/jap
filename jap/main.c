#include "utils/utils.h"
#include "driver/driver_loader.h"
int main() {
	log_set_level(LOG_TRACE);

	const wchar_t* vuln_driver_path = L"C:\\temp\\temp.sys";
	const wchar_t* vuln_driver_name = L"tempdrv";

	DriverState* driverState = malloc(sizeof(DriverState));
	driverState->vuln_driver_name = vuln_driver_name;
	driverState->vuln_driver_path = vuln_driver_path;

	CreateAndStartDriver(driverState);


	StopAndRemoveDriver(driverState);

	return 0;
}