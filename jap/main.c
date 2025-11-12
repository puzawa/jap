#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_connection.h"

#include "EasyPdb.h"

int main() {
	log_set_level(LOG_TRACE);

    char systemRootEnv[MAX_PATH];
    char win32k_path[MAX_PATH];

    UINT len = GetSystemDirectoryA(systemRootEnv, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        fprintf(stderr, "GetSystemDirectoryA failed or buffer too small\n");
        return 1;
    }

    if (snprintf(win32k_path, MAX_PATH, "%s\\win32k.sys", systemRootEnv) >= MAX_PATH) {
        fprintf(stderr, "Resulting path was truncated\n");
        return 1;
    }

    printf("win32k path: %s\n", win32k_path);

	int rva = EzPdbGetRva(win32k_path, "NtUserSetGestureConfig");
    log_info("rva: %d", rva);
    return 0;

	const wchar_t* vuln_driver_path = L"C:\\temp\\temp.sys";
	const wchar_t* vuln_driver_name = L"tempdrv";

	DriverState* driverState = malloc(sizeof(DriverState));
	driverState->vuln_driver_name = vuln_driver_name;
	driverState->vuln_driver_path = vuln_driver_path;

	CreateAndStartDriver(driverState);
	OpenDriverConnection(driverState);

	CloseDriverConnection(driverState);
	TryStopAndRemoveDriver(driverState);

	return 0;
}