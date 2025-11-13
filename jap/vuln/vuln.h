#pragma once
#include "driver/driver_state.h"

#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

bool TryLoadVuln(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** pDriverState);
bool UnloadVuln(DriverState* driverState);