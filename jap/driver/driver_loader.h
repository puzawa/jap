#pragma once
#include "driver_state.h"

#include <windows.h>
#include <winternl.h>

#include <stdio.h>
#include <stdbool.h>

// Creates the vulnerable driver file on disk, registers it as a service,
// and starts the driver
bool CreateAndStartDriver(const DriverState* driverState);

// Stops the driver service if running and removes both the service and driver file
bool TryStopAndRemoveDriver(const DriverState* driverState);
