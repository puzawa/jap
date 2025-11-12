#pragma once

#include "driver_state.h"

#include <windows.h>
#include <winternl.h>

#include <stdio.h>
#include <stdbool.h>

bool CreateAndStartDriver(const DriverState* driverState);
bool StopAndRemoveDriver(const DriverState* driverState);