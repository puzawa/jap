#pragma once
#include "driver/driver_state.h"

#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

/**
 * @brief Attempts to load a vulnerable driver and initialize the DriverState structure.
 *
 * This function performs pre-initialization steps, initializes the driver by creating and starting it,
 * opens a connection to the driver, and updates necessary kernel references (like swap_ref for function hooking).
 * It sets up the environment for interacting with kernel-mode functions via a vulnerable driver.
 * If any step fails, it cleans up and returns false. On success, it marks the driver as functional (vuln_fine = true).
 *
 * @param vuln_driver_path The full path to the vulnerable driver file (wide string).
 * @param vuln_driver_name The name of the vulnerable driver (wide string).
 * @param pDriverState Pointer to a DriverState pointer that will be allocated and initialized on success.
 * @return true if the driver was successfully loaded and initialized, false otherwise.
 */
bool TryLoadVuln(const wchar_t* vuln_driver_path, const wchar_t* vuln_driver_name, DriverState** pDriverState);

/**
 * @brief Unloads the vulnerable driver and cleans up the DriverState.
 *
 * This function closes the driver connection and attempts to stop and remove the driver service.
 * It is a wrapper around RemoveDriver and should be called to properly unload resources.
 *
 * @param driverState The DriverState structure representing the loaded driver.
 * @return true if unloading was successful, false otherwise.
 */
bool UnloadVuln(DriverState* driverState);

/**
 * @brief Calls a kernel function by temporarily hooking/swapping a reference in kernel memory.
 *
 * This function uses a pre-set swap mechanism (via swap_ref and swap_u) to redirect a kernel call.
 * It reads the original swap pointer, writes the target function address to it, invokes the user-mode stub
 * with up to 6 arguments, captures the return value, and restores the original swap pointer.
 * If return_out is NULL, a dummy return variable is used. It supports up to 6 arguments; extras are ignored.
 *
 * @param driverState The DriverState structure with swap configuration.
 * @param faddress The kernel address of the function to call.
 * @param return_out Pointer to store the return value of the kernel function (can be NULL).
 * @param args_count Number of arguments provided (up to 6).
 * @param args Array of uintptr_t arguments to pass to the kernel function.
 * @return true if the call was successful and memory restored, false on failure.
 */
bool CallKernelFunction(
    DriverState* driverState,
    uintptr_t faddress,
    uintptr_t* return_out, size_t args_count, uintptr_t* args
);

/**
 * @brief Maps a PE image into kernel memory and returns the address of its entry point.
 *
 * This function allocates kernel memory for the PE image, copies and relocates the image sections,
 * resolves imports from kernel modules (like ntoskrnl.exe), handles security cookie fixes (commented out),
 * writes the prepared image to kernel space, and computes the entry point address.
 * It uses ExAllocatePoolWithTag for allocation and relies on helper functions for PE parsing and memory operations.
 *
 * @param driverState The DriverState for kernel interactions (e.g., memory read/write, module exports).
 * @param image_in The raw byte array of the PE image to map.
 * @return The kernel address of the entry point on success, or 0 on failure.
 */
PVOID MMapKernelPeImage(DriverState* driverState, BYTE* image_in);