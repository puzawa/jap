#include <ntddk.h>

NTSTATUS DriverEntry()
{	
	DbgPrintEx(0, 0, "Hello world!");

	return 0xDEAD;
}