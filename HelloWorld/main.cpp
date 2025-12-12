#include <ntddk.h>

#define PROC_TAG 'cOrP'

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern "C" NTSTATUS ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

//
// Frees a process information buffer allocated from non-paged pool.
//
static __forceinline
VOID FreeProcBuffer(_In_opt_ PVOID Buffer)
{
    if (Buffer) {
        ExFreePool(Buffer);
    }
}

//
// Allocates a non-paged pool buffer for process information.
//
static
NTSTATUS AllocateProcBuffer(
    _In_ ULONG Size,
    _Outptr_result_bytebuffer_(Size) PVOID* Out
)
{
    if (!Out) return STATUS_INVALID_PARAMETER;

    *Out = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Size,
        PROC_TAG
    );

    return (*Out) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

//
// Compares two UNICODE_STRING values case-insensitively.
//
static __forceinline
BOOLEAN UnicodeEqualsInsensitive(
    _In_ PCUNICODE_STRING A,
    _In_ PCUNICODE_STRING B
)
{
    if (!A || !B) return FALSE;
    if (A->Length != B->Length) return FALSE;
    return (RtlCompareUnicodeString(A, B, TRUE) == 0);
}

//
// Queries SystemProcessInformation and returns a fully populated buffer.
//
static
NTSTATUS QuerySystemProcessInfo(
    _Outptr_result_bytebuffer_(*OutSize) PVOID* OutBuffer,
    _Out_ PULONG OutSize
)
{
    if (!OutBuffer || !OutSize) return STATUS_INVALID_PARAMETER;
    *OutBuffer = nullptr;
    *OutSize = 0;

    NTSTATUS status;
    ULONG size = 0;
    PVOID buffer = nullptr;

    // Probe for required size and retry if it changes.
    for (;;) {
        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            nullptr,
            0,
            &size
        );

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return status;
        }

        status = AllocateProcBuffer(size, &buffer);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            size,
            &size
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            FreeProcBuffer(buffer);
            buffer = nullptr;
            continue;
        }

        if (!NT_SUCCESS(status)) {
            FreeProcBuffer(buffer);
            return status;
        }

        *OutBuffer = buffer;
        *OutSize = size;
        return STATUS_SUCCESS;
    }
}

//
// Iterates process list and logs entries whose image name matches TargetName.
//
static
VOID LogMatchingProcesses(
    _In_ PVOID ProcessInfoBuffer,
    _In_ PCUNICODE_STRING TargetName
)
{
    if (!ProcessInfoBuffer || !TargetName) return;

    auto cur = static_cast<PSYSTEM_PROCESS_INFORMATION>(ProcessInfoBuffer);

    for (;;) {
        if (cur->ImageName.Buffer &&
            cur->ImageName.Length &&
            UnicodeEqualsInsensitive(&cur->ImageName, TargetName))
        {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "ProcEnum: match %wZ PID=%lu\n",
                &cur->ImageName,
                (ULONG)(ULONG_PTR)cur->UniqueProcessId
            );
        }

        if (cur->NextEntryOffset == 0) break;

        cur = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PUCHAR>(cur) + cur->NextEntryOffset
            );
    }
}

//
// Driver unload routine.
//
static
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ProcEnum: Unloaded\n");
}

//
// Driver entry point; enumerates processes and logs matching ones.
//
extern "C"
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "ProcEnum: Loaded, enumerating processes...\n"
    );

    PVOID buffer = nullptr;
    ULONG bufferSize = 0;

    NTSTATUS status = QuerySystemProcessInfo(&buffer, &bufferSize);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "ProcEnum: ZwQuerySystemInformation failed: 0x%08X\n",
            status
        );
        return status;
    }

    UNICODE_STRING target = RTL_CONSTANT_STRING(L"notepad.exe");
    LogMatchingProcesses(buffer, &target);

    FreeProcBuffer(buffer);
    return STATUS_SUCCESS;
}
