#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <cstdio>

//
// ============================================================
//  Thread enumeration via NtQuerySystemInformation class 5.
//
//  SystemProcessInformation returns a linked list of process
//  entries each containing an embedded SYSTEM_THREAD_INFORMATION
//  array. Gives start address, thread state, wait reason,
//  and context switch count for every thread in the system.
// ============================================================
//

typedef NTSTATUS
(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
    );

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;     // kernel-side entry (RtlUserThreadStart wrapper)
    CLIENT_ID     ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;      // 0=init 1=ready 2=running 3=standby 4=terminated 5=wait
    ULONG         WaitReason;
} MY_SYSTEM_THREAD_INFORMATION, * PMY_SYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION_FULL {
    ULONG                        NextEntryOffset;
    ULONG                        NumberOfThreads;
    LARGE_INTEGER                WorkingSetPrivateSize;
    ULONG                        HardFaultCount;
    ULONG                        NumberOfThreadsHighWatermark;
    ULONGLONG                    CycleTime;
    LARGE_INTEGER                CreateTime;
    LARGE_INTEGER                UserTime;
    LARGE_INTEGER                KernelTime;
    UNICODE_STRING               ImageName;
    LONG                         BasePriority;
    HANDLE                       UniqueProcessId;
    HANDLE                       InheritedFromUniqueProcessId;
    ULONG                        HandleCount;
    ULONG                        SessionId;
    ULONG_PTR                    UniqueProcessKey;
    SIZE_T                       PeakVirtualSize;
    SIZE_T                       VirtualSize;
    ULONG                        PageFaultCount;
    SIZE_T                       PeakWorkingSetSize;
    SIZE_T                       WorkingSetSize;
    SIZE_T                       QuotaPeakPagedPoolUsage;
    SIZE_T                       QuotaPagedPoolUsage;
    SIZE_T                       QuotaPeakNonPagedPoolUsage;
    SIZE_T                       QuotaNonPagedPoolUsage;
    SIZE_T                       PagefileUsage;
    SIZE_T                       PeakPagefileUsage;
    SIZE_T                       PrivatePageCount;
    LARGE_INTEGER                ReadOperationCount;
    LARGE_INTEGER                WriteOperationCount;
    LARGE_INTEGER                OtherOperationCount;
    LARGE_INTEGER                ReadTransferCount;
    LARGE_INTEGER                WriteTransferCount;
    LARGE_INTEGER                OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION_FULL, * PSYSTEM_PROCESS_INFORMATION_FULL;

VOID
EnumThreadsNtQuerySystem(
    _In_ DWORD TargetPid
)
{
    CONST PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );

    if (NtQuerySystemInformation == NULL)
    {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        return;
    }

    printf("[*] NtQuerySystemInformation (SystemProcessInformation)\n\n");

    ULONG    BufferSize = 0;
    PVOID    Buffer = NULL;
    NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;

    //
    // Grow the buffer until it fits the entire system process list.
    //
    while (Status == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (Buffer != NULL) HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize += 65536);
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize);
    }

    if (!NT_SUCCESS(Status))
    {
        printf("[-] NtQuerySystemInformation failed: 0x%08X\n", Status);
        HeapFree(GetProcessHeap(), 0, Buffer);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION_FULL Entry =
        (PSYSTEM_PROCESS_INFORMATION_FULL)Buffer;

    while (TRUE)
    {
        if ((DWORD)(ULONG_PTR)Entry->UniqueProcessId == TargetPid)
        {
            printf(
                "  Process : %ws  PID: %llu  Threads: %d\n\n",
                Entry->ImageName.Buffer ? Entry->ImageName.Buffer : L"<system>",
                (ULONG_PTR)Entry->UniqueProcessId,
                Entry->NumberOfThreads
            );

            LPCSTR StateStr[] = {
                "Initialized", "Ready", "Running",
                "Standby", "Terminated", "Wait",
                "Transition", "Unknown"
            };

            for (ULONG i = 0; i < Entry->NumberOfThreads; i++)
            {
                PMY_SYSTEM_THREAD_INFORMATION Thread = &Entry->Threads[i];
                DWORD State = Thread->ThreadState < 8 ? Thread->ThreadState : 7;

                printf(
                    "  TID: %-6llu  Start: %p  State: %-12s  CtxSwitches: %d\n",
                    (ULONG_PTR)Thread->ClientId.UniqueThread,
                    Thread->StartAddress,
                    StateStr[State],
                    Thread->ContextSwitches
                );
            }

            break;
        }

        if (Entry->NextEntryOffset == 0) break;

        Entry = (PSYSTEM_PROCESS_INFORMATION_FULL)
            ((PBYTE)Entry + Entry->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    printf("\n");
}

INT
main(
    VOID
)
{
    CONST DWORD TargetPid = GetCurrentProcessId();

    printf("[+] Enumerating threads for PID: %d\n\n", TargetPid);

    EnumThreadsNtQuerySystem(TargetPid);

    return 0;
}
