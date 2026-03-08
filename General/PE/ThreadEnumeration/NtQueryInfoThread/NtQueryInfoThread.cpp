#define WIN32_NO_STATUS
#include<Windows.h>
#undef WIN32_NO_STATUS
#include<ntstatus.h>
#include<winternl.h>
#include<cstdio>

//
// ============================================================
//  Thread enumeration via NtQueryInformationThread.
//
//  Combines NtGetNextThread iteration with two per-thread
//  queries:
//    Class 0 (ThreadBasicInformation) — TEB address, affinity
//    Class 9 (Win32StartAddress)      — real user callback
//
//  Class 9 is the actual function passed to CreateThread.
//  NtQuerySystemInformation's StartAddress always points to
//  RtlUserThreadStart (the ntdll wrapper) — class 9 skips
//  past it to the real function pointer.
// ============================================================
//

typedef NTSTATUS
(NTAPI* PFN_NT_GET_NEXT_THREAD)(
    _In_     HANDLE       ProcessHandle,
    _In_opt_ HANDLE       ThreadHandle,
    _In_     ACCESS_MASK  DesiredAccess,
    _In_     ULONG        HandleAttributes,
    _In_     ULONG        Flags,
    _Out_    PHANDLE      NewThreadHandle
    );

typedef NTSTATUS
(NTAPI* PFN_NT_QUERY_INFORMATION_THREAD)(
    _In_      HANDLE ThreadHandle,
    _In_      ULONG  ThreadInformationClass,
    _Out_     PVOID  ThreadInformation,
    _In_      ULONG  ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

//
// ThreadBasicInformation  — TEB, client ID, affinity, priority.
// ThreadQuerySetWin32StartAddress — real Win32 callback pointer.
//
#define ThreadBasicInformation          0
#define ThreadQuerySetWin32StartAddress 9

VOID
EnumThreadsDeepInfo(
    _In_ HANDLE ProcessHandle
)
{
    CONST PFN_NT_GET_NEXT_THREAD NtGetNextThread =
        (PFN_NT_GET_NEXT_THREAD)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtGetNextThread"
        );

    CONST PFN_NT_QUERY_INFORMATION_THREAD NtQueryInformationThread =
        (PFN_NT_QUERY_INFORMATION_THREAD)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQueryInformationThread"
        );

    if (NtGetNextThread == NULL || NtQueryInformationThread == NULL)
    {
        printf("[-] Failed to resolve Nt functions\n");
        return;
    }

    printf("[*] NtQueryInformationThread > \n\n");

    HANDLE CurrentThread = NULL;
    HANDLE NextThread = NULL;

    while (NtGetNextThread(
        ProcessHandle,
        CurrentThread,
        THREAD_QUERY_INFORMATION,
        0,
        0,
        &NextThread) == STATUS_SUCCESS)
    {
        //
        // Class 0 — basic info: TEB address, affinity, priority.
        //
        THREAD_BASIC_INFORMATION BasicInfo = { 0 };

        NtQueryInformationThread(
            NextThread,
            ThreadBasicInformation,
            &BasicInfo,
            sizeof(BasicInfo),
            NULL
        );

        //
        // Class 9 — Win32 start address.
        // This is the actual function pointer passed to CreateThread,
        // not the RtlUserThreadStart kernel wrapper that class 5 returns.
        //
        PVOID Win32StartAddress = NULL;

        NtQueryInformationThread(
            NextThread,
            ThreadQuerySetWin32StartAddress,
            &Win32StartAddress,
            sizeof(Win32StartAddress),
            NULL
        );

        printf(
            "  TID: %-6llu  TEB: %p  Win32Start: %p  Priority: %d  Affinity: 0x%llX\n",
            (ULONG_PTR)BasicInfo.ClientId.UniqueThread,
            BasicInfo.TebBaseAddress,
            Win32StartAddress,
            BasicInfo.Priority,
            BasicInfo.AffinityMask
        );

        if (CurrentThread != NULL)
        {
            CloseHandle(CurrentThread);
        }

        CurrentThread = NextThread;
    }

    if (CurrentThread != NULL)
    {
        CloseHandle(CurrentThread);
    }

    printf("\n");
}

INT
main(
    VOID
)
{
    CONST DWORD  TargetPid = GetCurrentProcessId();
    CONST HANDLE ProcessHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        FALSE,
        TargetPid
    );

    if (ProcessHandle == NULL)
    {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Enumerating threads for PID: %d\n\n", TargetPid);

    EnumThreadsDeepInfo(ProcessHandle);

    CloseHandle(ProcessHandle);
    return 0;
}
