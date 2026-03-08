#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <cstdio>

//
// ============================================================
//  Thread enumeration via NtGetNextThread.
//
//  No snapshot required. Enumerates live threads at call time.
//  Pass NULL as initial handle to get the first thread,
//  then pass the previous handle to walk forward.
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

VOID
EnumThreadsNtGetNext(
    _In_ HANDLE ProcessHandle
)
{
    CONST PFN_NT_GET_NEXT_THREAD NtGetNextThread =
        (PFN_NT_GET_NEXT_THREAD)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtGetNextThread"
        );

    if (NtGetNextThread == NULL)
    {
        printf("[-] Failed to resolve NtGetNextThread\n");
        return;
    }

    printf("[*] NtGetNextThread\n\n");

    HANDLE CurrentThread = NULL;
    HANDLE NextThread = NULL;

    //
    // Start with NULL — ntdll returns the first thread handle.
    // Each call hands back a handle to the next thread.
    // Loop ends when STATUS_NO_MORE_ENTRIES is returned.
    //
    while (NtGetNextThread(
        ProcessHandle,
        CurrentThread,
        THREAD_QUERY_INFORMATION,
        0,
        0,
        &NextThread) == STATUS_SUCCESS)
    {
        DWORD ThreadId = GetThreadId(NextThread);
        printf("  Thread ID: %d  Handle: %p\n", ThreadId, NextThread);

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

    EnumThreadsNtGetNext(ProcessHandle);

    CloseHandle(ProcessHandle);
    return 0;
}
