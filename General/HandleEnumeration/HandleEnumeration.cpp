#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <cstdio>
//
// ============================================================
//  SystemHandleInformation structures
// ============================================================
//

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG                          NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS
(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_     PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
    );

//
// ============================================================
//  EnumerateSysHandles
//  Grows the buffer until NtQuerySystemInformation succeeds.
// ============================================================
//

PSYSTEM_HANDLE_INFORMATION
EnumerateSysHandles(
    VOID
)
{
    CONST PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );

    ULONG   BufferSize = 0;
    PVOID   Buffer = NULL;
    NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;

    //
    // Retry with a growing buffer until the call succeeds.
    // NtQuerySystemInformation returns STATUS_INFO_LENGTH_MISMATCH
    // and fills ReturnLength with the required size each time.
    //
    while (Status == STATUS_INFO_LENGTH_MISMATCH)
    {
        Status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)16,     // SystemHandleInformation
            Buffer,
            BufferSize,
            &BufferSize
        );

        Buffer = HeapReAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            Buffer == NULL
            ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize)
            : Buffer,
            BufferSize
        );

        if (Buffer == NULL)
        {
            printf("[-] HeapReAlloc failed\n");
            return NULL;
        }
    }

    if (Status != 0)
    {
        printf("[-] NtQuerySystemInformation failed: 0x%08X\n", Status);
        HeapFree(GetProcessHeap(), 0, Buffer);
        return NULL;
    }

    return (PSYSTEM_HANDLE_INFORMATION)Buffer;
}

INT
main(
    VOID
)
{
    CONST PSYSTEM_HANDLE_INFORMATION HandleInfo = EnumerateSysHandles();
    if (HandleInfo == NULL)
    {
        return 1;
    }

    printf("[+] Total handles: %d\n\n", HandleInfo->NumberOfHandles);

    for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
    {
        //
        // Index into the flexible array at the end of the structure.
        //
        CONST PSYSTEM_HANDLE_TABLE_ENTRY_INFO Entry =
            &HandleInfo->Handles[i];

        printf(
            "  Owner PID: %-6d  Type: %-3d  Handle: 0x%04X  Access: 0x%08X\n",
            (DWORD)Entry->UniqueProcessId,
            (DWORD)Entry->ObjectTypeIndex,
            (DWORD)Entry->HandleValue,
            Entry->GrantedAccess
        );
    }

    HeapFree(GetProcessHeap(), 0, HandleInfo);
    return 0;
}
