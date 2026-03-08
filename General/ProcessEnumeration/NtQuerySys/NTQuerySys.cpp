#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS
( NTAPI *PFN_NT_QUERY_SYSTEM_INFORMATION )(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_     PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
    );

DWORD
GetProcessIdFromName(
    _In_ LPCSTR ProcessName
    )
{
    CONST PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        ( PFN_NT_QUERY_SYSTEM_INFORMATION )GetProcAddress(
            GetModuleHandleA( "ntdll.dll" ),
            "NtQuerySystemInformation"
        );

    ULONG BufferSize = 0;

    //
    // First call with NULL to obtain the required buffer size.
    //
    NtQuerySystemInformation(
        ( SYSTEM_INFORMATION_CLASS )5,
        NULL,
        0,
        &BufferSize
    );

    PVOID Buffer = HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, BufferSize );
    if ( Buffer == NULL )
    {
        printf( "[-] HeapAlloc failed\n" );
        return 0;
    }

    NTSTATUS Status = NtQuerySystemInformation(
        ( SYSTEM_INFORMATION_CLASS )5,
        Buffer,
        BufferSize,
        &BufferSize
    );

    if ( Status != 0 )
    {
        printf( "[-] NtQuerySystemInformation failed: 0x%08X\n", Status );
        HeapFree( GetProcessHeap( ), 0, Buffer );
        return 0;
    }

    DWORD Result = 0;

    PSYSTEM_PROCESS_INFORMATION Entry =
        ( PSYSTEM_PROCESS_INFORMATION )Buffer;

    //
    // Walk the linked list of SYSTEM_PROCESS_INFORMATION entries.
    // NextEntryOffset of 0 signals the last entry.
    //
    while ( Entry->NextEntryOffset != 0 )
    {
        Entry = ( PSYSTEM_PROCESS_INFORMATION )(
            ( PBYTE )Entry + Entry->NextEntryOffset
        );

        if ( Entry->ImageName.Buffer == NULL )
        {
            continue;
        }

        //
        // ImageName.Buffer is a wide string — convert for comparison.
        //
        CHAR NarrowName[ MAX_PATH ] = { 0 };
        WideCharToMultiByte(
            CP_ACP, 0,
            Entry->ImageName.Buffer,
            -1,
            NarrowName,
            MAX_PATH,
            NULL, NULL
        );

        if ( lstrcmpA( NarrowName, ProcessName ) == 0 )
        {
            Result = ( DWORD )( ULONG_PTR )Entry->UniqueProcessId;
            break;
        }
    }

    HeapFree( GetProcessHeap( ), 0, Buffer );
    return Result;
}

INT
main(
    VOID
    )
{
    CONST DWORD Id = GetProcessIdFromName( "Notepad.exe" );
    printf( "[+] Notepad PID: %d\n", Id );
    return 0;
}
