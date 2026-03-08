#include<Windows.h>
#include<Psapi.h>
#include<cstdio>
#pragma comment(lib, "Psapi.lib")

DWORD
GetProcessIdFromName(
    _In_ LPCSTR ProcessName
    )
{
    DWORD ProcessIds[ 1024 ] = { 0 };
    DWORD BytesNeeded        = 0;

    //
    // Enumerate all running process IDs into a fixed buffer.
    //
    if ( EnumProcesses( ProcessIds, sizeof( ProcessIds ), &BytesNeeded ) == FALSE )
    {
        printf( "[-] EnumProcesses failed: %d\n", GetLastError( ) );
        return 0;
    }

    CONST DWORD Count = BytesNeeded / sizeof( DWORD );

    for ( DWORD i = 0; i < Count; i++ )
    {
        CONST DWORD CurrentId = ProcessIds[ i ];

        CONST HANDLE ProcessHandle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            CurrentId
        );

        if ( ProcessHandle == NULL )
        {
            continue;
        }

        HMODULE MainModule  = NULL;
        DWORD   NeededSize  = 0;

        //
        // EnumProcessModules with a single slot gives us the main module handle.
        //
        if ( EnumProcessModules( ProcessHandle, &MainModule, sizeof( MainModule ), &NeededSize ) )
        {
            CHAR Name[ MAX_PATH ] = { 0 };

            GetModuleBaseNameA( ProcessHandle, MainModule, Name, MAX_PATH );

            if ( lstrcmpA( Name, ProcessName ) == 0 )
            {
                CloseHandle( ProcessHandle );
                return CurrentId;
            }
        }

        CloseHandle( ProcessHandle );
    }

    return 0;
}

INT
main(
    VOID
    )
{
    CONST DWORD Id = GetProcessIdFromName( "Notepad.exe" );
    printf( "[+] notepad PID: %d\n", Id );
    return 0;
}
