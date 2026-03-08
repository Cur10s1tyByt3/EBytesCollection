#include<Windows.h>
#include<Psapi.h>
#include<cstdio>
#pragma comment(lib, "Psapi.lib")

DWORD
GetDriverBases(
    _Out_ LPVOID* DriverBases,
    _In_  DWORD   BufferCount
)
{
    DWORD BytesNeeded = 0;

    //
    // Enumerate all loaded driver base addresses into the caller's buffer.
    //
    if (EnumDeviceDrivers(DriverBases, BufferCount * sizeof(LPVOID), &BytesNeeded) == FALSE)
    {
        printf("[-] EnumDeviceDrivers failed: %d\n", GetLastError());
        return 0;
    }

    return BytesNeeded / sizeof(LPVOID);
}

VOID
GetDriverName(
    _In_  LPVOID DriverBase,
    _Out_ CHAR* NameBuffer,
    _In_  DWORD  BufferSize
)
{
    //
    // Retrieves just the base name of the driver (e.g. "ntoskrnl.exe").
    //
    if (GetDeviceDriverBaseNameA(DriverBase, NameBuffer, BufferSize) == 0)
    {
        lstrcpyA(NameBuffer, "<unknown>");
    }
}

VOID
GetDriverFileName(
    _In_  LPVOID DriverBase,
    _Out_ CHAR* NameBuffer,
    _In_  DWORD  BufferSize
)
{
    //
    // Retrieves the full file path of the driver (e.g. \SystemRoot\system32\ntoskrnl.exe).
    //
    if (GetDeviceDriverFileNameA(DriverBase, NameBuffer, BufferSize) == 0)
    {
        lstrcpyA(NameBuffer, "<unknown>");
    }
}

INT
main(
    VOID
)
{
    LPVOID DriverBases[1024] = { 0 };

    CONST DWORD Count = GetDriverBases(DriverBases, 1024);
    if (Count == 0)
    {
        return 1;
    }

    printf("[+] Total drivers: %d\n\n", Count);

    for (DWORD i = 0; i < Count; i++)
    {
        //
        // Skip NULL entries — EnumDeviceDrivers returns zeroed bases
        // when called without Administrator privileges.
        //
        // What does that mean? -> RUN WITH ADMIN!
        if (DriverBases[i] == NULL)
        {
            continue;
        }

        CHAR Name[MAX_PATH] = { 0 };
        CHAR FilePath[MAX_PATH] = { 0 };

        GetDriverName(DriverBases[i], Name, MAX_PATH);
        GetDriverFileName(DriverBases[i], FilePath, MAX_PATH);

        printf("  Base:      %p\n", DriverBases[i]);
        printf("  Name:      %s\n", Name);
        printf("  FilePath:  %s\n", FilePath);
        printf("  ---------------------\n");
    }

    return 0;
}
