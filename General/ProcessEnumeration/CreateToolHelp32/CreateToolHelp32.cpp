#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>

DWORD
GetProcessIdFromName(
    _In_ LPCSTR ProcessName
)
{
    //
    // Snapshot all running processes at this moment in time.
    //
    CONST HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 Entry = { 0 };
    Entry.dwSize = sizeof(PROCESSENTRY32);

    DWORD Result = 0;

    //
    // Walk each process entry and compare the executable name.
    // szExeFile is a WCHAR buffer — use lstrcmpW for comparison.
    //
    while (Process32Next(Snapshot, &Entry))
    {
        CHAR NarrowName[MAX_PATH] = { 0 };
        WideCharToMultiByte(
            CP_ACP, 0,
            Entry.szExeFile,
            -1,
            NarrowName,
            MAX_PATH,
            NULL, NULL
        );

        if (lstrcmpA(NarrowName, ProcessName) == 0)
        {
            Result = Entry.th32ProcessID;
            break;
        }
    }

    CloseHandle(Snapshot);
    return Result;
}

INT
main(
    VOID
)
{
    CONST DWORD Id = GetProcessIdFromName("Notepad.exe");
    printf("[+] Notepad PID: %d\n", Id);
    return 0;
}
