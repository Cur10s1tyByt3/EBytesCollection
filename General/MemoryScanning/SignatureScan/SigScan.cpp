#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#pragma comment(lib, "Psapi.lib")

//
// ============================================================
//  SigScan
//  Scans a memory region for a byte pattern.
//  Use "??" as a wildcard for any byte.
//
//  Example pattern: "4C 8B D1 B8 ?? ?? ?? ?? F6"
// ============================================================
//

DWORD
SigScan(
    _In_  HANDLE  ProcessHandle,
    _In_  PVOID   StartAddress,
    _In_  SIZE_T  RegionSize,
    _In_  LPCSTR  Pattern,
    _Out_ PVOID* Results,
    _In_  DWORD   MaxResults
)
{
    //
    // Parse the space-delimited pattern string into a byte array.
    // "??" entries are flagged as wildcards via a parallel mask array.
    //
    BYTE  PatternBytes[256] = { 0 };
    BOOL  Wildcard[256] = { 0 };
    DWORD PatternLen = 0;

    CHAR  PatternCopy[1024] = { 0 };
    lstrcpyA(PatternCopy, Pattern);

    CHAR* Token = strtok(PatternCopy, " ");

    while (Token != NULL && PatternLen < 256)
    {
        if (lstrcmpA(Token, "??") == 0)
        {
            Wildcard[PatternLen] = TRUE;
            PatternBytes[PatternLen] = 0;
        }
        else
        {
            Wildcard[PatternLen] = FALSE;
            PatternBytes[PatternLen] = (BYTE)strtoul(Token, NULL, 16);
        }

        PatternLen++;
        Token = strtok(NULL, " ");
    }

    if (PatternLen == 0)
    {
        printf("[-] Empty pattern\n");
        return 0;
    }

    //
    // Read the entire target region into a local buffer.
    //
    PVOID Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RegionSize);
    if (Buffer == NULL)
    {
        printf("[-] HeapAlloc failed\n");
        return 0;
    }

    ReadProcessMemory(ProcessHandle, StartAddress, Buffer, RegionSize, NULL);

    DWORD MatchCount = 0;

    //
    // Slide the pattern across the buffer byte by byte.
    //
    for (SIZE_T Offset = 0; Offset <= RegionSize - PatternLen; Offset++)
    {
        BOOL Found = TRUE;

        for (DWORD i = 0; i < PatternLen; i++)
        {
            //
            // Wildcards always match — only compare concrete bytes.
            //
            if (Wildcard[i] == TRUE)
            {
                continue;
            }

            if (((PBYTE)Buffer)[Offset + i] != PatternBytes[i])
            {
                Found = FALSE;
                break;
            }
        }

        if (Found == TRUE && MatchCount < MaxResults)
        {
            Results[MatchCount] = (PVOID)((DWORD_PTR)StartAddress + Offset);
            MatchCount++;
        }
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    return MatchCount;
}

INT
main(
    VOID
)
{
    //
    // Example: scan ntdll.dll in the current process for syscall stubs.
    // Pattern: "4C 8B D1 B8 ?? ?? ?? ?? F6"
    //
    CONST HMODULE NtdllBase = GetModuleHandleA("ntdll.dll");

    MODULEINFO ModInfo = { 0 };
    GetModuleInformation(
        GetCurrentProcess(),
        NtdllBase,
        &ModInfo,
        sizeof(ModInfo)
    );

    PVOID Results[1024] = { 0 };

    CONST DWORD Count = SigScan(
        GetCurrentProcess(),
        ModInfo.lpBaseOfDll,
        ModInfo.SizeOfImage,
        "4C 8B D1 B8 ?? ?? ?? ?? F6",
        Results,
        1024
    );

    printf("[+] Found %d matches\n\n", Count);

    for (DWORD i = 0; i < Count; i++)
    {
        printf("  Syscall stub at 0x%p\n", Results[i]);
    }

    return 0;
}
