#include<Windows.h>
#include<cstdio>

//
// ============================================================
//  Memory region enumeration + scanning
// ============================================================
//

DWORD
GetProcessMemoryRegions(
    _In_  HANDLE                  ProcessHandle,
    _Out_ MEMORY_BASIC_INFORMATION* RegionBuffer,
    _In_  DWORD                   MaxRegions
)
{
    PVOID BaseAddress = NULL;
    DWORD Count = 0;

    //
    // Walk the virtual address space using VirtualQueryEx.
    // Advance by RegionSize each iteration to move to the next region.
    //
    while (Count < MaxRegions)
    {
        MEMORY_BASIC_INFORMATION Mbi = { 0 };

        if (VirtualQueryEx(ProcessHandle, BaseAddress, &Mbi, sizeof(Mbi)) == 0)
        {
            break;
        }

        //
        // Only collect committed regions — reserved and free regions
        // have no backing memory to read.
        //
        if ((Mbi.State & MEM_COMMIT) == MEM_COMMIT)
        {
            RegionBuffer[Count] = Mbi;
            Count++;
        }

        BaseAddress = (PVOID)((DWORD_PTR)Mbi.BaseAddress + Mbi.RegionSize);
    }

    return Count;
}

DWORD
ScanForDword(
    _In_  HANDLE                   ProcessHandle,
    _In_  MEMORY_BASIC_INFORMATION* Regions,
    _In_  DWORD                    RegionCount,
    _In_  DWORD                    TargetValue,
    _Out_ PVOID* Results,
    _In_  DWORD                    MaxResults
)
{
    DWORD MatchCount = 0;

    for (DWORD r = 0; r < RegionCount; r++)
    {
        CONST SIZE_T RegionSize = Regions[r].RegionSize;
        CONST PVOID  RegionBase = Regions[r].BaseAddress;

        PVOID Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RegionSize);
        if (Buffer == NULL)
        {
            continue;
        }

        ReadProcessMemory(ProcessHandle, RegionBase, Buffer, RegionSize, NULL);

        for (SIZE_T Offset = 0;
            Offset <= RegionSize - sizeof(DWORD) && MatchCount < MaxResults;
            Offset += sizeof(DWORD))
        {
            if (*(PDWORD)((PBYTE)Buffer + Offset) == TargetValue)
            {
                Results[MatchCount] = (PVOID)((DWORD_PTR)RegionBase + Offset);
                MatchCount++;
            }
        }

        HeapFree(GetProcessHeap(), 0, Buffer);
    }

    return MatchCount;
}

DWORD
ScanForString(
    _In_  HANDLE                   ProcessHandle,
    _In_  MEMORY_BASIC_INFORMATION* Regions,
    _In_  DWORD                    RegionCount,
    _In_  LPCSTR                   TargetString,
    _Out_ PVOID* Results,
    _In_  DWORD                    MaxResults
)
{
    CONST INT    StringLen = lstrlenA(TargetString);
    DWORD        MatchCount = 0;

    for (DWORD r = 0; r < RegionCount; r++)
    {
        CONST SIZE_T RegionSize = Regions[r].RegionSize;
        CONST PVOID  RegionBase = Regions[r].BaseAddress;

        PVOID Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RegionSize);
        if (Buffer == NULL)
        {
            continue;
        }

        ReadProcessMemory(ProcessHandle, RegionBase, Buffer, RegionSize, NULL);

        for (SIZE_T Offset = 0;
            Offset <= RegionSize - StringLen && MatchCount < MaxResults;
            Offset++)
        {
            if (lstrcmpA((LPCSTR)((PBYTE)Buffer + Offset), TargetString) == 0)
            {
                Results[MatchCount] = (PVOID)((DWORD_PTR)RegionBase + Offset);
                MatchCount++;
            }
        }

        HeapFree(GetProcessHeap(), 0, Buffer);
    }

    return MatchCount;
}

INT
main(
    VOID
)
{
    CONST HANDLE ProcessHandle = GetCurrentProcess();

    MEMORY_BASIC_INFORMATION Regions[4096] = { 0 };

    CONST DWORD RegionCount = GetProcessMemoryRegions(
        ProcessHandle,
        Regions,
        4096
    );

    printf("[+] Committed regions: %d\n\n", RegionCount);

    //
    // Scan for a DWORD value.
    //
    PVOID DwordResults[1024] = { 0 };

    CONST DWORD DwordCount = ScanForDword(
        ProcessHandle,
        Regions,
        RegionCount,
        4,
        DwordResults,
        1024
    );

    printf("[+] Found value 4 at %d addresses\n", DwordCount);
    for (DWORD i = 0; i < DwordCount; i++)
    {
        printf("  0x%p\n", DwordResults[i]);
    }

    //
    // Scan for a string.
    //
    PVOID StringResults[1024] = { 0 };

    CONST DWORD StringCount = ScanForString(
        ProcessHandle,
        Regions,
        RegionCount,
        "VirtualAlloc",
        StringResults,
        1024
    );

    printf("\n[+] Found string 'VirtualAlloc' at %d addresses\n", StringCount);
    for (DWORD i = 0; i < StringCount; i++)
    {
        printf("  0x%p\n", StringResults[i]);
    }

    return 0;
}
