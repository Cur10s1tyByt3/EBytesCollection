#include<Windows.h>
#include<cstdlib>
#include<cstdio>

//
// ============================================================
//  FreshyCalls.cpp
//  Sort Nt* exports by virtual address — index = SSN.
//
//  Never reads stub bytes. Completely hook-immune because it
//  only reads VA values from the EAT. The kernel assigns SSNs
//  in ascending VA order at build time so the sorted position
//  IS the SSN.
//
// ============================================================
//

#define MAX_SYSCALLS  512
#define MAX_NAME_LEN  128

typedef struct _SSN_ENTRY
{
    CHAR  Name[MAX_NAME_LEN];
    WORD  Ssn;
    PVOID Address;
} SSN_ENTRY, * PSSN_ENTRY;

typedef struct _SSN_TABLE
{
    SSN_ENTRY Entries[MAX_SYSCALLS];
    DWORD     Count;
} SSN_TABLE, * PSSN_TABLE;

typedef struct _SORT_ENTRY
{
    CHAR  Name[MAX_NAME_LEN];
    PVOID Address;
} SORT_ENTRY;

static SORT_ENTRY SortBuf[MAX_SYSCALLS];

static INT
CompareByAddress(
    _In_ CONST VOID* A,
    _In_ CONST VOID* B
)
{
    CONST SORT_ENTRY* Ea = (CONST SORT_ENTRY*)A;
    CONST SORT_ENTRY* Eb = (CONST SORT_ENTRY*)B;

    if ((ULONG_PTR)Ea->Address < (ULONG_PTR)Eb->Address) return -1;
    if ((ULONG_PTR)Ea->Address > (ULONG_PTR)Eb->Address) return  1;
    return 0;
}

static BOOL
FreshyCalls_DumpAll(
    _Out_ PSSN_TABLE Table
)
{
    Table->Count = 0;

    CONST PBYTE Base = (PBYTE)GetModuleHandleA("ntdll.dll");

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders =
        (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    CONST IMAGE_DATA_DIRECTORY ExportDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDir.Size == 0) return FALSE;

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDir.VirtualAddress);

    CONST PDWORD NameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    CONST PWORD  Ordinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    CONST PDWORD FuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);

    DWORD SortCount = 0;

    for (DWORD i = 0;
        i < Exports->NumberOfNames && SortCount < MAX_SYSCALLS;
        i++)
    {
        LPCSTR Name = (LPCSTR)(Base + NameRvas[i]);

        //
        // Nt* prefix only. Skip NtdllXxx loader internals —
        // those are not syscalls and would corrupt the SSN index.
        //
        if (Name[0] != 'N' || Name[1] != 't') continue;
        if (Name[2] == 'd' && Name[3] == 'l') continue;

        SortBuf[SortCount].Address = (PVOID)(Base + FuncRvas[Ordinals[i]]);
        lstrcpyA(SortBuf[SortCount].Name, Name);
        SortCount++;
    }

    //
    // Sort ascending by VA — lowest address maps to SSN 0.
    //
    qsort(SortBuf, SortCount, sizeof(SORT_ENTRY), CompareByAddress);

    for (DWORD i = 0; i < SortCount; i++)
    {
        PSSN_ENTRY E = &Table->Entries[Table->Count++];
        lstrcpyA(E->Name, SortBuf[i].Name);
        E->Ssn = (WORD)i;
        E->Address = SortBuf[i].Address;
    }

    return (Table->Count > 0);
}

INT main(VOID)
{
    SetConsoleOutputCP(CP_UTF8);

    SSN_TABLE Table = { 0 };

    if (FreshyCalls_DumpAll(&Table) == FALSE)
    {
        printf("[-] FreshyCalls failed\n");
        return 1;
    }

    printf("[+] FreshyCalls - %d syscalls\n\n", Table.Count);

    for (DWORD i = 0; i < Table.Count; i++)
    {
        printf(
            "  %-40s  SSN: 0x%04X (%4d)  Addr: %p\n",
            Table.Entries[i].Name,
            Table.Entries[i].Ssn,
            Table.Entries[i].Ssn,
            Table.Entries[i].Address
        );
    }

    return 0;
}
