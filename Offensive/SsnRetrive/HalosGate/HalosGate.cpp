#include<Windows.h>
#include<cstdio>

//
// ============================================================
//  HalosGate.cpp
//  Hell's Gate + neighbor scanning for hooked stubs.
//
//  When a stub starts with 0xE9 (JMP hook), scans adjacent
//  exports up to 8 slots in either direction. The first
//  unhooked neighbor reveals its SSN — we add or subtract
//  the slot distance to derive the hooked one.
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

static BOOL
GetNtdllExports(
    _Out_ PBYTE* OutBase,
    _Out_ PDWORD* OutNameRvas,
    _Out_ PWORD* OutOrdinals,
    _Out_ PDWORD* OutFuncRvas,
    _Out_ PDWORD   OutCount
)
{
    CONST PBYTE Base = (PBYTE)GetModuleHandleA("ntdll.dll");

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders =
        (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    CONST IMAGE_DATA_DIRECTORY ExportDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDir.Size == 0) return FALSE;

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDir.VirtualAddress);

    *OutBase = Base;
    *OutNameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    *OutOrdinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    *OutFuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);
    *OutCount = Exports->NumberOfNames;

    return TRUE;
}

static BOOL
ReadSsnFromStub(
    _In_  PVOID  FuncAddress,
    _Out_ PWORD  OutSsn
)
{
    CONST PBYTE Stub = (PBYTE)FuncAddress;

    for (INT Offset = 0; Offset < 32; Offset++)
    {
        if (Stub[Offset] == 0xE9) return FALSE;
        if (Stub[Offset] == 0x0F && Stub[Offset + 1] == 0x05) return FALSE;
        if (Stub[Offset] == 0xC3) return FALSE;

        if (Stub[Offset] == 0x4C &&
            Stub[Offset + 1] == 0x8B &&
            Stub[Offset + 2] == 0xD1 &&
            Stub[Offset + 3] == 0xB8 &&
            Stub[Offset + 6] == 0x00 &&
            Stub[Offset + 7] == 0x00)
        {
            *OutSsn = (WORD)(
                (Stub[Offset + 5] << 8) | Stub[Offset + 4]
                );
            return TRUE;
        }
    }

    return FALSE;
}

//
// ============================================================
//  HalosGate_ScanNeighbors
//  Scans up to 8 adjacent EAT slots and infers the hooked SSN.
// ============================================================
//

static BOOL
HalosGate_ScanNeighbors(
    _In_  INT     HookedIndex,
    _In_  PBYTE   Base,
    _In_  PDWORD  FuncRvas,
    _In_  PWORD   Ordinals,
    _In_  DWORD   ExportCount,
    _Out_ PWORD   OutSsn
)
{
    for (INT Delta = 1; Delta <= 8; Delta++)
    {
        for (INT Dir = -1; Dir <= 1; Dir += 2)
        {
            INT NeighborIdx = HookedIndex + (Dir * Delta);

            if (NeighborIdx < 0) continue;
            if ((DWORD)NeighborIdx >= ExportCount) continue;

            PVOID NeighborAddr = (PVOID)(
                Base + FuncRvas[Ordinals[NeighborIdx]]
                );

            WORD NeighborSsn = 0;
            if (ReadSsnFromStub(NeighborAddr, &NeighborSsn))
            {
                *OutSsn = (WORD)(NeighborSsn - (Dir * Delta));
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOL
HalosGate_DumpAll(
    _Out_ PSSN_TABLE Table
)
{
    Table->Count = 0;

    PBYTE  Base = NULL;
    PDWORD NameRvas = NULL;
    PWORD  Ordinals = NULL;
    PDWORD FuncRvas = NULL;
    DWORD  Count = 0;

    if (GetNtdllExports(&Base, &NameRvas, &Ordinals, &FuncRvas, &Count) == FALSE)
        return FALSE;

    for (DWORD i = 0; i < Count && Table->Count < MAX_SYSCALLS; i++)
    {
        LPCSTR Name = (LPCSTR)(Base + NameRvas[i]);
        if (Name[0] != 'Z' || Name[1] != 'w') continue;

        PVOID FuncAddr = (PVOID)(Base + FuncRvas[Ordinals[i]]);
        PBYTE Stub = (PBYTE)FuncAddr;
        WORD  Ssn = 0;
        BOOL  Found = FALSE;

        if (Stub[0] == 0xE9)
        {
            Found = HalosGate_ScanNeighbors(
                (INT)i, Base, FuncRvas, Ordinals, Count, &Ssn
            );
        }
        else
        {
            Found = ReadSsnFromStub(FuncAddr, &Ssn);
        }

        if (Found == FALSE) continue;

        PSSN_ENTRY E = &Table->Entries[Table->Count++];
        lstrcpyA(E->Name, Name);
        E->Ssn = Ssn;
        E->Address = FuncAddr;
    }

    return (Table->Count > 0);
}


INT main(VOID)
{
    SetConsoleOutputCP(CP_UTF8);

    SSN_TABLE Table = { 0 };

    if (HalosGate_DumpAll(&Table) == FALSE)
    {
        printf("[-] Halo's Gate failed\n");
        return 1;
    }

    printf("[+] Halo's Gate - %d syscalls\n\n", Table.Count);

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
