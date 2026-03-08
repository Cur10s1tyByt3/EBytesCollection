#include <Windows.h>
#include <cstdio>

//
// ============================================================
//  GuardCF.cpp
//  SSN retrieval via Control Flow Guard function table.
//
//  Reads IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable —
//  a list of every valid indirect call target sorted by RVA.
//  Matches each entry against Zw* EAT exports and increments
//  the SSN counter on each match. Hook-immune — never reads
//  stub bytes, only CFG table VAs and EAT RVAs.
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

#pragma pack( push, 1 )
typedef struct _IMAGE_CFG_ENTRY
{
    DWORD Rva;
    struct
    {
        BOOLEAN SuppressedCall : 1;
        BOOLEAN ExportSuppressed : 1;
        BOOLEAN LangExcptHandler : 1;
        BOOLEAN Xfg : 1;
        BOOLEAN Reserved : 4;
    } Flags;
} IMAGE_CFG_ENTRY, * PIMAGE_CFG_ENTRY;
#pragma pack( pop )

static BOOL
GuardCF_DumpAll(
    _Out_ PSSN_TABLE Table
)
{
    Table->Count = 0;

    CONST PBYTE Base = (PBYTE)GetModuleHandleA("ntdll.dll");

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders =
        (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    CONST IMAGE_DATA_DIRECTORY LoadCfgDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    if (LoadCfgDir.Size == 0) return FALSE;

    CONST PIMAGE_LOAD_CONFIG_DIRECTORY LoadCfg =
        (PIMAGE_LOAD_CONFIG_DIRECTORY)(Base + LoadCfgDir.VirtualAddress);

    if (LoadCfg->GuardCFFunctionTable == 0) return FALSE;

    //
    // GuardCFFunctionTable is an absolute VA not an RVA.
    //
    CONST PIMAGE_CFG_ENTRY CfgTable =
        (PIMAGE_CFG_ENTRY)LoadCfg->GuardCFFunctionTable;

    CONST IMAGE_DATA_DIRECTORY ExportDataDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDataDir.VirtualAddress);

    CONST PDWORD NameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    CONST PWORD  Ordinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    CONST PDWORD FuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);

    WORD Ssn = 0;

    for (DWORD x = 0;
        CfgTable[x].Rva != 0 && Table->Count < MAX_SYSCALLS;
        x++)
    {
        CONST DWORD GfRva = CfgTable[x].Rva;

        for (DWORD i = 0; i < Exports->NumberOfNames; i++)
        {
            LPCSTR Name = (LPCSTR)(Base + NameRvas[i]);
            DWORD  FuncRva = FuncRvas[Ordinals[i]];

            if (FuncRva != GfRva) continue;
            if (Name[0] != 'Z' || Name[1] != 'w') continue;

            PSSN_ENTRY E = &Table->Entries[Table->Count++];
            lstrcpyA(E->Name, Name);
            E->Ssn = Ssn;
            E->Address = (PVOID)(Base + FuncRva);

            Ssn++;
            break;
        }
    }

    return (Table->Count > 0);
}

static SSN_ENTRY
GuardCF_LookUpByName(
    _In_ LPCSTR           Name,
    _In_ CONST PSSN_TABLE Table
)
{
    for (DWORD i = 0; i < Table->Count; i++)
    {
        if (lstrcmpA(Table->Entries[i].Name, Name) == 0)
            return Table->Entries[i];
    }

    SSN_ENTRY Empty = { 0 };
    return Empty;
}

INT main(VOID)
{
    SetConsoleOutputCP(CP_UTF8);

    SSN_TABLE Table = { 0 };

    if (GuardCF_DumpAll(&Table) == FALSE)
    {
        printf("[-] GuardCF failed\n");
        return 1;
    }

    printf("[+] Guard CF Table - %d syscalls\n\n", Table.Count);

    //
    // Lookup for a few common functions.
    //
    LPCSTR Targets[] = {
        "ZwCreateFile",
        "ZwOpenProcess",
        "ZwAllocateVirtualMemory",
        "ZwProtectVirtualMemory",
        "ZwCreateThreadEx",
    };

    printf("%-40s  SSN     Address\n", "Name");
    printf("-------------------------------------------------------\n");

    for (INT i = 0; i < 5; i++)
    {
        CONST SSN_ENTRY Hit = GuardCF_LookUpByName(Targets[i], &Table);

        if (Hit.Address != NULL)
        {
            printf("%-40s  0x%04X  %p\n", Targets[i], Hit.Ssn, Hit.Address);
        }
        else
        {
            printf("%-40s  Not Found\n", Targets[i]);
        }
    }

    return 0;
}
