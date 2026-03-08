#include<Windows.h>
#include<cstdio>

//
// RUNTIME_FUNCTION structure for x64 exception handling.
// Only define it if not already defined by the SDK.
//
#ifndef _RUNTIME_FUNCTION_DEFINED
#define _RUNTIME_FUNCTION_DEFINED
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;
#endif

//
// ============================================================
//  Walk .pdata RUNTIME_FUNCTION table to derive SSNs.
//
//  .pdata entries are sorted by BeginAddress ascending at link
//  time. SSN increments each time a Zw* EAT RVA matches a
//  BeginAddress.
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
ExceptionDir_DumpAll(
    _Out_ PSSN_TABLE Table
)
{
    Table->Count = 0;

#ifndef _WIN64
    //
    // x86 uses stack-based SEH, not table-based exception handling.
    // There is no .pdata section on x86 builds.
    //
    printf("[-] Exception Directory method only works on x64\n");
    return FALSE;
#else

    CONST PBYTE Base = (PBYTE)GetModuleHandleA("ntdll.dll");

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders =
        (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    //
    // .pdata — sorted by BeginAddress ascending.
    // Walking it in order gives the SSN sequence directly.
    //
    CONST IMAGE_DATA_DIRECTORY ExceptionDataDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (ExceptionDataDir.Size == 0) return FALSE;

    CONST PRUNTIME_FUNCTION ExceptionDir = (PRUNTIME_FUNCTION)(
        Base + ExceptionDataDir.VirtualAddress
        );

    CONST IMAGE_DATA_DIRECTORY ExportDataDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDataDir.VirtualAddress);

    CONST PDWORD NameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    CONST PWORD  Ordinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    CONST PDWORD FuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);

    CONST DWORD ExceptionCount = ExceptionDataDir.Size / sizeof(RUNTIME_FUNCTION);
    WORD        Ssn = 0;

    for (DWORD i = 0; i < ExceptionCount && Table->Count < MAX_SYSCALLS; i++)
    {
        if (ExceptionDir[i].BeginAddress == 0) break;

        CONST DWORD BeginRva = ExceptionDir[i].BeginAddress;

        for (DWORD x = 0; x < Exports->NumberOfNames; x++)
        {
            LPCSTR Name = (LPCSTR)(Base + NameRvas[x]);
            DWORD  FuncRva = FuncRvas[Ordinals[x]];

            if (FuncRva != BeginRva) continue;
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
#endif
}

INT main(VOID)
{
    SetConsoleOutputCP(CP_UTF8);

    SSN_TABLE Table = { 0 };

    if (ExceptionDir_DumpAll(&Table) == FALSE)
    {
        printf("[-] Exception Directory failed\n");
        return 1;
    }

    printf("[+] Exception Directory - %d syscalls\n\n", Table.Count);

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
