#include <Windows.h>
#include <cstdio>

VOID
ParseEat(
    _In_ PVOID ImageBase
)
{
    CONST DWORD_PTR Base = (DWORD_PTR)ImageBase;

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        Base + DosHeader->e_lfanew
        );

    //
    // Locate the export directory from the data directory array.
    //
    CONST DWORD ExportRva = NtHeaders->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress;

    if (ExportRva == 0)
    {
        printf("[-] No export directory\n");
        return;
    }

    CONST PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        Base + ExportRva
        );

    //
    // Three parallel arrays make up the EAT:
    //   AddressOfFunctions    — array of RVAs to exported functions
    //   AddressOfNames        — array of RVAs to function name strings
    //   AddressOfNameOrdinals — array of indices into AddressOfFunctions
    //
    CONST PDWORD  Functions = (PDWORD)(Base + ExportDir->AddressOfFunctions);
    CONST PDWORD  Names = (PDWORD)(Base + ExportDir->AddressOfNames);
    CONST PWORD   Ordinals = (PWORD)(Base + ExportDir->AddressOfNameOrdinals);

    CONST LPCSTR  ModuleName = (LPCSTR)(Base + ExportDir->Name);

    printf("\n  [DLL] %s\n", ModuleName);
    printf("  Exports: %d named, %d total\n\n",
        ExportDir->NumberOfNames,
        ExportDir->NumberOfFunctions);

    //
    // Walk named exports — NumberOfNames entries in the Names array.
    // Each name maps to a function via the Ordinals table.
    //
    for (DWORD i = 0; i < ExportDir->NumberOfNames; i++)
    {
        CONST LPCSTR FunctionName = (LPCSTR)(Base + Names[i]);
        CONST WORD   OrdinalIndex = Ordinals[i];
        CONST DWORD  FunctionRva = Functions[OrdinalIndex];
        CONST PVOID  FunctionAddress = (PVOID)(Base + FunctionRva);
        CONST DWORD  Ordinal = ExportDir->Base + OrdinalIndex;

        printf(
            "    [+] %-50s  Ord: %-6d  ->  0x%p\n",
            FunctionName,
            Ordinal,
            FunctionAddress
        );
    }
}

INT
main(
    VOID
)
{
    //
    // Parse exports of a loaded module — swap for any loaded DLL base.
    //
    ParseEat(GetModuleHandleA("kernel32.dll"));

    return 0;
}
