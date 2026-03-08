#include <Windows.h>
#include <cstdio>

VOID
ParseIat(
    _In_ PVOID ImageBase
)
{
    CONST DWORD_PTR Base = (DWORD_PTR)ImageBase;

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        Base + DosHeader->e_lfanew
        );

    //
    // Locate the import directory from the data directory array.
    //
    CONST DWORD ImportRva = NtHeaders->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        .VirtualAddress;

    if (ImportRva == 0)
    {
        printf("[-] No import directory\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
        Base + ImportRva
        );

    //
    // Each descriptor is one DLL — a zeroed descriptor marks the end.
    //
    while (ImportDesc->Name != 0)
    {
        CONST LPCSTR DllName = (LPCSTR)(Base + ImportDesc->Name);

        printf("\n  [DLL] %s\n", DllName);

        PIMAGE_THUNK_DATA OrgThunk = (PIMAGE_THUNK_DATA)(
            Base + ImportDesc->OriginalFirstThunk
            );

        PIMAGE_THUNK_DATA Thunk = (PIMAGE_THUNK_DATA)(
            Base + ImportDesc->FirstThunk
            );

        //
        // Walk thunk pairs — OriginalFirstThunk = name,
        //                     FirstThunk        = resolved address.
        //
        while (OrgThunk->u1.AddressOfData != 0)
        {
            if (!(OrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                CONST PIMAGE_IMPORT_BY_NAME ImportByName =
                    (PIMAGE_IMPORT_BY_NAME)(Base + OrgThunk->u1.AddressOfData);

                printf(
                    "    [+] %-40s  ->  0x%p\n",
                    ImportByName->Name,
                    (PVOID)Thunk->u1.Function
                );
            }
            else
            {
                //
                // Imported by ordinal only — no name available.
                //
                printf(
                    "    [+] Ordinal %-4llu              ->  0x%p\n",
                    OrgThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG,
                    (PVOID)Thunk->u1.Function
                );
            }

            OrgThunk++;
            Thunk++;
        }

        ImportDesc++;
    }
}

INT
main(
    VOID
)
{
    //
    // Pass the base of the current process — same as GetModuleHandle(NULL).
    //
    ParseIat(GetModuleHandleA(NULL));

    return 0;
}
