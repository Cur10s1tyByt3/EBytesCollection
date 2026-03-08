#include <Windows.h>
#include <cstdio>

//
// ============================================================
//  Code cave finder
// ============================================================
//

typedef struct _CAVE {
    PIMAGE_SECTION_HEADER Section;
    CHAR                  SectionName[16];
    SIZE_T                Size;
    LPVOID                RawAddress;
    LPVOID                VirtualAddress;
} CAVE, * PCAVE;

DWORD
FindCaves(
    _In_  PVOID   ImageBase,
    _In_  SIZE_T  MinSize,
    _Out_ PCAVE   CaveBuffer,
    _In_  DWORD   MaxCaves
)
{
    CONST DWORD_PTR         Base = (DWORD_PTR)ImageBase;
    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        Base + DosHeader->e_lfanew
        );

    CONST DWORD ImageBasePreferred = NtHeaders->OptionalHeader.ImageBase;

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);

    DWORD CaveCount = 0;

    for (WORD s = 0; s < NtHeaders->FileHeader.NumberOfSections; s++)
    {
        CONST DWORD  PtrToData = Section->PointerToRawData;
        CONST DWORD  SectionSize = Section->SizeOfRawData;
        CONST PBYTE  SectionBase = (PBYTE)(Base + PtrToData);
        SIZE_T       FreeBytes = 0;

        for (DWORD i = 0; i <= SectionSize && CaveCount < MaxCaves; i++)
        {
            if (SectionBase[i] == 0x00)
            {
                //
                // Accumulate consecutive null bytes.
                //
                FreeBytes++;
            }
            else
            {
                //
                // Non-null byte encountered — check if the preceding
                // run of nulls meets the minimum cave size.
                //
                if (FreeBytes > MinSize)
                {
                    CONST DWORD CaveOffset = PtrToData + i - (DWORD)FreeBytes;

                    PCAVE Cave = &CaveBuffer[CaveCount];
                    Cave->Section = Section;
                    Cave->Size = FreeBytes;
                    Cave->RawAddress = (LPVOID)(DWORD_PTR)CaveOffset;
                    Cave->VirtualAddress = (LPVOID)(DWORD_PTR)(
                        ImageBasePreferred + CaveOffset
                        );

                    //
                    // Copy the section name — it is 8 bytes, not null-terminated.
                    //
                    RtlCopyMemory(Cave->SectionName, Section->Name, 8);
                    Cave->SectionName[8] = '\0';

                    CaveCount++;
                }

                FreeBytes = 0;
            }
        }

        Section++;
    }

    return CaveCount;
}

INT
main(
    VOID
)
{
    CONST HMODULE ImageBase = GetModuleHandleA(NULL);

    CAVE Caves[512] = { 0 };

    CONST DWORD Count = FindCaves(
        ImageBase,
        64,         // minimum cave size in bytes
        Caves,
        512
    );

    printf("[+] Found %d code caves\n\n", Count);

    for (DWORD i = 0; i < Count; i++)
    {
        printf(
            "  Section: %-10s  Size: %-6zu  Raw: 0x%p  VA: 0x%p\n",
            Caves[i].SectionName,
            Caves[i].Size,
            Caves[i].RawAddress,
            Caves[i].VirtualAddress
        );
    }

    return 0;
}
