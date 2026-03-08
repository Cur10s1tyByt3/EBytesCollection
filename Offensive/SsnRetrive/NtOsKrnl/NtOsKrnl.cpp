#include<Windows.h>
#include<cstdio>

//
// ============================================================
//  NtOsKrnl.cpp
//  SSN retrieval by scanning ntoskrnl.exe stub bytes.
//
//  Maps ntoskrnl.exe from disk as a data file (no DllMain),
//  then scans each Zw* export stub for 0xB8 (MOV EAX, imm32)
//  to extract the SSN. Useful as a cross-validation source
//  since the kernel image on disk is untouched by EDR hooks.
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

static DWORD
GetSsnFromStub(
    _In_ CONST PBYTE FnAddr
)
{
    for (WORD Offset = 0; Offset < 32; Offset++)
    {
        //
        // JMP — stub is hooked or invalid, bail.
        //
        if (FnAddr[Offset] == 0xE9) return 0;

        //
        // MOV EAX, imm32 — the immediate 32-bit value is the SSN.
        //
        if (FnAddr[Offset] == 0xB8)
            return *(PDWORD)(FnAddr + Offset + 1);
    }

    return 0;
}

static BOOL
NtOsKrnl_DumpAll(
    _Out_ PSSN_TABLE Table
)
{
    Table->Count = 0;

    //
    // BUG 1 — WOW64 FS redirection:
    //   In a 32-bit process on 64-bit Windows, GetSystemDirectoryA returns
    //   C:\Windows\SysWOW64 — ntoskrnl.exe is NOT there, only in the real
    //   System32. Disable FS redirection around the path query and load.
    //   GetProcAddress so this compileS.
    //   But it wont work on x86, i havent dug deeper.
    typedef BOOL(WINAPI* FnDisable)(PVOID*);
    typedef BOOL(WINAPI* FnRevert)(PVOID);

    CONST HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FnDisable pDisable = (FnDisable)GetProcAddress(hK32, "Wow64DisableWow64FsRedirection");
    FnRevert  pRevert = (FnRevert)GetProcAddress(hK32, "Wow64RevertWow64FsRedirection");

    PVOID OldRedirect = NULL;
    if (pDisable) pDisable(&OldRedirect);

    CHAR KernelPath[MAX_PATH] = { 0 };
    GetSystemDirectoryA(KernelPath, MAX_PATH);
    lstrcatA(KernelPath, "\\ntoskrnl.exe");

    // DOESNT WORK ON X86 >>>
    // BUG 2 — DONT_RESOLVE_DLL_REFERENCES still runs the PE loader machine-
    //   type check and refuses to map a x64 PE into a x86 process (error 193,
    //   "not a valid Win32 application").
    //
    //   LOAD_LIBRARY_AS_IMAGE_RESOURCE skips the machine-type check entirely
    //   AND maps sections at virtual alignment so RVAs remain valid.
    //   Side-effect: the returned HMODULE has bit 1 set as a tag — mask it
    //   off before treating the value as a base address pointer.
    //   And still doesnt wanna work on x86!!! only works on x64 At the Moment.
    CONST HMODULE KernelBase = LoadLibraryExA(
        KernelPath,
        NULL,
        LOAD_LIBRARY_AS_IMAGE_RESOURCE
    );

    if (pRevert) pRevert(OldRedirect);

    if (KernelBase == NULL)
    {
        printf("[-] NtOsKrnl: could not map %s (%d)\n", KernelPath, GetLastError());
        return FALSE;
    }

    //
    // LOAD_LIBRARY_AS_IMAGE_RESOURCE tags the handle — strip the low 2 bits.
    //
    CONST PBYTE Base = (PBYTE)((ULONG_PTR)KernelBase & ~(ULONG_PTR)3);

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders =
        (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    CONST IMAGE_DATA_DIRECTORY ExportDataDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDataDir.Size == 0)
    {
        FreeLibrary(KernelBase);
        return FALSE;
    }

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDataDir.VirtualAddress);

    CONST PDWORD NameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    CONST PWORD  Ordinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    CONST PDWORD FuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);

    for (DWORD i = 0;
        i < Exports->NumberOfFunctions && Table->Count < MAX_SYSCALLS;
        i++)
    {
        LPCSTR Name = (LPCSTR)(Base + NameRvas[i]);
        if (Name[0] != 'Z' || Name[1] != 'w') continue;

        CONST PBYTE FnAddr = Base + FuncRvas[Ordinals[i]];
        CONST DWORD Ssn = GetSsnFromStub(FnAddr);

        if (Ssn == 0) continue;

        PSSN_ENTRY E = &Table->Entries[Table->Count++];
        lstrcpyA(E->Name, Name);
        E->Ssn = (WORD)Ssn;
        E->Address = (PVOID)FnAddr;
    }

    FreeLibrary(KernelBase);
    return (Table->Count > 0);
}

INT main(VOID)
{
    SetConsoleOutputCP(CP_UTF8);

    SSN_TABLE Table = { 0 };

    if (NtOsKrnl_DumpAll(&Table) == FALSE)
    {
        printf("[-] NtOsKrnl failed\n");
        return 1;
    }

    printf("[+] NtOsKrnl - %d syscalls\n\n", Table.Count);

    for (DWORD i = 0; i < Table.Count; i++)
    {
        printf(
            "  %-40s  SSN: 0x%04X (%4d)\n",
            Table.Entries[i].Name,
            Table.Entries[i].Ssn,
            Table.Entries[i].Ssn
        );
    }

    return 0;
}
