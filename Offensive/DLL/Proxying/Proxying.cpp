#include<Windows.h>
#include<cstdio>

//
// ============================================================
//  ProxyDll
//  Walks the EAT of a loaded DLL and writes a #pragma comment
//  linker export directive for every named export.
//
//  Usage:
//    ProxyDll.exe <dll_path> <suffix>
//    e.g. ProxyDll.exe C:\Windows\System32\version.dll _orig
//
//  Output is always saved as proxied.h next to the running exe.
// ============================================================
//

static VOID
ProxyDll(
    _In_ LPCSTR DllPath,
    _In_ LPCSTR Suffix
)
{
    //
    // Load the target DLL so we can walk its in-memory EAT.
    // DONT_RESOLVE_DLL_REFERENCES skips DllMain and import resolution --
    // we only need the headers, not an initialized module.
    //
    CONST HMODULE Module = LoadLibraryExA(
        DllPath,
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (Module == NULL)
    {
        printf("[-] LoadLibraryExA failed for %s: %d\n", DllPath, GetLastError());
        return;
    }

    CONST PBYTE Base = (PBYTE)Module;

    CONST PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
    CONST PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    CONST IMAGE_DATA_DIRECTORY ExportDataDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDataDir.Size == 0)
    {
        printf("[-] %s has no export table\n", DllPath);
        FreeLibrary(Module);
        return;
    }

    CONST PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(Base + ExportDataDir.VirtualAddress);

    CONST PDWORD NameRvas = (PDWORD)(Base + Exports->AddressOfNames);
    CONST PWORD  Ordinals = (PWORD)(Base + Exports->AddressOfNameOrdinals);
    CONST PDWORD FuncRvas = (PDWORD)(Base + Exports->AddressOfFunctions);

    //
    // Build the DLL base name without extension for the forwarder path.
    // e.g. "C:\Windows\System32\version.dll" + "_orig" -> "version_orig"
    //
    CHAR DllNoExt[MAX_PATH] = { 0 };

    LPCSTR LastSlash = DllPath;
    for (LPCSTR p = DllPath; *p; p++)
    {
        if (*p == '\\' || *p == '/') LastSlash = p + 1;
    }
    lstrcpyA(DllNoExt, LastSlash);

    LPSTR DotPos = DllNoExt + lstrlenA(DllNoExt);
    while (DotPos > DllNoExt && *DotPos != '.') DotPos--;
    if (*DotPos == '.') *DotPos = '\0';

    //
    // Build the output path as <exedir>\proxied.h.
    // GetModuleFileNameA gives the full path of the running exe —
    // strip the filename to get just the directory, then append proxied.h.
    //
    CHAR OutputPath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, OutputPath, MAX_PATH);

    //
    // Find the last backslash and terminate there to get the directory.
    //
    LPSTR LastBackslash = OutputPath;
    for (LPSTR p = OutputPath; *p; p++)
    {
        if (*p == '\\' || *p == '/') LastBackslash = p;
    }
    *(LastBackslash + 1) = '\0';

    lstrcatA(OutputPath, "proxied.h");

    printf("[*] Writing to: %s\n", OutputPath);

    FILE* OutputFile = NULL;
    if (fopen_s(&OutputFile, OutputPath, "a") != 0 || OutputFile == NULL)
    {
        printf("[-] Could not open output file: %s\n", OutputPath);
        FreeLibrary(Module);
        return;
    }

    DWORD AmountProxied = 0;

    for (DWORD i = 0; i < Exports->NumberOfNames; i++)
    {
        CONST LPCSTR FuncName = (LPCSTR)(Base + NameRvas[i]);
        CONST WORD   FuncOrdinal = Ordinals[i];

        UNREFERENCED_PARAMETER(FuncRvas[FuncOrdinal]);

        //
        // Write the pragma directive for every export including forwarders.
        // Forwarder chains works fine: myproxy.Func -> OrigDll.Func -> RealImpl.
        // Skipping forwarders would silently drop exports and break ABI.
        //
        fprintf(
            OutputFile,
            "#pragma comment( linker, \"/export:%s=%s%s.%s\" )\n",
            FuncName,
            DllNoExt,
            Suffix,
            FuncName
        );

        printf("[+] Proxying %s\n", FuncName);
        AmountProxied++;
    }

    fclose(OutputFile);
    FreeLibrary(Module);

    printf("[+] Done - proxied %d functions\n", AmountProxied);
}

INT
main(
    _In_ INT   Argc,
    _In_ PCHAR Argv[]
)
{
    if (Argc < 3)
    {
        printf(
            "Usage  : %s <dll_path> <suffix>\n"
            "Example: %s C:\\Windows\\System32\\version.dll _orig\n"
            "\n"
            "Output is always saved as proxied.h next to the running exe.\n",
            Argv[0],
            Argv[0]
        );
        return 1;
    }

    CONST LPCSTR DllPath = Argv[1];
    CONST LPCSTR Suffix = Argv[2];

    printf("[*] Target DLL : %s\n", DllPath);
    printf("[*] Suffix     : %s\n", Suffix);
    printf("\n");

    ProxyDll(DllPath, Suffix);

    return 0;
}
