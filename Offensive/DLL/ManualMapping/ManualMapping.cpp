#include<Windows.h>
#include<cstdio>

//
// ============================================================
//  DllFromMemory — loads a DLL from a raw byte buffer without
//  touching the filesystem. Performs all steps the Windows
//  loader would do: section mapping, base relocation, import
//  resolution, TLS callbacks, and DllMain invocation.
//  ENJOY ! >:D
// ============================================================
//

typedef BOOL(WINAPI* PDLL_ENTRY)(HINSTANCE, DWORD, LPVOID);
typedef VOID(WINAPI* PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);

//
// Protection flag lookup table indexed by [executable][readable][writeable].
//
static CONST DWORD ProtectionFlags[2][2][2] =
{
    {
        //
        // Not executable.
        //
        { PAGE_NOACCESS,  PAGE_WRITECOPY  },
        { PAGE_READONLY,  PAGE_READWRITE  }
    },
    {
        //
        // Executable.
        //
        { PAGE_EXECUTE,          PAGE_EXECUTE_WRITECOPY  },
        { PAGE_EXECUTE_READ,     PAGE_EXECUTE_READWRITE  }
    }
};

typedef struct _SECTION_FINALIZE_DATA {
    PVOID  Address;
    PVOID  AlignedAddress;
    SIZE_T Size;
    DWORD  Characteristics;
    BOOL   Last;
} SECTION_FINALIZE_DATA, * PSECTION_FINALIZE_DATA;

typedef struct _DLL_FROM_MEMORY {
    PVOID    CodeBase;          // allocated region holding the mapped image
    PVOID    NtHeaders;         // pointer to nt* headers within CodeBase
    HMODULE* ImportModules;     // array of hadnles for each imported dll
    DWORD    ImportModuleCount;
    BOOL     IsDll;
    BOOL     Initialized;
    BOOL     ExceptionsRegistered;  // x64 excep table registration status
    PDLL_ENTRY DllEntry;
} DLL_FROM_MEMORY, * PDLL_FROM_MEMORY;

//
// ============================================================
//  Helpers
// ============================================================
//

static DWORD
AlignValueUp(
    _In_ DWORD Value,
    _In_ DWORD Alignment
)
{
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

static SIZE_T
GetRealSectionSize(
    _In_ PIMAGE_SECTION_HEADER  Section,
    _In_ PIMAGE_NT_HEADERS      NtHeaders
)
{
    DWORD Size = Section->SizeOfRawData;

    if (Size == 0)
    {
        if (Section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        {
            Size = NtHeaders->OptionalHeader.SizeOfInitializedData;
        }
        else if (Section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            Size = NtHeaders->OptionalHeader.SizeOfUninitializedData;
        }
    }

    return (SIZE_T)Size;
}

//
// ============================================================
//  CopySections
//  Maps each PE section from the raw buffer into the allocated
//  virtual region. Sections with no raw data are zeroed.
// ============================================================
//

static BOOL
CopySections(
    _In_ CONST PBYTE        Data,
    _In_ PIMAGE_NT_HEADERS  OrgNtHeaders,
    _In_ PVOID              CodeBase
)
{
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(OrgNtHeaders);

    for (WORD i = 0; i < OrgNtHeaders->FileHeader.NumberOfSections; i++, Section++)
    {
        if (Section->SizeOfRawData == 0)
        {
            //
            // Section has no raw data — allocate zeroed memory for BSS-style sections.
            //
            DWORD Size = OrgNtHeaders->OptionalHeader.SectionAlignment;
            if (Size == 0) continue;

            PVOID Dest = VirtualAlloc(
                (PBYTE)CodeBase + Section->VirtualAddress,
                Size,
                MEM_COMMIT,
                PAGE_READWRITE
            );

            if (Dest == NULL)
            {
                printf("[-] VirtualAlloc for section %d failed\n", i);
                return FALSE;
            }

            //
            // Store physical address for FinalizeSections to use.
            //
            Section->Misc.PhysicalAddress = (DWORD)((ULONG_PTR)Dest & 0xffffffff);
            RtlZeroMemory(Dest, Size);
            continue;
        }

        PVOID Dest = VirtualAlloc(
            (PBYTE)CodeBase + Section->VirtualAddress,
            Section->SizeOfRawData,
            MEM_COMMIT,
            PAGE_READWRITE
        );

        if (Dest == NULL)
        {
            printf("[-] VirtualAlloc for section %d failed\n", i);
            return FALSE;
        }

        RtlCopyMemory(Dest, Data + Section->PointerToRawData, Section->SizeOfRawData);
        Section->Misc.PhysicalAddress = (DWORD)((ULONG_PTR)Dest & 0xffffffff);
    }

    return TRUE;
}

//
// ============================================================
//  PerformBaseRelocation
//  Adjusts all absolute addresses in the image by the delta
//  between preferred and actual load address.
// ============================================================
//

static BOOL
PerformBaseRelocation(
    _In_ PIMAGE_NT_HEADERS OrgNtHeaders,
    _In_ PVOID             CodeBase,
    _In_ SSIZE_T           Delta
)
{
    if (OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
    {
        return (Delta == 0);
    }

    PIMAGE_BASE_RELOCATION Relocation = (PIMAGE_BASE_RELOCATION)(
        (PBYTE)CodeBase +
        OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );

    while (Relocation->VirtualAddress != 0)
    {
        PBYTE  Dest = (PBYTE)CodeBase + Relocation->VirtualAddress;
        PWORD  RelInfo = (PWORD)((PBYTE)Relocation + sizeof(IMAGE_BASE_RELOCATION));
        DWORD  RelCount = (Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < RelCount; i++, RelInfo++)
        {
            INT    Type = (*RelInfo) >> 12;
            INT    Offset = (*RelInfo) & 0xFFF;

            switch (Type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                //
                // No-op — used for alignment padding.
                //
                break;

            case IMAGE_REL_BASED_HIGHLOW:
            {
                //
                // 32-bit relocation — add delta to the DWORD at patch address.
                //
                PDWORD PatchAddr = (PDWORD)(Dest + Offset);
                *PatchAddr += (DWORD)Delta;
                break;
            }

            case IMAGE_REL_BASED_DIR64:
            {
                //
                // 64-bit relocation — add delta to the ULONGLONG at patch address.
                //
                PULONGLONG PatchAddr = (PULONGLONG)(Dest + Offset);
                *PatchAddr += (ULONGLONG)Delta;
                break;
            }
            }
        }

        Relocation = (PIMAGE_BASE_RELOCATION)(
            (PBYTE)Relocation + Relocation->SizeOfBlock
            );
    }

    return TRUE;
}

//
// ============================================================
//  BuildImportTable
//  Walks the import directory, loads each dependency with
//  LoadLibraryA, and resolves each thunk via GetProcAddress.
// ============================================================
//

static BOOL
BuildImportTable(
    _In_  PIMAGE_NT_HEADERS  OrgNtHeaders,
    _In_  PVOID              CodeBase,
    _Out_ HMODULE** OutModules,
    _Out_ PDWORD             OutCount
)
{
    *OutModules = NULL;
    *OutCount = 0;

    DWORD ImportSize = OrgNtHeaders->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (ImportSize == 0)
    {
        printf("[+] No imports to resolve\n");
        return TRUE;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
        (PBYTE)CodeBase +
        OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );

    //
    // Count import descriptors first so we can allocate the module array.
    //
    DWORD DescCount = 0;
    for (PIMAGE_IMPORT_DESCRIPTOR D = ImportDesc; D->Name != 0; D++) DescCount++;

    if (DescCount == 0) return TRUE;

    printf("[+] Found %d import descriptors\n", DescCount);

    HMODULE* Modules = (HMODULE*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        DescCount * sizeof(HMODULE)
    );

    DWORD ModuleIndex = 0;

    for (; ImportDesc->Name != 0; ImportDesc++)
    {
        LPCSTR DllName = (LPCSTR)((PBYTE)CodeBase + ImportDesc->Name);

        printf("[+] Loading import: %s\n", DllName);

        HMODULE Handle = LoadLibraryA(DllName);
        if (Handle == NULL)
        {
            printf("[-] LoadLibraryA failed for: %s\n", DllName);

            //
            // Free already-loaded modules before returning failure.
            //
            for (DWORD k = 0; k < ModuleIndex; k++) FreeLibrary(Modules[k]);
            HeapFree(GetProcessHeap(), 0, Modules);
            return FALSE;
        }

        Modules[ModuleIndex++] = Handle;

        PULONG_PTR ThunkRef, FuncRef;

        if (ImportDesc->OriginalFirstThunk != 0)
        {
            ThunkRef = (PULONG_PTR)((PBYTE)CodeBase + ImportDesc->OriginalFirstThunk);
            FuncRef = (PULONG_PTR)((PBYTE)CodeBase + ImportDesc->FirstThunk);
        }
        else
        {
            //
            // No OriginalFirstThunk — use FirstThunk for both name lookup and patching.
            //
            ThunkRef = (PULONG_PTR)((PBYTE)CodeBase + ImportDesc->FirstThunk);
            FuncRef = (PULONG_PTR)((PBYTE)CodeBase + ImportDesc->FirstThunk);
        }

        DWORD FuncCount = 0;
        for (; *ThunkRef != 0; ThunkRef++, FuncRef++)
        {
            FARPROC Func;

            if (IMAGE_SNAP_BY_ORDINAL(*ThunkRef))
            {
                //
                // Import by ordinal — pass ordinal number directly.
                // U Can be fancy and make ur own GetProcAddress.
                // If u have any reason u can use LdrGetProcedureAddress too
                //
                Func = GetProcAddress(Handle, (LPCSTR)IMAGE_ORDINAL(*ThunkRef));
            }
            else
            {
                //
                // Import by name — skip the 2-byte Hint field to get the name string.
                //
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(
                    (PBYTE)CodeBase + *ThunkRef
                    );
                Func = GetProcAddress(Handle, ImportByName->Name);
            }

            if (Func == NULL)
            {
                printf("[-] GetProcAddress failed\n");
                for (DWORD k = 0; k < ModuleIndex; k++) FreeLibrary(Modules[k]);
                HeapFree(GetProcessHeap(), 0, Modules);
                return FALSE;
            }

            *FuncRef = (ULONG_PTR)Func;
            FuncCount++;
        }
        
        printf("[+] Resolved %d functions from %s\n", FuncCount, DllName);
    }

    *OutModules = Modules;
    *OutCount = ModuleIndex;
    return TRUE;
}

//
// ============================================================
//  FinalizeSection / FinalizeSections
//  Sets correct VirtualProtect flags on each section based on
//  its IMAGE_SCN_MEM_READ / WRITE / EXECUTE characteristics.
//  Adjacent sections sharing the same page are merged.
// ============================================================
//

static VOID
FinalizeSection(
    _In_ PSECTION_FINALIZE_DATA SectionData,
    _In_ DWORD                  PageSize,
    _In_ DWORD                  SectionAlignment
)
{
    if (SectionData->Size == 0) return;

    if (SectionData->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        //
        // Discard section only if it sits on its own page boundary.
        //
        if (SectionData->Address == SectionData->AlignedAddress &&
            (SectionData->Last ||
                SectionAlignment == PageSize ||
                (SectionData->Size % PageSize) == 0))
        {
            VirtualFree(SectionData->Address, SectionData->Size, MEM_DECOMMIT);
        }
        return;
    }

    INT  Executable = (SectionData->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
    INT  Readable = (SectionData->Characteristics & IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
    INT  Writeable = (SectionData->Characteristics & IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;

    DWORD Protect = ProtectionFlags[Executable][Readable][Writeable];

    if (SectionData->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
    {
        Protect |= PAGE_NOCACHE;
    }

    DWORD OldProtect = 0;
    VirtualProtect(SectionData->Address, SectionData->Size, Protect, &OldProtect);
}

static VOID
FinalizeSections(
    _In_ PIMAGE_NT_HEADERS OrgNtHeaders,
    _In_ PVOID             CodeBase,
    _In_ DWORD             PageSize
)
{
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(OrgNtHeaders);

    //
    // On x64 the upper 32 bits of CodeBase must be preserved for page alignment.
    //
    ULONG_PTR ImageOffset = 0;
#ifdef _WIN64
    ImageOffset = (ULONG_PTR)CodeBase & 0xffffffff00000000ULL;
#endif

    SECTION_FINALIZE_DATA SectionData = { 0 };
    SectionData.Address = (PVOID)((ULONG_PTR)Section->Misc.PhysicalAddress | ImageOffset);
    SectionData.AlignedAddress = (PVOID)((ULONG_PTR)SectionData.Address & ~((ULONG_PTR)PageSize - 1));
    SectionData.Size = GetRealSectionSize(Section, OrgNtHeaders);
    SectionData.Characteristics = Section->Characteristics;
    SectionData.Last = FALSE;
    Section++;

    for (WORD i = 1; i < OrgNtHeaders->FileHeader.NumberOfSections; i++, Section++)
    {
        PVOID  SectionAddress = (PVOID)((ULONG_PTR)Section->Misc.PhysicalAddress | ImageOffset);
        PVOID  AlignedAddress = (PVOID)((ULONG_PTR)SectionAddress & ~((ULONG_PTR)PageSize - 1));
        SIZE_T SectionSize = GetRealSectionSize(Section, OrgNtHeaders);

        //
        // If this section overlaps the previous one's page, merge them.
        //
        if (SectionData.AlignedAddress == AlignedAddress ||
            (ULONG_PTR)SectionData.Address + SectionData.Size > (ULONG_PTR)AlignedAddress)
        {
            if ((Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 ||
                (SectionData.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
            {
                SectionData.Characteristics =
                    (SectionData.Characteristics | Section->Characteristics) &
                    ~IMAGE_SCN_MEM_DISCARDABLE;
            }
            else
            {
                SectionData.Characteristics |= Section->Characteristics;
            }

            SectionData.Size = (SIZE_T)(
                (ULONG_PTR)SectionAddress + SectionSize - (ULONG_PTR)SectionData.Address
                );
            continue;
        }

        FinalizeSection(&SectionData, PageSize, OrgNtHeaders->OptionalHeader.SectionAlignment);

        SectionData.Address = SectionAddress;
        SectionData.AlignedAddress = AlignedAddress;
        SectionData.Size = SectionSize;
        SectionData.Characteristics = Section->Characteristics;
    }

    SectionData.Last = TRUE;
    FinalizeSection(&SectionData, PageSize, OrgNtHeaders->OptionalHeader.SectionAlignment);
}

//
// ============================================================
//  ExecuteTLS
//  Fires any TLS callbacks registered in the PE's TLS directory.
// ============================================================
//

static VOID
ExecuteTLS(
    _In_ PIMAGE_NT_HEADERS OrgNtHeaders,
    _In_ PVOID             CodeBase
)
{
    if (OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
    {
        return;
    }

    PIMAGE_TLS_DIRECTORY TlsDir = (PIMAGE_TLS_DIRECTORY)(
        (PBYTE)CodeBase +
        OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
        );

    PULONG_PTR CallbackPtr = (PULONG_PTR)TlsDir->AddressOfCallBacks;
    if (CallbackPtr == NULL) return;

    while (*CallbackPtr != 0)
    {
        PIMAGE_TLS_CALLBACK Callback = (PIMAGE_TLS_CALLBACK)*CallbackPtr;
        Callback(CodeBase, DLL_PROCESS_ATTACH, NULL);
        CallbackPtr++;
    }
}

//
// ============================================================
//  RegisterExceptionHandlers
//  x64 uses table-based exception handling — the OS walks the
//  RUNTIME_FUNCTION table in .pdata to find unwind info when
//  any exception occurs, including normal stack unwinds during
//  function returns. Without this call, any exception inside
//  the manually mapped image terminates the process immediately
//  because RtlDispatchException cannot locate the handlers.
//
//  This is the #1 reason manually mapped DLLs crash on x64.
// ============================================================
//

static BOOL
RegisterExceptionHandlers(
    _In_ PIMAGE_NT_HEADERS OrgNtHeaders,
    _In_ PVOID             CodeBase
)
{
#ifdef _WIN64
    PIMAGE_DATA_DIRECTORY ExceptionDir =
        &OrgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (ExceptionDir->Size == 0)
    {
        //
        // No exception directory — leafonly DLL, no unwind info needed..,
        //
        return TRUE;
    }

    PRUNTIME_FUNCTION FuncTable = (PRUNTIME_FUNCTION)(
        (PBYTE)CodeBase + ExceptionDir->VirtualAddress
        );

    DWORD EntryCount = ExceptionDir->Size / sizeof(RUNTIME_FUNCTION);

    if (RtlAddFunctionTable(FuncTable, EntryCount, (DWORD64)CodeBase) == FALSE)
    {
        printf("[-] RtlAddFunctionTable failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Registered %d exception handlers via RtlAddFunctionTable\n", EntryCount);
    return TRUE;
#else
    //
    // x86 uses stack-based SEH — no table registration needed.
    //
    UNREFERENCED_PARAMETER(OrgNtHeaders);
    UNREFERENCED_PARAMETER(CodeBase);
    return TRUE;
#endif
}

//
// ============================================================
//  MemoryLoadLibrary
//  Main entry — maps a raw PE byte buffer into executable memory.
// ============================================================
//

PDLL_FROM_MEMORY
MemoryLoadLibrary(
    _In_ CONST PBYTE Data,
    _In_ SIZE_T       DataSize,
    _In_ BOOL         SkipEntryPoint
)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Data;

    if (DataSize < sizeof(IMAGE_DOS_HEADER) ||
        DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] Not a valid PE file\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS OrgNtHeaders = (PIMAGE_NT_HEADERS)(Data + DosHeader->e_lfanew);

    if (OrgNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Invalid NT signature\n");
        return NULL;
    }


    //
    // Determine at runtime whether we are a 64-bit process.
    // sizeof(PVOID) == 8 in a 64-bit process, 4 in a 32-bit process.
    //
    CONST BOOL Is64BitProcess = (sizeof(PVOID) == 8);

    CONST WORD ExpectedMachine = Is64BitProcess
        ? IMAGE_FILE_MACHINE_AMD64
        : IMAGE_FILE_MACHINE_I386;

    if (OrgNtHeaders->FileHeader.Machine != ExpectedMachine)
    {
        printf("[-] Machine type mismatch (i386 vs AMD64)\n");
        return NULL;
    }

    //
    // Get system page size for section alignment logic.
    //
    SYSTEM_INFO SysInfo = { 0 };
    GetNativeSystemInfo(&SysInfo);

    //
    // Calculate last section end to verify alignment.
    //
    DWORD LastSectionEnd = 0;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(OrgNtHeaders);

    for (WORD i = 0; i < OrgNtHeaders->FileHeader.NumberOfSections; i++, Section++)
    {
        DWORD EndOfSection = Section->VirtualAddress +
            (Section->SizeOfRawData > 0
                ? Section->SizeOfRawData
                : OrgNtHeaders->OptionalHeader.SectionAlignment);

        if (EndOfSection > LastSectionEnd) LastSectionEnd = EndOfSection;
    }

    DWORD AlignedImageSize = AlignValueUp(OrgNtHeaders->OptionalHeader.SizeOfImage, SysInfo.dwPageSize);
    DWORD AlignedLastSection = AlignValueUp(LastSectionEnd, SysInfo.dwPageSize);

    if (AlignedImageSize != AlignedLastSection)
    {
        printf("[-] Section alignment mismatch\n");
        return NULL;
    }

    //
    // Try to allocate at the preferred image base first.
    //
    PVOID PreferredBase = (PVOID)(ULONG_PTR)OrgNtHeaders->OptionalHeader.ImageBase;

    PVOID CodeBase = VirtualAlloc(
        PreferredBase,
        OrgNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (CodeBase == NULL)
    {
        CodeBase = VirtualAlloc(
            NULL,
            OrgNtHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
    }

    if (CodeBase == NULL)
    {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return NULL;
    }

    //
    // If we are a 64-bit process and the allocated region spans the 4GB
    // boundary, HIGHLOW (32-bit) relocations would silently overflow.
    // Block off unsuitable regions and retry until we get one that sits
    // entirely below 4GB
    //
    if (Is64BitProcess)
    {
        PVOID BlockedRegions[64] = { 0 };
        DWORD BlockedCount = 0;

        while (((ULONG_PTR)CodeBase >> 32) <
            (((ULONG_PTR)CodeBase + AlignedImageSize) >> 32) &&
            BlockedCount < 64)
        {
            BlockedRegions[BlockedCount++] = CodeBase;

            CodeBase = VirtualAlloc(
                NULL,
                AlignedImageSize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            );

            if (CodeBase == NULL) break;
        }

        //
        // Release all blocked regions regardless of outcome.
        //
        for (DWORD k = 0; k < BlockedCount; k++)
        {
            VirtualFree(BlockedRegions[k], 0, MEM_RELEASE);
        }

        if (CodeBase == NULL)
        {
            printf("[-] Could not find memory region below 4GB\n");
            return NULL;
        }
    }


    //
    // Allocate and track the DLL_FROM_MEMORY context.
    //
    PDLL_FROM_MEMORY Dll = (PDLL_FROM_MEMORY)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(DLL_FROM_MEMORY)
    );

    Dll->CodeBase = CodeBase;

    //
    // Copy headers into the allocated region.
    //
    VirtualAlloc(
        CodeBase,
        OrgNtHeaders->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT,
        PAGE_READWRITE
    );

    RtlCopyMemory(CodeBase, Data, OrgNtHeaders->OptionalHeader.SizeOfHeaders);
    Dll->NtHeaders = (PBYTE)CodeBase + DosHeader->e_lfanew;

    //
    // Patch ImageBase in the in-memory headers to reflect actual load address.
    //
    SSIZE_T LocationDelta = (SSIZE_T)((ULONG_PTR)CodeBase - OrgNtHeaders->OptionalHeader.ImageBase);

    if (LocationDelta != 0)
    {
        PIMAGE_NT_HEADERS InMemNtHeaders = (PIMAGE_NT_HEADERS)Dll->NtHeaders;
        InMemNtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)CodeBase;
    }

    printf("[+] Copying sections...\n");
    if (!CopySections(Data,  OrgNtHeaders,  CodeBase))
    {
        printf("[-] CopySections failed\n");
        VirtualFree(CodeBase, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, Dll);
        return NULL;
    }

    printf("[+] Performing base relocation (delta: 0x%llx)...\n", (LONGLONG)LocationDelta);
    if (LocationDelta != 0)
    {
        if (!PerformBaseRelocation(OrgNtHeaders, CodeBase, LocationDelta))
        {
            printf("[-] Base relocation failed\n");
            VirtualFree(CodeBase, 0, MEM_RELEASE);
            HeapFree(GetProcessHeap(), 0, Dll);
            return NULL;
        }
    }

    printf("[+] Building import table...\n");
    if (!BuildImportTable(OrgNtHeaders, CodeBase, &Dll->ImportModules, &Dll->ImportModuleCount))
    {
        printf("[-] BuildImportTable failed\n");
        VirtualFree(CodeBase, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, Dll);
        return NULL;
    }

    printf("[+] Finalizing sections...\n");
    FinalizeSections(OrgNtHeaders, CodeBase, SysInfo.dwPageSize);

    printf("[+] Registering exception handlers...\n");
    Dll->ExceptionsRegistered = RegisterExceptionHandlers(OrgNtHeaders,  CodeBase );

    if (Dll->ExceptionsRegistered == FALSE)
    {
        //
        // Non-fatal on x86. Fatal on x64 — any function call will crash.
        //
#ifdef _WIN64
        printf("[-] Exception registration failed — DllMain will crash\n");
        VirtualFree(CodeBase, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, Dll);
        return NULL;
#endif
    }

    printf("[+] Executing TLS callbacks...\n");
    ExecuteTLS(OrgNtHeaders, CodeBase);

    Dll->IsDll = (OrgNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    if (!SkipEntryPoint && OrgNtHeaders->OptionalHeader.AddressOfEntryPoint != 0)
    {
        PVOID EntryPtr = (PBYTE)CodeBase + OrgNtHeaders->OptionalHeader.AddressOfEntryPoint;

        printf("[+] Calling entry point at: %p\n", EntryPtr);
        
        if (Dll->IsDll)
        {
            Dll->DllEntry = (PDLL_ENTRY)EntryPtr;
            
            __try
            {
                Dll->Initialized = Dll->DllEntry((HINSTANCE)CodeBase, DLL_PROCESS_ATTACH, NULL);
                printf("[+] DllMain returned: %d\n", Dll->Initialized);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                printf("[-] DllMain crashed with exception: 0x%08X\n", GetExceptionCode());
                Dll->Initialized = FALSE;
            }
        }
    }

    return Dll;
}

//
// ============================================================
//  MemoryGetProcAddress
//  Walks the EAT to find a function by name. Returns its
//  address within the mapped image.
// ============================================================
//

PVOID
MemoryGetProcAddress(
    _In_ PDLL_FROM_MEMORY Dll,
    _In_ LPCSTR           FuncName
)
{
    PVOID CodeBase = Dll->CodeBase;

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)Dll->NtHeaders;

    IMAGE_DATA_DIRECTORY ExportDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDir.Size == 0)
    {
        printf("[-] DLL has no export table\n");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)CodeBase + ExportDir.VirtualAddress
        );

    if (Exports->NumberOfNames == 0 || Exports->NumberOfFunctions == 0)
    {
        printf("[-] DLL exports no functions\n");
        return NULL;
    }

    PDWORD  NameRvas = (PDWORD)((PBYTE)CodeBase + Exports->AddressOfNames);
    PWORD   Ordinals = (PWORD)((PBYTE)CodeBase + Exports->AddressOfNameOrdinals);
    PDWORD  FuncRvas = (PDWORD)((PBYTE)CodeBase + Exports->AddressOfFunctions);

    for (DWORD i = 0; i < Exports->NumberOfNames; i++)
    {
        LPCSTR Name = (LPCSTR)((PBYTE)CodeBase + NameRvas[i]);

        if (lstrcmpA(Name, FuncName) == 0)
        {
            WORD Ordinal = Ordinals[i];

            if (Ordinal >= Exports->NumberOfFunctions)
            {
                printf("[-] Invalid ordinal\n");
                return NULL;
            }

            return (PBYTE)CodeBase + FuncRvas[Ordinal];
        }
    }

    printf("[-] Function not found: %s\n", FuncName);
    return NULL;
}

//
// ============================================================
//  MemoryFreeLibrary
//  Calls DllMain with DLL_PROCESS_DETACH, frees imported
//  module handles, and releases the virtual allocation.
// ============================================================
//

VOID
MemoryFreeLibrary(
    _In_ PDLL_FROM_MEMORY Dll
)
{
    if (Dll == NULL) return;

    if (Dll->Initialized && Dll->DllEntry != NULL)
    {
        Dll->DllEntry((HINSTANCE)Dll->CodeBase, DLL_PROCESS_DETACH, NULL);
        Dll->Initialized = FALSE;
    }

    if (Dll->ImportModules != NULL)
    {
        for (DWORD i = 0; i < Dll->ImportModuleCount; i++)
        {
            if (Dll->ImportModules[i] != NULL)
            {
                FreeLibrary(Dll->ImportModules[i]);
            }
        }

        HeapFree(GetProcessHeap(), 0, Dll->ImportModules);
        Dll->ImportModules = NULL;
    }

#ifdef _WIN64
    //
    // Deregister exception handlers — must happen before the memory is freed
    // or the OS will hold a dangling pointer into the released region.
    //
    if (Dll->ExceptionsRegistered == TRUE && Dll->CodeBase != NULL)
    {
        PIMAGE_NT_HEADERS NtHdrs = (PIMAGE_NT_HEADERS)Dll->NtHeaders;
        PIMAGE_DATA_DIRECTORY ExceptionDir =
            &NtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if (ExceptionDir->Size > 0)
        {
            PRUNTIME_FUNCTION FuncTable = (PRUNTIME_FUNCTION)(
                (PBYTE)Dll->CodeBase + ExceptionDir->VirtualAddress
                );

            RtlDeleteFunctionTable(FuncTable);
        }
    }
#endif

    if (Dll->CodeBase != NULL)
    {
        VirtualFree(Dll->CodeBase, 0, MEM_RELEASE);
        Dll->CodeBase = NULL;
        Dll->NtHeaders = NULL;
    }

    HeapFree(GetProcessHeap(), 0, Dll);
}



//
// ============================================================
//  Example usage
// ============================================================
//

INT
main(
    VOID
)
{
    //
    // Read SimpleDll.dll from disk into a heap buffer.
    //
    CONST LPCSTR DllPath = "YOUR FILE PATH HERE";

    printf("[*] Loading: %s\n", DllPath);

    CONST HANDLE FileHandle = CreateFileA(
        DllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        printf("[-] Could not open SimpleDll.dll: %d\n", GetLastError());
        return 1;
    }

    CONST DWORD FileSize = GetFileSize(FileHandle, NULL);
    PBYTE Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize);

    DWORD BytesRead = 0;
    ReadFile(FileHandle, Buffer, FileSize, &BytesRead, NULL);
    CloseHandle(FileHandle);

    printf("[+] Read %d bytes\n", BytesRead);

    //
    // Load Test.dll from the raw buffer — no LoadLibrary call.
    // Pass FALSE to call DllMain since Test.dll is safe to initialize.
    //
    PDLL_FROM_MEMORY Dll = MemoryLoadLibrary(Buffer, FileSize, FALSE);
    HeapFree(GetProcessHeap(), 0, Buffer);

    if (Dll == NULL)
    {
        printf("[-] MemoryLoadLibrary failed\n");
        return 1;
    }

    printf("[+] Loaded SimpleDll.dll from memory at: %p\n", Dll->CodeBase);

    if (Dll->Initialized)
    {
        printf("[+] DllMain returned TRUE\n");
        
        //
        // Test calling an exported function from the memory-loaded DLL.
        //
        typedef INT(*PFUNC_TEST)(INT, INT);
        PFUNC_TEST pTestFunction = (PFUNC_TEST)MemoryGetProcAddress(Dll, "TestFunction");
        
        if (pTestFunction != NULL)
        {
            INT Result = pTestFunction(5, 10);
            printf("[+] TestFunction(5, 10) = %d\n", Result);
        }
        else
        {
            printf("[-] Failed to resolve TestFunction\n");
        }
    }
    else
    {
        printf("[-] DllMain returned FALSE\n");
    }

    MemoryFreeLibrary(Dll);
    printf("[+] Cleaned up successfully\n");
    return 0;
}
