# Manual PE Loader (Memory DLL Loading)

This is a complete manual PE loader implementation that maps DLL files directly into memory without touching the filesystem or calling LoadLibrary. Took me about 2 hours to get all the edge cases right.

## What It Does

Windows normally loads DLLs through LoadLibrary which goes through the NT loader, touches disk, creates loader data structures, and leaves forensic artifacts everywhere. This implementation skips all that — you hand it raw PE bytes and it does everything the OS loader would do, but entirely in usermode memory.

## Why Manual Mapping Matters

When you call LoadLibrary, Windows registers the module in the PEB, creates a loader lock, updates the InLoadOrderModuleList, and leaves the DLL path in PROCESS_BASIC_INFORMATION. Security tools enumerate loaded modules via EnumProcessModules or by walking the PEB — they'll see everything LoadLibrary touches.

Manual mapping bypasses this. The DLL exists only as executable memory with no loader metadata. Module enumeration tools won't find it. The IAT still points to real system DLLs (we call LoadLibrary for dependencies like kernel32.dll), but the payload itself is invisible to standard enumeration.

## Implementation Details

The loader handles every step the NT loader performs:

**Section Mapping** — PE files on disk have sections (code, data, imports) laid out for file alignment. In memory they need to be at different offsets based on section alignment. We VirtualAlloc a region matching SizeOfImage, then copy each section to its VirtualAddress. Sections with no raw data (like .bss) get zero-filled.

**Base Relocation** — DLLs have a preferred ImageBase baked in at compile time. If we can't allocate at that address (and we usually can't), every absolute pointer in the image is wrong. The .reloc section contains a table of every address that needs patching. We calculate the delta between preferred and actual base, then walk the relocation table and add the delta to each pointer. On x64 this is IMAGE_REL_BASED_DIR64, on x86 it's IMAGE_REL_BASED_HIGHLOW.

**Import Resolution** — The IAT (Import Address Table) starts as a list of DLL names and function names. We walk the import directory, LoadLibraryA each dependency, then GetProcAddress each function and patch the thunk. After this step, when the DLL calls CreateFileA, it jumps to the real kernel32 export.

**Exception Handler Registration** — This is the #1 reason manual loaders crash on x64. Windows uses table-based exception handling — the OS walks the RUNTIME_FUNCTION table in the .pdata section to unwind stacks during exceptions or even normal function returns. Without calling RtlAddFunctionTable, any function with a prolog/epilog (which is every function MSVC compiles) will crash the process when it tries to return. We register the exception directory after finalizing sections.

**TLS Callbacks** — Thread Local Storage callbacks run before DllMain. The TLS directory contains an array of function pointers that need to be invoked with DLL_PROCESS_ATTACH. Most DLLs don't use TLS, but if they do and you skip this step, the DLL will crash when it tries to access uninitialized TLS data.

**Memory Protection** — After copying sections, everything is PAGE_READWRITE. We walk each section's characteristics (IMAGE_SCN_MEM_READ/WRITE/EXECUTE) and VirtualProtect to the correct flags. Code sections become PAGE_EXECUTE_READ, data sections become PAGE_READWRITE, read-only data becomes PAGE_READONLY. Without this step, DEP kills the process the instant it tries to execute from a non-executable page.

**DllMain Invocation** — Finally we call the entry point with DLL_PROCESS_ATTACH. The entry point address comes from OptionalHeader.AddressOfEntryPoint. We wrap it in __try/__except because even with everything set up correctly, a DLL can still crash in its own initialization code.

## The x64 Exception Handler Bug

This took forever to debug. On x64, every function compiled by MSVC has a prolog that saves registers and an epilog that restores them. When the epilog runs, Windows needs to know how to unwind the stack — it looks up the function's address in the .pdata section (IMAGE_DIRECTORY_ENTRY_EXCEPTION) to find the UNWIND_INFO structure.

If you don't call RtlAddFunctionTable to register the exception directory, the OS has no idea how to unwind your manually mapped code. The instant any function tries to return, RtlDispatchException fails to find the handler, and the process terminates with STATUS_ACCESS_VIOLATION.

The fix is simple — after FinalizeSections, call RtlAddFunctionTable with the RUNTIME_FUNCTION array from .pdata. On cleanup, call RtlDeleteFunctionTable before freeing the memory. x86 doesn't need this because it uses stack-based SEH instead of table-based unwinding.

## The Header Sync Bug

Another subtle bug — CopySections updates Section->Misc.PhysicalAddress in the original headers (the Data buffer) to store the VirtualAlloc'd address of each section. But FinalizeSections was reading from Dll->NtHeaders, which is the stale in-memory copy from the initial RtlCopyMemory. The PhysicalAddress fields in that copy still had the linker's placeholder values.

FinalizeSections then ORs those garbage values with the upper 32 bits of CodeBase, producing completely wrong addresses for VirtualProtect. The .text section stays PAGE_READWRITE (no execute bit), and DEP kills the process when it tries to execute DllMain.

The fix is passing OrgNtHeaders (the updated buffer) to FinalizeSections instead of Dll->NtHeaders (the stale copy).

## Testing with SimpleDll

The test DLL (SimpleDll.cpp) has no CRT dependencies — it uses only raw Windows API calls. This is critical because MSVC normally inserts _DllMainCRTStartup as the real entry point, which runs CRT initialization before calling your DllMain. That CRT init crashes in a manually mapped context because it expects the NT loader's full initialization.

We bypass this with `#pragma comment(linker, "/ENTRY:DllMain")` to set the entry point directly, and `#pragma comment(linker, "/NODEFAULTLIB")` to strip the CRT. We also disable stack cookies with `/GS-` because __security_init_cookie lives in the CRT we just removed.

SimpleDll exports a TestFunction that adds two integers. The loader resolves it via MemoryGetProcAddress (which walks the EAT just like GetProcAddress), calls it, and prints the result.

## Limitations

This is a DLL loader, not an EXE loader. The code has an ExeEntry field but never invokes it — if you want to run executables from memory, you'd need to set up a fake PEB, create a thread at the entry point, and handle the different initialization path.

We only manually map the target DLL. Dependencies (kernel32, user32, ntdll, etc.) still go through LoadLibrary. You could recursively manually map the entire dependency tree, but that's overkill for most use cases and breaks if any dependency uses delay-load imports or complex loader features.

The SkipEntryPoint parameter exists for special DLLs like kernel32 or ntdll whose DllMain crashes when called twice in an already-running process. For normal DLLs, always pass FALSE.

## Usage

```cpp
// Load from disk
// i recommend loading by bytes, or by resource etc...
HANDLE hFile = CreateFileA("payload.dll", GENERIC_READ, ...);
DWORD size = GetFileSize(hFile, NULL);
PBYTE buffer = HeapAlloc(GetProcessHeap(), 0, size);
ReadFile(hFile, buffer, size, &bytesRead, NULL);
CloseHandle(hFile);

PDLL_FROM_MEMORY dll = MemoryLoadLibrary(buffer, size, FALSE);
HeapFree(GetProcessHeap(), 0, buffer);

// Resolve and call an export
typedef int (*PFUNC)(int, int);
PFUNC pFunc = (PFUNC)MemoryGetProcAddress(dll, "MyFunction");
int result = pFunc(5, 10);

// Cleanup
MemoryFreeLibrary(dll);
```

The loader returns a DLL_FROM_MEMORY structure containing the base address, NT headers, import module handles, and initialization state. MemoryFreeLibrary calls DllMain with DLL_PROCESS_DETACH, frees all imported modules, deregisters exception handlers, and releases the memory.
