# Export Address Table (EAT) Hooking
Intercepting function calls by patching the export table directly

## tl;dr

GetProcAddress walks the export address table to find functions. we can overwrite entries in that table to redirect calls to our hook. no inline patching, no IAT hooking, just modify the RVA in the EAT and watch everything that calls GetProcAddress get your hook instead.

## Background

when you call GetProcAddress, Windows walks three tables in the target DLL:
- Export Name Table (function names as strings)
- Export Ordinal Table (maps name index to ordinal)
- Export Address Table (RVAs to actual function code)

the flow is: name → ordinal → RVA → actual address

EAT hooking works by replacing the RVA in the Export Address Table with an RVA to our jump stub. now every future GetProcAddress call returns our hook.

## Implementation Walkthrough

### Step 1: Parse PE Headers

```c
IMAGE_EXPORT_DIRECTORY* GetExportDirectory( _In_ HMODULE Module ) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)( (BYTE*)Module + DosHeader->e_lfanew );
    
    DWORD ExportRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if ( !ExportRva )
        return nullptr;
    
    return RvaToPointer<IMAGE_EXPORT_DIRECTORY>( Module , ExportRva );
}
```

manual PE parsing. no dbghelp.dll needed. just follow the DOS header to NT headers, grab the export directory RVA from the data directory array.

### Step 2: Find Target Function in EAT

```c
DWORD* GetEATEntry( _In_ HMODULE Module , _In_ const char* FunctionName ) {
    IMAGE_EXPORT_DIRECTORY* ExportDir = GetExportDirectory( Module );
    if ( !ExportDir )
        return nullptr;
    
    DWORD* Functions = RvaToPointer<DWORD>( Module , ExportDir->AddressOfFunctions );
    DWORD* Names = RvaToPointer<DWORD>( Module , ExportDir->AddressOfNames );
    WORD* Ordinals = RvaToPointer<WORD>( Module , ExportDir->AddressOfNameOrdinals );
    
    for ( DWORD i = 0; i < ExportDir->NumberOfNames; i++ ) {
        char* Name = RvaToPointer<char>( Module , Names[i] );
        if ( lstrcmpA( Name , FunctionName ) == 0 ) {
            return &Functions[Ordinals[i]];
        }
    }
    
    return nullptr;
}
```

walk the name table, compare strings, use the ordinal to index into the function table. return a pointer to the DWORD entry (not the value, the actual entry address so we can modify it).

### Step 3: Allocate Memory Near Module

here's the problem: EAT entries are 32-bit RVAs. on x64, if your jump stub is more than 2GB away from the module base, the RVA won't fit in a DWORD.

solution: allocate memory close to the target module

```c
void* AllocateNearModule( _In_ HMODULE Module , _In_ SIZE_T Size ) {
    MODULEINFO ModInfo{};
    GetModuleInformation( GetCurrentProcess() , Module , &ModInfo , sizeof( ModInfo ) );
    
    BYTE* StartAddr = (BYTE*)ModInfo.lpBaseOfDll + ModInfo.SizeOfImage;
    BYTE* MaxAddr = StartAddr + 0x7FFF0000;
    
    for ( BYTE* Addr = StartAddr; Addr < MaxAddr; Addr += 0x10000 ) {
        void* Allocated = VirtualAlloc( Addr , Size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
        if ( Allocated )
            return Allocated;
    }
    
    return VirtualAlloc( nullptr , Size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
}
```

start right after the module ends, try allocating in 64KB increments (allocation granularity). if nothing works within 2GB, fall back to allocating anywhere and hope for the best.

### Step 4: Write Jump Stub

need different jumps for x86 vs x64:

```c
SIZE_T WriteJump( _In_ void* Destination , _In_ void* Target ) {
    BYTE* Code = (BYTE*)Destination;
    
#ifdef _WIN64
    Code[0] = 0x48;
    Code[1] = 0xB8;
    *(ULONG_PTR*)( Code + 2 ) = (ULONG_PTR)Target;
    Code[10] = 0xFF;
    Code[11] = 0xE0;
    return 12;
#else
    Code[0] = 0xE9;
    *(DWORD*)( Code + 1 ) = (DWORD)( (ULONG_PTR)Target - (ULONG_PTR)Destination - 5 );
    return 5;
#endif
}
```

x64: `mov rax, Target; jmp rax` (12 bytes, absolute jump)
x86: `jmp rel32` (5 bytes, relative jump)

### Step 5: Patch the EAT Entry

```c
DWORD OldProtect;
VirtualProtect( EatEntry , sizeof( DWORD ) , PAGE_READWRITE , &OldProtect );
*EatEntry = PointerToRva( JumpStub , Module );
VirtualProtect( EatEntry , sizeof( DWORD ) , OldProtect , &OldProtect );
```

change memory protection, overwrite the RVA, restore protection. flush instruction cache because CPUs cache decoded instructions and we just modified executable code.

## Full Hook Installation

```c
BOOL InstallEATHook( _In_ const char* ModuleName , _In_ const char* FunctionName , 
    _In_ void* HookFunction , _Out_ void** OriginalFunction ) {
    HMODULE Module = GetModuleHandleA( ModuleName );
    if ( !Module )
        return FALSE;
    
    DWORD* EatEntry = GetEATEntry( Module , FunctionName );
    if ( !EatEntry )
        return FALSE;
    
    *OriginalFunction = RvaToPointer<void>( Module , *EatEntry );
    
#ifdef _WIN64
    SIZE_T JumpSize = 12;
#else
    SIZE_T JumpSize = 5;
#endif
    
    void* JumpStub = AllocateNearModule( Module , JumpSize );
    if ( !JumpStub )
        return FALSE;
    
    SIZE_T Written = WriteJump( JumpStub , HookFunction );
    FlushInstructionCache( GetCurrentProcess() , JumpStub , Written );
    
    DWORD OldProtect;
    VirtualProtect( EatEntry , sizeof( DWORD ) , PAGE_READWRITE , &OldProtect );
    *EatEntry = PointerToRva( JumpStub , Module );
    VirtualProtect( EatEntry , sizeof( DWORD ) , OldProtect , &OldProtect );
    
    return TRUE;
}
```

## Usage Example

```c
typedef int( WINAPI* MessageBoxA_t )( HWND , LPCSTR , LPCSTR , UINT );
MessageBoxA_t g_OriginalMessageBoxA = nullptr;

int WINAPI HookedMessageBoxA( _In_opt_ HWND hWnd , _In_opt_ LPCSTR lpText , 
    _In_opt_ LPCSTR lpCaption , _In_ UINT uType ) {
    return g_OriginalMessageBoxA( hWnd , "Hooked Hello World!" , lpCaption , uType );
}

int main( ) {
    HMODULE User32 = LoadLibraryA( "user32.dll" );
    
    g_OriginalMessageBoxA = (MessageBoxA_t)GetProcAddress( User32 , "MessageBoxA" );
    
    void* Unused = nullptr;
    InstallEATHook( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , &Unused );
    
    MessageBoxA_t MessageBoxFunc = (MessageBoxA_t)GetProcAddress( User32 , "MessageBoxA" );
    
    MessageBoxFunc( nullptr , "Hello World!" , "Test" , MB_OK );
    
    return 0;
}
```

output: message box shows "Hooked Hello World!" instead of "Hello World!"

## Important Notes

### Why Load user32.dll First?

user32.dll isn't loaded by default in console apps. if you try to hook it before loading, GetModuleHandleA returns NULL and everything breaks.

solution: LoadLibraryA before hooking.

### Why Save Original Before Hooking?

if you install the hook first, then try to get the original function pointer, you'll get your hook instead. save the real function pointer BEFORE patching the EAT, u can also make it restore,remove,add and make the code prettier :)

## Limitations

### RVA Size Limitation

EAT entries are DWORDs. if you can't allocate within 2GB of the module, the RVA won't fit and the hook will fail (or worse, corrupt memory with a truncated address).

the fallback allocation helps but isn't guaranteed to work.

## Credits and References

**based on:** codereversing.com's "Function Hooking: Export Address Table Hooks (7/7)"

**tools used:**
- Visual Studio 2026
- x64dbg for debugging

## Disclaimer

**IMPORTANT: READ THIS BEFORE USING THIS CODE**

the author is not responsible for misuse. you've been warned.

---
