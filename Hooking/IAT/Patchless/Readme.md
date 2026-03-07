# VEH-Based IAT Hooking via Hardware Breakpoints
Hooking imported functions using vectored exception handlers and debug registers

## tl;dr

instead of patching the import address table directly, we set hardware breakpoints on the imported function addresses. when the function gets called, a SINGLE_STEP exception fires, our VEH catches it, and redirects execution to our hook. no memory modifications in the IAT, no inline patches, just CPU debug registers doing the work.

## why did i write this

wanted something stealthier than traditional IAT hooks. modifying the IAT is easy to detect (just scan for changed entries). hardware breakpoints leave no memory artifacts.
spoiler: it works perfectly for single-threaded apps. multi-threaded apps need extra work since debug registers are per-thread. but it's a solid technique for specific use cases.

## Background

traditional IAT hooking overwrites entries in the import address table to point to your hook. this works but:
- modifies memory (detectable via IAT scanning)
- leaves artifacts that can be signature scanned
- easy to detect and restore

VEH + hardware breakpoint approach:
- no memory modifications in the IAT
- uses CPU debug registers (Dr0-Dr3)
- vectored exception handler catches SINGLE_STEP exceptions
- redirects execution at the CPU level

## How It Works

### Step 1: Parse the IAT

walk the import directory to find the target function:

```cpp
PeImage ParsePeImage( LPCSTR ImageName ) {
    PVOID ImageBase = GetModuleHandleA( ImageName );
    DWORD_PTR PeBase = (DWORD_PTR)ImageBase;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ImageBase;
    
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)( PeBase + Dos->e_lfanew );
    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)( PeBase + 
        OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
    
    return PeImage{ ImageBase , Dos , NtHeaders , OptionalHeader , FileHeader , ImportDescriptor , ExportDirectory };
}
```

find the specific import:

```cpp
PeImage Pe = ParsePeImage( NULL );  // NULL = current process
DWORD_PTR Base = (DWORD_PTR)Pe.ImageBase;
auto ImportDescriptor = Pe.ImportDescriptor;

while ( ImportDescriptor->Name ) {
    LPCSTR LibName = (LPCSTR)( Base + ImportDescriptor->Name );
    
    if ( _strcmpi( LibName , Module ) == 0 ) {
        auto OrigThunk = (PIMAGE_THUNK_DATA)( Base + ImportDescriptor->OriginalFirstThunk );
        auto Thunk = (PIMAGE_THUNK_DATA)( Base + ImportDescriptor->FirstThunk );
        
        while ( OrigThunk->u1.AddressOfData ) {
            auto ByName = (PIMAGE_IMPORT_BY_NAME)( Base + OrigThunk->u1.AddressOfData );
            
            if ( _strcmpi( ByName->Name , Proc ) == 0 ) {
                PVOID Address = (PVOID)Thunk->u1.Function;
                // found it!
            }
            
            OrigThunk++;
            Thunk++;
        }
    }
    
    ImportDescriptor++;
}
```

the IAT has two thunk tables:
- OriginalFirstThunk: points to import names (read-only)
- FirstThunk: points to actual function addresses (writable, this is the IAT)

we walk both in parallel to find our function.

### Step 2: Set Hardware Breakpoint

same as EAT hooking - find a free debug register and set it:

```cpp
DWORD FindFreeDrIndex( PCONTEXT Ctx ) {
    for ( DWORD i = 0; i < 4; i++ ) {
        if ( !( Ctx->Dr7 & ( 1ULL << ( i * 2 ) ) ) )
            return i;
    }
    return (DWORD)-1;
}

BOOL SetHardwareBreakpoint( PVOID Address , DWORD DrIndex ) {
    HANDLE Thread = GetCurrentThread( );
    CONTEXT Ctx = { 0 };
    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    GetThreadContext( Thread , &Ctx );
    
    switch ( DrIndex ) {
        case 0: Ctx.Dr0 = (DWORD_PTR)Address; break;
        case 1: Ctx.Dr1 = (DWORD_PTR)Address; break;
        case 2: Ctx.Dr2 = (DWORD_PTR)Address; break;
        case 3: Ctx.Dr3 = (DWORD_PTR)Address; break;
    }
    
    Ctx.Dr7 |= ( 1ULL << ( DrIndex * 2 ) );
    Ctx.Dr7 &= ~( 3ULL << ( 16 + DrIndex * 4 ) );
    Ctx.Dr7 &= ~( 3ULL << ( 18 + DrIndex * 4 ) );
    
    return SetThreadContext( Thread , &Ctx );
}
```

### Step 3: VEH Handler

catch SINGLE_STEP exceptions and redirect:

```cpp
LONG CALLBACK VectoredHandler( PEXCEPTION_POINTERS Info ) {
    if ( Info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP )
        return EXCEPTION_CONTINUE_SEARCH;
    
    DWORD_PTR CurrentIp = GetInstructionPointer( Info->ContextRecord );
    
    if ( CurrentIp == (DWORD_PTR)State.OriginalFunction ) {
        printf( "[*] VEH Triggered for %p\n" , State.OriginalFunction );
        SetInstructionPointer( Info->ContextRecord , (DWORD_PTR)State.HookFunction );
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}
```

### Step 4: Calling the Original

temporarily disable the breakpoint to call the original:

```cpp
template<typename Ret , typename... Args>
Ret CallOriginal( Args... args ) {
    RemoveHardwareBreakpoint( State.DrIndex );
    
    typedef Ret( *FuncType )( Args... );
    Ret Result = ( (FuncType)State.OriginalFunction )( args... );
    
    SetHardwareBreakpoint( State.OriginalFunction , State.DrIndex );
    return Result;
}
```

## Full Implementation

```cpp
namespace FunStuff {

class EatHook {
private:
    static VehHookState State;
    static PVOID VehHandle;
    
    static DWORD FindFreeDrIndex( PCONTEXT Ctx );
    static BOOL SetHardwareBreakpoint( PVOID Address , DWORD DrIndex );
    static BOOL RemoveHardwareBreakpoint( DWORD DrIndex );
    static LONG CALLBACK VectoredHandler( PEXCEPTION_POINTERS Info );

public:
    static BOOL Install( LPCSTR Module , LPCSTR Proc , PVOID HookFunc , PVOID* OutOriginal );
    static BOOL Remove( );
    
    template<typename Ret , typename... Args>
    static Ret CallOriginal( Args... args );
};

}
```

yeah the class is called EatHook but it does IAT hooking, i will fix the code dw. ignore it >:)

## Usage Example

```cpp
int WINAPI HookedMessageBoxA( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType ) {
    printf( "[*] MessageBoxA hooked via VEH!\n" );
    auto Result = FunStuff::EatHook::CallOriginal<int>( hWnd , "Hooked via VEH!" , lpCaption , uType );
    return Result;
}

int main( ) {
    printf( "[*] Loading user32.dll...\n" );
    HMODULE User32 = LoadLibraryA( "user32.dll" );
    
    PVOID OriginalFunc = nullptr;
    
    printf( "[*] Installing MessageBoxA IAT hook...\n" );
    FunStuff::EatHook::Install( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , &OriginalFunc );
    
    printf( "[+] MessageBoxA hooked!\n\n" );
    MessageBoxA( nullptr , "Hello World!" , "Test" , MB_OK );
    
    FunStuff::EatHook::Remove( );
    
    return 0;
}
```

output:
```
[*] Loading user32.dll...
[*] Installing MessageBoxA IAT hook...
[+] IAT Original Address: 0x00007FFC12345678
[+] MessageBoxA hooked!

[*] Testing MessageBoxA...
[*] VEH Triggered for 0x00007FFC12345678
[*] MessageBoxA hooked via VEH!
```

message box shows "Hooked via VEH!" instead of "Hello World!"

## Important Notes

### Why Load user32.dll First?

console apps don't automatically import user32.dll. if it's not loaded, there's no IAT entry for it.

LoadLibraryA forces the DLL to load and creates IAT entries.

### IAT vs EAT Hooking

IAT hooking:
- hooks imports in YOUR process
- only affects YOUR process
- each process has its own IAT

EAT hooking:
- hooks exports in the TARGET DLL
- affects ALL processes that call GetProcAddress
- global across the system

this implementation does IAT hooking, so it only affects the current process.

### Per-Thread Limitation

hardware breakpoints are per-thread. if you have multiple threads calling the hooked function, you need to set breakpoints on each thread.

this implementation only hooks the current thread.

### Only 4 Breakpoints

x86/x64 CPUs only have 4 debug registers. you can only hook 4 functions simultaneously per thread.

### Cross-Platform Support

works on x86, x64, ARM, and ARM64 thanks to the IP helper functions:

```cpp
DWORD_PTR GetInstructionPointer( PCONTEXT Ctx ) {
#if defined( _M_X64 ) || defined( __x86_64__ )
    return Ctx->Rip;
#elif defined( _M_IX86 ) || defined( __i386__ )
    return Ctx->Eip;
#elif defined( _M_ARM64 ) || defined( __aarch64__ )
    return Ctx->Pc;
#elif defined( _M_ARM ) || defined( __arm__ )
    return Ctx->Pc;
#endif
}
```

## Advantages

### No IAT Modifications

traditional IAT hooks overwrite entries in the import address table. this approach doesn't touch the IAT at all.

harder to detect via IAT scanning.
