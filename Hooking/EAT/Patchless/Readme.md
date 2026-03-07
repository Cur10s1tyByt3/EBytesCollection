# VEH-Based EAT Hooking via Hardware Breakpoints
Hooking exported functions using vectored exception handlers and debug registers

## tl;dr

instead of patching the export address table directly, we set hardware breakpoints on the exported function addresses. when the function gets called, a SINGLE_STEP exception fires, our VEH catches it, and redirects execution to our hook. no memory modifications, no inline patches...

## why did i write this

was reading about different hooking techniques and thought "what if we combine EAT hooking with hardware breakpoints instead of memory patches?"

also wanted something that doesn't modify any executable memory which makes it harder to detect than traditional hooks. antivirus can't signature scan what isn't written to memory.

spoiler: it works great for single threaded scenarios but gets messy with multiple threads since debug registers are per thread. but hey, it's a cool proof of concept.

## Background

traditional EAT hooking modifies the export address table entries to point to your hook. this works but:
- modifies executable memory (detectable)
- needs to allocate jump stubs near the module
- leaves artifacts in memory

## How It Works

### Step 1: Find the Export

parse the PE headers manually to find the export address table:

```cpp
PeImage ParsePeImage( LPCSTR ImageName ) {
    PVOID ImageBase = GetModuleHandleA( ImageName );
    DWORD_PTR PeBase = (DWORD_PTR)ImageBase;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ImageBase;
    
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)( PeBase + Dos->e_lfanew );
    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)( PeBase + 
        OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    
    return PeImage{ ImageBase , Dos , NtHeaders , OptionalHeader , FileHeader , ExportDirectory };
}
```

walk the export name table, find your function, get its RVA:

```cpp
PDWORD Names = (PDWORD)( Base + Dir->AddressOfNames );
PDWORD Funcs = (PDWORD)( Base + Dir->AddressOfFunctions );
PWORD Ords = (PWORD)( Base + Dir->AddressOfNameOrdinals );

for ( DWORD i = 0; i < Dir->NumberOfNames; i++ ) {
    LPCSTR Current = (LPCSTR)( Base + Names[i] );
    if ( _strcmpi( Current , Proc ) == 0 ) {
        DWORD RVA = Funcs[Ords[i]];
        PVOID Address = (PVOID)( Base + RVA );
        // found it!
    }
}
```

### Step 2: Set Hardware Breakpoint

find a free debug register and set it:

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
    
    // set the debug register
    switch ( DrIndex ) {
        case 0: Ctx.Dr0 = (DWORD_PTR)Address; break;
        case 1: Ctx.Dr1 = (DWORD_PTR)Address; break;
        case 2: Ctx.Dr2 = (DWORD_PTR)Address; break;
        case 3: Ctx.Dr3 = (DWORD_PTR)Address; break;
    }
    
    // enable the breakpoint in Dr7
    Ctx.Dr7 |= ( 1ULL << ( DrIndex * 2 ) );
    Ctx.Dr7 &= ~( 3ULL << ( 16 + DrIndex * 4 ) );  // execution breakpoint
    Ctx.Dr7 &= ~( 3ULL << ( 18 + DrIndex * 4 ) );  // 1 byte size
    
    return SetThreadContext( Thread , &Ctx );
}
```

Dr7 is the control register:
- bits 0,2,4,6: local enable for Dr0-Dr3
- bits 16-31: breakpoint conditions and sizes

### Step 3: Install VEH Handler

register a vectored exception handler to catch SINGLE_STEP exceptions:

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

when the CPU hits the breakpoint, it fires EXCEPTION_SINGLE_STEP. we check if the instruction pointer matches our hooked function, then redirect it to our hook.

### Step 4: Cross-Platform IP Handling

different architectures use different register names for the instruction pointer:

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

void SetInstructionPointer( PCONTEXT Ctx , DWORD_PTR Address ) {
#if defined( _M_X64 ) || defined( __x86_64__ )
    Ctx->Rip = Address;
#elif defined( _M_IX86 ) || defined( __i386__ )
    Ctx->Eip = (DWORD)Address;
#elif defined( _M_ARM64 ) || defined( __aarch64__ )
    Ctx->Pc = Address;
#elif defined( _M_ARM ) || defined( __arm__ )
    Ctx->Pc = (DWORD)Address;
#endif
}
```

x86/x64 use Eip/Rip, ARM uses Pc. handle them all.

### Step 5: Calling the Original

to call the original function, temporarily disable the breakpoint:

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

remove breakpoint → call original → restore breakpoint. simple.

## Full Implementation

```cpp
namespace FunStuff {

class VehHook {
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

methods defined outside the class using `::` notation for clean separation.

## Usage Example

```cpp
int WINAPI HookedMessageBoxA( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType ) {
    printf( "[*] MessageBoxA hooked via VEH!\n" );
    auto Result = FunStuff::VehHook::CallOriginal<int>( hWnd , "Hooked via VEH!" , lpCaption , uType );
    return Result;
}

int main( ) {
    printf( "[*] Loading user32.dll...\n" );
    HMODULE User32 = LoadLibraryA( "user32.dll" );
    
    PVOID OriginalFunc = nullptr;
    
    printf( "[*] Installing MessageBoxA EAT hook...\n" );
    FunStuff::VehHook::Install( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , &OriginalFunc );
    
    printf( "[+] MessageBoxA hooked!\n\n" );
    MessageBoxA( nullptr , "Hello World!" , "Test" , MB_OK );
    
    FunStuff::VehHook::Remove( );
    
    return 0;
}
```

output:
```
[*] Loading user32.dll...
[*] Installing MessageBoxA EAT hook...
[+] EAT Original Address: 0x00007FFC12345678
[+] MessageBoxA hooked!

[*] Testing MessageBoxA...
[*] VEH Triggered for 0x00007FFC12345678
[*] MessageBoxA hooked via VEH!
```

message box shows "Hooked via VEH!" instead of "Hello World!"

## Important Notes

### Why Load user32.dll First?

console apps don't load user32.dll by default. if you try to hook it before loading, GetModuleHandleA returns NULL and everything breaks.

always LoadLibraryA before hooking.

### Per-Thread Limitation

hardware breakpoints are per-thread. if you have multiple threads calling the hooked function, you need to set breakpoints on each thread.

this implementation only hooks the current thread...
or use a thread creation hook to set breakpoints on new threads automatically.

### Only 4 Breakpoints

x86/x64 CPUs only have 4 debug registers. you can only hook 4 functions simultaneously per thread.

if you need more, you'll have to get creative (or use a different hooking method).

### VEH Priority

vectored exception handlers run before structured exception handlers. we register with priority 1 (first) so we get the exception before anyone else.

if another VEH is registered with higher priority, it might interfere.

## Advantages

### No Memory Modifications

traditional hooks modify executable memory (inline patches, IAT/EAT patches). this approach doesn't touch any memory in the target module.

harder to detect via memory scanning.

### No Jump Stubs

EAT hooks usually need to allocate jump stubs near the module. this approach doesn't need any allocations.

cleaner, less artifacts.

### Works Across Architectures

with the IP helper functions, this works on x86, x64, ARM, and ARM64 with the same code.

just recompile for your target architecture.

## Disadvantages

### Per-Thread

biggest limitation. only works for the thread that set the breakpoint.

multi-threaded apps need extra work.

### Limited Slots

only 4 debug registers = only 4 hooks per thread.

if you need more, use a different method.

### Performance

every call to the hooked function triggers an exception. exceptions are slow.

for high-frequency functions this might be noticeable.

2026
