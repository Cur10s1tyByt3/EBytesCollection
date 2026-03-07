# Import Address Table (IAT) Hooking
- 👋
## tl;dr

when your program imports functions from DLLs, Windows creates an import address table (IAT) with pointers to those functions. we just overwrite those pointers with our own. simple, effective, and way easier than inline hooking because we don't need to disassemble instructions or deal with relative jumps.

## why did i write this

IAT hooking is one of the simplest hooking techniques and a great starting point for learning how Windows loaders work.

also it's way cleaner than inline hooks. no instruction disassembly, no jump calculations, no worrying about function prologues. just change a pointer and you're done.

## Background

when a PE file imports functions from DLLs, the Windows loader creates several tables:
- Import Directory: list of DLLs being imported
- Import Name Table (INT): function names (read-only)
- Import Address Table (IAT): function pointers (writable)

at load time, the loader resolves function names to addresses and fills in the IAT. when your code calls an imported function, it goes through the IAT.

IAT hooking works by:
1. find the IAT entry for your target function
2. save the original address
3. overwrite it with your hook address
4. profit

interesting parts:
- IAT is in writable memory (needs VirtualProtect to modify)
- only affects imports, not GetProcAddress calls
- super easy to detect (just scan IAT for modified entries)

## How It Works

### Step 1: Parse PE Headers

get the import directory from the PE headers:

```cpp
PeImage ParsePeImage( LPCSTR ImageName ) {
    PVOID ImageBase = GetModuleHandleA( ImageName );
    DWORD_PTR PeBase = (DWORD_PTR)ImageBase;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ImageBase;
    
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)( PeBase + Dos->e_lfanew );
    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)( PeBase + 
        OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
    
    return PeImage{ ImageBase , Dos , NtHeaders , OptionalHeader , FileHeader , ImportDescriptor };
}
```

pass NULL to get the current process's PE.

### Step 2: Find the IAT Entry

walk the import directory to find your target DLL and function:

```cpp
PeImage Pe = ParsePeImage( NULL );
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
                // found it!
                PVOID OriginalFunction = (PVOID)Thunk->u1.Function;
                PVOID* IatEntry = (PVOID*)&Thunk->u1.Function;
            }
            
            OrigThunk++;
            Thunk++;
        }
    }
    
    ImportDescriptor++;
}
```

important: OriginalFirstThunk has the names, FirstThunk has the addresses. we modify FirstThunk.

### Step 3: Patch the IAT Entry

change memory protection, overwrite the pointer, restore protection:

```cpp
DWORD OldProtect;
VirtualProtect( IatEntry , sizeof( PVOID ) , PAGE_READWRITE , &OldProtect );
*IatEntry = HookFunc;
VirtualProtect( IatEntry , sizeof( PVOID ) , OldProtect , &OldProtect );
```

that's it. now all calls through the IAT go to your hook.

### Step 4: Calling the Original

just call the saved original pointer:

```cpp
int WINAPI HookedMessageBoxA( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType ) {
    printf( "[*] MessageBoxA hooked!\n" );
    return g_OriginalMessageBoxA( hWnd , "Hooked via IAT!" , lpCaption , uType );
}
```

no need to remove hooks or anything fancy. the original pointer still works.

### Step 5: Unhooking

restore the original pointer:

```cpp
BOOL Remove( ) {
    if ( !IatEntry || !OriginalFunction )
        return FALSE;
    
    DWORD OldProtect;
    VirtualProtect( IatEntry , sizeof( PVOID ) , PAGE_READWRITE , &OldProtect );
    *IatEntry = OriginalFunction;
    VirtualProtect( IatEntry , sizeof( PVOID ) , OldProtect , &OldProtect );
    
    return TRUE;
}
```

## Full Implementation

```cpp
namespace FunStuff {

class IatHook {
private:
    static PVOID OriginalFunction;
    static PVOID* IatEntry;

public:
    static BOOL Install( LPCSTR Module , LPCSTR Proc , PVOID HookFunc , PVOID* OutOriginal );
    static BOOL Remove( );
};

}
```

simple class with static members. no templates, no VEH, no hardware breakpoints. just pointer swapping.

## Usage Example

```cpp
typedef int( WINAPI* MessageBoxA_t )( HWND , LPCSTR , LPCSTR , UINT );
MessageBoxA_t g_OriginalMessageBoxA = nullptr;

int WINAPI HookedMessageBoxA( HWND hWnd , LPCSTR lpText , LPCSTR lpCaption , UINT uType ) {
    printf( "[*] MessageBoxA hooked!\n" );
    return g_OriginalMessageBoxA( hWnd , "Hooked via IAT!" , lpCaption , uType );
}

int main( ) {
    printf( "[*] Loading user32.dll...\n" );
    LoadLibraryA( "user32.dll" );
    
    printf( "[*] Installing MessageBoxA IAT hook...\n" );
    FunStuff::IatHook::Install( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , (PVOID*)&g_OriginalMessageBoxA );
    
    printf( "[+] MessageBoxA hooked!\n\n" );
    MessageBoxA( nullptr , "Hello World!" , "Test" , MB_OK );
    
    FunStuff::IatHook::Remove( );
    
    return 0;
}
```

output:
```
[*] Loading user32.dll...
[*] Installing MessageBoxA IAT hook...
[+] IAT Original Address: 0x00007FFC12345678
[+] IAT Entry Location: 0x00007FF612340000
[+] MessageBoxA hooked!

[*] Testing MessageBoxA...
[*] MessageBoxA hooked!
```

message box shows "Hooked via IAT!" instead of "Hello World!"

## Important Notes

### Why Load the DLL First?

if the DLL isn't loaded, there's no IAT entry for it. LoadLibraryA forces the loader to create IAT entries.

console apps don't automatically import user32.dll, so we need to load it manually.

### IAT vs GetProcAddress

IAT hooks only affect calls that go through the IAT. if code uses GetProcAddress to get a function pointer, it bypasses the IAT entirely.

example:
```cpp
// this goes through IAT (hooked)
MessageBoxA( ... );

// this bypasses IAT (not hooked)
auto func = (MessageBoxA_t)GetProcAddress( GetModuleHandleA( "user32.dll" ) , "MessageBoxA" );
func( ... );
```

### Per-Process

each process has its own IAT. hooking your IAT doesn't affect other processes.

if you want to hook other processes, you need to inject into them and hook their IAT.

### Easy to Detect

IAT hooks are trivial to detect:
1. walk the IAT
2. check if pointers point outside the target DLL
3. if yes, it's hooked

antivirus and anti-cheat software do this all the time.

### Memory Protection

the IAT is usually in read-only memory. you need VirtualProtect to make it writable before modifying.

some packers/protectors make the IAT read-only and use guard pages to detect modifications.

## Advantages

### Simple

no instruction disassembly, no jump calculations, no worrying about function prologues. just change a pointer.

easiest hooking technique to implement.

### Reliable

no issues with position-independent code, no problems with short functions, no edge cases with instruction boundaries.

if the function is imported, you can hook it.

### Clean Unhooking

just restore the original pointer. no need to restore instructions or worry about concurrent execution.

### Cross-Platform

works on x86, x64, ARM, ARM64. pointer sizes change but the technique is the same.

## Disadvantages

### Only Hooks Imports

if code doesn't import the function (uses GetProcAddress instead), the hook doesn't work.

### Easy to Detect

trivial to scan for modified IAT entries. not stealthy at all.

### Per-Process

only affects the current process. can't do system-wide hooks without injecting into every process.

### Doesn't Hook Delay-Loaded Imports

delay-loaded imports use a different mechanism. you'd need to hook the delay-load helper function.

## Common Use Cases

### API Monitoring

hook APIs in your own process to log calls:
```cpp
HANDLE WINAPI HookedCreateFileA( ... ) {
    printf( "[*] CreateFileA: %s\n" , lpFileName );
    return g_OriginalCreateFileA( ... );
}
```

### DLL Injection

inject a DLL into a process and hook its imports to modify behavior.

### Testing

hook functions in unit tests to mock dependencies without changing code.

### Debugging

hook APIs to add logging or breakpoints without modifying the target binary.

## Debugging Tips

if it doesn't work:

1. is the DLL loaded? (LoadLibraryA before hooking)
2. is the function imported? (check with PE viewer)
3. are you modifying FirstThunk? (not OriginalFirstThunk)
4. did VirtualProtect succeed? (check return value)
5. is the IAT entry correct? (print the address)

common mistake: modifying OriginalFirstThunk instead of FirstThunk. OriginalFirstThunk is read-only and used for name lookups.

## Credits and References

**classic technique:** been around since the 90s, used in countless game trainers and malware
