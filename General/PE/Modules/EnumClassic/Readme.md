# Process Module Enumeration

Enumerates all loaded modules (DLLs) in a target process and retrieves their base addresses, sizes, and entry points. Essential for code injection, hooking, and reverse engineering.

## What are Modules?

In Windows, a module is a loaded executable file - either the main EXE or a DLL. Every process has multiple modules:

- **Main executable** - The .exe file (e.g., notepad.exe)
- **System DLLs** - ntdll.dll, kernel32.dll, user32.dll, etc.
- **Runtime libraries** - MSVCRT, VCRUNTIME, etc.
- **Third-party DLLs** - Game engines, anti-cheat, plugins

Each module is loaded at a base address in the process's virtual memory space. Knowing these addresses is crucial for:
- Finding functions to hook
- Code injection
- Memory scanning
- Debugging
- Reverse engineering

## How It Works

### 1. Get Process ID

```cpp
DWORD GetProcessIdByName( const char* ProcessName ) {
    HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
    PROCESSENTRY32 ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof( PROCESSENTRY32 );
    
    Process32First( Snapshot , &ProcessEntry );
    
    do {
        if ( _stricmp( ProcessEntry.szExeFile , ProcessName ) == 0 ) {
            return ProcessEntry.th32ProcessID;
        }
    } while ( Process32Next( Snapshot , &ProcessEntry ) );
    
    return 0;
}
```

Uses `CreateToolhelp32Snapshot` to enumerate all running processes and find the target by name.

### 2. Open Process Handle

```cpp
HANDLE ProcessHandle = OpenProcess(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
    FALSE,
    ProcessId
);
```

**Required permissions:**
- `PROCESS_QUERY_INFORMATION` - Query process information
- `PROCESS_VM_READ` - Read process memory (for module names/paths)

### 3. Enumerate Modules

```cpp
std::vector<HMODULE> GetProcessModules( HANDLE ProcessHandle ) {
    HMODULE ModuleArray[1024];
    DWORD BytesNeeded;
    
    EnumProcessModules( ProcessHandle , ModuleArray , sizeof( ModuleArray ) , &BytesNeeded );
    
    DWORD ModuleCount = BytesNeeded / sizeof( HMODULE );
    
    // Return vector of module handles
}
```

`EnumProcessModules` fills an array with module handles (HMODULEs). Each HMODULE is actually the module's base address.

### 4. Get Module Information

```cpp
MODULEINFO ModInfo;
GetModuleInformation( ProcessHandle , Module , &ModInfo , sizeof( MODULEINFO ) );

typedef struct _MODULEINFO {
    LPVOID lpBaseOfDll;    // Base address
    DWORD SizeOfImage;     // Size in bytes
    LPVOID EntryPoint;     // Entry point address
} MODULEINFO;
```

**lpBaseOfDll** - Where the module is loaded in memory
**SizeOfImage** - Total size of the module (from PE header)
**EntryPoint** - DllMain address (for DLLs) or main entry point (for EXEs)

### 5. Get Module Name and Path

```cpp
char ModuleName[MAX_PATH];
char ModulePath[MAX_PATH];

GetModuleBaseNameA( ProcessHandle , Module , ModuleName , MAX_PATH );
GetModuleFileNameExA( ProcessHandle , Module , ModulePath , MAX_PATH );
```

**GetModuleBaseNameA** - Just the filename (e.g., "ntdll.dll")
**GetModuleFileNameExA** - Full path (e.g., "C:\Windows\System32\ntdll.dll")

## Module Loading Order

Modules are loaded in a specific order:

1. **Main executable** - Always first
2. **ntdll.dll** - Lowest-level Windows API
3. **kernel32.dll** - Core Windows API
4. **kernelbase.dll** - Kernel32 implementation
5. **Static dependencies** - DLLs linked at compile time
6. **Dynamic dependencies** - DLLs loaded via LoadLibrary

This order matters for:
- Import resolution
- Initialization order (DllMain calls)
- Hook installation (hook ntdll before kernel32)

## Finding Specific Modules

```cpp
PVOID GetModuleBaseAddress( HANDLE ProcessHandle , const char* ModuleName ) {
    std::vector<HMODULE> Modules = GetProcessModules( ProcessHandle );
    
    for ( HMODULE Module : Modules ) {
        char CurrentModuleName[MAX_PATH];
        GetModuleBaseNameA( ProcessHandle , Module , CurrentModuleName , MAX_PATH );
        
        if ( _stricmp( CurrentModuleName , ModuleName ) == 0 ) {
            MODULEINFO ModInfo;
            GetModuleInformation( ProcessHandle , Module , &ModInfo , sizeof( MODULEINFO ) );
            return ModInfo.lpBaseOfDll;
        }
    }
    
    return NULL;
}
```

Case-insensitive search for a module by name. Returns its base address.
