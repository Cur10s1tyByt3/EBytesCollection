
# PEB Enumeration: Deep Dive into Windows Process Internals

A comprehensive exploration of the Process Environment Block (PEB) - one of the most critical undocumented structures in Windows. This implementation demonstrates both local and remote PEB enumeration with full support for 64-bit native and WOW64 (32-bit on 64-bit) processes.

## Table of Contents
- [What is the PEB?](#what-is-the-peb)
- [PEB Architecture](#peb-architecture)
- [Accessing the PEB](#accessing-the-peb)
- [PEB Structure Deep Dive](#peb-structure-deep-dive)
- [Module Enumeration via PEB](#module-enumeration-via-peb)
- [64-bit vs WOW64](#64-bit-vs-wow64)
- [Implementation Details](#implementation-details)

## What is the PEB?

The Process Environment Block (PEB) is a critical data structure in the Windows NT operating system family that exists in user-mode memory space. Despite being undocumented and marked as "opaque" by Microsoft, the PEB is fundamental to how Windows processes operate.

### Core Purpose

The PEB serves as a centralized repository for process-wide information that needs to be accessible from user mode. It contains:

- **Loader Data**: Information about all loaded modules (EXE and DLLs)
- **Process Parameters**: Command line arguments, image path, environment variables
- **Heap Information**: Default process heap and list of all heaps
- **Debug Flags**: Indicators for debugger presence and debugging behavior
- **System Information**: Number of processors, OS version data
- **Subsystem Data**: Information for Win32, POSIX, or OS/2 subsystems

### Why User Mode?

The PEB resides in user-mode memory (not kernel mode) because it's designed to be accessed by user-mode components like:
- **NTDLL.DLL**: The native API layer that bridges user and kernel mode
- **Image Loader**: The PE loader that loads executables and DLLs
- **Heap Manager**: The memory allocation subsystem
- **Runtime Libraries**: C runtime and other system libraries

This design allows these components to access process information without expensive kernel-mode transitions.

### Design Philosophy

The PEB embodies several Windows design principles:

1. **Separation of Concerns**: Kernel manages process creation, user mode manages process behavior
2. **Performance**: Frequently accessed data in user mode avoids syscall overhead
3. **Flexibility**: Undocumented structure allows Microsoft to evolve it without breaking compatibility
4. **Security Through Obscurity**: Lack of documentation makes it harder for malware to abuse (though this has failed)



## PEB Architecture

### Memory Layout

The PEB is allocated in user-mode address space during process creation. Its location is deterministic and accessible through the Thread Environment Block (TEB).

```
Process Address Space
+----------------------------------+
| Kernel Space (High Addresses)    |
| - Not accessible from user mode  |
+----------------------------------+
| User Space (Low Addresses)       |
|                                  |
|  +----------------------------+  |
|  | Stack                      |  |
|  +----------------------------+  |
|  | Heap(s)                    |  |
|  +----------------------------+  |
|  | Loaded Modules (DLLs)      |  |
|  +----------------------------+  |
|  | PEB (Single Instance)      |  | <- One per process
|  +----------------------------+  |
|  | TEB(s) (One per thread)    |  | <- Multiple per process
|  +----------------------------+  |
|  | Executable Image           |  |
|  +----------------------------+  |
+----------------------------------+
```

### Relationship: Process → TEB → PEB

Every Windows process has:
- **One PEB**: Shared across all threads in the process
- **Multiple TEBs**: One for each thread

The relationship:
```
Process
  ├── Thread 1 → TEB 1 ──┐
  ├── Thread 2 → TEB 2 ──┼──→ PEB (Shared)
  ├── Thread 3 → TEB 3 ──┘
  └── Thread N → TEB N ──┘
```

Each TEB contains a pointer to the process's PEB at a fixed offset, allowing any thread to access process-wide information.



## Accessing the PEB

### Local Process (Current Process)

The PEB is accessed through the TEB (Thread Environment Block), which is pointed to by segment registers.

#### x86 (32-bit) Architecture

On 32-bit Windows, the FS segment register points to the TEB:

```
FS Segment Register → TEB
TEB + 0x30 → PEB
```

Assembly code:
```asm
mov eax, fs:[0x30]    ; Load PEB address from TEB
```

C/C++ code:
```cpp
PPEB Peb = (PPEB)__readfsdword( 0x30 );
```

Or using the documented API:
```cpp
PPEB Peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
```

#### x64 (64-bit) Architecture

On 64-bit Windows, the GS segment register points to the TEB:

```
GS Segment Register → TEB
TEB + 0x60 → PEB
```

Assembly code:
```asm
mov rax, gs:[0x60]    ; Load PEB address from TEB
```

C/C++ code:
```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
```

Or using the documented API:
```cpp
PPEB Peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
```

#### Why Different Offsets?

The offset difference (0x30 vs 0x60) exists because:
- **x86**: Pointers are 4 bytes, so fields are more compact
- **x64**: Pointers are 8 bytes, requiring different alignment
- The TEB structure layout differs between architectures to maintain optimal alignment

### Segment Registers: FS and GS

#### Historical Background

Segment registers (CS, DS, ES, FS, GS, SS) are remnants from the x86 segmented memory model. In modern flat memory models, most segments are unused, but FS and GS serve special purposes:

**FS Register (x86)**
- Points to TEB in user mode
- Points to KPCR (Kernel Processor Control Region) in kernel mode
- Allows fast access to thread-local data without function calls

**GS Register (x64)**
- Points to TEB in user mode
- Points to KPCR in kernel mode
- Chosen over FS for x64 to avoid conflicts with some compilers

#### How Segment Registers Work

In x64, segmentation is mostly disabled, but FS and GS are exceptions:

```
Linear Address = Segment Base + Offset

For GS:[0x60]:
  Segment Base = TEB Address (set by kernel)
  Offset = 0x60
  Result = TEB Address + 0x60 = PEB Address
```

The kernel sets the segment base when creating a thread:
```cpp
// Kernel-mode pseudocode
WRMSR( IA32_GS_BASE , TebAddress );  // Set GS base to TEB
```

This allows user-mode code to access the TEB without knowing its address.



### Remote Process (Other Processes)

Accessing another process's PEB requires different techniques since you can't directly access its segment registers.

#### Method 1: NtQueryInformationProcess (64-bit Process)

For 64-bit processes, use `ProcessBasicInformation` (class 0):

```cpp
// 1. Open the target process
HANDLE hProcess = OpenProcess( 
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , 
    FALSE , 
    ProcessId 
);

// 2. Query for PROCESS_BASIC_INFORMATION
PROCESS_BASIC_INFORMATION Pbi = { 0 };
ULONG ReturnLength = 0;

NTSTATUS Status = NtQueryInformationProcess(
    hProcess ,
    ProcessBasicInformation ,  // Class 0
    &Pbi ,
    sizeof( PROCESS_BASIC_INFORMATION ) ,
    &ReturnLength
);

// 3. PEB address is in Pbi.PebBaseAddress
PPEB RemotePebAddress = Pbi.PebBaseAddress;

// 4. Read the remote PEB
PEB RemotePeb = { 0 };
SIZE_T BytesRead = 0;

ReadProcessMemory( 
    hProcess , 
    RemotePebAddress , 
    &RemotePeb , 
    sizeof( PEB ) , 
    &BytesRead 
);
```

#### Method 2: NtQueryInformationProcess (WOW64 Process)

For 32-bit processes running on 64-bit Windows (WOW64), use `ProcessWow64Information` (class 26):

```cpp
// 1. Check if process is WOW64
BOOL IsWow64 = FALSE;
IsWow64Process( hProcess , &IsWow64 );

if ( IsWow64 ) {
    // 2. Query for 32-bit PEB address
    PVOID Peb32Address = NULL;
    
    NtQueryInformationProcess(
        hProcess ,
        (PROCESSINFOCLASS)26 ,  // ProcessWow64Information
        &Peb32Address ,
        sizeof( PVOID ) ,
        NULL
    );
    
    // 3. Read 32-bit PEB structure
    PEB32 RemotePeb32 = { 0 };
    ReadProcessMemory( 
        hProcess , 
        Peb32Address , 
        &RemotePeb32 , 
        sizeof( PEB32 ) , 
        &BytesRead 
    );
}
```

#### Why Two Different Classes?

WOW64 processes have TWO PEBs:
- **64-bit PEB**: For the WOW64 subsystem itself (class 0)
- **32-bit PEB**: For the 32-bit application (class 26)

The 32-bit PEB contains the actual application's modules and data, while the 64-bit PEB contains WOW64 infrastructure.



## PEB Structure Deep Dive

### Complete PEB Layout (Simplified)

```cpp
typedef struct _PEB {
    BYTE InheritedAddressSpace;              // 0x000
    BYTE ReadImageFileExecOptions;           // 0x001
    BYTE BeingDebugged;                      // 0x002 - Debugger flag
    BYTE BitField;                           // 0x003
    PVOID Mutant;                            // 0x008
    PVOID ImageBaseAddress;                  // 0x010 - EXE base address
    PPEB_LDR_DATA Ldr;                       // 0x018 - Loader data
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  // 0x020
    PVOID SubSystemData;                     // 0x028
    PVOID ProcessHeap;                       // 0x030 - Default heap
    PRTL_CRITICAL_SECTION FastPebLock;       // 0x038
    // ... many more fields ...
    ULONG NtGlobalFlag;                      // 0x0BC (x64) - Debug flags
    // ... many more fields ...
    ULONG NumberOfHeaps;                     // Number of heaps
    ULONG MaximumNumberOfHeaps;              // Max heaps
    PVOID* ProcessHeaps;                     // Array of heap handles
    // ... many more fields ...
} PEB, *PPEB;
```

### Key Fields Explained

#### BeingDebugged (Offset 0x002)

The most famous PEB field. Set to 1 when a debugger is attached.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
if ( Peb->BeingDebugged ) {
    // Debugger detected!
}
```

**How it works:**
- When you attach a debugger (WinDbg, x64dbg, Visual Studio), Windows calls `DbgUiRemoteBreakin`
- This eventually calls `NtSetInformationProcess` with `ProcessDebugPort`
- The kernel sets `EPROCESS->DebugPort` and updates `PEB->BeingDebugged`

**Trivial bypass:**
```cpp
// Manually clear the flag - takes one instruction
PPEB Peb = (PPEB)__readgsqword( 0x60 );
Peb->BeingDebugged = 0;
```

**Reality:** This flag is in user-mode memory and can be modified by the process itself or by debugger plugins (ScyllaHide, TitanHide, etc.). It's useful for learning but unreliable for actual anti-debugging.

#### ImageBaseAddress (Offset 0x010)

Points to where the main executable is loaded in memory.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
PVOID ExeBase = Peb->ImageBaseAddress;

// This is the same as:
PVOID ExeBase = GetModuleHandle( NULL );
```

**Use case:** Shellcode often uses this to locate the executable without calling APIs.

#### Ldr (Offset 0x018)

Pointer to `PEB_LDR_DATA` structure containing loaded module information. This is the gateway to enumerating all DLLs.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
PPEB_LDR_DATA Ldr = Peb->Ldr;

// Now you can walk module lists
PLIST_ENTRY ModuleList = &Ldr->InLoadOrderModuleList;
```

#### ProcessParameters (Offset 0x020)

Pointer to `RTL_USER_PROCESS_PARAMETERS` containing startup information.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
PRTL_USER_PROCESS_PARAMETERS Params = Peb->ProcessParameters;

wprintf( L"Image: %s\n" , Params->ImagePathName.Buffer );
wprintf( L"Command Line: %s\n" , Params->CommandLine.Buffer );
wprintf( L"Current Dir: %s\n" , Params->CurrentDirectory.DosPath.Buffer );
```

#### ProcessHeap (Offset 0x030)

The default process heap created during process initialization.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
PVOID DefaultHeap = Peb->ProcessHeap;

// This is the same as:
PVOID DefaultHeap = GetProcessHeap( );
```

#### NtGlobalFlag (Offset 0x0BC on x64, 0x068 on x86)

Contains flags that affect process behavior, especially during debugging.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
ULONG Flags = Peb->NtGlobalFlag;

// When debugging, these flags are set:
#define FLG_HEAP_ENABLE_TAIL_CHECK      0x10
#define FLG_HEAP_ENABLE_FREE_CHECK      0x20
#define FLG_HEAP_VALIDATE_PARAMETERS    0x40

if ( Flags & (FLG_HEAP_ENABLE_TAIL_CHECK | 
              FLG_HEAP_ENABLE_FREE_CHECK | 
              FLG_HEAP_VALIDATE_PARAMETERS) ) {
    // Debugger detected!
}
```

**Why these flags?**
When debugging, Windows enables heap validation to catch memory corruption bugs. This makes heap operations slower but safer.

**Trivial bypass:**
```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
Peb->NtGlobalFlag &= ~0x70;  // Clear all three heap flags
```

**Reality:** Like BeingDebugged, this is in user-mode memory and easily patched. Modern debuggers clear this automatically.

#### NumberOfHeaps / ProcessHeaps

Information about all heaps in the process.

```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );

printf( "Number of heaps: %d\n" , Peb->NumberOfHeaps );

for ( ULONG i = 0; i < Peb->NumberOfHeaps; i++ ) {
    printf( "Heap[%d]: %p\n" , i , Peb->ProcessHeaps[i] );
}
```



### PEB_LDR_DATA Structure

The loader data structure is the heart of module enumeration.

```cpp
typedef struct _PEB_LDR_DATA {
    ULONG Length;                                    // Size of structure
    BOOLEAN Initialized;                             // Loader initialized?
    PVOID SsHandle;                                  // Subsystem handle
    LIST_ENTRY InLoadOrderModuleList;                // Load order
    LIST_ENTRY InMemoryOrderModuleList;              // Memory order
    LIST_ENTRY InInitializationOrderModuleList;      // Init order
    PVOID EntryInProgress;                           // Currently loading
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

#### The Three Module Lists

Each list contains the same modules but in different orders:

**1. InLoadOrderModuleList**
- Order: Executable first, then DLLs in the order they were loaded
- Example: `program.exe → ntdll.dll → kernel32.dll → user32.dll → ...`
- Use case: Understanding load sequence, finding first/last loaded DLL

**2. InMemoryOrderModuleList**
- Order: Modules sorted by their base address in memory
- Example: `0x00400000 (exe) → 0x77000000 (ntdll) → 0x76000000 (kernel32) → ...`
- Use case: Memory layout analysis, finding modules by address

**3. InInitializationOrderModuleList**
- Order: DLLs in the order their DllMain was called (NO executable entry!)
- Example: `ntdll.dll → kernel32.dll → kernelbase.dll → ...`
- Use case: Understanding initialization dependencies
- **Important**: The main executable is NOT in this list!

#### Why Three Lists?

Different use cases require different orderings:
- **Loader**: Needs load order to properly unload in reverse
- **Debugger**: Needs memory order to map addresses to modules
- **Dependency Walker**: Needs init order to understand dependencies

### LDR_DATA_TABLE_ENTRY Structure

Each module in the lists is represented by this structure:

```cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;                // Link in load order list
    LIST_ENTRY InMemoryOrderLinks;              // Link in memory order list
    LIST_ENTRY InInitializationOrderLinks;      // Link in init order list
    PVOID DllBase;                              // Module base address
    PVOID EntryPoint;                           // DllMain or entry point
    ULONG SizeOfImage;                          // Module size in bytes
    UNICODE_STRING FullDllName;                 // Full path
    UNICODE_STRING BaseDllName;                 // Just filename
    ULONG Flags;                                // Various flags
    USHORT LoadCount;                           // Reference count
    USHORT TlsIndex;                            // TLS index
    LIST_ENTRY HashLinks;                       // Hash table links
    ULONG TimeDateStamp;                        // PE timestamp
    PVOID EntryPointActivationContext;          // Activation context
    PVOID PatchInformation;                     // Hotpatch info
    // ... more fields in newer Windows versions
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

#### Key Fields

**DllBase**
- Base address where the module is loaded
- Same as what `GetModuleHandle()` returns
- Used to calculate RVAs: `ActualAddress = DllBase + RVA`

**EntryPoint**
- Address of DllMain for DLLs
- Address of main/WinMain for executables
- NULL if no entry point

**SizeOfImage**
- Total size of the module in memory
- Includes all sections (code, data, resources)
- Used for memory protection and validation

**FullDllName vs BaseDllName**
```
FullDllName: C:\Windows\System32\kernel32.dll
BaseDllName: kernel32.dll
```

**LoadCount**
- Reference count for the module
- Incremented by `LoadLibrary`, decremented by `FreeLibrary`
- Module is unloaded when count reaches 0
- Special value 0xFFFF means "never unload" (system DLLs)



### RTL_USER_PROCESS_PARAMETERS Structure

Contains process startup information passed from the parent process.

```cpp
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;                        // Buffer size
    ULONG Length;                               // Used size
    ULONG Flags;                                // Flags
    ULONG DebugFlags;                           // Debug flags
    PVOID ConsoleHandle;                        // Console handle
    ULONG ConsoleFlags;                         // Console flags
    HANDLE StandardInput;                       // stdin
    HANDLE StandardOutput;                      // stdout
    HANDLE StandardError;                       // stderr
    CURDIR CurrentDirectory;                    // Current directory
    UNICODE_STRING DllPath;                     // DLL search path
    UNICODE_STRING ImagePathName;               // Executable path
    UNICODE_STRING CommandLine;                 // Command line
    PVOID Environment;                          // Environment block
    ULONG StartingX;                            // Window position X
    ULONG StartingY;                            // Window position Y
    ULONG CountX;                               // Window width
    ULONG CountY;                               // Window height
    ULONG CountCharsX;                          // Console width
    ULONG CountCharsY;                          // Console height
    ULONG FillAttribute;                        // Console colors
    ULONG WindowFlags;                          // Window flags
    ULONG ShowWindowFlags;                      // Show window flags
    UNICODE_STRING WindowTitle;                 // Window title
    UNICODE_STRING DesktopInfo;                 // Desktop name
    UNICODE_STRING ShellInfo;                   // Shell info
    UNICODE_STRING RuntimeData;                 // Runtime data
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];  // Per-drive current dirs
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

#### Accessing Process Information

**Command Line**
```cpp
PPEB Peb = (PPEB)__readgsqword( 0x60 );
PRTL_USER_PROCESS_PARAMETERS Params = Peb->ProcessParameters;

wprintf( L"Command Line: %s\n" , Params->CommandLine.Buffer );

// Example output:
// Command Line: notepad.exe C:\Users\Admin\file.txt
```

**Image Path**
```cpp
wprintf( L"Image Path: %s\n" , Params->ImagePathName.Buffer );

// Example output:
// Image Path: C:\Windows\System32\notepad.exe
```

**Current Directory**
```cpp
wprintf( L"Current Dir: %s\n" , Params->CurrentDirectory.DosPath.Buffer );

// Example output:
// Current Dir: C:\Users\Admin\Documents
```

**Environment Variables**
```cpp
PWCHAR Env = (PWCHAR)Params->Environment;

// Environment is a double-null-terminated string list
while ( *Env ) {
    wprintf( L"%s\n" , Env );
    Env += wcslen( Env ) + 1;
}

// Example output:
// PATH=C:\Windows\System32;C:\Windows;...
// TEMP=C:\Users\Admin\AppData\Local\Temp
// USERNAME=Admin
// ...
```

#### UNICODE_STRING Structure

Many PEB fields use `UNICODE_STRING`:

```cpp
typedef struct _UNICODE_STRING {
    USHORT Length;          // Length in bytes (not including null terminator)
    USHORT MaximumLength;   // Buffer size in bytes
    PWSTR Buffer;           // Pointer to wide string
} UNICODE_STRING, *PUNICODE_STRING;
```

**Important notes:**
- `Length` is in BYTES, not characters
- `Length` does NOT include the null terminator
- `Buffer` may not be null-terminated
- Always use `Length` when reading: `ReadProcessMemory( ... , Buffer , Length , ... )`



## Module Enumeration via PEB

### Walking the Module List (Local Process)

```cpp
// Get PEB
PPEB Peb = (PPEB)__readgsqword( 0x60 );

// Get loader data
PPEB_LDR_DATA Ldr = Peb->Ldr;

// Get list head
PLIST_ENTRY Head = &Ldr->InLoadOrderModuleList;

// Walk the list
for ( PLIST_ENTRY Current = Head->Flink; Current != Head; Current = Current->Flink ) {
    // Get the LDR_DATA_TABLE_ENTRY from the list entry
    PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD( 
        Current , 
        LDR_DATA_TABLE_ENTRY , 
        InLoadOrderLinks 
    );
    
    // Access module information
    wprintf( L"Module: %s\n" , Entry->BaseDllName.Buffer );
    printf( "  Base: %p\n" , Entry->DllBase );
    printf( "  Size: 0x%X\n" , Entry->SizeOfImage );
    printf( "  Entry: %p\n" , Entry->EntryPoint );
}
```

### Understanding CONTAINING_RECORD

The `CONTAINING_RECORD` macro is crucial for list walking. It calculates the structure address from a member address.

```cpp
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
```

**How it works:**

```
LDR_DATA_TABLE_ENTRY Structure:
+----------------------------------+
| InLoadOrderLinks (LIST_ENTRY)    | <- Offset 0x00
+----------------------------------+
| InMemoryOrderLinks (LIST_ENTRY)  | <- Offset 0x10
+----------------------------------+
| InInitializationOrderLinks       | <- Offset 0x20
+----------------------------------+
| DllBase (PVOID)                  | <- Offset 0x30
+----------------------------------+
| ... more fields ...              |
+----------------------------------+

If Current points to InLoadOrderLinks at 0x12340000:
  Structure start = 0x12340000 - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)
  Structure start = 0x12340000 - 0x00
  Structure start = 0x12340000
```

**Why needed?**
The list entries (Flink/Blink) point to other LIST_ENTRY structures, not to the beginning of LDR_DATA_TABLE_ENTRY. CONTAINING_RECORD calculates the structure start from the list entry address.

### Walking Different Lists

**Load Order (includes executable)**
```cpp
PLIST_ENTRY Head = &Ldr->InLoadOrderModuleList;
// First entry is usually the executable
```

**Memory Order (includes executable)**
```cpp
PLIST_ENTRY Head = &Ldr->InMemoryOrderModuleList;
// Sorted by base address
```

**Initialization Order (NO executable!)**
```cpp
PLIST_ENTRY Head = &Ldr->InInitializationOrderModuleList;
// First entry is usually ntdll.dll
// Executable is NOT in this list!
```

### LIST_ENTRY and Doubly-Linked Lists

```cpp
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;  // Forward link (next)
    struct _LIST_ENTRY *Blink;  // Backward link (previous)
} LIST_ENTRY, *PLIST_ENTRY;
```

**Circular doubly-linked list:**

```
Head (in PEB_LDR_DATA)
  ↓
[Entry 1] ←→ [Entry 2] ←→ [Entry 3] ←→ [Head]
  ↑                                      ↓
  └──────────────────────────────────────┘
```

**Walking forward:**
```cpp
for ( PLIST_ENTRY Current = Head->Flink; Current != Head; Current = Current->Flink ) {
    // Process entry
}
```

**Walking backward:**
```cpp
for ( PLIST_ENTRY Current = Head->Blink; Current != Head; Current = Current->Blink ) {
    // Process entry
}
```

**Empty list check:**
```cpp
if ( Head->Flink == Head ) {
    // List is empty
}
```



### Walking Remote Module Lists

Remote enumeration is more complex because you must read memory from another process.

```cpp
// 1. Get remote PEB address
PROCESS_BASIC_INFORMATION Pbi;
NtQueryInformationProcess( hProcess , 0 , &Pbi , sizeof(Pbi) , NULL );

// 2. Read remote PEB
PEB RemotePeb;
ReadProcessMemory( hProcess , Pbi.PebBaseAddress , &RemotePeb , sizeof(PEB) , NULL );

// 3. Read remote loader data
PEB_LDR_DATA RemoteLdr;
ReadProcessMemory( hProcess , RemotePeb.Ldr , &RemoteLdr , sizeof(PEB_LDR_DATA) , NULL );

// 4. Walk the list
PLIST_ENTRY Head = &RemotePeb.Ldr->InLoadOrderModuleList;  // Remote address!
PLIST_ENTRY Current = RemoteLdr.InLoadOrderModuleList.Flink;  // Local copy

while ( Current != Head ) {
    // 5. Read remote entry
    LDR_DATA_TABLE_ENTRY RemoteEntry;
    PLDR_DATA_TABLE_ENTRY EntryAddress = CONTAINING_RECORD( 
        Current , 
        LDR_DATA_TABLE_ENTRY , 
        InLoadOrderLinks 
    );
    
    ReadProcessMemory( hProcess , EntryAddress , &RemoteEntry , sizeof(LDR_DATA_TABLE_ENTRY) , NULL );
    
    // 6. Read module name
    if ( RemoteEntry.BaseDllName.Buffer && RemoteEntry.BaseDllName.Length > 0 ) {
        WCHAR ModuleName[MAX_PATH];
        ReadProcessMemory( 
            hProcess , 
            RemoteEntry.BaseDllName.Buffer , 
            ModuleName , 
            RemoteEntry.BaseDllName.Length ,  // Use Length, not MaximumLength!
            NULL 
        );
        
        wprintf( L"Module: %s at %p\n" , ModuleName , RemoteEntry.DllBase );
    }
    
    // 7. Advance using LOCAL copy of Flink
    Current = RemoteEntry.InLoadOrderLinks.Flink;
}
```

**Critical points:**
1. `Head` is a remote address (in target process)
2. `Current` starts as a local copy of the remote Flink
3. Always use the LOCAL copy of Flink to advance
4. Never dereference remote pointers directly
5. Use `Length` field when reading UNICODE_STRING buffers



## 64-bit vs WOW64

### The WOW64 Subsystem

WOW64 (Windows 32-bit on Windows 64-bit) is a compatibility layer that allows 32-bit applications to run on 64-bit Windows.

**Architecture:**
```
64-bit Windows
├── Native 64-bit Applications
│   └── Use 64-bit ntdll.dll, kernel32.dll, etc.
│
└── WOW64 Subsystem
    ├── wow64.dll (CPU emulation)
    ├── wow64win.dll (GUI emulation)
    ├── wow64cpu.dll (x86 emulation)
    │
    └── 32-bit Applications
        └── Use 32-bit ntdll.dll, kernel32.dll, etc.
            (located in C:\Windows\SysWOW64\)
```

### Dual PEB Architecture

WOW64 processes have TWO PEBs:

**64-bit PEB (WOW64 Infrastructure)**
- Contains 64-bit WOW64 DLLs (wow64.dll, wow64win.dll, wow64cpu.dll)
- Located at normal PEB address
- Accessed via `ProcessBasicInformation` (class 0)
- Used by the WOW64 layer itself

**32-bit PEB (Application)**
- Contains 32-bit application DLLs (ntdll.dll, kernel32.dll from SysWOW64)
- Located at a different address
- Accessed via `ProcessWow64Information` (class 26)
- Used by the 32-bit application

```
WOW64 Process Memory Layout:
+----------------------------------+
| 64-bit PEB                       | <- Class 0
|   - wow64.dll                    |
|   - wow64win.dll                 |
|   - wow64cpu.dll                 |
|   - 64-bit ntdll.dll             |
+----------------------------------+
| 32-bit PEB                       | <- Class 26
|   - 32-bit ntdll.dll (SysWOW64) |
|   - 32-bit kernel32.dll          |
|   - Application DLLs             |
+----------------------------------+
| Application Code/Data            |
+----------------------------------+
```

### Structure Differences

The main difference is pointer size:

**64-bit Structures**
```cpp
typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY InLoadOrderLinks;        // 16 bytes (2 x 8-byte pointers)
    LIST_ENTRY InMemoryOrderLinks;      // 16 bytes
    LIST_ENTRY InInitializationOrderLinks;  // 16 bytes
    PVOID DllBase;                      // 8 bytes
    PVOID EntryPoint;                   // 8 bytes
    ULONG SizeOfImage;                  // 4 bytes
    UNICODE_STRING FullDllName;         // 16 bytes (2+2+4+8)
    UNICODE_STRING BaseDllName;         // 16 bytes
} LDR_DATA_TABLE_ENTRY64;
```

**32-bit Structures (WOW64)**
```cpp
typedef struct _UNICODE_STRING32 {
    USHORT Length;          // 2 bytes
    USHORT MaximumLength;   // 2 bytes
    DWORD Buffer;           // 4 bytes (32-bit pointer!)
} UNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    DWORD InLoadOrderLinks[2];          // 8 bytes (2 x 4-byte pointers)
    DWORD InMemoryOrderLinks[2];        // 8 bytes
    DWORD InInitializationOrderLinks[2];  // 8 bytes
    DWORD DllBase;                      // 4 bytes
    DWORD EntryPoint;                   // 4 bytes
    ULONG SizeOfImage;                  // 4 bytes
    UNICODE_STRING32 FullDllName;       // 8 bytes (2+2+4)
    UNICODE_STRING32 BaseDllName;       // 8 bytes
} LDR_DATA_TABLE_ENTRY32;
```

**Key differences:**
1. All pointers are DWORD (4 bytes) instead of PVOID (8 bytes)
2. LIST_ENTRY is `DWORD[2]` instead of `PLIST_ENTRY`
3. UNICODE_STRING.Buffer is DWORD instead of PWSTR
4. Structure sizes are roughly half

### Detecting WOW64

```cpp
BOOL IsWow64Process_Check( HANDLE hProcess ) {
    BOOL IsWow64 = FALSE;
    
    // IsWow64Process is available on Windows XP SP2+
    typedef BOOL (WINAPI *IsWow64Process_t)( HANDLE , PBOOL );
    
    HMODULE Kernel32 = GetModuleHandleA( "kernel32.dll" );
    IsWow64Process_t pIsWow64Process = (IsWow64Process_t)GetProcAddress( Kernel32 , "IsWow64Process" );
    
    if ( pIsWow64Process ) {
        pIsWow64Process( hProcess , &IsWow64 );
    }
    
    return IsWow64;
}
```

### Enumerating WOW64 Modules

```cpp
// 1. Get 32-bit PEB address
PVOID Peb32Address = NULL;
NtQueryInformationProcess( hProcess , 26 , &Peb32Address , sizeof(PVOID) , NULL );

// 2. Read 32-bit PEB
PEB32 RemotePeb32;
ReadProcessMemory( hProcess , Peb32Address , &RemotePeb32 , sizeof(PEB32) , NULL );

// 3. Read 32-bit loader data
PEB_LDR_DATA32 RemoteLdr32;
ReadProcessMemory( 
    hProcess , 
    (PVOID)(ULONG_PTR)RemotePeb32.Ldr ,  // Cast DWORD to pointer
    &RemoteLdr32 , 
    sizeof(PEB_LDR_DATA32) , 
    NULL 
);

// 4. Calculate list head address
DWORD Head = RemotePeb32.Ldr + offsetof( PEB_LDR_DATA32 , InLoadOrderModuleList );
DWORD Current = RemoteLdr32.InLoadOrderModuleList[0];  // Array, not pointer!

// 5. Walk the list
while ( Current != Head ) {
    LDR_DATA_TABLE_ENTRY32 RemoteEntry32;
    
    ReadProcessMemory( 
        hProcess , 
        (PVOID)(ULONG_PTR)Current ,  // Cast DWORD to pointer
        &RemoteEntry32 , 
        sizeof(LDR_DATA_TABLE_ENTRY32) , 
        NULL 
    );
    
    // Read module name
    if ( RemoteEntry32.BaseDllName.Buffer != 0 && RemoteEntry32.BaseDllName.Length > 0 ) {
        WCHAR ModuleName[MAX_PATH];
        
        ReadProcessMemory( 
            hProcess , 
            (PVOID)(ULONG_PTR)RemoteEntry32.BaseDllName.Buffer ,  // Cast DWORD to pointer
            ModuleName , 
            RemoteEntry32.BaseDllName.Length , 
            NULL 
        );
        
        wprintf( L"Module: %s at %08X\n" , ModuleName , RemoteEntry32.DllBase );
    }
    
    // Advance using array index [0] for Flink
    Current = RemoteEntry32.InLoadOrderLinks[0];
}
```

**Critical WOW64 points:**
1. All "pointers" are actually DWORD (32-bit values)
2. Must cast DWORD to PVOID when calling ReadProcessMemory
3. LIST_ENTRY is an array `DWORD[2]`, not a structure
4. Use `[0]` for Flink, `[1]` for Blink
5. Calculate list head manually: `Ldr + offsetof(...)`



## Implementation Details

### Our Implementation

The provided code demonstrates:

1. **Local PEB Enumeration**: Direct access via TEB
2. **Remote 64-bit PEB Enumeration**: Using ProcessBasicInformation
3. **Remote WOW64 PEB Enumeration**: Using ProcessWow64Information
4. **Automatic Detection**: Detects WOW64 and routes appropriately

### Code Flow

```
main()
  │
  ├─→ EnumerateLocalPeb()
  │     ├─ Get PEB via NtCurrentTeb()
  │     ├─ Read Ldr, ProcessParameters
  │     └─ Walk InLoadOrderModuleList
  │
  └─→ EnumerateRemotePeb(PID)
        ├─ OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        ├─ IsWow64Process() to detect architecture
        │
        ├─→ If 64-bit: EnumerateRemotePeb64()
        │     ├─ NtQueryInformationProcess(class 0)
        │     ├─ ReadProcessMemory(PEB)
        │     ├─ ReadProcessMemory(PEB_LDR_DATA)
        │     └─ Walk module list with ReadProcessMemory
        │
        └─→ If WOW64: EnumerateRemotePeb32()
              ├─ NtQueryInformationProcess(class 26)
              ├─ ReadProcessMemory(PEB32)
              ├─ ReadProcessMemory(PEB_LDR_DATA32)
              └─ Walk module list with ReadProcessMemory
```
