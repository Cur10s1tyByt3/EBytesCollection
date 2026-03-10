#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 5105)
#endif
#include<Windows.h>
#include<TlHelp32.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<wchar.h>

#if defined(_MSC_VER)
#define FUNSTUFF_NOINLINE __declspec(noinline)
#else
#define FUNSTUFF_NOINLINE __attribute__((noinline))
#endif

typedef decltype( &DebugActiveProcess ) PFN_DEBUGACTIVEPROCESS;
typedef decltype( &DebugActiveProcessStop ) PFN_DEBUGACTIVEPROCESSSTOP;
typedef decltype( &DebugSetProcessKillOnExit ) PFN_DEBUGSETPROCESSKILLONEXIT;
typedef decltype( &WaitForDebugEvent ) PFN_WAITFORDEBUGEVENT;
typedef decltype( &ContinueDebugEvent ) PFN_CONTINUEDEBUGEVENT;
typedef decltype( &GetFinalPathNameByHandleW ) PFN_GETFINALPATHNAMEBYHANDLEW;
typedef decltype( &GetThreadContext ) PFN_GETTHREADCONTEXT;
typedef decltype( &IsWow64Process ) PFN_ISWOW64PROCESS;

#if defined(_WIN64)
typedef BOOL( WINAPI* PFN_WOW64GETTHREADCONTEXT )(
    _In_ HANDLE hThread,
    _Inout_ PWOW64_CONTEXT lpContext
    );
#endif

typedef BOOL( WINAPI* PFN_WAITFORDEBUGEVENTEX )(
    _Out_ LPDEBUG_EVENT lpDebugEvent,
    _In_ DWORD dwMilliseconds
    );

typedef struct _FUNSTUFF_DEBUGGER_RUNTIME
{
    HMODULE Kernel32;
    PFN_DEBUGACTIVEPROCESS DebugActiveProcessFn;
    PFN_DEBUGACTIVEPROCESSSTOP DebugActiveProcessStopFn;
    PFN_DEBUGSETPROCESSKILLONEXIT DebugSetProcessKillOnExitFn;
    PFN_WAITFORDEBUGEVENT WaitForDebugEventFn;
    PFN_WAITFORDEBUGEVENTEX WaitForDebugEventExFn;
    PFN_CONTINUEDEBUGEVENT ContinueDebugEventFn;
    PFN_GETFINALPATHNAMEBYHANDLEW GetFinalPathNameByHandleWFn;
    PFN_GETTHREADCONTEXT GetThreadContextFn;
    PFN_ISWOW64PROCESS IsWow64ProcessFn;
#if defined(_WIN64)
    PFN_WOW64GETTHREADCONTEXT Wow64GetThreadContextFn;
#endif
    BOOL Ready;
} FUNSTUFF_DEBUGGER_RUNTIME, *PFUNSTUFF_DEBUGGER_RUNTIME;

static FUNSTUFF_DEBUGGER_RUNTIME g_FunStuffDebuggerApi = { 0 };
static HANDLE g_FunStuffDebuggeeProcess = NULL;
static DWORD g_FunStuffAttachedProcessId = 0;
static BOOL g_FunStuffTargetWow64 = FALSE;

static VOID
FunStuff_Debugger_PrintUsage(
    VOID
    )
{
    wprintf( L"Usage: FunStuff.exe <process-name.exe | pid>\n" );
}

static FARPROC
FunStuff_CustomGetProcAddressInternal(
    _In_ HMODULE Module,
    _In_ LPCSTR ProcedureName,
    _In_ ULONG Depth
    );

static FARPROC
FunStuff_CustomGetProcAddress(
    _In_ HMODULE Module,
    _In_ LPCSTR ProcedureName
    )
{
    return FunStuff_CustomGetProcAddressInternal( Module, ProcedureName, 0 );
}

#if defined(_MSC_VER)
#pragma optimize( "", off )
#endif

FUNSTUFF_NOINLINE
static FARPROC
FunStuff_CustomGetProcAddressInternal(
    _In_ HMODULE Module,
    _In_ LPCSTR ProcedureName,
    _In_ ULONG Depth
    )
{
    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD FunctionTable = NULL;
    PDWORD NameTable = NULL;
    PWORD OrdinalTable = NULL;
    DWORD ExportRva = 0;
    DWORD ExportSize = 0;
    DWORD FunctionRva = 0;
    DWORD FunctionIndex = 0;
    ULONG NameIndex = 0;

    if ( Module == NULL || ProcedureName == NULL || Depth > 8 )
    {
        return NULL;
    }

    DosHeader = ( PIMAGE_DOS_HEADER )Module;
    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        return NULL;
    }

    NtHeaders = ( PIMAGE_NT_HEADERS )( ( PUCHAR )Module + DosHeader->e_lfanew );
    if ( NtHeaders->Signature != IMAGE_NT_SIGNATURE )
    {
        return NULL;
    }

    ExportRva = NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    ExportSize = NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    if ( ExportRva == 0 || ExportSize == 0 )
    {
        return NULL;
    }

    ExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( ( PUCHAR )Module + ExportRva );
    FunctionTable = ( PDWORD )( ( PUCHAR )Module + ExportDirectory->AddressOfFunctions );
    NameTable = ( PDWORD )( ( PUCHAR )Module + ExportDirectory->AddressOfNames );
    OrdinalTable = ( PWORD )( ( PUCHAR )Module + ExportDirectory->AddressOfNameOrdinals );

    if ( ( ( ULONG_PTR )ProcedureName >> 16 ) == 0 )
    {
        USHORT Ordinal = LOWORD( ProcedureName );

        if ( Ordinal < ExportDirectory->Base )
        {
            return NULL;
        }

        FunctionIndex = Ordinal - ExportDirectory->Base;
    }
    else
    {
        for ( NameIndex = 0; NameIndex < ExportDirectory->NumberOfNames; NameIndex++ )
        {
            LPCSTR ExportedName = ( LPCSTR )( ( PUCHAR )Module + NameTable[ NameIndex ] );

            if ( strcmp( ExportedName, ProcedureName ) == 0 )
            {
                FunctionIndex = OrdinalTable[ NameIndex ];
                break;
            }
        }

        if ( NameIndex == ExportDirectory->NumberOfNames )
        {
            return NULL;
        }
    }

    if ( FunctionIndex >= ExportDirectory->NumberOfFunctions )
    {
        return NULL;
    }

    FunctionRva = FunctionTable[ FunctionIndex ];
    if ( FunctionRva == 0 )
    {
        return NULL;
    }

    if ( FunctionRva >= ExportRva && FunctionRva < ( ExportRva + ExportSize ) )
    {
        CHAR ForwardedModuleName[ MAX_PATH ] = { 0 };
        CHAR ForwardedProcedure[ 128 ] = { 0 };
        HMODULE ForwardedModule = NULL;
        LPCSTR Forwarder = ( LPCSTR )( ( PUCHAR )Module + FunctionRva );
        LPCSTR Separator = strchr( Forwarder, '.' );
        size_t ModuleNameLength = 0;

        if ( Separator == NULL || Separator == Forwarder || Separator[ 1 ] == '\0' )
        {
            return NULL;
        }

        ModuleNameLength = ( size_t )( Separator - Forwarder );
        if ( ModuleNameLength >= MAX_PATH - 4 )
        {
            return NULL;
        }

        memcpy( ForwardedModuleName, Forwarder, ModuleNameLength );
        ForwardedModuleName[ ModuleNameLength ] = '\0';

        if ( strchr( ForwardedModuleName, '.' ) == NULL )
        {
            strcat_s( ForwardedModuleName, sizeof( ForwardedModuleName ), ".dll" );
        }

        strcpy_s( ForwardedProcedure, sizeof( ForwardedProcedure ), Separator + 1 );

        ForwardedModule = LoadLibraryA( ForwardedModuleName );
        if ( ForwardedModule == NULL )
        {
            return NULL;
        }

        if ( ForwardedProcedure[ 0 ] == '#' )
        {
            ULONG ForwardedOrdinal = strtoul( ForwardedProcedure + 1, NULL, 10 );
            return FunStuff_CustomGetProcAddressInternal(
                ForwardedModule,
                ( LPCSTR )( ULONG_PTR )ForwardedOrdinal,
                Depth + 1
                );
        }

        return FunStuff_CustomGetProcAddressInternal(
            ForwardedModule,
            ForwardedProcedure,
            Depth + 1
            );
    }

    return ( FARPROC )( ( PUCHAR )Module + FunctionRva );
}

FUNSTUFF_NOINLINE
static BOOL
FunStuff_Debugger_EnsureLoaded(
    VOID
    )
{
    FUNSTUFF_DEBUGGER_RUNTIME Api = { 0 };

    if ( g_FunStuffDebuggerApi.Ready == TRUE )
    {
        return TRUE;
    }

    Api.Kernel32 = GetModuleHandleW( L"kernel32.dll" );
    if ( Api.Kernel32 == NULL )
    {
        Api.Kernel32 = LoadLibraryW( L"kernel32.dll" );
    }

    if ( Api.Kernel32 == NULL )
    {
        printf( "[-] Failed to load kernel32.dll (%lu)\n", GetLastError( ) );
        return FALSE;
    }

    Api.DebugActiveProcessFn = ( PFN_DEBUGACTIVEPROCESS )FunStuff_CustomGetProcAddress( Api.Kernel32, "DebugActiveProcess" );
    Api.DebugActiveProcessStopFn = ( PFN_DEBUGACTIVEPROCESSSTOP )FunStuff_CustomGetProcAddress( Api.Kernel32, "DebugActiveProcessStop" );
    Api.DebugSetProcessKillOnExitFn = ( PFN_DEBUGSETPROCESSKILLONEXIT )FunStuff_CustomGetProcAddress( Api.Kernel32, "DebugSetProcessKillOnExit" );
    Api.WaitForDebugEventFn = ( PFN_WAITFORDEBUGEVENT )FunStuff_CustomGetProcAddress( Api.Kernel32, "WaitForDebugEvent" );
    Api.WaitForDebugEventExFn = ( PFN_WAITFORDEBUGEVENTEX )FunStuff_CustomGetProcAddress( Api.Kernel32, "WaitForDebugEventEx" );
    Api.ContinueDebugEventFn = ( PFN_CONTINUEDEBUGEVENT )FunStuff_CustomGetProcAddress( Api.Kernel32, "ContinueDebugEvent" );
    Api.GetFinalPathNameByHandleWFn = ( PFN_GETFINALPATHNAMEBYHANDLEW )FunStuff_CustomGetProcAddress( Api.Kernel32, "GetFinalPathNameByHandleW" );
    Api.GetThreadContextFn = ( PFN_GETTHREADCONTEXT )FunStuff_CustomGetProcAddress( Api.Kernel32, "GetThreadContext" );
    Api.IsWow64ProcessFn = ( PFN_ISWOW64PROCESS )FunStuff_CustomGetProcAddress( Api.Kernel32, "IsWow64Process" );
#if defined(_WIN64)
    Api.Wow64GetThreadContextFn = ( PFN_WOW64GETTHREADCONTEXT )FunStuff_CustomGetProcAddress( Api.Kernel32, "Wow64GetThreadContext" );
#endif

    if ( Api.DebugActiveProcessFn == NULL ||
        Api.DebugActiveProcessStopFn == NULL ||
        Api.DebugSetProcessKillOnExitFn == NULL ||
        Api.WaitForDebugEventFn == NULL ||
        Api.ContinueDebugEventFn == NULL ||
        Api.GetThreadContextFn == NULL )
    {
        printf( "[-] Failed to resolve debugger APIs from kernel32.dll\n" );
        return FALSE;
    }

    Api.Ready = TRUE;
    g_FunStuffDebuggerApi = Api;
    return TRUE;
}

FUNSTUFF_NOINLINE
static DWORD
FunStuff_Debugger_GetProcessIdFromName(
    _In_z_ LPCWSTR ProcessName
    )
{
    PROCESSENTRY32W ProcessEntry = { 0 };
    HANDLE Snapshot = INVALID_HANDLE_VALUE;

    if ( ProcessName == NULL || ProcessName[ 0 ] == L'\0' )
    {
        return 0;
    }

    Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( Snapshot == INVALID_HANDLE_VALUE )
    {
        return 0;
    }

    ProcessEntry.dwSize = sizeof( ProcessEntry );
    if ( Process32FirstW( Snapshot, &ProcessEntry ) == FALSE )
    {
        CloseHandle( Snapshot );
        return 0;
    }

    do
    {
        if ( _wcsicmp( ProcessEntry.szExeFile, ProcessName ) == 0 )
        {
            CloseHandle( Snapshot );
            return ProcessEntry.th32ProcessID;
        }
    } while ( Process32NextW( Snapshot, &ProcessEntry ) != FALSE );

    CloseHandle( Snapshot );
    return 0;
}

static VOID
FunStuff_Debugger_CacheTargetArchitecture(
    VOID
    )
{
    BOOL IsWow64 = FALSE;

    g_FunStuffTargetWow64 = FALSE;

    if ( g_FunStuffDebuggeeProcess == NULL || g_FunStuffDebuggerApi.IsWow64ProcessFn == NULL )
    {
        return;
    }

    if ( g_FunStuffDebuggerApi.IsWow64ProcessFn( g_FunStuffDebuggeeProcess, &IsWow64 ) != FALSE )
    {
        g_FunStuffTargetWow64 = IsWow64;
    }
}

static VOID
FunStuff_Debugger_SetDebuggeeProcessHandle(
    _In_opt_ HANDLE ProcessHandle
    )
{
    if ( ProcessHandle == NULL )
    {
        return;
    }

    if ( g_FunStuffDebuggeeProcess != NULL && g_FunStuffDebuggeeProcess != ProcessHandle )
    {
        CloseHandle( g_FunStuffDebuggeeProcess );
    }

    g_FunStuffDebuggeeProcess = ProcessHandle;
    FunStuff_Debugger_CacheTargetArchitecture( );
}

static BOOL
FunStuff_Debugger_OpenDebuggeeProcessHandle(
    _In_ DWORD ProcessId
    )
{
    HANDLE ProcessHandle = NULL;

    if ( ProcessId == 0 )
    {
        return FALSE;
    }

    ProcessHandle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId );
    if ( ProcessHandle == NULL )
    {
        ProcessHandle = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId );
    }

    if ( ProcessHandle == NULL )
    {
        return FALSE;
    }

    FunStuff_Debugger_SetDebuggeeProcessHandle( ProcessHandle );
    return TRUE;
}

static LPCWSTR
FunStuff_Debugger_GetTargetArchLabel(
    VOID
    )
{
#if defined(_WIN64)
    if ( g_FunStuffTargetWow64 != FALSE )
    {
        return L"x86 (WOW64)";
    }

    return L"x64";
#else
    if ( g_FunStuffTargetWow64 != FALSE )
    {
        return L"x86 (WOW64-hosted debugger)";
    }

    return L"x86";
#endif
}

static BOOL
FunStuff_Debugger_QueryThreadContextRegisters(
    _In_ DWORD ThreadId,
    _Out_ ULONG_PTR* InstructionPointer,
    _Out_ ULONG_PTR* StackPointer,
    _Out_ ULONG_PTR* FramePointer,
    _Out_ LPCSTR* InstructionLabel,
    _Out_ LPCSTR* StackLabel,
    _Out_ LPCSTR* FrameLabel,
    _Out_ LPCWSTR* ArchLabel
    )
{
    HANDLE ThreadHandle = NULL;
    BOOL Success = FALSE;

    if ( InstructionPointer == NULL ||
        StackPointer == NULL ||
        FramePointer == NULL ||
        InstructionLabel == NULL ||
        StackLabel == NULL ||
        FrameLabel == NULL ||
        ArchLabel == NULL )
    {
        return FALSE;
    }

    *InstructionPointer = 0;
    *StackPointer = 0;
    *FramePointer = 0;
    *InstructionLabel = "IP";
    *StackLabel = "SP";
    *FrameLabel = "BP";
    *ArchLabel = FunStuff_Debugger_GetTargetArchLabel( );

    if ( FunStuff_Debugger_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    ThreadHandle = OpenThread( THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, ThreadId );
    if ( ThreadHandle == NULL )
    {
        return FALSE;
    }

#if defined(_WIN64)
    if ( g_FunStuffTargetWow64 != FALSE && g_FunStuffDebuggerApi.Wow64GetThreadContextFn != NULL )
    {
        WOW64_CONTEXT Wow64Context = { 0 };

        Wow64Context.ContextFlags = WOW64_CONTEXT_CONTROL;
        if ( g_FunStuffDebuggerApi.Wow64GetThreadContextFn( ThreadHandle, &Wow64Context ) != FALSE )
        {
            *InstructionPointer = ( ULONG_PTR )Wow64Context.Eip;
            *StackPointer = ( ULONG_PTR )Wow64Context.Esp;
            *FramePointer = ( ULONG_PTR )Wow64Context.Ebp;
            *InstructionLabel = "EIP";
            *StackLabel = "ESP";
            *FrameLabel = "EBP";
            *ArchLabel = L"x86 (WOW64)";
            Success = TRUE;
        }
    }
#endif

    if ( Success == FALSE )
    {
        CONTEXT NativeContext = { 0 };

        NativeContext.ContextFlags = CONTEXT_CONTROL;
        if ( g_FunStuffDebuggerApi.GetThreadContextFn( ThreadHandle, &NativeContext ) != FALSE )
        {
#if defined(_WIN64)
            *InstructionPointer = ( ULONG_PTR )NativeContext.Rip;
            *StackPointer = ( ULONG_PTR )NativeContext.Rsp;
            *FramePointer = ( ULONG_PTR )NativeContext.Rbp;
            *InstructionLabel = "RIP";
            *StackLabel = "RSP";
            *FrameLabel = "RBP";
            *ArchLabel = L"x64";
#elif defined(_M_IX86)
            *InstructionPointer = ( ULONG_PTR )NativeContext.Eip;
            *StackPointer = ( ULONG_PTR )NativeContext.Esp;
            *FramePointer = ( ULONG_PTR )NativeContext.Ebp;
            *InstructionLabel = "EIP";
            *StackLabel = "ESP";
            *FrameLabel = "EBP";
            *ArchLabel = L"x86";
#else
            *InstructionPointer = 0;
            *StackPointer = 0;
            *FramePointer = 0;
#endif
            Success = TRUE;
        }
    }

    CloseHandle( ThreadHandle );
    return Success;
}

static VOID
FunStuff_Debugger_PrintThreadContext(
    _In_ DWORD ThreadId
    )
{
    ULONG_PTR InstructionPointer = 0;
    ULONG_PTR StackPointer = 0;
    ULONG_PTR FramePointer = 0;
    LPCSTR InstructionLabel = "IP";
    LPCSTR StackLabel = "SP";
    LPCSTR FrameLabel = "BP";
    LPCWSTR ArchLabel = L"unknown";

    if ( FunStuff_Debugger_QueryThreadContextRegisters(
        ThreadId,
        &InstructionPointer,
        &StackPointer,
        &FramePointer,
        &InstructionLabel,
        &StackLabel,
        &FrameLabel,
        &ArchLabel
        ) == FALSE )
    {
        printf( "    [ThreadCtx] TID=%lu <unavailable>\n", ThreadId );
        return;
    }

    printf(
        "    [ThreadCtx] TID=%lu %s=%p %s=%p %s=%p Arch=",
        ThreadId,
        InstructionLabel,
        ( VOID* )InstructionPointer,
        StackLabel,
        ( VOID* )StackPointer,
        FrameLabel,
        ( VOID* )FramePointer
        );
    wprintf( L"%ls\n", ArchLabel );
}

static BOOL
FunStuff_Debugger_TryGetThreadEntry(
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _Out_ THREADENTRY32* ThreadEntry
    )
{
    HANDLE Snapshot = INVALID_HANDLE_VALUE;
    THREADENTRY32 Entry = { 0 };

    if ( ThreadEntry == NULL )
    {
        return FALSE;
    }

    Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( Snapshot == INVALID_HANDLE_VALUE )
    {
        return FALSE;
    }

    Entry.dwSize = sizeof( Entry );
    if ( Thread32First( Snapshot, &Entry ) == FALSE )
    {
        CloseHandle( Snapshot );
        return FALSE;
    }

    do
    {
        if ( Entry.th32OwnerProcessID == ProcessId && Entry.th32ThreadID == ThreadId )
        {
            *ThreadEntry = Entry;
            CloseHandle( Snapshot );
            return TRUE;
        }
    } while ( Thread32Next( Snapshot, &Entry ) != FALSE );

    CloseHandle( Snapshot );
    return FALSE;
}

static VOID
FunStuff_Debugger_PrintThreadMetadata(
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId
    )
{
    THREADENTRY32 ThreadEntry = { 0 };

    if ( FunStuff_Debugger_TryGetThreadEntry( ProcessId, ThreadId, &ThreadEntry ) == FALSE )
    {
        return;
    }

    printf(
        "    [ThreadInfo] TID=%lu BasePri=%ld DeltaPri=%ld\n",
        ThreadEntry.th32ThreadID,
        ThreadEntry.tpBasePri,
        ThreadEntry.tpDeltaPri
        );
}

static VOID
FunStuff_Debugger_DumpThreadSnapshot(
    _In_ DWORD ProcessId
    )
{
    HANDLE Snapshot = INVALID_HANDLE_VALUE;
    THREADENTRY32 ThreadEntry = { 0 };

    Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( Snapshot == INVALID_HANDLE_VALUE )
    {
        printf( "[Threads] Snapshot failed (%lu)\n", GetLastError( ) );
        return;
    }

    ThreadEntry.dwSize = sizeof( ThreadEntry );
    if ( Thread32First( Snapshot, &ThreadEntry ) == FALSE )
    {
        CloseHandle( Snapshot );
        return;
    }

    printf( "[Threads] Current thread list for PID %lu\n", ProcessId );

    do
    {
        if ( ThreadEntry.th32OwnerProcessID == ProcessId )
        {
            printf(
                "    [Thread] TID=%lu BasePri=%ld DeltaPri=%ld\n",
                ThreadEntry.th32ThreadID,
                ThreadEntry.tpBasePri,
                ThreadEntry.tpDeltaPri
                );
            FunStuff_Debugger_PrintThreadContext( ThreadEntry.th32ThreadID );
        }
    } while ( Thread32Next( Snapshot, &ThreadEntry ) != FALSE );

    CloseHandle( Snapshot );
}

static BOOL
FunStuff_Debugger_TryGetModuleEntryByBase(
    _In_ DWORD ProcessId,
    _In_opt_ LPCVOID ModuleBase,
    _Out_ MODULEENTRY32W* ModuleEntry
    )
{
    HANDLE Snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W Entry = { 0 };

    if ( ModuleEntry == NULL || ModuleBase == NULL )
    {
        return FALSE;
    }

    Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId );
    if ( Snapshot == INVALID_HANDLE_VALUE )
    {
        return FALSE;
    }

    Entry.dwSize = sizeof( Entry );
    if ( Module32FirstW( Snapshot, &Entry ) == FALSE )
    {
        CloseHandle( Snapshot );
        return FALSE;
    }

    do
    {
        if ( Entry.modBaseAddr == ( BYTE* )ModuleBase )
        {
            *ModuleEntry = Entry;
            CloseHandle( Snapshot );
            return TRUE;
        }
    } while ( Module32NextW( Snapshot, &Entry ) != FALSE );

    CloseHandle( Snapshot );
    return FALSE;
}

static VOID
FunStuff_Debugger_DumpModuleSnapshot(
    _In_ DWORD ProcessId
    )
{
    HANDLE Snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W ModuleEntry = { 0 };

    Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId );
    if ( Snapshot == INVALID_HANDLE_VALUE )
    {
        printf( "[Modules] Snapshot failed (%lu)\n", GetLastError( ) );
        return;
    }

    ModuleEntry.dwSize = sizeof( ModuleEntry );
    if ( Module32FirstW( Snapshot, &ModuleEntry ) == FALSE )
    {
        CloseHandle( Snapshot );
        return;
    }

    printf( "[Modules] Current module list for PID %lu\n", ProcessId );

    do
    {
        printf(
            "    [Module] Base=%p Size=0x%08lX Name=",
            ModuleEntry.modBaseAddr,
            ModuleEntry.modBaseSize
            );
        wprintf( L"%ls Path=%ls\n", ModuleEntry.szModule, ModuleEntry.szExePath );
    } while ( Module32NextW( Snapshot, &ModuleEntry ) != FALSE );

    CloseHandle( Snapshot );
}

FUNSTUFF_NOINLINE
static BOOL
FunStuff_Debugger_WaitForEvent(
    _Out_ LPDEBUG_EVENT DebugEvent,
    _In_ DWORD Milliseconds
    )
{
    if ( DebugEvent == NULL )
    {
        return FALSE;
    }

    if ( FunStuff_Debugger_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    if ( g_FunStuffDebuggerApi.WaitForDebugEventExFn != NULL )
    {
        return g_FunStuffDebuggerApi.WaitForDebugEventExFn( DebugEvent, Milliseconds );
    }

    return g_FunStuffDebuggerApi.WaitForDebugEventFn( DebugEvent, Milliseconds );
}

FUNSTUFF_NOINLINE
static BOOL
FunStuff_Debugger_Attach(
    _In_ DWORD ProcessId
    )
{
    if ( ProcessId == 0 )
    {
        return FALSE;
    }

    if ( FunStuff_Debugger_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    if ( g_FunStuffDebuggerApi.DebugActiveProcessFn( ProcessId ) == FALSE )
    {
        printf( "[-] DebugActiveProcess failed (%lu)\n", GetLastError( ) );
        return FALSE;
    }

    if ( g_FunStuffDebuggerApi.DebugSetProcessKillOnExitFn( FALSE ) == FALSE )
    {
        printf( "[!] DebugSetProcessKillOnExit failed (%lu)\n", GetLastError( ) );
    }

    g_FunStuffAttachedProcessId = ProcessId;
    if ( FunStuff_Debugger_OpenDebuggeeProcessHandle( ProcessId ) == FALSE )
    {
        printf( "[!] Attached, but process-query handle was unavailable\n" );
    }

    return TRUE;
}

#if defined(_MSC_VER)
#pragma optimize( "", on )
#endif

static BOOL
FunStuff_Debugger_TryGetPathFromFileHandle(
    _In_opt_ HANDLE FileHandle,
    _Out_writes_( BufferCount ) WCHAR* Buffer,
    _In_ DWORD BufferCount
    )
{
    DWORD Result = 0;

    if ( Buffer == NULL || BufferCount == 0 )
    {
        return FALSE;
    }

    Buffer[ 0 ] = L'\0';

    if ( FileHandle == NULL || FileHandle == INVALID_HANDLE_VALUE )
    {
        return FALSE;
    }

    if ( g_FunStuffDebuggerApi.GetFinalPathNameByHandleWFn == NULL )
    {
        return FALSE;
    }

    Result = g_FunStuffDebuggerApi.GetFinalPathNameByHandleWFn(
        FileHandle,
        Buffer,
        BufferCount,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        );

    if ( Result == 0 || Result >= BufferCount )
    {
        Buffer[ 0 ] = L'\0';
        return FALSE;
    }

    return TRUE;
}

static BOOL
FunStuff_Debugger_ReadRemoteString(
    _In_ HANDLE ProcessHandle,
    _In_opt_ LPCVOID RemoteAddress,
    _In_ BOOL Unicode,
    _Out_writes_( BufferCount ) WCHAR* Buffer,
    _In_ SIZE_T BufferCount
    )
{
    SIZE_T MaximumCharacters = 260;
    SIZE_T CharacterIndex = 0;

    if ( Buffer == NULL || BufferCount == 0 )
    {
        return FALSE;
    }

    Buffer[ 0 ] = L'\0';

    if ( ProcessHandle == NULL || RemoteAddress == NULL )
    {
        return FALSE;
    }

    if ( Unicode != FALSE )
    {
        SIZE_T CharacterLimit = BufferCount - 1;

        if ( CharacterLimit > MaximumCharacters )
        {
            CharacterLimit = MaximumCharacters;
        }

        for ( CharacterIndex = 0; CharacterIndex < CharacterLimit; CharacterIndex++ )
        {
            WCHAR Current = L'\0';
            SIZE_T BytesRead = 0;

            if ( ReadProcessMemory(
                ProcessHandle,
                ( CONST BYTE* )RemoteAddress + ( CharacterIndex * sizeof( WCHAR ) ),
                &Current,
                sizeof( Current ),
                &BytesRead
                ) == FALSE || BytesRead != sizeof( Current ) )
            {
                break;
            }

            Buffer[ CharacterIndex ] = Current;
            if ( Current == L'\0' )
            {
                return TRUE;
            }
        }
    }
    else
    {
        SIZE_T CharacterLimit = BufferCount - 1;

        if ( CharacterLimit > MaximumCharacters )
        {
            CharacterLimit = MaximumCharacters;
        }

        for ( CharacterIndex = 0; CharacterIndex < CharacterLimit; CharacterIndex++ )
        {
            CHAR Current = '\0';
            SIZE_T BytesRead = 0;

            if ( ReadProcessMemory(
                ProcessHandle,
                ( CONST BYTE* )RemoteAddress + CharacterIndex,
                &Current,
                sizeof( Current ),
                &BytesRead
                ) == FALSE || BytesRead != sizeof( Current ) )
            {
                break;
            }

            Buffer[ CharacterIndex ] = ( WCHAR )( BYTE )Current;
            if ( Current == '\0' )
            {
                return TRUE;
            }
        }
    }

    Buffer[ CharacterIndex ] = L'\0';
    return CharacterIndex != 0;
}

static VOID
FunStuff_Debugger_HandleException(
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _In_ CONST EXCEPTION_DEBUG_INFO* ExceptionInfo
    )
{
    if ( ExceptionInfo == NULL )
    {
        return;
    }

    printf(
        "[Exception] PID=%lu TID=%lu Address=%p Code=0x%08lX FirstChance=%lu\n",
        ProcessId,
        ThreadId,
        ExceptionInfo->ExceptionRecord.ExceptionAddress,
        ExceptionInfo->ExceptionRecord.ExceptionCode,
        ExceptionInfo->dwFirstChance
        );
    FunStuff_Debugger_PrintThreadMetadata( ProcessId, ThreadId );
    FunStuff_Debugger_PrintThreadContext( ThreadId );
}

static VOID
FunStuff_Debugger_HandleCreateProcess(
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _In_ CONST CREATE_PROCESS_DEBUG_INFO* CreateInfo
    )
{
    WCHAR ImagePath[ MAX_PATH ] = { 0 };

    if ( CreateInfo == NULL )
    {
        return;
    }

    if ( CreateInfo->hProcess != NULL )
    {
        FunStuff_Debugger_SetDebuggeeProcessHandle( CreateInfo->hProcess );
    }

    if ( FunStuff_Debugger_TryGetPathFromFileHandle( CreateInfo->hFile, ImagePath, MAX_PATH ) == FALSE )
    {
        wcscpy_s( ImagePath, MAX_PATH, L"<unknown>" );
    }

    printf(
        "[CreateProcess] PID=%lu TID=%lu Base=%p Start=%p Arch=",
        ProcessId,
        ThreadId,
        CreateInfo->lpBaseOfImage,
        CreateInfo->lpStartAddress
        );
    wprintf( L"%ls Image=%ls\n", FunStuff_Debugger_GetTargetArchLabel( ), ImagePath );
    FunStuff_Debugger_PrintThreadMetadata( ProcessId, ThreadId );
    FunStuff_Debugger_PrintThreadContext( ThreadId );

    if ( CreateInfo->hThread != NULL )
    {
        CloseHandle( CreateInfo->hThread );
    }

    if ( CreateInfo->hProcess != NULL && CreateInfo->hProcess != g_FunStuffDebuggeeProcess )
    {
        CloseHandle( CreateInfo->hProcess );
    }

    if ( CreateInfo->hFile != NULL )
    {
        CloseHandle( CreateInfo->hFile );
    }
}

static VOID
FunStuff_Debugger_HandleCreateThread(
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _In_ CONST CREATE_THREAD_DEBUG_INFO* ThreadInfo
    )
{
    if ( ThreadInfo == NULL )
    {
        return;
    }

    printf(
        "[CreateThread] PID=%lu TID=%lu Start=%p\n",
        ProcessId,
        ThreadId,
        ThreadInfo->lpStartAddress
        );
    FunStuff_Debugger_PrintThreadMetadata( ProcessId, ThreadId );
    FunStuff_Debugger_PrintThreadContext( ThreadId );

    if ( ThreadInfo->hThread != NULL )
    {
        CloseHandle( ThreadInfo->hThread );
    }
}

static VOID
FunStuff_Debugger_HandleLoadDll(
    _In_ DWORD ProcessId,
    _In_ CONST LOAD_DLL_DEBUG_INFO* LoadInfo
    )
{
    WCHAR DllPath[ MAX_PATH ] = { 0 };
    MODULEENTRY32W ModuleEntry = { 0 };
    BOOL HaveModuleEntry = FALSE;

    if ( LoadInfo == NULL )
    {
        return;
    }

    if ( FunStuff_Debugger_TryGetPathFromFileHandle( LoadInfo->hFile, DllPath, MAX_PATH ) == FALSE &&
        FunStuff_Debugger_ReadRemoteString(
            g_FunStuffDebuggeeProcess,
            LoadInfo->lpImageName,
            LoadInfo->fUnicode,
            DllPath,
            MAX_PATH
            ) == FALSE )
    {
        wcscpy_s( DllPath, MAX_PATH, L"<unknown>" );
    }

    HaveModuleEntry = FunStuff_Debugger_TryGetModuleEntryByBase( ProcessId, LoadInfo->lpBaseOfDll, &ModuleEntry );

    printf( "[LoadDll] Base=%p ", LoadInfo->lpBaseOfDll );
    if ( HaveModuleEntry != FALSE )
    {
        printf( "Size=0x%08lX Name=", ModuleEntry.modBaseSize );
        wprintf( L"%ls Path=%ls\n", ModuleEntry.szModule, ModuleEntry.szExePath );
    }
    else
    {
        printf( "Path=" );
        wprintf( L"%ls\n", DllPath );
    }

    if ( LoadInfo->hFile != NULL )
    {
        CloseHandle( LoadInfo->hFile );
    }
}

static VOID
FunStuff_Debugger_HandleOutputDebugString(
    _In_ DWORD ThreadId,
    _In_ CONST OUTPUT_DEBUG_STRING_INFO* StringInfo
    )
{
    WCHAR DebugText[ 512 ] = { 0 };
    SIZE_T CharacterLimit = 0;

    if ( StringInfo == NULL )
    {
        return;
    }

    CharacterLimit = StringInfo->nDebugStringLength;
    if ( CharacterLimit >= 511 )
    {
        CharacterLimit = 511;
    }

    if ( CharacterLimit == 0 )
    {
        printf( "[OutputDebugString] <empty>\n" );
        return;
    }

    if ( FunStuff_Debugger_ReadRemoteString(
        g_FunStuffDebuggeeProcess,
        StringInfo->lpDebugStringData,
        StringInfo->fUnicode,
        DebugText,
        CharacterLimit + 1
        ) == FALSE )
    {
        printf( "[OutputDebugString] <unavailable>\n" );
        return;
    }

    printf( "[OutputDebugString] TID=%lu ", ThreadId );
    wprintf( L"%ls\n", DebugText );
    FunStuff_Debugger_PrintThreadContext( ThreadId );
}

static DWORD
FunStuff_Debugger_GetContinueStatus(
    _In_ CONST DEBUG_EVENT* DebugEvent
    )
{
    DWORD ExceptionCode = 0;

    if ( DebugEvent == NULL )
    {
        return DBG_CONTINUE;
    }

    if ( DebugEvent->dwDebugEventCode != EXCEPTION_DEBUG_EVENT )
    {
        return DBG_CONTINUE;
    }

    ExceptionCode = DebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
    if ( ExceptionCode == EXCEPTION_BREAKPOINT || ExceptionCode == EXCEPTION_SINGLE_STEP )
    {
        return DBG_CONTINUE;
    }

    return DBG_EXCEPTION_NOT_HANDLED;
}

FUNSTUFF_NOINLINE
static INT
FunStuff_Debugger_MainLoop(
    _In_ DWORD AttachedProcessId
    )
{
    BOOL KeepRunning = TRUE;

    while ( KeepRunning != FALSE )
    {
        DEBUG_EVENT DebugEvent = { 0 };
        DWORD ContinueStatus = DBG_CONTINUE;

        if ( FunStuff_Debugger_WaitForEvent( &DebugEvent, INFINITE ) == FALSE )
        {
            printf( "[-] WaitForDebugEvent failed (%lu)\n", GetLastError( ) );
            break;
        }

        switch ( DebugEvent.dwDebugEventCode )
        {
        case EXCEPTION_DEBUG_EVENT:
            FunStuff_Debugger_HandleException(
                DebugEvent.dwProcessId,
                DebugEvent.dwThreadId,
                &DebugEvent.u.Exception
                );
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            FunStuff_Debugger_HandleCreateThread(
                DebugEvent.dwProcessId,
                DebugEvent.dwThreadId,
                &DebugEvent.u.CreateThread
                );
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            FunStuff_Debugger_HandleCreateProcess(
                DebugEvent.dwProcessId,
                DebugEvent.dwThreadId,
                &DebugEvent.u.CreateProcessInfo
                );
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            printf(
                "[ExitThread] PID=%lu TID=%lu Code=%lu\n",
                DebugEvent.dwProcessId,
                DebugEvent.dwThreadId,
                DebugEvent.u.ExitThread.dwExitCode
                );
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            printf(
                "[ExitProcess] PID=%lu Code=%lu\n",
                DebugEvent.dwProcessId,
                DebugEvent.u.ExitProcess.dwExitCode
                );
            KeepRunning = FALSE;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            FunStuff_Debugger_HandleLoadDll( DebugEvent.dwProcessId, &DebugEvent.u.LoadDll );
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
        {
            MODULEENTRY32W ModuleEntry = { 0 };

            printf( "[UnloadDll] Base=%p", DebugEvent.u.UnloadDll.lpBaseOfDll );
            if ( FunStuff_Debugger_TryGetModuleEntryByBase(
                DebugEvent.dwProcessId,
                DebugEvent.u.UnloadDll.lpBaseOfDll,
                &ModuleEntry
                ) != FALSE )
            {
                printf( " Name=" );
                wprintf( L"%ls Path=%ls\n", ModuleEntry.szModule, ModuleEntry.szExePath );
            }
            else
            {
                printf( "\n" );
            }
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT:
            FunStuff_Debugger_HandleOutputDebugString( DebugEvent.dwThreadId, &DebugEvent.u.DebugString );
            break;

        case RIP_EVENT:
            printf(
                "[RipEvent] PID=%lu TID=%lu Error=%lu Type=%lu\n",
                DebugEvent.dwProcessId,
                DebugEvent.dwThreadId,
                DebugEvent.u.RipInfo.dwError,
                DebugEvent.u.RipInfo.dwType
                );
            FunStuff_Debugger_PrintThreadMetadata( DebugEvent.dwProcessId, DebugEvent.dwThreadId );
            FunStuff_Debugger_PrintThreadContext( DebugEvent.dwThreadId );
            break;

        default:
            break;
        }

        ContinueStatus = FunStuff_Debugger_GetContinueStatus( &DebugEvent );
        if ( g_FunStuffDebuggerApi.ContinueDebugEventFn(
            DebugEvent.dwProcessId,
            DebugEvent.dwThreadId,
            ContinueStatus
            ) == FALSE )
        {
            printf( "[-] ContinueDebugEvent failed (%lu)\n", GetLastError( ) );
            break;
        }
    }

    if ( g_FunStuffDebuggeeProcess != NULL )
    {
        CloseHandle( g_FunStuffDebuggeeProcess );
        g_FunStuffDebuggeeProcess = NULL;
    }

    if ( AttachedProcessId != 0 && g_FunStuffDebuggerApi.DebugActiveProcessStopFn != NULL )
    {
        g_FunStuffDebuggerApi.DebugActiveProcessStopFn( AttachedProcessId );
    }

    return 0;
}

static BOOL
FunStuff_Debugger_TryParseProcessId(
    _In_z_ LPCWSTR Text,
    _Out_ DWORD* ProcessId
    )
{
    WCHAR* End = NULL;
    unsigned long Parsed = 0;

    if ( ProcessId == NULL )
    {
        return FALSE;
    }

    *ProcessId = 0;

    if ( Text == NULL || Text[ 0 ] == L'\0' )
    {
        return FALSE;
    }

    Parsed = wcstoul( Text, &End, 10 );
    if ( End == Text || *End != L'\0' || Parsed == 0 )
    {
        return FALSE;
    }

    *ProcessId = ( DWORD )Parsed;
    return TRUE;
}

int
wmain(
    int argc,
    wchar_t* argv[]
    )
{
    DWORD ProcessId = 0;

    if ( argc != 2 )
    {
        FunStuff_Debugger_PrintUsage( );
        return 1;
    }

    if ( FunStuff_Debugger_TryParseProcessId( argv[ 1 ], &ProcessId ) == FALSE )
    {
        ProcessId = FunStuff_Debugger_GetProcessIdFromName( argv[ 1 ] );
    }

    if ( ProcessId == 0 )
    {
        wprintf( L"[-] Could not find process: %ls\n", argv[ 1 ] );
        return 1;
    }

    if ( FunStuff_Debugger_Attach( ProcessId ) == FALSE )
    {
        return 1;
    }

    printf( "[+] Attached to PID %lu successfully\n", ProcessId );
    printf( "[Target] Architecture=" );
    wprintf( L"%ls\n", FunStuff_Debugger_GetTargetArchLabel( ) );
    FunStuff_Debugger_DumpThreadSnapshot( ProcessId );
    FunStuff_Debugger_DumpModuleSnapshot( ProcessId );
    return FunStuff_Debugger_MainLoop( ProcessId );
}
