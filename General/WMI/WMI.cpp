#include<Windows.h>
#include<Wbemidl.h>
#include<winternl.h>
#include<strsafe.h>
#include<stdio.h>
#include<wchar.h>

#pragma comment( lib, "wbemuuid.lib" )
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

typedef struct _WMI_CONTEXT
{
    IWbemLocator* Locator;
    IWbemServices* Services;
    BOOL ComInitialized;
    BOOL Ready;
    COAUTHIDENTITY AuthIdentity;
    WCHAR AuthUser[ 128 ];
    WCHAR AuthPassword[ 128 ];
    WCHAR AuthDomain[ 128 ];
    BOOL HasAuthIdentity;
} WMI_CONTEXT, *PWMI_CONTEXT;

template <typename TChar, size_t N>
struct WMI_ENCODED_LITERAL
{
    TChar Data[ N ];
    BYTE Key;
    static constexpr size_t Length = N;

    constexpr VOID Decode(
        _Out_writes_( N ) TChar* Out
        ) const
    {
        size_t Index = 0;
        for ( Index = 0; Index < N; Index++ )
        {
            Out[ Index ] = ( TChar )( Data[ Index ] ^ ( TChar )Key );
        }
    }
};

template <size_t N>
constexpr WMI_ENCODED_LITERAL<WCHAR, N>
WmiLite_EncodeWideLiteral(
    CONST WCHAR ( &Literal )[ N ],
    _In_ BYTE Key
    )
{
    WMI_ENCODED_LITERAL<WCHAR, N> Encoded = { { 0 }, Key };
    size_t Index = 0;

    for ( Index = 0; Index < N; Index++ )
    {
        Encoded.Data[ Index ] = ( WCHAR )( Literal[ Index ] ^ ( WCHAR )Key );
    }
    return Encoded;
}

template <size_t N>
constexpr WMI_ENCODED_LITERAL<CHAR, N>
WmiLite_EncodeAnsiLiteral(
    CONST CHAR ( &Literal )[ N ],
    _In_ BYTE Key
    )
{
    WMI_ENCODED_LITERAL<CHAR, N> Encoded = { { 0 }, Key };
    size_t Index = 0;

    for ( Index = 0; Index < N; Index++ )
    {
        Encoded.Data[ Index ] = ( CHAR )( Literal[ Index ] ^ ( CHAR )Key );
    }
    return Encoded;
}

constexpr BYTE
WmiLite_MakeObfKey(
    _In_ unsigned Seed
    )
{
    BYTE Key = ( BYTE )( ( Seed * 167u + 29u ) & 0xFFu );
    if ( Key == 0u )
    {
        Key = 0xA5u;
    }
    return Key;
}

#define WMI_ENCODE_STR_IMPL( Name, Literal, Counter )                                 \
    CONST BYTE Name##Key = WmiLite_MakeObfKey( ( unsigned )( Counter ) );             \
    CONST auto Name##Encoded = WmiLite_EncodeWideLiteral( Literal, Name##Key );       \
    WCHAR Name[ Name##Encoded.Length ] = { 0 };                                        \
    Name##Encoded.Decode( Name )

#define ENCODE_STR( Name, Literal ) \
    WMI_ENCODE_STR_IMPL( Name, Literal, __COUNTER__ )

template <size_t N, typename... TArgs>
static VOID
WmiLite_PrintObf(
    _In_ BYTE Key,
    CONST CHAR ( &FormatLiteral )[ N ],
    TArgs... Args
    )
{
    CONST auto Encoded = WmiLite_EncodeAnsiLiteral( FormatLiteral, Key );
    CHAR Format[ N ] = { 0 };

    Encoded.Decode( Format );
    printf( Format, Args... );
}

#define WMILITE_PRINT( ... ) \
    WmiLite_PrintObf( ( BYTE )WmiLite_MakeObfKey( ( unsigned )__COUNTER__ ), __VA_ARGS__ )

typedef decltype( &CoInitializeEx ) PFN_COINITIALIZEEX;
typedef decltype( &CoInitializeSecurity ) PFN_COINITIALIZESECURITY;
typedef decltype( &CoCreateInstance ) PFN_COCREATEINSTANCE;
typedef decltype( &CoSetProxyBlanket ) PFN_COSETPROXYBLANKET;
typedef decltype( &CoUninitialize ) PFN_COUNINITIALIZE;
typedef decltype( &SysAllocString ) PFN_SYSALLOCSTRING;
typedef decltype( &SysFreeString ) PFN_SYSFREESTRING;
typedef decltype( &VariantClear ) PFN_VARIANTCLEAR;

typedef struct _WMILITE_API_TABLE
{
    HMODULE Ole32Module;
    HMODULE OleAut32Module;
    PFN_COINITIALIZEEX CoInitializeExFn;
    PFN_COINITIALIZESECURITY CoInitializeSecurityFn;
    PFN_COCREATEINSTANCE CoCreateInstanceFn;
    PFN_COSETPROXYBLANKET CoSetProxyBlanketFn;
    PFN_COUNINITIALIZE CoUninitializeFn;
    PFN_SYSALLOCSTRING SysAllocStringFn;
    PFN_SYSFREESTRING SysFreeStringFn;
    PFN_VARIANTCLEAR VariantClearFn;
} WMILITE_API_TABLE;

static WMILITE_API_TABLE g_WmiLiteApi = { 0 };

_Must_inspect_result_
static PPEB
WmiLite_GetPeb(
    VOID
    )
{
    PTEB Teb = NtCurrentTeb( );
    if ( Teb == NULL )
    {
        return NULL;
    }

    return Teb->ProcessEnvironmentBlock;
}

_Must_inspect_result_
static BOOL
WmiLite_EqualsUnicodeInsensitive(
    _In_reads_( LeftChars ) CONST WCHAR* Left,
    _In_ CONST USHORT LeftChars,
    _In_z_ CONST WCHAR* Right
    )
{
    INT CompareResult = 0;
    INT RightChars = 0;

    if ( Left == NULL || Right == NULL )
    {
        return FALSE;
    }

    RightChars = lstrlenW( Right );
    if ( RightChars <= 0 || ( USHORT )RightChars != LeftChars )
    {
        return FALSE;
    }

    CompareResult = CompareStringOrdinal(
        Left,
        ( INT )LeftChars,
        Right,
        RightChars,
        TRUE
        );
    return ( CompareResult == CSTR_EQUAL );
}

static VOID
WmiLite_GetBaseNameView(
    _In_ CONST UNICODE_STRING* FullName,
    _Outptr_result_buffer_( *BaseChars ) CONST WCHAR** BaseName,
    _Out_ USHORT* BaseChars
    )
{
    USHORT Index = 0;
    USHORT Start = 0;
    USHORT FullChars = 0;

    if ( BaseName == NULL || BaseChars == NULL )
    {
        return;
    }

    *BaseName = NULL;
    *BaseChars = 0;

    if ( FullName == NULL || FullName->Buffer == NULL || FullName->Length == 0 )
    {
        return;
    }

    FullChars = ( USHORT )( FullName->Length / sizeof( WCHAR ) );
    for ( Index = 0; Index < FullChars; Index++ )
    {
        if ( FullName->Buffer[ Index ] == L'\\' ||
            FullName->Buffer[ Index ] == L'/' )
        {
            Start = ( USHORT )( Index + 1 );
        }
    }

    *BaseName = &FullName->Buffer[ Start ];
    *BaseChars = ( USHORT )( FullChars - Start );
}

_Must_inspect_result_
static HMODULE
WmiLite_CustomGetModuleHandleW(
    _In_opt_z_ CONST WCHAR* ModuleName
    )
{
    PPEB Peb = NULL;
    PPEB_LDR_DATA Ldr = NULL;
    PLIST_ENTRY Head = NULL;
    PLIST_ENTRY Current = NULL;
    CONST WCHAR* SecondaryModuleName = NULL;
    WCHAR ModuleNameWithDll[ MAX_PATH ] = { 0 };

    if ( ModuleName != NULL && ModuleName[ 0 ] == L'\0' )
    {
        return NULL;
    }

    if ( ModuleName != NULL )
    {
        CONST WCHAR* ModuleBaseName = ModuleName;
        CONST WCHAR* Cursor = ModuleName;
        HRESULT NameHr = S_OK;

        while ( *Cursor != L'\0' )
        {
            if ( *Cursor == L'\\' || *Cursor == L'/' )
            {
                ModuleBaseName = Cursor + 1;
            }

            Cursor++;
        }

        if ( wcschr( ModuleBaseName, L'.' ) == NULL )
        {
            NameHr = StringCchPrintfW(
                ModuleNameWithDll,
                ARRAYSIZE( ModuleNameWithDll ),
                L"%ws.dll",
                ModuleName
                );
            if ( SUCCEEDED( NameHr ) == TRUE )
            {
                SecondaryModuleName = ModuleNameWithDll;
            }
        }
    }

    Peb = WmiLite_GetPeb( );
    if ( Peb == NULL || Peb->Ldr == NULL )
    {
        return NULL;
    }

    Ldr = Peb->Ldr;
    Head = &Ldr->InMemoryOrderModuleList;
    Current = Head->Flink;

    while ( Current != NULL && Current != Head )
    {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(
            Current,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
            );
        CONST WCHAR* BaseName = NULL;
        USHORT BaseChars = 0;

        if ( Entry->DllBase == NULL )
        {
            Current = Current->Flink;
            continue;
        }

        if ( ModuleName == NULL )
        {
            return ( HMODULE )Entry->DllBase;
        }

        if ( Entry->FullDllName.Buffer != NULL && Entry->FullDllName.Length > 0 )
        {
            if ( WmiLite_EqualsUnicodeInsensitive(
                Entry->FullDllName.Buffer,
                ( USHORT )( Entry->FullDllName.Length / sizeof( WCHAR ) ),
                ModuleName
                ) == TRUE )
            {
                return ( HMODULE )Entry->DllBase;
            }

            if ( SecondaryModuleName != NULL &&
                WmiLite_EqualsUnicodeInsensitive(
                    Entry->FullDllName.Buffer,
                    ( USHORT )( Entry->FullDllName.Length / sizeof( WCHAR ) ),
                    SecondaryModuleName
                    ) == TRUE )
            {
                return ( HMODULE )Entry->DllBase;
            }

            WmiLite_GetBaseNameView( &Entry->FullDllName, &BaseName, &BaseChars );
            if ( BaseName != NULL &&
                WmiLite_EqualsUnicodeInsensitive( BaseName, BaseChars, ModuleName ) == TRUE )
            {
                return ( HMODULE )Entry->DllBase;
            }

            if ( BaseName != NULL &&
                SecondaryModuleName != NULL &&
                WmiLite_EqualsUnicodeInsensitive( BaseName, BaseChars, SecondaryModuleName ) == TRUE )
            {
                return ( HMODULE )Entry->DllBase;
            }
        }

        Current = Current->Flink;
    }

    return NULL;
}

_Must_inspect_result_
static FARPROC
WmiLite_CustomGetProcAddressInternal(
    _In_ HMODULE ModuleHandle,
    _In_ LPCSTR ProcName,
    _In_ DWORD Depth
    )
{
    BYTE* Base = NULL;
    IMAGE_DOS_HEADER* DosHeader = NULL;
    IMAGE_NT_HEADERS* NtHeaders = NULL;
    IMAGE_EXPORT_DIRECTORY* ExportDirectory = NULL;
    DWORD ExportRva = 0;
    DWORD ExportSize = 0;
    DWORD* NameTable = NULL;
    WORD* OrdinalTable = NULL;
    DWORD* FunctionTable = NULL;
    DWORD RequestedOrdinal = 0;
    DWORD OrdinalIndex = 0;
    DWORD FunctionRva = 0;
    DWORD Index = 0;
    BOOL ByOrdinal = FALSE;
    CONST CHAR* Forwarder = NULL;
    SIZE_T ForwarderLength = 0;
    SIZE_T DotIndex = 0;
    CHAR ForwardModuleA[ MAX_PATH ] = { 0 };
    CHAR ForwardSymbolA[ MAX_PATH ] = { 0 };
    WCHAR ForwardModuleW[ MAX_PATH ] = { 0 };
    INT WideChars = 0;
    HMODULE ForwardModule = NULL;

    if ( Depth >= 8 )
    {
        return NULL;
    }

    if ( ModuleHandle == NULL || ProcName == NULL )
    {
        return NULL;
    }

    ByOrdinal = ( ( ( ULONG_PTR )ProcName >> 16 ) == 0 );
    if ( ByOrdinal == FALSE && ProcName[ 0 ] == '\0' )
    {
        return NULL;
    }

    Base = ( BYTE* )ModuleHandle;
    DosHeader = ( IMAGE_DOS_HEADER* )Base;
    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        return NULL;
    }

    NtHeaders = ( IMAGE_NT_HEADERS* )( Base + DosHeader->e_lfanew );
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

    ExportDirectory = ( IMAGE_EXPORT_DIRECTORY* )( Base + ExportRva );
    NameTable = ( DWORD* )( Base + ExportDirectory->AddressOfNames );
    OrdinalTable = ( WORD* )( Base + ExportDirectory->AddressOfNameOrdinals );
    FunctionTable = ( DWORD* )( Base + ExportDirectory->AddressOfFunctions );

    if ( ByOrdinal == TRUE )
    {
        RequestedOrdinal = LOWORD( ProcName );
        if ( RequestedOrdinal < ExportDirectory->Base )
        {
            return NULL;
        }

        OrdinalIndex = RequestedOrdinal - ExportDirectory->Base;
    }
    else
    {
        for ( Index = 0; Index < ExportDirectory->NumberOfNames; Index++ )
        {
            CONST CHAR* ExportName = ( CONST CHAR* )( Base + NameTable[ Index ] );
            if ( lstrcmpA( ExportName, ProcName ) == 0 )
            {
                OrdinalIndex = ( DWORD )OrdinalTable[ Index ];
                break;
            }
        }

        if ( Index >= ExportDirectory->NumberOfNames )
        {
            return NULL;
        }
    }

    if ( OrdinalIndex >= ExportDirectory->NumberOfFunctions )
    {
        return NULL;
    }

    FunctionRva = FunctionTable[ OrdinalIndex ];
    if ( FunctionRva >= ExportRva && FunctionRva < ( ExportRva + ExportSize ) )
    {
        //
        // Handle forwarded exports, e.g. "combase.CoInitializeEx" or
        // "ntdll.#123". This is common for COM APIs on modern Windows.
        //
        Forwarder = ( CONST CHAR* )( Base + FunctionRva );
        while ( ForwarderLength < ( MAX_PATH - 1 ) && Forwarder[ ForwarderLength ] != '\0' )
        {
            ForwarderLength++;
        }

        if ( ForwarderLength == 0 || ForwarderLength >= ( MAX_PATH - 1 ) )
        {
            return NULL;
        }

        for ( DotIndex = ForwarderLength; DotIndex > 0; DotIndex-- )
        {
            if ( Forwarder[ DotIndex - 1 ] == '.' )
            {
                break;
            }
        }

        if ( DotIndex == 0 || DotIndex == ForwarderLength )
        {
            return NULL;
        }

        CopyMemory( ForwardModuleA, Forwarder, DotIndex - 1 );
        ForwardModuleA[ DotIndex - 1 ] = '\0';
        CopyMemory(
            ForwardSymbolA,
            Forwarder + DotIndex,
            ForwarderLength - DotIndex
            );
        ForwardSymbolA[ ForwarderLength - DotIndex ] = '\0';

        WideChars = MultiByteToWideChar(
            CP_ACP,
            0,
            ForwardModuleA,
            -1,
            ForwardModuleW,
            ARRAYSIZE( ForwardModuleW )
            );
        if ( WideChars > 0 )
        {
            ForwardModule = WmiLite_CustomGetModuleHandleW( ForwardModuleW );
        }

        if ( ForwardModule == NULL )
        {
            ForwardModule = LoadLibraryA( ForwardModuleA );
        }

        if ( ForwardModule == NULL )
        {
            return NULL;
        }

        if ( ForwardSymbolA[ 0 ] == '#' )
        {
            DWORD OrdinalValue = 0;
            SIZE_T Pos = 1;

            if ( ForwardSymbolA[ Pos ] == '\0' )
            {
                return NULL;
            }

            while ( ForwardSymbolA[ Pos ] != '\0' )
            {
                CHAR Ch = ForwardSymbolA[ Pos ];
                if ( Ch < '0' || Ch > '9' )
                {
                    return NULL;
                }

                OrdinalValue = ( OrdinalValue * 10u ) + ( DWORD )( Ch - '0' );
                if ( OrdinalValue > 0xFFFFu )
                {
                    return NULL;
                }

                Pos++;
            }

            return WmiLite_CustomGetProcAddressInternal(
                ForwardModule,
                MAKEINTRESOURCEA( ( WORD )OrdinalValue ),
                Depth + 1
                );
        }

        return WmiLite_CustomGetProcAddressInternal(
            ForwardModule,
            ForwardSymbolA,
            Depth + 1
            );
    }

    return ( FARPROC )( Base + FunctionRva );
}

_Must_inspect_result_
static FARPROC
WmiLite_CustomGetProcAddress(
    _In_ HMODULE ModuleHandle,
    _In_ LPCSTR ProcName
    )
{
    return WmiLite_CustomGetProcAddressInternal( ModuleHandle, ProcName, 0 );
}

_Must_inspect_result_
static BOOL
WmiLite_ResolveRuntimeApis(
    VOID
    )
{
    WMILITE_API_TABLE Api = { 0 };
    HMODULE Ole32Module = NULL;
    HMODULE OleAut32Module = NULL;

    if ( g_WmiLiteApi.CoInitializeExFn != NULL &&
        g_WmiLiteApi.CoInitializeSecurityFn != NULL &&
        g_WmiLiteApi.CoCreateInstanceFn != NULL &&
        g_WmiLiteApi.CoSetProxyBlanketFn != NULL &&
        g_WmiLiteApi.CoUninitializeFn != NULL &&
        g_WmiLiteApi.SysAllocStringFn != NULL &&
        g_WmiLiteApi.SysFreeStringFn != NULL &&
        g_WmiLiteApi.VariantClearFn != NULL )
    {
        return TRUE;
    }

    Ole32Module = WmiLite_CustomGetModuleHandleW( L"ole32.dll" );
    if ( Ole32Module == NULL )
    {
        Ole32Module = LoadLibraryW( L"ole32.dll" );
        if ( Ole32Module == NULL )
        {
            WMILITE_PRINT( "[-] LoadLibraryW( ole32.dll ) failed (%lu)\n", GetLastError( ) );
            return FALSE;
        }
    }

    OleAut32Module = WmiLite_CustomGetModuleHandleW( L"oleaut32.dll" );
    if ( OleAut32Module == NULL )
    {
        OleAut32Module = LoadLibraryW( L"oleaut32.dll" );
        if ( OleAut32Module == NULL )
        {
            WMILITE_PRINT( "[-] LoadLibraryW( oleaut32.dll ) failed (%lu)\n", GetLastError( ) );
            return FALSE;
        }
    }

    Api.Ole32Module = Ole32Module;
    Api.OleAut32Module = OleAut32Module;
    Api.CoInitializeExFn = ( PFN_COINITIALIZEEX )WmiLite_CustomGetProcAddress( Ole32Module, "CoInitializeEx" );
    Api.CoInitializeSecurityFn = ( PFN_COINITIALIZESECURITY )WmiLite_CustomGetProcAddress( Ole32Module, "CoInitializeSecurity" );
    Api.CoCreateInstanceFn = ( PFN_COCREATEINSTANCE )WmiLite_CustomGetProcAddress( Ole32Module, "CoCreateInstance" );
    Api.CoSetProxyBlanketFn = ( PFN_COSETPROXYBLANKET )WmiLite_CustomGetProcAddress( Ole32Module, "CoSetProxyBlanket" );
    Api.CoUninitializeFn = ( PFN_COUNINITIALIZE )WmiLite_CustomGetProcAddress( Ole32Module, "CoUninitialize" );
    Api.SysAllocStringFn = ( PFN_SYSALLOCSTRING )WmiLite_CustomGetProcAddress( OleAut32Module, "SysAllocString" );
    Api.SysFreeStringFn = ( PFN_SYSFREESTRING )WmiLite_CustomGetProcAddress( OleAut32Module, "SysFreeString" );
    Api.VariantClearFn = ( PFN_VARIANTCLEAR )WmiLite_CustomGetProcAddress( OleAut32Module, "VariantClear" );

    if ( Api.CoInitializeExFn == NULL ||
        Api.CoInitializeSecurityFn == NULL ||
        Api.CoCreateInstanceFn == NULL ||
        Api.CoSetProxyBlanketFn == NULL ||
        Api.CoUninitializeFn == NULL ||
        Api.SysAllocStringFn == NULL ||
        Api.SysFreeStringFn == NULL ||
        Api.VariantClearFn == NULL )
    {
        if ( Api.CoInitializeExFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: CoInitializeEx\n" );
        }
        if ( Api.CoInitializeSecurityFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: CoInitializeSecurity\n" );
        }
        if ( Api.CoCreateInstanceFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: CoCreateInstance\n" );
        }
        if ( Api.CoSetProxyBlanketFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: CoSetProxyBlanket\n" );
        }
        if ( Api.CoUninitializeFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: CoUninitialize\n" );
        }
        if ( Api.SysAllocStringFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: SysAllocString\n" );
        }
        if ( Api.SysFreeStringFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: SysFreeString\n" );
        }
        if ( Api.VariantClearFn == NULL )
        {
            WMILITE_PRINT( "[-] Resolve failed: VariantClear\n" );
        }

        WMILITE_PRINT( "[-] Failed to resolve one or more COM/OLE exports\n" );
        return FALSE;
    }

    g_WmiLiteApi = Api;
    return TRUE;
}

_Must_inspect_result_
static BOOL
WmiLite_Initialize(
    _Out_ PWMI_CONTEXT Context
    )
{
    HRESULT Hr = S_OK;
    BSTR Namespace = NULL;

    if ( Context == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_Initialize: Context is NULL\n" );
        return FALSE;
    }

    //
    // Zeroing the context up front guarantees one consistent cleanup path.
    //
    RtlZeroMemory( Context, sizeof( WMI_CONTEXT ) );

    //
    // Resolve runtime COM/OLE exports and ensure required DLLs are present.
    //
    if ( WmiLite_ResolveRuntimeApis( ) == FALSE )
    {
        WMILITE_PRINT( "[-] WmiLite_Initialize: failed to resolve COM/OLE APIs\n" );
        return FALSE;
    }

    //
    // Multi-threaded COM is required to avoid apartment surprises in callers.
    //
    Hr = g_WmiLiteApi.CoInitializeExFn( NULL, COINIT_MULTITHREADED );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] CoInitializeEx -> 0x%08lX\n", Hr );
        return FALSE;
    }
    Context->ComInitialized = TRUE;

    //
    // Process-wide COM security must exist before talking to WMI proxies.
    //
    Hr = g_WmiLiteApi.CoInitializeSecurityFn(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
        );
    if ( FAILED( Hr ) == TRUE )
    {
        //
        // RPC_E_TOO_LATE means COM security was already configured by another
        // module in this process, which is expected in shared-host scenarios.
        //
        if ( Hr != RPC_E_TOO_LATE )
        {
            WMILITE_PRINT( "[-] CoInitializeSecurity -> 0x%08lX\n", Hr );
            g_WmiLiteApi.CoUninitializeFn( );
            Context->ComInitialized = FALSE;
            return FALSE;
        }
    }

    //
    // WMI object creation is delayed until security state is known-good.
    //
    Hr = g_WmiLiteApi.CoCreateInstanceFn(
        CLSID_WbemLocator,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        ( PVOID* )&Context->Locator
        );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] CoCreateInstance( IWbemLocator ) -> 0x%08lX\n", Hr );
        g_WmiLiteApi.CoUninitializeFn( );
        Context->ComInitialized = FALSE;
        return FALSE;
    }

    //
    // ROOT\\CIMV2 is the default namespace for most host telemetry classes.
    //
    ENCODE_STR( NamespaceText, L"ROOT\\CIMV2" );
    Namespace = g_WmiLiteApi.SysAllocStringFn( NamespaceText );
    if ( Namespace == NULL )
    {
        WMILITE_PRINT( "[-] SysAllocString( Namespace ) failed\n" );
        Context->Locator->Release( );
        Context->Locator = NULL;
        g_WmiLiteApi.CoUninitializeFn( );
        Context->ComInitialized = FALSE;
        return FALSE;
    }

    Hr = Context->Locator->ConnectServer(
        Namespace,
        NULL,
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        &Context->Services
        );
    g_WmiLiteApi.SysFreeStringFn( Namespace );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] IWbemLocator::ConnectServer -> 0x%08lX\n", Hr );
        Context->Locator->Release( );
        Context->Locator = NULL;
        g_WmiLiteApi.CoUninitializeFn( );
        Context->ComInitialized = FALSE;
        return FALSE;
    }

    //
    // Proxy blanket enforces authenticated RPC calls for WMI method traffic.
    //
    Hr = g_WmiLiteApi.CoSetProxyBlanketFn(
        Context->Services,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
        );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] CoSetProxyBlanket -> 0x%08lX\n", Hr );
        Context->Services->Release( );
        Context->Services = NULL;
        Context->Locator->Release( );
        Context->Locator = NULL;
        g_WmiLiteApi.CoUninitializeFn( );
        Context->ComInitialized = FALSE;
        return FALSE;
    }

    Context->Ready = TRUE;
    return TRUE;
}

static VOID
WmiLite_Shutdown(
    _Inout_ PWMI_CONTEXT Context
    )
{
    if ( Context == NULL )
    {
        return;
    }

    //
    // Releasing interfaces before CoUninitialize avoids dangling proxies.
    //
    if ( Context->Services != NULL )
    {
        Context->Services->Release( );
        Context->Services = NULL;
    }

    if ( Context->Locator != NULL )
    {
        Context->Locator->Release( );
        Context->Locator = NULL;
    }

    //
    // Uninitialization only runs when this module created the COM apartment.
    //
    if ( Context->ComInitialized == TRUE )
    {
        if ( g_WmiLiteApi.CoUninitializeFn != NULL )
        {
            g_WmiLiteApi.CoUninitializeFn( );
        }
        Context->ComInitialized = FALSE;
    }

    //
    // Credential buffers are scrubbed so secrets do not persist in process
    // memory beyond the lifetime of this WMI context.
    //
    RtlSecureZeroMemory( &Context->AuthIdentity, sizeof( Context->AuthIdentity ) );
    RtlSecureZeroMemory( Context->AuthUser, sizeof( Context->AuthUser ) );
    RtlSecureZeroMemory( Context->AuthPassword, sizeof( Context->AuthPassword ) );
    RtlSecureZeroMemory( Context->AuthDomain, sizeof( Context->AuthDomain ) );
    Context->HasAuthIdentity = FALSE;

    Context->Ready = FALSE;
}

_Must_inspect_result_
static BOOL
WmiLite_QueryFirstString(
    _In_ CONST WMI_CONTEXT* Context,
    _In_z_ CONST WCHAR* Query,
    _In_z_ CONST WCHAR* PropertyName,
    _Out_writes_( OutChars ) WCHAR* OutValue,
    _In_ CONST DWORD OutChars
    )
{
    HRESULT Hr = S_OK;
    IEnumWbemClassObject* Enumerator = NULL;
    IWbemClassObject* Result = NULL;
    ULONG Returned = 0;
    VARIANT Value;
    BSTR QueryLanguage = NULL;
    BSTR QueryText = NULL;
    HRESULT GetHr = S_OK;

    if ( Context == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: Context is NULL\n" );
        return FALSE;
    }

    if ( Context->Ready == FALSE )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: Context is not initialized\n" );
        return FALSE;
    }

    if ( g_WmiLiteApi.SysAllocStringFn == NULL ||
        g_WmiLiteApi.SysFreeStringFn == NULL ||
        g_WmiLiteApi.VariantClearFn == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: OLE API table is not resolved\n" );
        return FALSE;
    }

    if ( Query == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: Query is NULL\n" );
        return FALSE;
    }

    if ( PropertyName == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: PropertyName is NULL\n" );
        return FALSE;
    }

    if ( OutValue == NULL )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: OutValue is NULL\n" );
        return FALSE;
    }

    if ( OutChars == 0 )
    {
        WMILITE_PRINT( "[-] WmiLite_QueryFirstString: OutChars is 0\n" );
        return FALSE;
    }

    OutValue[ 0 ] = L'\0';
    VariantInit( &Value );

    //
    // Allocating BSTRs once keeps the query path simple and predictable.
    //
    ENCODE_STR( QueryLanguageText, L"WQL" );
    QueryLanguage = g_WmiLiteApi.SysAllocStringFn( QueryLanguageText );
    QueryText = g_WmiLiteApi.SysAllocStringFn( Query );
    if ( QueryLanguage == NULL || QueryText == NULL )
    {
        WMILITE_PRINT( "[-] SysAllocString failed (%lu)\n", GetLastError( ) );
        if ( QueryText != NULL )
        {
            g_WmiLiteApi.SysFreeStringFn( QueryText );
        }
        if ( QueryLanguage != NULL )
        {
            g_WmiLiteApi.SysFreeStringFn( QueryLanguage );
        }
        return FALSE;
    }

    //
    // Forward-only query limits memory footprint for single-row extraction.
    //
    Hr = Context->Services->ExecQuery(
        QueryLanguage,
        QueryText,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &Enumerator
        );
    g_WmiLiteApi.SysFreeStringFn( QueryText );
    g_WmiLiteApi.SysFreeStringFn( QueryLanguage );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] IWbemServices::ExecQuery -> 0x%08lX\n", Hr );
        return FALSE;
    }

    //
    // Pulling only the first result keeps this helper lightweight by design.
    //
    Hr = Enumerator->Next( WBEM_INFINITE, 1, &Result, &Returned );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] IEnumWbemClassObject::Next -> 0x%08lX\n", Hr );
        Enumerator->Release( );
        return FALSE;
    }

    if ( Returned == 0 )
    {
        WMILITE_PRINT( "[-] Query returned no rows\n" );
        Enumerator->Release( );
        return FALSE;
    }

    //
    // VT_BSTR is enforced so callers get deterministic string output.
    //
    GetHr = Result->Get( PropertyName, 0, &Value, NULL, NULL );
    if ( FAILED( GetHr ) == TRUE )
    {
        WMILITE_PRINT( "[-] IWbemClassObject::Get -> 0x%08lX\n", GetHr );
        Result->Release( );
        Enumerator->Release( );
        return FALSE;
    }

    if ( Value.vt != VT_BSTR || Value.bstrVal == NULL )
    {
        WMILITE_PRINT( "[-] Property is not a valid VT_BSTR\n" );
        g_WmiLiteApi.VariantClearFn( &Value );
        Result->Release( );
        Enumerator->Release( );
        return FALSE;
    }

    Hr = StringCchCopyW( OutValue, OutChars, Value.bstrVal );
    if ( FAILED( Hr ) == TRUE )
    {
        WMILITE_PRINT( "[-] StringCchCopyW -> 0x%08lX\n", Hr );
        g_WmiLiteApi.VariantClearFn( &Value );
        Result->Release( );
        Enumerator->Release( );
        return FALSE;
    }

    g_WmiLiteApi.VariantClearFn( &Value );
    Result->Release( );
    Enumerator->Release( );
    return TRUE;
}

_Must_inspect_result_
static INT
WmiLite_RunDemo(
    VOID
    )
{
    WMI_CONTEXT Context;
    WCHAR Value[ 256 ];
    ENCODE_STR( Query, L"SELECT Caption FROM Win32_OperatingSystem" );
    ENCODE_STR( Property, L"Caption" );
    BOOL Ok = FALSE;

    //
    // A short demo validates initialization and one end-to-end query path.
    //
    Ok = WmiLite_Initialize( &Context );
    if ( Ok == FALSE )
    {
        return 1;
    }

    Ok = WmiLite_QueryFirstString(
        &Context,
        Query,
        Property,
        Value,
        ( DWORD )ARRAYSIZE( Value )
        );
    if ( Ok == FALSE )
    {
        WmiLite_Shutdown( &Context );
        return 1;
    }

    WMILITE_PRINT( "[+] %ws: %ws\n", Property, Value );

    WmiLite_Shutdown( &Context );
    return 0;
}

#ifndef WMILITE_STANDALONE
#define WMILITE_STANDALONE
#endif

#ifdef WMILITE_STANDALONE
_Must_inspect_result_
INT
main(
    VOID
    )
{
    return WmiLite_RunDemo( );
}
#endif
