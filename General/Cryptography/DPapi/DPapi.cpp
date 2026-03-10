#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 5105)
#endif
#include<Windows.h>
#include<wincrypt.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#if defined(_MSC_VER)
#define FUNSTUFF_NOINLINE __declspec(noinline)
#else
#define FUNSTUFF_NOINLINE __attribute__((noinline))
#endif

typedef decltype( &CryptProtectData ) PFN_CRYPTPROTECTDATA;
typedef decltype( &CryptUnprotectData ) PFN_CRYPTUNPROTECTDATA;

typedef struct _FUNSTUFF_DPAPI_RUNTIME
{
    HMODULE Module;
    PFN_CRYPTPROTECTDATA ProtectDataFn;
    PFN_CRYPTUNPROTECTDATA UnprotectDataFn;
    BOOL Ready;
} FUNSTUFF_DPAPI_RUNTIME, *PFUNSTUFF_DPAPI_RUNTIME;

static FUNSTUFF_DPAPI_RUNTIME g_FunStuffDpapiApi = { 0 };

static VOID
FunStuff_Dpapi_PrintHex(
    _In_reads_bytes_( BufferSize ) CONST BYTE* Buffer,
    _In_ DWORD BufferSize
    )
{
    DWORD Index = 0;

    if ( Buffer == NULL )
    {
        return;
    }

    for ( Index = 0; Index < BufferSize; Index++ )
    {
        printf( "%02X", Buffer[ Index ] );
    }
}

static VOID
FunStuff_Dpapi_FreeBlob(
    _Inout_ DATA_BLOB* Blob
    )
{
    if ( Blob == NULL )
    {
        return;
    }

    if ( Blob->pbData != NULL )
    {
        RtlSecureZeroMemory( Blob->pbData, Blob->cbData );
        LocalFree( Blob->pbData );
        Blob->pbData = NULL;
    }

    Blob->cbData = 0;
}

static VOID
FunStuff_Dpapi_FreeDescription(
    _Inout_opt_ LPWSTR* Description
    )
{
    if ( Description == NULL || *Description == NULL )
    {
        return;
    }

    LocalFree( *Description );
    *Description = NULL;
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
FunStuff_Dpapi_EnsureLoaded(
    VOID
    )
{
    FUNSTUFF_DPAPI_RUNTIME Api = { 0 };

    if ( g_FunStuffDpapiApi.Ready == TRUE )
    {
        return TRUE;
    }

    Api.Module = LoadLibraryW( L"crypt32.dll" );
    if ( Api.Module == NULL )
    {
        // 
        // SHOULDNT HAPPEN ! 
        //
        printf( "[-] LoadLibraryW( crypt32.dll ) failed (%lu)\n", GetLastError( ) );
        return FALSE;
    }

    Api.ProtectDataFn = ( PFN_CRYPTPROTECTDATA )FunStuff_CustomGetProcAddress( Api.Module, "CryptProtectData" );
    Api.UnprotectDataFn = ( PFN_CRYPTUNPROTECTDATA )FunStuff_CustomGetProcAddress( Api.Module, "CryptUnprotectData" );

    if ( Api.ProtectDataFn == NULL || Api.UnprotectDataFn == NULL )
    {
        printf( "[-] FunStuff_CustomGetProcAddress( crypt32.dll ) failed\n" );
        FreeLibrary( Api.Module );
        return FALSE;
    }

    Api.Ready = TRUE;
    g_FunStuffDpapiApi = Api;
    return TRUE;
}

FUNSTUFF_NOINLINE
static BOOL
FunStuff_Dpapi_Protect(
    _In_reads_bytes_opt_( PlaintextSize ) CONST BYTE* Plaintext,
    _In_ DWORD PlaintextSize,
    _In_reads_bytes_opt_( EntropySize ) CONST BYTE* OptionalEntropy,
    _In_ DWORD EntropySize,
    _In_opt_z_ LPCWSTR Description,
    _In_ DWORD Flags,
    _Out_ DATA_BLOB* ProtectedData
    )
{
    DATA_BLOB Input = { 0 };
    DATA_BLOB Entropy = { 0 };

    if ( ProtectedData == NULL )
    {
        printf( "[-] FunStuff_Dpapi_Protect: ProtectedData is NULL\n" );
        return FALSE;
    }

    RtlZeroMemory( ProtectedData, sizeof( *ProtectedData ) );

    if ( Plaintext == NULL && PlaintextSize != 0 )
    {
        printf( "[-] FunStuff_Dpapi_Protect: Plaintext is NULL\n" );
        return FALSE;
    }

    if ( OptionalEntropy == NULL && EntropySize != 0 )
    {
        printf( "[-] FunStuff_Dpapi_Protect: OptionalEntropy is NULL\n" );
        return FALSE;
    }

    if ( FunStuff_Dpapi_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    Input.pbData = ( BYTE* )Plaintext;
    Input.cbData = PlaintextSize;

    if ( EntropySize != 0 )
    {
        Entropy.pbData = ( BYTE* )OptionalEntropy;
        Entropy.cbData = EntropySize;
    }

    if ( g_FunStuffDpapiApi.ProtectDataFn(
        &Input,
        Description,
        ( EntropySize != 0 ) ? &Entropy : NULL,
        NULL,
        NULL,
        Flags | CRYPTPROTECT_UI_FORBIDDEN,
        ProtectedData
        ) == FALSE )
    {
        printf( "[-] CryptProtectData failed (%lu)\n", GetLastError( ) );
        return FALSE;
    }

    return TRUE;
}

FUNSTUFF_NOINLINE
static BOOL
FunStuff_Dpapi_Unprotect(
    _In_ CONST DATA_BLOB* ProtectedData,
    _In_reads_bytes_opt_( EntropySize ) CONST BYTE* OptionalEntropy,
    _In_ DWORD EntropySize,
    _In_ DWORD Flags,
    _Out_opt_ LPWSTR* Description,
    _Out_ DATA_BLOB* Plaintext
    )
{
    DATA_BLOB Entropy = { 0 };
    LPWSTR DecodedDescription = NULL;

    if ( Description != NULL )
    {
        *Description = NULL;
    }

    if ( Plaintext == NULL )
    {
        printf( "[-] FunStuff_Dpapi_Unprotect: Plaintext is NULL\n" );
        return FALSE;
    }

    RtlZeroMemory( Plaintext, sizeof( *Plaintext ) );

    if ( ProtectedData == NULL || ProtectedData->pbData == NULL || ProtectedData->cbData == 0 )
    {
        printf( "[-] FunStuff_Dpapi_Unprotect: ProtectedData is invalid\n" );
        return FALSE;
    }

    if ( OptionalEntropy == NULL && EntropySize != 0 )
    {
        printf( "[-] FunStuff_Dpapi_Unprotect: OptionalEntropy is NULL\n" );
        return FALSE;
    }

    if ( FunStuff_Dpapi_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    if ( EntropySize != 0 )
    {
        Entropy.pbData = ( BYTE* )OptionalEntropy;
        Entropy.cbData = EntropySize;
    }

    if ( g_FunStuffDpapiApi.UnprotectDataFn(
        ( DATA_BLOB* )ProtectedData,
        ( Description != NULL ) ? &DecodedDescription : NULL,
        ( EntropySize != 0 ) ? &Entropy : NULL,
        NULL,
        NULL,
        Flags | CRYPTPROTECT_UI_FORBIDDEN,
        Plaintext
        ) == FALSE )
    {
        printf( "[-] CryptUnprotectData failed (%lu)\n", GetLastError( ) );
        return FALSE;
    }

    if ( Description != NULL )
    {
        *Description = DecodedDescription;
    }
    else
    {
        FunStuff_Dpapi_FreeDescription( &DecodedDescription );
    }

    return TRUE;
}

#if defined(_MSC_VER)
#pragma optimize( "", on )
#endif

FUNSTUFF_NOINLINE
static INT
FunStuff_Dpapi_RunDemo(
    VOID
    )
{
    CONST BYTE Plaintext[] = "FunStuff DPAPI demo";
    CONST BYTE OptionalEntropy[] = "FunStuff entropy random idk";
    DATA_BLOB ProtectedData = { 0 };
    DATA_BLOB UnprotectedData = { 0 };
    LPWSTR Description = NULL;
    BOOL Ok = FALSE;

    Ok = FunStuff_Dpapi_Protect(
        Plaintext,
        ( DWORD )( sizeof( Plaintext ) - 1 ),
        OptionalEntropy,
        ( DWORD )( sizeof( OptionalEntropy ) - 1 ),
        L"FunStuff DPAPI blob",
        0,
        &ProtectedData
        );
    if ( Ok == FALSE )
    {
        return 1;
    }

    printf( "[+] DPAPI blob: " );
    FunStuff_Dpapi_PrintHex( ProtectedData.pbData, ProtectedData.cbData );
    printf( "\n" );

    Ok = FunStuff_Dpapi_Unprotect(
        &ProtectedData,
        OptionalEntropy,
        ( DWORD )( sizeof( OptionalEntropy ) - 1 ),
        0,
        &Description,
        &UnprotectedData
        );
    if ( Ok == FALSE )
    {
        FunStuff_Dpapi_FreeBlob( &ProtectedData );
        return 1;
    }

    if ( Description != NULL )
    {
        printf( "[+] Description: %ws\n", Description );
    }

    printf( "[+] Plaintext: %.*s\n", ( int )UnprotectedData.cbData, UnprotectedData.pbData );

    if ( UnprotectedData.cbData != sizeof( Plaintext ) - 1 ||
        memcmp( UnprotectedData.pbData, Plaintext, sizeof( Plaintext ) - 1 ) != 0 )
    {
        printf( "[-] DPAPI verification mismatch\n" );
        FunStuff_Dpapi_FreeDescription( &Description );
        FunStuff_Dpapi_FreeBlob( &UnprotectedData );
        FunStuff_Dpapi_FreeBlob( &ProtectedData );
        return 1;
    }

    FunStuff_Dpapi_FreeDescription( &Description );
    FunStuff_Dpapi_FreeBlob( &UnprotectedData );
    FunStuff_Dpapi_FreeBlob( &ProtectedData );
    return 0;
}

INT
main(
    VOID
    )
{
    return FunStuff_Dpapi_RunDemo( );
}
