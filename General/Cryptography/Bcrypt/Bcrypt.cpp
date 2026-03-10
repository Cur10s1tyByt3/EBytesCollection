#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS( Status ) ( ( ( NTSTATUS )( Status ) ) >= 0 )
#endif

typedef decltype( &BCryptOpenAlgorithmProvider ) PFN_BCRYPTOPENALGORITHMPROVIDER;
typedef decltype( &BCryptCloseAlgorithmProvider ) PFN_BCRYPTCLOSEALGORITHMPROVIDER;
typedef decltype( &BCryptGetProperty ) PFN_BCRYPTGETPROPERTY;
typedef decltype( &BCryptSetProperty ) PFN_BCRYPTSETPROPERTY;
typedef decltype( &BCryptCreateHash ) PFN_BCRYPTCREATEHASH;
typedef decltype( &BCryptHashData ) PFN_BCRYPTHASHDATA;
typedef decltype( &BCryptFinishHash ) PFN_BCRYPTFINISHHASH;
typedef decltype( &BCryptDestroyHash ) PFN_BCRYPTDESTROYHASH;
typedef decltype( &BCryptGenRandom ) PFN_BCRYPTGENRANDOM;
typedef decltype( &BCryptGetFipsAlgorithmMode ) PFN_BCRYPTGETFIPSALGORITHMMODE;
typedef decltype( &BCryptGenerateSymmetricKey ) PFN_BCRYPTGENERATESYMMETRICKEY;
typedef decltype( &BCryptDestroyKey ) PFN_BCRYPTDESTROYKEY;
typedef decltype( &BCryptEncrypt ) PFN_BCRYPTENCRYPT;
typedef decltype( &BCryptDecrypt ) PFN_BCRYPTDECRYPT;

typedef struct _FUNSTUFF_BCRYPT_RUNTIME
{
    HMODULE Module;
    PFN_BCRYPTOPENALGORITHMPROVIDER OpenAlgorithmProviderFn;
    PFN_BCRYPTCLOSEALGORITHMPROVIDER CloseAlgorithmProviderFn;
    PFN_BCRYPTGETPROPERTY GetPropertyFn;
    PFN_BCRYPTSETPROPERTY SetPropertyFn;
    PFN_BCRYPTCREATEHASH CreateHashFn;
    PFN_BCRYPTHASHDATA HashDataFn;
    PFN_BCRYPTFINISHHASH FinishHashFn;
    PFN_BCRYPTDESTROYHASH DestroyHashFn;
    PFN_BCRYPTGENRANDOM GenRandomFn;
    PFN_BCRYPTGETFIPSALGORITHMMODE GetFipsAlgorithmModeFn;
    PFN_BCRYPTGENERATESYMMETRICKEY GenerateSymmetricKeyFn;
    PFN_BCRYPTDESTROYKEY DestroyKeyFn;
    PFN_BCRYPTENCRYPT EncryptFn;
    PFN_BCRYPTDECRYPT DecryptFn;
    BOOL Ready;
} FUNSTUFF_BCRYPT_RUNTIME, *PFUNSTUFF_BCRYPT_RUNTIME;

typedef struct _FUNSTUFF_BCRYPT_HASH_CONTEXT
{
    BCRYPT_ALG_HANDLE Algorithm;
    BCRYPT_HASH_HANDLE Hash;
    PUCHAR ObjectBuffer;
    ULONG ObjectLength;
    ULONG HashLength;
    BOOL Ready;
} FUNSTUFF_BCRYPT_HASH_CONTEXT, *PFUNSTUFF_BCRYPT_HASH_CONTEXT;

static FUNSTUFF_BCRYPT_RUNTIME g_FunStuffBcryptApi = { 0 };

//
// Small helper for debug/demo output.
//
static VOID
FunStuff_Bcrypt_PrintHex(
    _In_reads_bytes_( BufferSize ) CONST BYTE* Buffer,
    _In_ ULONG BufferSize
    )
{
    ULONG Index = 0;

    if ( Buffer == NULL )
    {
        return;
    }

    for ( Index = 0; Index < BufferSize; Index++ )
    {
        printf( "%02X", Buffer[ Index ] );
    }
}

static FARPROC
FunStuff_CustomGetProcAddressInternal(
    _In_ HMODULE Module,
    _In_ LPCSTR ProcedureName,
    _In_ ULONG Depth
    );

_Must_inspect_result_
static FARPROC
FunStuff_CustomGetProcAddress(
    _In_ HMODULE Module,
    _In_ LPCSTR ProcedureName
    )
{
    return FunStuff_CustomGetProcAddressInternal( Module, ProcedureName, 0 );
}

_Must_inspect_result_
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

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_EnsureLoaded(
    VOID
    )
{
    FUNSTUFF_BCRYPT_RUNTIME Api = { 0 };

    if ( g_FunStuffBcryptApi.Ready == TRUE )
    {
        return TRUE;
    }

    //
    // BCrypt is loaded lazily so the rest of the wrapper can resolve the API
    // If ur bored , u can also manually map it :)
    //
    Api.Module = LoadLibraryW( L"bcrypt.dll" );
    if ( Api.Module == NULL )
    {
        printf( "[-] LoadLibW ( bcrypt.dll ) failed (%lu)\n", GetLastError( ) );
        return FALSE;
    }
    printf( "[+] Loaded Bcrypt.dll >:D ! \n"); 
    Api.OpenAlgorithmProviderFn = ( PFN_BCRYPTOPENALGORITHMPROVIDER )FunStuff_CustomGetProcAddress( Api.Module, "BCryptOpenAlgorithmProvider" );
    Api.CloseAlgorithmProviderFn = ( PFN_BCRYPTCLOSEALGORITHMPROVIDER )FunStuff_CustomGetProcAddress( Api.Module, "BCryptCloseAlgorithmProvider" );
    Api.GetPropertyFn = ( PFN_BCRYPTGETPROPERTY )FunStuff_CustomGetProcAddress( Api.Module, "BCryptGetProperty" );
    Api.SetPropertyFn = ( PFN_BCRYPTSETPROPERTY )FunStuff_CustomGetProcAddress( Api.Module, "BCryptSetProperty" );
    Api.CreateHashFn = ( PFN_BCRYPTCREATEHASH )FunStuff_CustomGetProcAddress( Api.Module, "BCryptCreateHash" );
    Api.HashDataFn = ( PFN_BCRYPTHASHDATA )FunStuff_CustomGetProcAddress( Api.Module, "BCryptHashData" );
    Api.FinishHashFn = ( PFN_BCRYPTFINISHHASH )FunStuff_CustomGetProcAddress( Api.Module, "BCryptFinishHash" );
    Api.DestroyHashFn = ( PFN_BCRYPTDESTROYHASH )FunStuff_CustomGetProcAddress( Api.Module, "BCryptDestroyHash" );
    Api.GenRandomFn = ( PFN_BCRYPTGENRANDOM )FunStuff_CustomGetProcAddress( Api.Module, "BCryptGenRandom" );
    Api.GetFipsAlgorithmModeFn = ( PFN_BCRYPTGETFIPSALGORITHMMODE )FunStuff_CustomGetProcAddress( Api.Module, "BCryptGetFipsAlgorithmMode" );
    Api.GenerateSymmetricKeyFn = ( PFN_BCRYPTGENERATESYMMETRICKEY )FunStuff_CustomGetProcAddress( Api.Module, "BCryptGenerateSymmetricKey" );
    Api.DestroyKeyFn = ( PFN_BCRYPTDESTROYKEY )FunStuff_CustomGetProcAddress( Api.Module, "BCryptDestroyKey" );
    Api.EncryptFn = ( PFN_BCRYPTENCRYPT )FunStuff_CustomGetProcAddress( Api.Module, "BCryptEncrypt" );
    Api.DecryptFn = ( PFN_BCRYPTDECRYPT )FunStuff_CustomGetProcAddress( Api.Module, "BCryptDecrypt" );

    if ( Api.OpenAlgorithmProviderFn == NULL ||
        Api.CloseAlgorithmProviderFn == NULL ||
        Api.GetPropertyFn == NULL ||
        Api.SetPropertyFn == NULL ||
        Api.CreateHashFn == NULL ||
        Api.HashDataFn == NULL ||
        Api.FinishHashFn == NULL ||
        Api.DestroyHashFn == NULL ||
        Api.GenRandomFn == NULL ||
        Api.GenerateSymmetricKeyFn == NULL ||
        Api.DestroyKeyFn == NULL ||
        Api.EncryptFn == NULL ||
        Api.DecryptFn == NULL )
    {
        //
        // If this fails which SHOULDN'T something is wrong ! 
        //
        printf( "[-] FunStuff_CustomGetProcAddress( bcrypt.dll ) failed\n" );
        FreeLibrary( Api.Module );
        return FALSE;
    }

    Api.Ready = TRUE;
    g_FunStuffBcryptApi = Api;
    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_GetFipsMode(
    _Out_ BOOLEAN* Enabled
    )
{
    BOOLEAN FipsEnabled = FALSE;
    NTSTATUS Status = 0;

    if ( Enabled == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_GetFipsMode: Enabled is NULL\n" );
        return FALSE;
    }

    if ( FunStuff_Bcrypt_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    if ( g_FunStuffBcryptApi.GetFipsAlgorithmModeFn == NULL )
    {
        printf( "[!] BCryptGetFipsAlgorithmMode is unavailable\n" );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GetFipsAlgorithmModeFn( &FipsEnabled );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGetFipsAlgorithmMode -> 0x%08lX\n", Status );
        return FALSE;
    }

    *Enabled = FipsEnabled;
    return TRUE;
}

static VOID
FunStuff_Bcrypt_ShutdownHash(
    _Inout_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context
    )
{
    if ( Context == NULL )
    {
        return;
    }

    if ( Context->Hash != NULL && g_FunStuffBcryptApi.DestroyHashFn != NULL )
    {
        g_FunStuffBcryptApi.DestroyHashFn( Context->Hash );
        Context->Hash = NULL;
    }

    if ( Context->ObjectBuffer != NULL )
    {
        RtlSecureZeroMemory( Context->ObjectBuffer, Context->ObjectLength );
        HeapFree( GetProcessHeap( ), 0, Context->ObjectBuffer );
        Context->ObjectBuffer = NULL;
    }

    if ( Context->Algorithm != NULL && g_FunStuffBcryptApi.CloseAlgorithmProviderFn != NULL )
    {
        g_FunStuffBcryptApi.CloseAlgorithmProviderFn( Context->Algorithm, 0 );
        Context->Algorithm = NULL;
    }

    Context->ObjectLength = 0;
    Context->HashLength = 0;
    Context->Ready = FALSE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_InitializeHashEx(
    _Out_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context,
    _In_z_ LPCWSTR AlgorithmId,
    _In_reads_bytes_opt_( SecretSize ) CONST BYTE* Secret,
    _In_ ULONG SecretSize,
    _In_ ULONG Flags
    )
{
    NTSTATUS Status = 0;
    ULONG BytesNeeded = 0;

    if ( Context == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_InitializeHashEx: Context is NULL\n" );
        return FALSE;
    }

    if ( AlgorithmId == NULL || AlgorithmId[ 0 ] == L'\0' )
    {
        printf( "[-] FunStuff_Bcrypt_InitializeHashEx: AlgorithmId is NULL\n" );
        return FALSE;
    }

    if ( Secret == NULL && SecretSize != 0 )
    {
        printf( "[-] FunStuff_Bcrypt_InitializeHashEx: Secret is NULL\n" );
        return FALSE;
    }

    if ( FunStuff_Bcrypt_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    RtlZeroMemory( Context, sizeof( FUNSTUFF_BCRYPT_HASH_CONTEXT ) );

    //
    // The hash context owns both the algorithm provider and the hash object so
    // callers get a single cleanup path.
    //
    Status = g_FunStuffBcryptApi.OpenAlgorithmProviderFn(
        &Context->Algorithm,
        AlgorithmId,
        NULL,
        Flags
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptOpenAlgorithmProvider -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_ShutdownHash( Context );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GetPropertyFn(
        Context->Algorithm,
        BCRYPT_OBJECT_LENGTH,
        ( PUCHAR )&Context->ObjectLength,
        sizeof( Context->ObjectLength ),
        &BytesNeeded,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGetProperty( OBJECT_LENGTH ) -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_ShutdownHash( Context );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GetPropertyFn(
        Context->Algorithm,
        BCRYPT_HASH_LENGTH,
        ( PUCHAR )&Context->HashLength,
        sizeof( Context->HashLength ),
        &BytesNeeded,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGetProperty( HASH_LENGTH ) -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_ShutdownHash( Context );
        return FALSE;
    }

    Context->ObjectBuffer = ( PUCHAR )HeapAlloc(
        GetProcessHeap( ),
        HEAP_ZERO_MEMORY,
        Context->ObjectLength
        );
    if ( Context->ObjectBuffer == NULL )
    {
        printf( "[-] HeapAlloc( ObjectBuffer ) failed (%lu)\n", GetLastError( ) );
        FunStuff_Bcrypt_ShutdownHash( Context );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.CreateHashFn(
        Context->Algorithm,
        &Context->Hash,
        Context->ObjectBuffer,
        Context->ObjectLength,
        ( PUCHAR )Secret,
        SecretSize,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptCreateHash -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_ShutdownHash( Context );
        return FALSE;
    }

    Context->Ready = TRUE;
    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_InitializeHash(
    _Out_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context,
    _In_z_ LPCWSTR AlgorithmId
    )
{
    return FunStuff_Bcrypt_InitializeHashEx( Context, AlgorithmId, NULL, 0, 0 );
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_InitializeHmac(
    _Out_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context,
    _In_z_ LPCWSTR AlgorithmId,
    _In_reads_bytes_( SecretSize ) CONST BYTE* Secret,
    _In_ ULONG SecretSize
    )
{
    return FunStuff_Bcrypt_InitializeHashEx(
        Context,
        AlgorithmId,
        Secret,
        SecretSize,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
        );
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_UpdateHash(
    _Inout_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context,
    _In_reads_bytes_( DataSize ) CONST BYTE* Data,
    _In_ ULONG DataSize
    )
{
    NTSTATUS Status = 0;

    if ( Context == NULL || Context->Ready == FALSE || Context->Hash == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_UpdateHash: Context is not ready\n" );
        return FALSE;
    }

    if ( Data == NULL && DataSize != 0 )
    {
        printf( "[-] FunStuff_Bcrypt_UpdateHash: Data is NULL\n" );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.HashDataFn(
        Context->Hash,
        ( PUCHAR )Data,
        DataSize,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptHashData -> 0x%08lX\n", Status );
        return FALSE;
    }

    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_FinishHash(
    _Inout_ PFUNSTUFF_BCRYPT_HASH_CONTEXT Context,
    _Out_writes_bytes_( OutputSize ) BYTE* Output,
    _In_ ULONG OutputSize,
    _Out_opt_ ULONG* BytesWritten
    )
{
    NTSTATUS Status = 0;

    if ( BytesWritten != NULL )
    {
        *BytesWritten = 0;
    }

    if ( Context == NULL || Context->Ready == FALSE || Context->Hash == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_FinishHash: Context is not ready\n" );
        return FALSE;
    }

    if ( Output == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_FinishHash: Output is NULL\n" );
        return FALSE;
    }

    if ( OutputSize < Context->HashLength )
    {
        printf(
            "[-] FunStuff_Bcrypt_FinishHash: Output buffer too small (%lu < %lu)\n",
            OutputSize,
            Context->HashLength
            );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.FinishHashFn(
        Context->Hash,
        Output,
        Context->HashLength,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptFinishHash -> 0x%08lX\n", Status );
        return FALSE;
    }

    if ( BytesWritten != NULL )
    {
        *BytesWritten = Context->HashLength;
    }

    Context->Ready = FALSE;
    g_FunStuffBcryptApi.DestroyHashFn( Context->Hash );
    Context->Hash = NULL;
    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_HashBuffer(
    _In_z_ LPCWSTR AlgorithmId,
    _In_reads_bytes_( DataSize ) CONST BYTE* Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_( OutputSize ) BYTE* Output,
    _In_ ULONG OutputSize,
    _Out_opt_ ULONG* BytesWritten
    )
{
    FUNSTUFF_BCRYPT_HASH_CONTEXT Context;
    BOOL Ok = FALSE;

    RtlZeroMemory( &Context, sizeof( Context ) );

    Ok = FunStuff_Bcrypt_InitializeHash( &Context, AlgorithmId );
    if ( Ok == FALSE )
    {
        return FALSE;
    }

    Ok = FunStuff_Bcrypt_UpdateHash( &Context, Data, DataSize );
    if ( Ok == FALSE )
    {
        FunStuff_Bcrypt_ShutdownHash( &Context );
        return FALSE;
    }

    Ok = FunStuff_Bcrypt_FinishHash( &Context, Output, OutputSize, BytesWritten );
    FunStuff_Bcrypt_ShutdownHash( &Context );
    return Ok;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_HmacBuffer(
    _In_z_ LPCWSTR AlgorithmId,
    _In_reads_bytes_( SecretSize ) CONST BYTE* Secret,
    _In_ ULONG SecretSize,
    _In_reads_bytes_( DataSize ) CONST BYTE* Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_( OutputSize ) BYTE* Output,
    _In_ ULONG OutputSize,
    _Out_opt_ ULONG* BytesWritten
    )
{
    FUNSTUFF_BCRYPT_HASH_CONTEXT Context;
    BOOL Ok = FALSE;

    RtlZeroMemory( &Context, sizeof( Context ) );

    Ok = FunStuff_Bcrypt_InitializeHmac( &Context, AlgorithmId, Secret, SecretSize );
    if ( Ok == FALSE )
    {
        return FALSE;
    }

    Ok = FunStuff_Bcrypt_UpdateHash( &Context, Data, DataSize );
    if ( Ok == FALSE )
    {
        FunStuff_Bcrypt_ShutdownHash( &Context );
        return FALSE;
    }

    Ok = FunStuff_Bcrypt_FinishHash( &Context, Output, OutputSize, BytesWritten );
    FunStuff_Bcrypt_ShutdownHash( &Context );
    return Ok;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_GenRandom(
    _Out_writes_bytes_( BufferSize ) BYTE* Buffer,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS Status = 0;

    if ( Buffer == NULL )
    {
        printf( "[-] FunStuff_Bcrypt_GenRandom: Buffer is NULL\n" );
        return FALSE;
    }

    if ( BufferSize == 0 )
    {
        printf( "[-] FunStuff_Bcrypt_GenRandom: BufferSize is 0\n" );
        return FALSE;
    }

    if ( FunStuff_Bcrypt_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GenRandomFn(
        NULL,
        Buffer,
        BufferSize,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGenRandom -> 0x%08lX\n", Status );
        return FALSE;
    }

    return TRUE;
}

static VOID
FunStuff_Bcrypt_CleanupAes(
    _In_opt_ BCRYPT_ALG_HANDLE Algorithm,
    _In_opt_ BCRYPT_KEY_HANDLE Key,
    _Inout_updates_bytes_opt_( ObjectLength ) PUCHAR ObjectBuffer,
    _In_ ULONG ObjectLength
    )
{
    if ( Key != NULL && g_FunStuffBcryptApi.DestroyKeyFn != NULL )
    {
        g_FunStuffBcryptApi.DestroyKeyFn( Key );
    }

    if ( ObjectBuffer != NULL )
    {
        RtlSecureZeroMemory( ObjectBuffer, ObjectLength );
        HeapFree( GetProcessHeap( ), 0, ObjectBuffer );
    }

    if ( Algorithm != NULL && g_FunStuffBcryptApi.CloseAlgorithmProviderFn != NULL )
    {
        g_FunStuffBcryptApi.CloseAlgorithmProviderFn( Algorithm, 0 );
    }
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_ValidateGcmTagLength(
    _In_ BCRYPT_ALG_HANDLE Algorithm,
    _In_ ULONG TagSize
    )
{
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT TagLengths;
    ULONG BytesNeeded = 0;
    NTSTATUS Status = 0;

    RtlZeroMemory( &TagLengths, sizeof( TagLengths ) );

    Status = g_FunStuffBcryptApi.GetPropertyFn(
        Algorithm,
        BCRYPT_AUTH_TAG_LENGTH,
        ( PUCHAR )&TagLengths,
        sizeof( TagLengths ),
        &BytesNeeded,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGetProperty( AUTH_TAG_LENGTH ) -> 0x%08lX\n", Status );
        return FALSE;
    }

    if ( TagSize < TagLengths.dwMinLength || TagSize > TagLengths.dwMaxLength )
    {
        printf( "[-] AES-GCM tag size is unsupported (%lu)\n", TagSize );
        return FALSE;
    }

    if ( TagLengths.dwIncrement != 0 &&
        ( ( TagSize - TagLengths.dwMinLength ) % TagLengths.dwIncrement ) != 0 )
    {
        printf( "[-] AES-GCM tag size increment is invalid (%lu)\n", TagSize );
        return FALSE;
    }

    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_AesGcmCrypt256(
    _In_ BOOL Encrypt,
    _In_reads_bytes_( 32 ) CONST BYTE* KeyBytes,
    _In_ ULONG KeySize,
    _In_reads_bytes_( NonceSize ) CONST BYTE* Nonce,
    _In_ ULONG NonceSize,
    _In_reads_bytes_opt_( AadSize ) CONST BYTE* Aad,
    _In_ ULONG AadSize,
    _In_reads_bytes_( InputSize ) CONST BYTE* Input,
    _In_ ULONG InputSize,
    _Out_writes_bytes_( OutputSize ) BYTE* Output,
    _In_ ULONG OutputSize,
    _Inout_updates_bytes_( TagSize ) BYTE* Tag,
    _In_ ULONG TagSize
    )
{
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_KEY_HANDLE Key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    PUCHAR ObjectBuffer = NULL;
    ULONG ObjectLength = 0;
    ULONG BytesNeeded = 0;
    ULONG ResultSize = 0;
    NTSTATUS Status = 0;
    BOOL Ok = FALSE;

    if ( KeyBytes == NULL || KeySize != 32 )
    {
        printf( "[-] AES-GCM-256 requires a 32-byte key!!\n" );
        return FALSE;
    }

    if ( Nonce == NULL || NonceSize == 0 )
    {
        printf( "[-] AES-GCM-256 requires a nonce!!!\n" );
        return FALSE;
    }

    if ( Input == NULL && InputSize != 0 )
    {
        printf( "[-] AES-GCM-256 input is NULL D;\n" );
        return FALSE;
    }

    if ( Output == NULL && InputSize != 0 )
    {
        printf( "[-] AES-GCM-256 output is NULL  !!\n" );
        return FALSE;
    }

    if ( OutputSize < InputSize )
    {
        printf( "[-] AES-GCM-256 output buffer too small D: \n" );
        return FALSE;
    }

    if ( Tag == NULL || TagSize == 0 )
    {
        printf( "[-] AES-GCM-256 tag buffer is invalid!! \n" );
        return FALSE;
    }

    if ( Aad == NULL && AadSize != 0 )
    {
        printf( "[-] AES-GCM-256 AAD is NULL !!! \n" );
        return FALSE;
    }

    if ( FunStuff_Bcrypt_EnsureLoaded( ) == FALSE )
    {
        return FALSE;
    }

    //
    // AES-GCM needs the chaining mode configured on the algorithm provider
    // before the symmetric key is created.
    //
    Status = g_FunStuffBcryptApi.OpenAlgorithmProviderFn(
        &Algorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptOpenAlgorithmProvider( AES ) -> 0x%08lX\n", Status );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.SetPropertyFn(
        Algorithm,
        BCRYPT_CHAINING_MODE,
        ( PUCHAR )BCRYPT_CHAIN_MODE_GCM,
        ( ULONG )( ( lstrlenW( BCRYPT_CHAIN_MODE_GCM ) + 1 ) * sizeof( WCHAR ) ),
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptSetProperty( GCM ) -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    Ok = FunStuff_Bcrypt_ValidateGcmTagLength( Algorithm, TagSize );
    if ( Ok == FALSE )
    {
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GetPropertyFn(
        Algorithm,
        BCRYPT_OBJECT_LENGTH,
        ( PUCHAR )&ObjectLength,
        sizeof( ObjectLength ),
        &BytesNeeded,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGetProperty( AES OBJECT_LENGTH ) -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    ObjectBuffer = ( PUCHAR )HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, ObjectLength );
    if ( ObjectBuffer == NULL )
    {
        printf( "[-] HeapAlloc( AES ObjectBuffer ) failed (%lu)\n", GetLastError( ) );
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    Status = g_FunStuffBcryptApi.GenerateSymmetricKeyFn(
        Algorithm,
        &Key,
        ObjectBuffer,
        ObjectLength,
        ( PUCHAR )KeyBytes,
        KeySize,
        0
        );
    if ( NT_SUCCESS( Status ) == FALSE )
    {
        printf( "[-] BCryptGenerateSymmetricKey -> 0x%08lX\n", Status );
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    //
    // AuthInfo carries the nonce, AAD, and atuh tag for both the
    // encrypt and decrypt paths.
    //
    BCRYPT_INIT_AUTH_MODE_INFO( AuthInfo );
    AuthInfo.pbNonce = ( PUCHAR )Nonce;
    AuthInfo.cbNonce = NonceSize;
    AuthInfo.pbAuthData = ( PUCHAR )Aad;
    AuthInfo.cbAuthData = AadSize;
    AuthInfo.pbTag = Tag;
    AuthInfo.cbTag = TagSize;

    if ( Encrypt == TRUE )
    {
        Status = g_FunStuffBcryptApi.EncryptFn(
            Key,
            ( PUCHAR )Input,
            InputSize,
            &AuthInfo,
            NULL,
            0,
            Output,
            OutputSize,
            &ResultSize,
            0
            );
        if ( NT_SUCCESS( Status ) == FALSE )
        {
            printf( "[-] BCryptEncrypt( AES-GCM ) -> 0x%08lX\n", Status );
            FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
            return FALSE;
        }
    }
    else
    {
        Status = g_FunStuffBcryptApi.DecryptFn(
            Key,
            ( PUCHAR )Input,
            InputSize,
            &AuthInfo,
            NULL,
            0,
            Output,
            OutputSize,
            &ResultSize,
            0
            );
        if ( NT_SUCCESS( Status ) == FALSE )
        {
            printf( "[-] BCryptDecrypt( AES-GCM ) -> 0x%08lX\n", Status );
            FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
            return FALSE;
        }
    }

    if ( ResultSize != InputSize )
    {
        printf( "[-] AES-GCM result length mismatch (%lu != %lu)\n", ResultSize, InputSize );
        FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
        return FALSE;
    }

    FunStuff_Bcrypt_CleanupAes( Algorithm, Key, ObjectBuffer, ObjectLength );
    return TRUE;
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_AesGcmEncrypt256(
    _In_reads_bytes_( 32 ) CONST BYTE* KeyBytes,
    _In_ ULONG KeySize,
    _In_reads_bytes_( NonceSize ) CONST BYTE* Nonce,
    _In_ ULONG NonceSize,
    _In_reads_bytes_opt_( AadSize ) CONST BYTE* Aad,
    _In_ ULONG AadSize,
    _In_reads_bytes_( PlaintextSize ) CONST BYTE* Plaintext,
    _In_ ULONG PlaintextSize,
    _Out_writes_bytes_( CiphertextSize ) BYTE* Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_( TagSize ) BYTE* Tag,
    _In_ ULONG TagSize
    )
{
    return FunStuff_Bcrypt_AesGcmCrypt256(
        TRUE,
        KeyBytes,
        KeySize,
        Nonce,
        NonceSize,
        Aad,
        AadSize,
        Plaintext,
        PlaintextSize,
        Ciphertext,
        CiphertextSize,
        Tag,
        TagSize
        );
}

_Must_inspect_result_
static BOOL
FunStuff_Bcrypt_AesGcmDecrypt256(
    _In_reads_bytes_( 32 ) CONST BYTE* KeyBytes,
    _In_ ULONG KeySize,
    _In_reads_bytes_( NonceSize ) CONST BYTE* Nonce,
    _In_ ULONG NonceSize,
    _In_reads_bytes_opt_( AadSize ) CONST BYTE* Aad,
    _In_ ULONG AadSize,
    _In_reads_bytes_( CiphertextSize ) CONST BYTE* Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_( PlaintextSize ) BYTE* Plaintext,
    _In_ ULONG PlaintextSize,
    _Inout_updates_bytes_( TagSize ) BYTE* Tag,
    _In_ ULONG TagSize
    )
{
    return FunStuff_Bcrypt_AesGcmCrypt256(
        FALSE,
        KeyBytes,
        KeySize,
        Nonce,
        NonceSize,
        Aad,
        AadSize,
        Ciphertext,
        CiphertextSize,
        Plaintext,
        PlaintextSize,
        Tag,
        TagSize
        );
}

_Must_inspect_result_
static INT
FunStuff_Bcrypt_RunDemo(
    VOID
    )
{
    CONST BYTE DemoText[] = "FunStuff BCrypt demo"; // U CAN AND SHOULD REPALCE WITH URS :)
    CONST BYTE HmacKey[] = "FunStuff HMAC key";
    CONST BYTE Aad[] = "FunStuff AAD";
    CONST BYTE Plaintext[] = "AES-GCM-256 sample";
    BYTE Digest[ 64 ] = { 0 };
    BYTE Hmac[ 64 ] = { 0 };
    BYTE RandomBytes[ 16 ] = { 0 };
    BYTE AesKey[ 32 ] = { 0 };
    BYTE Nonce[ 12 ] = { 0 };
    BYTE Ciphertext[ sizeof( Plaintext ) - 1 ] = { 0 };
    BYTE Decrypted[ sizeof( Plaintext ) ] = { 0 };
    BYTE Tag[ 16 ] = { 0 };
    ULONG DigestLength = 0;
    ULONG HmacLength = 0;
    BOOLEAN FipsEnabled = FALSE;
    BOOL Ok = FALSE;

    //
    // The demo tests the main surfaces: hashing, HMAC, AES-GCM, and RNG.
    //
    Ok = FunStuff_Bcrypt_HashBuffer(
        BCRYPT_SHA256_ALGORITHM,
        DemoText,
        ( ULONG )( sizeof( DemoText ) - 1 ),
        Digest,
        sizeof( Digest ),
        &DigestLength
        );
    if ( Ok == FALSE )
    {
        return 1;
    }

    printf( "[+] SHA256: " );
    FunStuff_Bcrypt_PrintHex( Digest, DigestLength );
    printf( "\n" );

    Ok = FunStuff_Bcrypt_HmacBuffer(
        BCRYPT_SHA256_ALGORITHM,
        HmacKey,
        ( ULONG )( sizeof( HmacKey ) - 1 ),
        DemoText,
        ( ULONG )( sizeof( DemoText ) - 1 ),
        Hmac,
        sizeof( Hmac ),
        &HmacLength
        );
    if ( Ok == FALSE )
    {
        return 1;
    }

    printf( "[+] HMAC-SHA256: " );
    FunStuff_Bcrypt_PrintHex( Hmac, HmacLength );
    printf( "\n" );

    if ( FunStuff_Bcrypt_GetFipsMode( &FipsEnabled ) == TRUE )
    {
        //
        // What iS FIPS ?  - >  Federal Information Processing Standards
        //
        printf( "[+] FIPS mode: %s\n", ( FipsEnabled != FALSE ) ? "enabled :D" : "disabled D:" );
    }

    Ok = FunStuff_Bcrypt_GenRandom( AesKey, sizeof( AesKey ) );
    if ( Ok == FALSE )
    {
        return 1;
    }

    Ok = FunStuff_Bcrypt_GenRandom( Nonce, sizeof( Nonce ) );
    if ( Ok == FALSE )
    {
        return 1;
    }

    Ok = FunStuff_Bcrypt_AesGcmEncrypt256(
        AesKey,
        sizeof( AesKey ),
        Nonce,
        sizeof( Nonce ),
        Aad,
        ( ULONG )( sizeof( Aad ) - 1 ),
        Plaintext,
        ( ULONG )( sizeof( Plaintext ) - 1 ),
        Ciphertext,
        sizeof( Ciphertext ),
        Tag,
        sizeof( Tag )
        );
    if ( Ok == FALSE )
    {
        return 1;
    }

    printf( "[+] AES-GCM Ciphertext: " );
    FunStuff_Bcrypt_PrintHex( Ciphertext, sizeof( Ciphertext ) );
    printf( "\n" );

    printf( "[+] AES-GCM Tag: " );
    FunStuff_Bcrypt_PrintHex( Tag, sizeof( Tag ) );
    printf( "\n" );

    Ok = FunStuff_Bcrypt_AesGcmDecrypt256(
        AesKey,
        sizeof( AesKey ),
        Nonce,
        sizeof( Nonce ),
        Aad,
        ( ULONG )( sizeof( Aad ) - 1 ),
        Ciphertext,
        sizeof( Ciphertext ),
        Decrypted,
        sizeof( Plaintext ) - 1,
        Tag,
        sizeof( Tag )
        );
    if ( Ok == FALSE )
    {
        return 1;
    }

    Decrypted[ sizeof( Plaintext ) - 1 ] = '\0';
    printf( "[+] AES-GCM Plaintext: %s\n", Decrypted );

    if ( memcmp( Decrypted, Plaintext, sizeof( Plaintext ) - 1 ) != 0 )
    {
        printf( "[-] AES-GCM verification mismatch\n" );
        return 1;
    }

    Ok = FunStuff_Bcrypt_GenRandom( RandomBytes, sizeof( RandomBytes ) );
    if ( Ok == FALSE )
    {
        return 1;
    }

    printf( "[+] RAND : " );
    FunStuff_Bcrypt_PrintHex( RandomBytes, sizeof( RandomBytes ) );
    printf( "\n" );

    return 0;
}

INT
main(
    VOID
    )
{
    return FunStuff_Bcrypt_RunDemo( );
}
