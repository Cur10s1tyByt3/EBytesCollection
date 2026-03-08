#include <Windows.h>
#include <cstdio>

//
// ============================================================
//  NopAllInt3s — patches all 0xCC (INT3) bytes in the .text
//  section of a PE file to 0x90 (NOP) and writes the result
//  to a new output file.
//
//  Usage: NopAllInt3s.exe <input.exe> <output.exe>
// ============================================================
//

DWORD
FetchFileSize(
    _In_ LPCSTR FilePath
    )
{
    CONST HANDLE FileHandle = CreateFileA(
        FilePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if ( FileHandle == INVALID_HANDLE_VALUE )
    {
        return 0;
    }

    CONST DWORD Size = GetFileSize( FileHandle, NULL );
    CloseHandle( FileHandle );
    return Size;
}

PVOID
MapFileIntoMemory(
    _In_  LPCSTR FilePath,
    _Out_ PHANDLE OutFileHandle,
    _Out_ PHANDLE OutMappingHandle
    )
{
    //
    // Open the file for read+write so we can patch in-place in memory.
    //
    CONST HANDLE FileHandle = CreateFileA(
        FilePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if ( FileHandle == INVALID_HANDLE_VALUE )
    {
        printf( "[-] CreateFileA failed: %d\n", GetLastError( ) );
        return NULL;
    }

    CONST HANDLE MappingHandle = CreateFileMappingA(
        FileHandle,
        NULL,
        PAGE_READWRITE,
        0,
        0,
        NULL
    );

    if ( MappingHandle == NULL )
    {
        printf( "[-] CreateFileMappingA failed: %d\n", GetLastError( ) );
        CloseHandle( FileHandle );
        return NULL;
    }

    PVOID ImageBase = MapViewOfFile(
        MappingHandle,
        FILE_MAP_READ | FILE_MAP_WRITE,
        0,
        0,
        0
    );

    if ( ImageBase == NULL )
    {
        printf( "[-] MapViewOfFile failed: %d\n", GetLastError( ) );
        CloseHandle( MappingHandle );
        CloseHandle( FileHandle );
        return NULL;
    }

    *OutFileHandle    = FileHandle;
    *OutMappingHandle = MappingHandle;
    return ImageBase;
}

VOID
NopAllInt3s(
    _In_ LPCSTR InputPath,
    _In_ LPCSTR OutputPath
    )
{
    HANDLE FileHandle    = NULL;
    HANDLE MappingHandle = NULL;

    PVOID ImageBase = MapFileIntoMemory( InputPath, &FileHandle, &MappingHandle );

    if ( ImageBase == NULL )
    {
        return;
    }

    CONST PIMAGE_DOS_HEADER DosHeader =
        ( PIMAGE_DOS_HEADER )ImageBase;

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        printf( "[-] Not a valid PE file\n" );
        UnmapViewOfFile( ImageBase );
        CloseHandle( MappingHandle );
        CloseHandle( FileHandle );
        return;
    }

    CONST PIMAGE_NT_HEADERS NtHeaders =
        ( PIMAGE_NT_HEADERS )( ( PBYTE )ImageBase + DosHeader->e_lfanew );

    if ( NtHeaders->Signature != IMAGE_NT_SIGNATURE )
    {
        printf( "[-] Invalid NT headers\n" );
        UnmapViewOfFile( ImageBase );
        CloseHandle( MappingHandle );
        CloseHandle( FileHandle );
        return;
    }

    //
    // Walk sections to find .text
    //
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( NtHeaders );
    PIMAGE_SECTION_HEADER TextSection = NULL;

    for ( WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        //
        // Section name is 8 bytes, not guaranteed null-terminated.
        //
        if ( RtlCompareMemory( Section[ i ].Name, ".text", 5 ) == 5 )
        {
            TextSection = &Section[ i ];
            break;
        }
    }

    if ( TextSection == NULL )
    {
        printf( "[-] .text section not found\n" );
        UnmapViewOfFile( ImageBase );
        CloseHandle( MappingHandle );
        CloseHandle( FileHandle );
        return;
    }

    //
    // PointerToRawData is the file offset of the section data.
    // Add it to ImageBase to get the mapped address of .text.
    //
    PBYTE SectionData     = ( PBYTE )ImageBase + TextSection->PointerToRawData;
    DWORD SectionDataSize = TextSection->SizeOfRawData;
    DWORD NoppedCount     = 0;

    for ( DWORD i = 0; i < SectionDataSize; i++ )
    {
        if ( SectionData[ i ] == 0xCC )
        {
            SectionData[ i ] = 0x90;
            NoppedCount++;
        }
    }

    printf( "[+] Nopped out %d INT3s\n", NoppedCount );

    //
    // Flush changes and unmap before writing the output file.
    //
    FlushViewOfFile( ImageBase, 0 );
    UnmapViewOfFile( ImageBase );
    CloseHandle( MappingHandle );
    CloseHandle( FileHandle );

    //
    // Read the patched file back and write to output path.
    //
    CONST DWORD FileSize = FetchFileSize( InputPath );

    PBYTE ReadBuffer = ( PBYTE )HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, FileSize );

    CONST HANDLE ReadHandle = CreateFileA(
        InputPath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    DWORD BytesRead = 0;
    ReadFile( ReadHandle, ReadBuffer, FileSize, &BytesRead, NULL );
    CloseHandle( ReadHandle );

    CONST HANDLE OutputHandle = CreateFileA(
        OutputPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if ( OutputHandle == INVALID_HANDLE_VALUE )
    {
        printf( "[-] CreateFileA output failed: %d\n", GetLastError( ) );
        HeapFree( GetProcessHeap( ), 0, ReadBuffer );
        return;
    }

    DWORD BytesWritten = 0;

    if ( WriteFile( OutputHandle, ReadBuffer, FileSize, &BytesWritten, NULL ) == TRUE )
    {
        printf( "[+] Wrote nopped binary to: %s\n", OutputPath );
    }
    else
    {
        printf( "[-] WriteFile failed: %d\n", GetLastError( ) );
    }

    CloseHandle( OutputHandle );
    HeapFree( GetProcessHeap( ), 0, ReadBuffer );
}

INT
main(
    _In_ INT   Argc,
    _In_ CHAR* Argv[]
    )
{
    if ( Argc < 3 )
    {
        printf( "Usage: %s <input.exe> <output.exe>\n", Argv[ 0 ] );
        return 1;
    }

    NopAllInt3s( Argv[ 1 ], Argv[ 2 ] );

    return 0;
}
