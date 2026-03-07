#include<Windows.h>
#include<Psapi.h>
#include<cstdio>

#pragma comment( lib , "Psapi.lib" )


namespace FunStuff {

struct PeImage {
    PVOID ImageBase;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
#ifdef _WIN64
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
    IMAGE_FILE_HEADER FileHeader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
};


PeImage ParsePeImage( LPCSTR ImageName );


class IatHook {
private:
    static PVOID OriginalFunction;
    static PVOID* IatEntry;

public:
    static BOOL Install( LPCSTR Module , LPCSTR Proc , PVOID HookFunc , PVOID* OutOriginal );
    static BOOL Remove( );
};


PVOID IatHook::OriginalFunction = nullptr;
PVOID* IatHook::IatEntry = nullptr;

}


FunStuff::PeImage FunStuff::ParsePeImage( LPCSTR ImageName ) {
    PVOID ImageBase = GetModuleHandleA( ImageName );
    DWORD_PTR PeBase = (DWORD_PTR)ImageBase;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ImageBase;

#ifdef _WIN64
    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)( PeBase + Dos->e_lfanew );
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader = &NtHeaders->OptionalHeader;
#else
    PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)( PeBase + Dos->e_lfanew );
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader = &NtHeaders->OptionalHeader;
#endif

    IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;
    
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)( PeBase + 
        OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

    return PeImage{ ImageBase , Dos , NtHeaders , OptionalHeader , FileHeader , ImportDescriptor };
}


BOOL FunStuff::IatHook::Install( LPCSTR Module , LPCSTR Proc , PVOID HookFunc , PVOID* OutOriginal ) {
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
                    OriginalFunction = (PVOID)Thunk->u1.Function;
                    *OutOriginal = OriginalFunction;
                    IatEntry = (PVOID*)&Thunk->u1.Function;
                    
                    printf( "[+] IAT Original Address: %p\n" , OriginalFunction );
                    printf( "[+] IAT Entry Location: %p\n" , IatEntry );

                    DWORD OldProtect;
                    VirtualProtect( IatEntry , sizeof( PVOID ) , PAGE_READWRITE , &OldProtect );
                    *IatEntry = HookFunc;
                    VirtualProtect( IatEntry , sizeof( PVOID ) , OldProtect , &OldProtect );

                    return TRUE;
                }
                
                OrigThunk++;
                Thunk++;
            }
        }
        
        ImportDescriptor++;
    }

    return FALSE;
}


BOOL FunStuff::IatHook::Remove( ) {
    if ( !IatEntry || !OriginalFunction )
        return FALSE;

    DWORD OldProtect;
    VirtualProtect( IatEntry , sizeof( PVOID ) , PAGE_READWRITE , &OldProtect );
    *IatEntry = OriginalFunction;
    VirtualProtect( IatEntry , sizeof( PVOID ) , OldProtect , &OldProtect );

    return TRUE;
}


typedef int( WINAPI* MessageBoxA_t )( HWND , LPCSTR , LPCSTR , UINT );
MessageBoxA_t g_OriginalMessageBoxA = nullptr;


int WINAPI HookedMessageBoxA( _In_opt_ HWND hWnd , _In_opt_ LPCSTR lpText , _In_opt_ LPCSTR lpCaption , _In_ UINT uType ) {
    printf( "[*] MessageBoxA hooked!\n" );
    return g_OriginalMessageBoxA( hWnd , "Hooked via IAT!" , lpCaption , uType );
}


int main( ) {
    printf( "[*] Loading user32.dll...\n" );
    HMODULE User32 = LoadLibraryA( "user32.dll" );
    if ( !User32 ) {
        printf( "[-] Failed to load user32.dll\n" );
        return -1;
    }

    printf( "[*] Installing MessageBoxA IAT hook...\n" );
    if ( !FunStuff::IatHook::Install( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , (PVOID*)&g_OriginalMessageBoxA ) ) {
        printf( "[-] Failed to hook MessageBoxA\n" );
        return -1;
    }

    printf( "[+] MessageBoxA hooked!\n\n" );
    printf( "[*] Testing MessageBoxA...\n" );
    MessageBoxA( nullptr , "Hello World!" , "Test" , MB_OK );

    printf( "\n[*] Press any key to unhook...\n" );
    getchar( );

    if ( FunStuff::IatHook::Remove( ) )
        printf( "[+] IAT hook removed!\n" );

    return 0;
}
