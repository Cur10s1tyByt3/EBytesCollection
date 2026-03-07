#include <Windows.h>
#include <Psapi.h>

#pragma comment( lib , "Psapi.lib" )


template <typename T>
T* RvaToPointer( _In_ void* ModuleBase , _In_ DWORD Rva ) {
    return (T*)( (BYTE*)ModuleBase + Rva );
}


DWORD PointerToRva( _In_ void* Pointer , _In_ void* ModuleBase ) {
    return (DWORD)( (ULONG_PTR)Pointer - (ULONG_PTR)ModuleBase );
}


IMAGE_EXPORT_DIRECTORY* GetExportDirectory( _In_ HMODULE Module ) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)( (BYTE*)Module + DosHeader->e_lfanew );
    
    DWORD ExportRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if ( !ExportRva )
        return nullptr;
    
    return RvaToPointer<IMAGE_EXPORT_DIRECTORY>( Module , ExportRva );
}


DWORD* GetEATEntry( _In_ HMODULE Module , _In_ const char* FunctionName ) {
    IMAGE_EXPORT_DIRECTORY* ExportDir = GetExportDirectory( Module );
    if ( !ExportDir )
        return nullptr;
    
    DWORD* Functions = RvaToPointer<DWORD>( Module , ExportDir->AddressOfFunctions );
    DWORD* Names = RvaToPointer<DWORD>( Module , ExportDir->AddressOfNames );
    WORD* Ordinals = RvaToPointer<WORD>( Module , ExportDir->AddressOfNameOrdinals );
    
    for ( DWORD i = 0; i < ExportDir->NumberOfNames; i++ ) {
        char* Name = RvaToPointer<char>( Module , Names[i] );
        if ( lstrcmpA( Name , FunctionName ) == 0 ) {
            return &Functions[Ordinals[i]];
        }
    }
    
    return nullptr;
}


void* AllocateNearModule( _In_ HMODULE Module , _In_ SIZE_T Size ) {
    MODULEINFO ModInfo{};
    GetModuleInformation( GetCurrentProcess() , Module , &ModInfo , sizeof( ModInfo ) );
    
    BYTE* StartAddr = (BYTE*)ModInfo.lpBaseOfDll + ModInfo.SizeOfImage;
    BYTE* MaxAddr = StartAddr + 0x7FFF0000;
    
    for ( BYTE* Addr = StartAddr; Addr < MaxAddr; Addr += 0x10000 ) {
        void* Allocated = VirtualAlloc( Addr , Size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
        if ( Allocated )
            return Allocated;
    }
    
    return VirtualAlloc( nullptr , Size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
}


SIZE_T WriteJump( _In_ void* Destination , _In_ void* Target ) {
    BYTE* Code = (BYTE*)Destination;
    
#ifdef _WIN64
    Code[0] = 0x48;
    Code[1] = 0xB8;
    *(ULONG_PTR*)( Code + 2 ) = (ULONG_PTR)Target;
    Code[10] = 0xFF;
    Code[11] = 0xE0;
    return 12;
#else
    Code[0] = 0xE9;
    *(DWORD*)( Code + 1 ) = (DWORD)( (ULONG_PTR)Target - (ULONG_PTR)Destination - 5 );
    return 5;
#endif
}


BOOL InstallEATHook( _In_ const char* ModuleName , _In_ const char* FunctionName , 
    _In_ void* HookFunction , _Out_ void** OriginalFunction ) {
    HMODULE Module = GetModuleHandleA( ModuleName );
    if ( !Module )
        return FALSE;
    
    DWORD* EatEntry = GetEATEntry( Module , FunctionName );
    if ( !EatEntry )
        return FALSE;
    
    *OriginalFunction = RvaToPointer<void>( Module , *EatEntry );
    
#ifdef _WIN64
    SIZE_T JumpSize = 12;
#else
    SIZE_T JumpSize = 5;
#endif
    
    void* JumpStub = AllocateNearModule( Module , JumpSize );
    if ( !JumpStub )
        return FALSE;
    
    SIZE_T Written = WriteJump( JumpStub , HookFunction );
    FlushInstructionCache( GetCurrentProcess() , JumpStub , Written );
    
    DWORD OldProtect;
    VirtualProtect( EatEntry , sizeof( DWORD ) , PAGE_READWRITE , &OldProtect );
    *EatEntry = PointerToRva( JumpStub , Module );
    VirtualProtect( EatEntry , sizeof( DWORD ) , OldProtect , &OldProtect );
    
    return TRUE;
}


typedef int( WINAPI* MessageBoxA_t )( HWND , LPCSTR , LPCSTR , UINT );
MessageBoxA_t g_OriginalMessageBoxA = nullptr;


int WINAPI HookedMessageBoxA( _In_opt_ HWND hWnd , _In_opt_ LPCSTR lpText , 
    _In_opt_ LPCSTR lpCaption , _In_ UINT uType ) {
    return g_OriginalMessageBoxA( hWnd , "Hooked Hello World!" , lpCaption , uType );
}


int main( ) {
    HMODULE User32 = LoadLibraryA( "user32.dll" );
    if ( !User32 )
        return -1;
    
    g_OriginalMessageBoxA = (MessageBoxA_t)GetProcAddress( User32 , "MessageBoxA" );
    if ( !g_OriginalMessageBoxA )
        return -1;
    
    void* Unused = nullptr;
    if ( !InstallEATHook( "user32.dll" , "MessageBoxA" , HookedMessageBoxA , &Unused ) )
        return -1;
    
    MessageBoxA_t MessageBoxFunc = (MessageBoxA_t)GetProcAddress( User32 , "MessageBoxA" );
    if ( !MessageBoxFunc )
        return -1;
    
    MessageBoxFunc( nullptr , "Hello World!" , "Test" , MB_OK );
    
    return 0;
}
