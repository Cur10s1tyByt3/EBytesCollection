#include <Windows.h>
#include <cstdio>


namespace FunStuff {

size_t GetInstructionLength( void* Address ) {
    unsigned char* Bytes = (unsigned char*)Address;
    
    unsigned char Byte = Bytes[0];
    
    if ( Byte == 0x48 || Byte == 0x4C || Byte == 0x49 || Byte == 0x4D ||
         Byte == 0x40 || Byte == 0x41 || Byte == 0x42 || Byte == 0x43 ||
         Byte == 0x44 || Byte == 0x45 || Byte == 0x46 || Byte == 0x47 ) {
        return 1 + GetInstructionLength( Bytes + 1 );
    }
    
    if ( Byte == 0x66 || Byte == 0x67 ) {
        return 1 + GetInstructionLength( Bytes + 1 );
    }
    
    if ( Byte == 0x83 ) {
        unsigned char ModRM = Bytes[1];
        size_t Len = 3;
        
        if ( ( ModRM & 0xC0 ) == 0x40 )
            Len += 1;
        else if ( ( ModRM & 0xC0 ) == 0x80 )
            Len += 4;
        
        return Len;
    }
    
    if ( Byte == 0x33 ) {
        return 2;
    }
    
    if ( Byte == 0x8B || Byte == 0x89 || Byte == 0x8D ) {
        unsigned char ModRM = Bytes[1];
        size_t Len = 2;
        
        if ( ( ModRM & 0xC0 ) == 0x40 )
            Len += 1;
        else if ( ( ModRM & 0xC0 ) == 0x80 )
            Len += 4;
        
        return Len;
    }
    
    if ( Byte == 0xE9 || Byte == 0xE8 ) {
        return 5;
    }
    
    if ( ( Byte & 0xF0 ) == 0x50 ) {
        return 1;
    }
    
    return 3;
}


size_t GetMinimumHookSize( void* Address , size_t MinSize ) {
    size_t TotalSize = 0;
    unsigned char* Current = (unsigned char*)Address;
    
    while ( TotalSize < MinSize ) {
        size_t InstrLen = GetInstructionLength( Current );
        TotalSize += InstrLen;
        Current += InstrLen;
    }
    
    return TotalSize;
}


class InlineHook {
private:
    static void* TargetAddress;
    static void* HookFunction;
    static void* TrampolineFunction;
    static unsigned char OriginalBytes[32];
    static size_t OriginalSize;

public:
    static BOOL Install( void* Target , void* Hook , void** OutTrampoline );
    static BOOL Remove( );
};


void* InlineHook::TargetAddress = nullptr;
void* InlineHook::HookFunction = nullptr;
void* InlineHook::TrampolineFunction = nullptr;
unsigned char InlineHook::OriginalBytes[32] = { 0 };
size_t InlineHook::OriginalSize = 0;


BOOL InlineHook::Install( void* Target , void* Hook , void** OutTrampoline ) {
    if ( !Target || !Hook )
        return FALSE;

    TargetAddress = Target;
    HookFunction = Hook;

#ifdef _WIN64
    size_t MinSize = 12;
#else
    size_t MinSize = 5;
#endif

    OriginalSize = GetMinimumHookSize( TargetAddress , MinSize );
    
    printf( "[+] Target Address: %p\n" , TargetAddress );
    printf( "[+] Hook Function: %p\n" , HookFunction );
    printf( "[+] Stealing %zu bytes\n" , OriginalSize );

    memcpy( OriginalBytes , TargetAddress , OriginalSize );

    size_t TrampolineSize = OriginalSize + 14;
    TrampolineFunction = VirtualAlloc( nullptr , TrampolineSize , MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE );
    if ( !TrampolineFunction ) {
        printf( "[-] VirtualAlloc failed\n" );
        return FALSE;
    }

    unsigned char* Trampoline = (unsigned char*)TrampolineFunction;
    memcpy( Trampoline , OriginalBytes , OriginalSize );

    void* ReturnAddress = (unsigned char*)TargetAddress + OriginalSize;
    
#ifdef _WIN64
    Trampoline[OriginalSize + 0] = 0x48;
    Trampoline[OriginalSize + 1] = 0xB8;
    *(DWORD64*)&Trampoline[OriginalSize + 2] = (DWORD64)ReturnAddress;
    Trampoline[OriginalSize + 10] = 0xFF;
    Trampoline[OriginalSize + 11] = 0xE0;
#else
    Trampoline[OriginalSize + 0] = 0xE9;
    *(DWORD*)&Trampoline[OriginalSize + 1] = (DWORD)( (unsigned char*)ReturnAddress - ( Trampoline + OriginalSize + 5 ) );
#endif

    *OutTrampoline = TrampolineFunction;

    printf( "[+] Trampoline: %p\n" , TrampolineFunction );
    printf( "[+] Return Address: %p\n" , ReturnAddress );

    DWORD OldProtect;
    VirtualProtect( TargetAddress , OriginalSize , PAGE_EXECUTE_READWRITE , &OldProtect );

    unsigned char* Target8 = (unsigned char*)TargetAddress;
    
#ifdef _WIN64
    Target8[0] = 0x48;
    Target8[1] = 0xB8;
    *(DWORD64*)&Target8[2] = (DWORD64)HookFunction;
    Target8[10] = 0xFF;
    Target8[11] = 0xE0;
    
    for ( size_t i = 12; i < OriginalSize; i++ )
        Target8[i] = 0x90;
#else
    INT64 Offset64 = (INT64)( (unsigned char*)HookFunction - ( Target8 + 5 ) );
    DWORD RelativeOffset = (DWORD)Offset64;
    
    if ( Offset64 > 0x7FFFFFFFLL || Offset64 < -0x80000000LL ) {
        printf( "[-] Hook function too far away for relative jump!\n" );
        VirtualProtect( TargetAddress , OriginalSize , OldProtect , &OldProtect );
        return FALSE;
    }
    
    Target8[0] = 0xE9;
    *(DWORD*)&Target8[1] = RelativeOffset;
    
    for ( size_t i = 5; i < OriginalSize; i++ )
        Target8[i] = 0x90;
#endif

    VirtualProtect( TargetAddress , OriginalSize , OldProtect , &OldProtect );
    
    FlushInstructionCache( GetCurrentProcess( ) , TargetAddress , OriginalSize );
    FlushInstructionCache( GetCurrentProcess( ) , TrampolineFunction , TrampolineSize );

    return TRUE;
}


BOOL InlineHook::Remove( ) {
    if ( !TargetAddress )
        return FALSE;

    DWORD OldProtect;
    VirtualProtect( TargetAddress , OriginalSize , PAGE_EXECUTE_READWRITE , &OldProtect );
    memcpy( TargetAddress , OriginalBytes , OriginalSize );
    VirtualProtect( TargetAddress , OriginalSize , OldProtect , &OldProtect );

    if ( TrampolineFunction ) {
        VirtualFree( TrampolineFunction , 0 , MEM_RELEASE );
        TrampolineFunction = nullptr;
    }

    return TRUE;
}

}


typedef int ( WINAPI* MessageBoxAPtr )( HWND , LPCSTR , LPCSTR , UINT );
static MessageBoxAPtr TrampolineMessageBoxA = nullptr;


int WINAPI HookMessageBoxA( HWND H , LPCSTR T , LPCSTR C , UINT U ) {
    printf( "[*] MessageBoxA hooked via inline hook!\n" );
    
    FunStuff::InlineHook::Remove( );
    int Result = MessageBoxA( H , "Hooked!" , "Inline Hook" , U );
    FunStuff::InlineHook::Install( (void*)MessageBoxA , (void*)HookMessageBoxA , (void**)&TrampolineMessageBoxA );
    
    return Result;
}


int main( ) {
    LoadLibraryA( "user32.dll" );

    printf( "[*] Installing inline hook on MessageBoxA...\n" );
    if ( FunStuff::InlineHook::Install( (void*)MessageBoxA , (void*)HookMessageBoxA , (void**)&TrampolineMessageBoxA ) )
        printf( "[+] Inline hook installed!\n" );
    else
        printf( "[-] Inline hook failed!\n" );

    printf( "\n[*] Testing MessageBoxA...\n" );
    MessageBoxA( NULL , "Test" , "Test" , 0 );

    printf( "\n[*] Testing MessageBoxA again...\n" );
    MessageBoxA( NULL , "Test 2" , "Test 2" , 0 );

    printf( "\n[*] Press any key to unhook...\n" );
    getchar( );

    if ( FunStuff::InlineHook::Remove( ) )
        printf( "[+] Inline hook removed!\n" );

    printf( "\n[*] Testing MessageBoxA after unhook...\n" );
    MessageBoxA( NULL , "Test 3" , "Test 3" , 0 );

    return 0;
}
