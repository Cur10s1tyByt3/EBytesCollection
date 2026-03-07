#include <Windows.h>
#include <cstdio>


namespace FunStuff {

class Int3Hook {
private:
    static void* TargetAddress;
    static void* HookFunction;
    static unsigned char OriginalByte;
    static PVOID VehHandle;
    static BOOL IsInstalled;
    
    static LONG WINAPI ExceptionHandler( _In_ PEXCEPTION_POINTERS ExceptionInfo );

public:
    static BOOL Install( _In_ void* Target , _In_ void* Hook );
    static BOOL Remove( );
};


void* Int3Hook::TargetAddress = nullptr;
void* Int3Hook::HookFunction = nullptr;
unsigned char Int3Hook::OriginalByte = 0;
PVOID Int3Hook::VehHandle = nullptr;
BOOL Int3Hook::IsInstalled = FALSE;


LONG WINAPI Int3Hook::ExceptionHandler( _In_ PEXCEPTION_POINTERS ExceptionInfo ) {
    if ( ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT )
        return EXCEPTION_CONTINUE_SEARCH;
    
    void* ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    if ( ExceptionAddress != TargetAddress )
        return EXCEPTION_CONTINUE_SEARCH;
    
    printf( "[*] EXCEPTION_BREAKPOINT at %p\n" , ExceptionAddress );
    printf( "[*] MessageBoxA hooked via INT3!\n" );
    
#ifdef _WIN64
    LPCSTR OriginalText = (LPCSTR)ExceptionInfo->ContextRecord->Rdx;
    LPCSTR OriginalCaption = (LPCSTR)ExceptionInfo->ContextRecord->R8;
    
    printf( "[*] Original: \"%s\" / \"%s\"\n" , OriginalText , OriginalCaption );
    
    ExceptionInfo->ContextRecord->Rdx = (DWORD64)"Hooked via INT3!";
    ExceptionInfo->ContextRecord->R8 = (DWORD64)"INT3 Hook";
    
    printf( "[*] Modified: \"Hooked via INT3!\" / \"INT3 Hook\"\n" );
#else
    DWORD* Stack = (DWORD*)ExceptionInfo->ContextRecord->Esp;
    LPCSTR OriginalText = (LPCSTR)Stack[2];
    LPCSTR OriginalCaption = (LPCSTR)Stack[3];
    
    printf( "[*] Original: \"%s\" / \"%s\"\n" , OriginalText , OriginalCaption );
    
    Stack[2] = (DWORD)"Hooked via INT3!";
    Stack[3] = (DWORD)"INT3 Hook";
    
    printf( "[*] Modified: \"Hooked via INT3!\" / \"INT3 Hook\"\n" );
#endif
    
    DWORD OldProtect;
    VirtualProtect( TargetAddress , 1 , PAGE_EXECUTE_READWRITE , &OldProtect );
    *(unsigned char*)TargetAddress = OriginalByte;
    VirtualProtect( TargetAddress , 1 , OldProtect , &OldProtect );
    
    printf( "[*] Restored original byte: %02X\n" , OriginalByte );
    
#ifdef _WIN64
    ExceptionInfo->ContextRecord->Rip = (DWORD64)TargetAddress;
#else
    ExceptionInfo->ContextRecord->Eip = (DWORD)TargetAddress;
#endif
    
    printf( "[*] Adjusted RIP to %p\n" , TargetAddress );
    
    IsInstalled = FALSE;
    
    return EXCEPTION_CONTINUE_EXECUTION;
}


BOOL Int3Hook::Install( _In_ void* Target , _In_ void* Hook ) {
    if ( !Target )
        return FALSE;
    
    if ( IsInstalled )
        return FALSE;
    
    TargetAddress = Target;
    HookFunction = Hook;
    
    OriginalByte = *(unsigned char*)TargetAddress;
    
    printf( "[+] Target Address: %p\n" , TargetAddress );
    printf( "[+] Original Byte: %02X\n" , OriginalByte );
    
    VehHandle = AddVectoredExceptionHandler( 1 , ExceptionHandler );
    if ( !VehHandle ) {
        printf( "[-] AddVectoredExceptionHandler failed\n" );
        return FALSE;
    }
    
    printf( "[+] VEH Handler: %p\n" , VehHandle );
    
    DWORD OldProtect;
    VirtualProtect( TargetAddress , 1 , PAGE_EXECUTE_READWRITE , &OldProtect );
    *(unsigned char*)TargetAddress = 0xCC;
    VirtualProtect( TargetAddress , 1 , OldProtect , &OldProtect );
    
    FlushInstructionCache( GetCurrentProcess( ) , TargetAddress , 1 );
    
    IsInstalled = TRUE;
    
    return TRUE;
}


BOOL Int3Hook::Remove( ) {
    if ( !IsInstalled )
        return FALSE;
    
    DWORD OldProtect;
    VirtualProtect( TargetAddress , 1 , PAGE_EXECUTE_READWRITE , &OldProtect );
    *(unsigned char*)TargetAddress = OriginalByte;
    VirtualProtect( TargetAddress , 1 , OldProtect , &OldProtect );
    
    if ( VehHandle ) {
        RemoveVectoredExceptionHandler( VehHandle );
        VehHandle = nullptr;
    }
    
    IsInstalled = FALSE;
    
    return TRUE;
}

}


int main( ) {
    LoadLibraryA( "user32.dll" );
    
    printf( "[*] Installing INT3 hook on MessageBoxA...\n" );
    if ( FunStuff::Int3Hook::Install( (void*)MessageBoxA , nullptr ) )
        printf( "[+] INT3 hook installed!\n" );
    else
        printf( "[-] INT3 hook failed!\n" );
    
    printf( "\n[*] Testing MessageBoxA...\n" );
    MessageBoxA( NULL , "Test" , "Test" , 0 );
    
    printf( "\n[*] Testing MessageBoxA again (hook should be gone)...\n" );
    MessageBoxA( NULL , "Test 2" , "Test 2" , 0 );
    
    printf( "\n[*] Press any key to exit...\n" );
    getchar( );
    
    if ( FunStuff::Int3Hook::Remove( ) )
        printf( "[+] INT3 hook removed!\n" );
    
    return 0;
}
