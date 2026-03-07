#include <Windows.h>
#include <cstdio>


namespace FunStuff {

class HardwareBreakpointHook {
private:
    static void* TargetAddress;
    static void* HookFunction;
    static void* OriginalFunction;
    static PVOID VehHandle;
    static BOOL IsActive;
    static DWORD DrIndex;

public:
    static BOOL Install( void* Target , void* Hook , void** OutOriginal );
    static BOOL Remove( );
    static LONG CALLBACK ExceptionHandler( PEXCEPTION_POINTERS ExceptionInfo );
    
    template<typename Ret , typename... Args>
    static Ret CallOriginal( Args... args ) {
        typedef Ret( *FuncType )( Args... );
        return ( (FuncType)OriginalFunction )( args... );
    }
};


void* HardwareBreakpointHook::TargetAddress = nullptr;
void* HardwareBreakpointHook::HookFunction = nullptr;
void* HardwareBreakpointHook::OriginalFunction = nullptr;
PVOID HardwareBreakpointHook::VehHandle = nullptr;
BOOL HardwareBreakpointHook::IsActive = FALSE;
DWORD HardwareBreakpointHook::DrIndex = 0;

}


DWORD FunStuff::FindFreeDrIndex( PCONTEXT Ctx ) {
    for ( DWORD i = 0; i < 4; i++ ) {
        if ( !( Ctx->Dr7 & ( 1ULL << ( i * 2 ) ) ) )
            return i;
    }
    return (DWORD)-1;
}


BOOL FunStuff::SetHardwareBreakpoint( void* Address , DWORD DrIndex ) {
    HANDLE Thread = GetCurrentThread( );
    CONTEXT Ctx = { 0 };
    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if ( !GetThreadContext( Thread , &Ctx ) )
        return FALSE;

    switch ( DrIndex ) {
        case 0: Ctx.Dr0 = (DWORD_PTR)Address; break;
        case 1: Ctx.Dr1 = (DWORD_PTR)Address; break;
        case 2: Ctx.Dr2 = (DWORD_PTR)Address; break;
        case 3: Ctx.Dr3 = (DWORD_PTR)Address; break;
        default: return FALSE;
    }

    Ctx.Dr7 |= ( 1ULL << ( DrIndex * 2 ) );
    Ctx.Dr7 &= ~( 3ULL << ( 16 + DrIndex * 4 ) );
    Ctx.Dr7 &= ~( 3ULL << ( 18 + DrIndex * 4 ) );

    return SetThreadContext( Thread , &Ctx );
}


BOOL FunStuff::RemoveHardwareBreakpoint( DWORD DrIndex ) {
    HANDLE Thread = GetCurrentThread( );
    CONTEXT Ctx = { 0 };
    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if ( !GetThreadContext( Thread , &Ctx ) )
        return FALSE;

    Ctx.Dr7 &= ~( 1ULL << ( DrIndex * 2 ) );

    switch ( DrIndex ) {
        case 0: Ctx.Dr0 = 0; break;
        case 1: Ctx.Dr1 = 0; break;
        case 2: Ctx.Dr2 = 0; break;
        case 3: Ctx.Dr3 = 0; break;
        default: return FALSE;
    }

    return SetThreadContext( Thread , &Ctx );
}


BOOL FunStuff::HardwareBreakpointHook::Install( void* Target , void* Hook , void** OutOriginal ) {
    if ( !Target || !Hook )
        return FALSE;

    TargetAddress = Target;
    HookFunction = Hook;
    OriginalFunction = Target;
    *OutOriginal = OriginalFunction;

    CONTEXT Ctx = { 0 };
    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext( GetCurrentThread( ) , &Ctx );

    DrIndex = FindFreeDrIndex( &Ctx );
    if ( DrIndex == (DWORD)-1 ) {
        printf( "[-] No free debug registers available\n" );
        return FALSE;
    }

    printf( "[+] Target Address: %p\n" , TargetAddress );
    printf( "[+] Using Dr%lu\n" , DrIndex );

    if ( !SetHardwareBreakpoint( TargetAddress , DrIndex ) ) {
        printf( "[-] SetHardwareBreakpoint failed\n" );
        return FALSE;
    }

    VehHandle = AddVectoredExceptionHandler( 1 , ExceptionHandler );
    if ( !VehHandle ) {
        printf( "[-] AddVectoredExceptionHandler failed\n" );
        return FALSE;
    }

    IsActive = TRUE;
    return TRUE;
}


BOOL FunStuff::HardwareBreakpointHook::Remove( ) {
    if ( !IsActive )
        return FALSE;

    IsActive = FALSE;

    RemoveHardwareBreakpoint( DrIndex );

    if ( VehHandle ) {
        RemoveVectoredExceptionHandler( VehHandle );
        VehHandle = nullptr;
    }

    return TRUE;
}


LONG CALLBACK FunStuff::HardwareBreakpointHook::ExceptionHandler( PEXCEPTION_POINTERS ExceptionInfo ) {
    if ( !IsActive )
        return EXCEPTION_CONTINUE_SEARCH;

    if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
        DWORD_PTR ExceptionAddress = 0;

#if defined(_M_ARM64) || defined(__aarch64__)
        ExceptionAddress = ExceptionInfo->ContextRecord->Pc;
#elif defined(_M_ARM) || defined(__arm__)
        ExceptionAddress = ExceptionInfo->ContextRecord->Pc;
#elif defined(_WIN64) || defined(__x86_64__)
        ExceptionAddress = ExceptionInfo->ContextRecord->Rip;
#else
        ExceptionAddress = ExceptionInfo->ContextRecord->Eip;
#endif

        if ( ExceptionAddress == (DWORD_PTR)TargetAddress ) {
            DWORD DrMask = ( 1ULL << DrIndex );
            
            if ( ExceptionInfo->ContextRecord->Dr6 & DrMask ) {
                printf( "[*] Hardware breakpoint triggered at %p\n" , (void*)ExceptionAddress );

#if defined(_M_ARM64) || defined(__aarch64__)
                ExceptionInfo->ContextRecord->Pc = (DWORD64)HookFunction;
#elif defined(_M_ARM) || defined(__arm__)
                ExceptionInfo->ContextRecord->Pc = (DWORD)HookFunction;
#elif defined(_WIN64) || defined(__x86_64__)
                ExceptionInfo->ContextRecord->Rip = (DWORD64)HookFunction;
#else
                ExceptionInfo->ContextRecord->Eip = (DWORD)HookFunction;
#endif

                ExceptionInfo->ContextRecord->EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


typedef int ( WINAPI* MessageBoxAPtr )( HWND , LPCSTR , LPCSTR , UINT );
static MessageBoxAPtr OriginalMessageBoxA = nullptr;


int WINAPI HookMessageBoxA( HWND H , LPCSTR T , LPCSTR C , UINT U ) {
    printf( "[*] MessageBoxA hooked via hardware breakpoint!\n" );
    
    return FunStuff::HardwareBreakpointHook::CallOriginal<int>( H , "Hooked!" , "Hardware Breakpoint" , U );
}


int main( ) {
    LoadLibraryA( "user32.dll" );

    OriginalMessageBoxA = MessageBoxA;

    printf( "[*] Installing hardware breakpoint hook on MessageBoxA...\n" );
    if ( FunStuff::HardwareBreakpointHook::Install( (void*)MessageBoxA , (void*)HookMessageBoxA , (void**)&OriginalMessageBoxA ) )
        printf( "[+] Hardware breakpoint hook installed!\n" );
    else
        printf( "[-] Hardware breakpoint hook failed!\n" );

    printf( "\n[*] Testing MessageBoxA...\n" );
    MessageBoxA( NULL , "Test" , "Test" , 0 );

    printf( "\n[*] Testing MessageBoxA again...\n" );
    MessageBoxA( NULL , "Test 2" , "Test 2" , 0 );

    printf( "\n[*] Press any key to unhook...\n" );
    getchar( );

    if ( FunStuff::HardwareBreakpointHook::Remove( ) )
        printf( "[+] Hardware breakpoint hook removed!\n" );

    return 0;
}
