#include<Windows.h>
#include<cstdio>


namespace FunStuff {

class PageGuardHook {
private:
    static void* TargetAddress;
    static void* HookFunction;
    static void* OriginalFunction;
    static PVOID VehHandle;
    static BOOL IsActive;
    static BOOL IsExecuting;
    static MEMORY_BASIC_INFORMATION PageInfo;

public:
    static BOOL Install( void* Target , void* Hook , void** OutOriginal );
    static BOOL Remove( );
    static LONG CALLBACK ExceptionHandler( PEXCEPTION_POINTERS ExceptionInfo );
    
    template<typename Ret , typename... Args>
    static Ret CallOriginal( Args... args ) {
        IsExecuting = TRUE;
        
        DWORD OldProtect;
        VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , PageInfo.Protect , &OldProtect );
        
        typedef Ret( *FuncType )( Args... );
        Ret Result = ( (FuncType)OriginalFunction )( args... );
        
        VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , PageInfo.Protect | PAGE_GUARD , &OldProtect );
        
        IsExecuting = FALSE;
        return Result;
    }
};


void* PageGuardHook::TargetAddress = nullptr;
void* PageGuardHook::HookFunction = nullptr;
void* PageGuardHook::OriginalFunction = nullptr;
PVOID PageGuardHook::VehHandle = nullptr;
BOOL PageGuardHook::IsActive = FALSE;
BOOL PageGuardHook::IsExecuting = FALSE;
MEMORY_BASIC_INFORMATION PageGuardHook::PageInfo{};

}


BOOL FunStuff::PageGuardHook::Install( void* Target , void* Hook , void** OutOriginal ) {
    if ( !Target || !Hook )
        return FALSE;

    TargetAddress = Target;
    HookFunction = Hook;
    OriginalFunction = Target;
    *OutOriginal = OriginalFunction;

    if ( !VirtualQuery( TargetAddress , &PageInfo , sizeof( PageInfo ) ) )
        return FALSE;

    printf( "[+] Target Address: %p\n" , TargetAddress );
    printf( "[+] Page Base: %p\n" , PageInfo.BaseAddress );
    printf( "[+] Page Size: %zu bytes\n" , PageInfo.RegionSize );
    printf( "[+] Original Protection: 0x%lX\n" , PageInfo.Protect );

    DWORD OldProtect;
    if ( !VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , PageInfo.Protect | PAGE_GUARD , &OldProtect ) ) {
        printf( "[-] VirtualProtect failed: %lu\n" , GetLastError( ) );
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


BOOL FunStuff::PageGuardHook::Remove( ) {
    if ( !IsActive )
        return FALSE;

    IsActive = FALSE;

    DWORD OldProtect;
    VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , PageInfo.Protect , &OldProtect );

    if ( VehHandle ) {
        RemoveVectoredExceptionHandler( VehHandle );
        VehHandle = nullptr;
    }

    return TRUE;
}


LONG CALLBACK FunStuff::PageGuardHook::ExceptionHandler( PEXCEPTION_POINTERS ExceptionInfo ) {
    if ( !IsActive )
        return EXCEPTION_CONTINUE_SEARCH;

    if ( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION ) {
        void* ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;

        if ( ExceptionAddress == TargetAddress && !IsExecuting ) {
            printf( "[*] PAGE_GUARD triggered at %p\n" , ExceptionAddress );

#if defined(_M_ARM64) || defined(__aarch64__)
            ExceptionInfo->ContextRecord->Pc = (DWORD64)HookFunction;
#elif defined(_M_ARM) || defined(__arm__)
            ExceptionInfo->ContextRecord->Pc = (DWORD)HookFunction;
#elif defined(_WIN64) || defined(__x86_64__)
            ExceptionInfo->ContextRecord->Rip = (DWORD64)HookFunction;
#else
            ExceptionInfo->ContextRecord->Eip = (DWORD)HookFunction;
#endif

            ExceptionInfo->ContextRecord->EFlags |= 0x100;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        ExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
        if ( !IsExecuting ) {
            DWORD OldProtect;
            VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , PageInfo.Protect | PAGE_GUARD , &OldProtect );
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


typedef int ( WINAPI* MessageBoxAPtr )( HWND , LPCSTR , LPCSTR , UINT );
static MessageBoxAPtr OriginalMessageBoxA = nullptr;


int WINAPI HookMessageBoxA( HWND H , LPCSTR T , LPCSTR C , UINT U ) {
    printf( "[*] MessageBoxA hooked via PAGE_GUARD!\n" );
    
    return FunStuff::PageGuardHook::CallOriginal<int>( H , "Hooked!" , "PAGE_GUARD Hook" , U );
}


int main( ) {
    LoadLibraryA( "user32.dll" );

    OriginalMessageBoxA = MessageBoxA;

    printf( "[*] Installing PAGE_GUARD hook on MessageBoxA...\n" );
    if ( FunStuff::PageGuardHook::Install( (void*)MessageBoxA , (void*)HookMessageBoxA , (void**)&OriginalMessageBoxA ) )
        printf( "[+] PAGE_GUARD hook installed!\n" );
    else
        printf( "[-] PAGE_GUARD hook failed!\n" );

    printf( "\n[*] Testing MessageBoxA...\n" );
    MessageBoxA( NULL , "Test" , "Test" , 0 );

    printf( "\n[*] Testing MessageBoxA again...\n" );
    MessageBoxA( NULL , "Test 2" , "Test 2" , 0 );

    printf( "\n[*] Press any key to unhook...\n" );
    getchar( );

    if ( FunStuff::PageGuardHook::Remove( ) )
        printf( "[+] PAGE_GUARD hook removed!\n" );

    return 0;
}
