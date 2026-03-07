#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <Psapi.h>

#pragma comment( lib , "Psapi.lib" )


namespace FunStuff {

BOOL IsPointerInModuleCodeSection( void* Ptr ) {
    MEMORY_BASIC_INFORMATION Mbi{};
    if ( !VirtualQuery( Ptr , &Mbi , sizeof( Mbi ) ) )
        return FALSE;
    
    if ( Mbi.State != MEM_COMMIT )
        return FALSE;
    
    if ( Mbi.Type != MEM_IMAGE )
        return FALSE;
    
    if ( !( Mbi.Protect & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) ) )
        return FALSE;
    
    return TRUE;
}


BOOL IsValidVTablePointer( void** VTablePtr ) {
    if ( !VTablePtr )
        return FALSE;
    
    if ( (DWORD_PTR)VTablePtr % sizeof( void* ) != 0 )
        return FALSE;
    
    MEMORY_BASIC_INFORMATION Mbi{};
    if ( !VirtualQuery( VTablePtr , &Mbi , sizeof( Mbi ) ) )
        return FALSE;
    
    if ( Mbi.State != MEM_COMMIT )
        return FALSE;
    
    if ( !( Mbi.Protect & ( PAGE_READONLY | PAGE_READWRITE ) ) )
        return FALSE;
    
    return TRUE;
}


BOOL IsValidVTableEntry( void* Entry ) {
    if ( !Entry )
        return FALSE;
    
    if ( (DWORD_PTR)Entry % sizeof( void* ) != 0 )
        return FALSE;
    
    return IsPointerInModuleCodeSection( Entry );
}


BOOL HasRTTI( void** VTableBase ) {
    if ( !VTableBase )
        return FALSE;
    
    MEMORY_BASIC_INFORMATION VtableMbi{};
    if ( !VirtualQuery( VTableBase , &VtableMbi , sizeof( VtableMbi ) ) )
        return FALSE;
    
    if ( VtableMbi.Type != MEM_IMAGE )
        return FALSE;
    
    void* RttiPtr = VTableBase[-1];
    
    MEMORY_BASIC_INFORMATION RttiMbi{};
    if ( !VirtualQuery( RttiPtr , &RttiMbi , sizeof( RttiMbi ) ) )
        return FALSE;
    
    if ( RttiMbi.State != MEM_COMMIT )
        return FALSE;
    
    if ( RttiMbi.Type != MEM_IMAGE )
        return FALSE;
    
    return TRUE;
}


size_t ScanVTableSize( void* Instance ) {
    if ( !Instance )
        return 0;
    
    void** VTableBase = *(void***)Instance;
    
    if ( !IsValidVTablePointer( VTableBase ) )
        return 0;
    
    size_t Count = 0;
    MEMORY_BASIC_INFORMATION FirstMbi{};
    VirtualQuery( VTableBase , &FirstMbi , sizeof( FirstMbi ) );
    
    for ( size_t i = 0; i < 200; i++ ) {
        void* Entry = VTableBase[i];
        
        MEMORY_BASIC_INFORMATION CurrentMbi{};
        if ( !VirtualQuery( &VTableBase[i] , &CurrentMbi , sizeof( CurrentMbi ) ) )
            break;
        
        if ( CurrentMbi.BaseAddress != FirstMbi.BaseAddress )
            break;
        
        if ( !IsValidVTableEntry( Entry ) )
            break;
        
        Count++;
    }
    
    return Count;
}


void DumpVTable( void* Instance , const char* ClassName , size_t Count ) {
    if ( !Instance ) {
        printf( "[-] Invalid instance\n" );
        return;
    }

    void** VTableBase = *(void***)Instance;
    
    printf( "\n[*] VTable Dump for %s\n" , ClassName );
    printf( "[*] Instance Address: %p\n" , Instance );
    printf( "[*] VTable Base: %p\n" , VTableBase );
    
    if ( HasRTTI( VTableBase ) )
        printf( "[*] RTTI Detected: %p\n" , VTableBase[-1] );
    
    printf( "[*] ========================================\n" );
    
    for ( size_t i = 0; i < Count; i++ ) {
        void* Entry = VTableBase[i];
        printf( "  [%zu] %p\n" , i , Entry );
    }
    
    printf( "[*] ========================================\n" );
}


void DumpVTableAuto( void* Instance , const char* ClassName ) {
    size_t Count = ScanVTableSize( Instance );
    printf( "[*] Auto-detected %zu vtable entries\n" , Count );
    DumpVTable( Instance , ClassName , Count );
}


class VTableHook {
private:
    static void** OriginalVTable;
    static void** ShadowVTable;
    static void* OriginalFunction;
    static void* Instance;
    static size_t VTableSize;
    static size_t HookedIndex;

public:
    static BOOL Install( void* Inst , size_t Index , void* HookFunc , void** OutOriginal );
    static BOOL Remove( );
};


void** VTableHook::OriginalVTable = nullptr;
void** VTableHook::ShadowVTable = nullptr;
void* VTableHook::OriginalFunction = nullptr;
void* VTableHook::Instance = nullptr;
size_t VTableHook::VTableSize = 0;
size_t VTableHook::HookedIndex = 0;

}


BOOL FunStuff::VTableHook::Install( void* Inst , size_t Index , void* HookFunc , void** OutOriginal ) {
    if ( !Inst )
        return FALSE;

    Instance = Inst;
    OriginalVTable = *(void***)Instance;
    VTableSize = ScanVTableSize( Instance );
    
    if ( VTableSize == 0 || Index >= VTableSize )
        return FALSE;

    OriginalFunction = OriginalVTable[Index];
    HookedIndex = Index;
    *OutOriginal = OriginalFunction;

    printf( "[+] Original VTable: %p\n" , OriginalVTable );
    printf( "[+] VTable Size: %zu entries\n" , VTableSize );
    printf( "[+] Original Function: %p\n" , OriginalFunction );
    printf( "[+] Hook Index: %zu\n" , Index );

    ShadowVTable = (void**)VirtualAlloc( nullptr , VTableSize * sizeof( void* ) , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );
    if ( !ShadowVTable )
        return FALSE;

    for ( size_t i = 0; i < VTableSize; i++ )
        ShadowVTable[i] = OriginalVTable[i];

    ShadowVTable[Index] = HookFunc;

    printf( "[+] Shadow VTable: %p\n" , ShadowVTable );

    DWORD OldProtect;
    VirtualProtect( Instance , sizeof( void* ) , PAGE_READWRITE , &OldProtect );
    *(void***)Instance = ShadowVTable;
    VirtualProtect( Instance , sizeof( void* ) , OldProtect , &OldProtect );

    return TRUE;
}


BOOL FunStuff::VTableHook::Remove( ) {
    if ( !Instance || !OriginalVTable || !ShadowVTable )
        return FALSE;

    DWORD OldProtect;
    VirtualProtect( Instance , sizeof( void* ) , PAGE_READWRITE , &OldProtect );
    *(void***)Instance = OriginalVTable;
    VirtualProtect( Instance , sizeof( void* ) , OldProtect , &OldProtect );

    VirtualFree( ShadowVTable , 0 , MEM_RELEASE );
    ShadowVTable = nullptr;

    return TRUE;
}


class BaseClass {
public:
    virtual ~BaseClass( ) = default;

    virtual void Hello( ) const {
        std::cout << "Hello" << std::endl;
    }

    virtual void Name( ) const {
        std::cout << "Base" << std::endl;
    }

    virtual void Order( ) const {
        std::cout << "0" << std::endl;
    }
};


class DerivedClass : public BaseClass {
public:
    void Name( ) const override {
        std::cout << "Derived" << std::endl;
    }

    void Order( ) const override {
        std::cout << "1" << std::endl;
    }
};


typedef void( __stdcall* NamePtr )( void* ThisPointer );
static NamePtr OriginalName = nullptr;


void HookName( void* ThisPointer ) {
    std::cout << "[*] Hooked Name!" << std::endl;
    OriginalName( ThisPointer );
}


int main( ) {
    BaseClass* Base = new BaseClass{ };
    BaseClass* Derived = new DerivedClass{ };

    printf( "[*] Calling Base->Name()...\n" );
    Base->Name( );

    printf( "\n[*] Calling Derived->Name()...\n" );
    Derived->Name( );

    printf( "\n[*] ========================================\n" );
    printf( "[*] VTable Scanner/Dumper\n" );
    printf( "[*] ========================================\n" );
    
    FunStuff::DumpVTableAuto( Base , "BaseClass" );
    FunStuff::DumpVTableAuto( Derived , "DerivedClass" );

    printf( "\n[*] Installing VTable hook on Derived->Name()...\n" );
    FunStuff::VTableHook::Install( Derived , 2 , HookName , (void**)&OriginalName );

    printf( "\n[*] Calling Derived->Name() after hook...\n" );
    Derived->Name( );
    
    printf( "\n[*] VTable after hooking:\n" );
    FunStuff::DumpVTableAuto( Derived , "DerivedClass (Hooked)" );

    printf( "\n[*] Press any key to unhook...\n" );
    getchar( );

    if ( FunStuff::VTableHook::Remove( ) )
        printf( "[+] VTable hook removed!\n" );

    printf( "\n[*] Calling Derived->Name() after unhook...\n" );
    Derived->Name( );
    
    printf( "\n[*] VTable after unhooking:\n" );
    FunStuff::DumpVTableAuto( Derived , "DerivedClass (Restored)" );

    delete Base;
    delete Derived;

    return 0;
}
