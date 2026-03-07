#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "psapi.lib")


namespace ModuleEnum {

std::vector<HMODULE> GetProcessModules( _In_ HANDLE ProcessHandle ) {
    std::vector<HMODULE> Modules;
    HMODULE ModuleArray[1024];
    DWORD BytesNeeded;
    
    if ( !EnumProcessModules( ProcessHandle , ModuleArray , sizeof( ModuleArray ) , &BytesNeeded ) ) {
        printf( "[-] EnumProcessModules failed: %d\n" , GetLastError( ) );
        return Modules;
    }
    
    DWORD ModuleCount = BytesNeeded / sizeof( HMODULE );
    
    for ( DWORD i = 0; i < ModuleCount; i++ ) {
        Modules.push_back( ModuleArray[i] );
    }
    
    return Modules;
}


MODULEINFO GetModuleInfo( _In_ HANDLE ProcessHandle , _In_ const char* ModuleName ) {
    MODULEINFO ModInfo = { 0 };
    
    std::vector<HMODULE> Modules = GetProcessModules( ProcessHandle );
    
    for ( HMODULE Module : Modules ) {
        char CurrentModuleName[MAX_PATH];
        
        if ( !GetModuleBaseNameA( ProcessHandle , Module , CurrentModuleName , MAX_PATH ) ) {
            continue;
        }
        
        if ( _stricmp( CurrentModuleName , ModuleName ) == 0 ) {
            if ( GetModuleInformation( ProcessHandle , Module , &ModInfo , sizeof( MODULEINFO ) ) ) {
                return ModInfo;
            }
        }
    }
    
    return ModInfo;
}


PVOID GetModuleBaseAddress( _In_ HANDLE ProcessHandle , _In_ const char* ModuleName ) {
    MODULEINFO ModInfo = GetModuleInfo( ProcessHandle , ModuleName );
    return ModInfo.lpBaseOfDll;
}


DWORD GetProcessIdByName( _In_ const char* ProcessName ) {
    HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
    if ( Snapshot == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateToolhelp32Snapshot failed: %d\n" , GetLastError( ) );
        return 0;
    }
    
    PROCESSENTRY32W ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof( PROCESSENTRY32W );
    
    if ( !Process32FirstW( Snapshot , &ProcessEntry ) ) {
        printf( "[-] Process32First failed: %d\n" , GetLastError( ) );
        CloseHandle( Snapshot );
        return 0;
    }
    
    WCHAR WideProcessName[MAX_PATH];
    MultiByteToWideChar( CP_ACP , 0 , ProcessName , -1 , WideProcessName , MAX_PATH );
    
    do {
        if ( _wcsicmp( ProcessEntry.szExeFile , WideProcessName ) == 0 ) {
            CloseHandle( Snapshot );
            return ProcessEntry.th32ProcessID;
        }
    } while ( Process32NextW( Snapshot , &ProcessEntry ) );
    
    CloseHandle( Snapshot );
    return 0;
}


void EnumerateProcessModules( _In_ HANDLE ProcessHandle , _In_ DWORD ProcessId ) {
    printf( "\n[*] Enumerating modules for PID %d...\n" , ProcessId );
    
    std::vector<HMODULE> Modules = GetProcessModules( ProcessHandle );
    
    if ( Modules.empty( ) ) {
        printf( "[-] No modules found\n" );
        return;
    }
    
    printf( "[+] Found %zu modules:\n\n" , Modules.size( ) );
    
    for ( size_t i = 0; i < Modules.size( ); i++ ) {
        HMODULE Module = Modules[i];
        
        char ModuleName[MAX_PATH];
        char ModulePath[MAX_PATH];
        MODULEINFO ModInfo;
        
        if ( GetModuleBaseNameA( ProcessHandle , Module , ModuleName , MAX_PATH ) ) {
            if ( GetModuleFileNameExA( ProcessHandle , Module , ModulePath , MAX_PATH ) ) {
                if ( GetModuleInformation( ProcessHandle , Module , &ModInfo , sizeof( MODULEINFO ) ) ) {
                    printf( "[%3zu] %s\n" , i + 1 , ModuleName );
                    printf( "      Base Address: %p\n" , ModInfo.lpBaseOfDll );
                    printf( "      Size: %d bytes (0x%X)\n" , ModInfo.SizeOfImage , ModInfo.SizeOfImage );
                    printf( "      Entry Point: %p\n" , ModInfo.EntryPoint );
                    printf( "      Path: %s\n\n" , ModulePath );
                }
            }
        }
    }
}

}


int main( int argc , char* argv[] ) {
    printf( "[*] Process Module Enumeration\n" );
    printf( "[*] ===========================\n\n" );
    
    const char* TargetProcess = "notepad.exe";
    
    if ( argc > 1 ) {
        TargetProcess = argv[1];
    }
    
    printf( "[*] Target Process: %s\n" , TargetProcess );
    
    DWORD ProcessId = ModuleEnum::GetProcessIdByName( TargetProcess );
    
    if ( ProcessId == 0 ) {
        printf( "[-] Process not found: %s\n" , TargetProcess );
        printf( "[*] Make sure the process is running\n" );
        return 1;
    }
    
    printf( "[+] Found process: PID %d\n" , ProcessId );
    
    HANDLE ProcessHandle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , ProcessId );
    
    if ( !ProcessHandle ) {
        printf( "[-] OpenProcess failed: %d\n" , GetLastError( ) );
        printf( "[*] Try running as administrator\n" );
        return 1;
    }
    
    printf( "[+] Process handle opened: %p\n" , ProcessHandle );
    
    ModuleEnum::EnumerateProcessModules( ProcessHandle , ProcessId );
    
    printf( "\n[*] Testing specific module lookup...\n" );
    
    PVOID NtdllBase = ModuleEnum::GetModuleBaseAddress( ProcessHandle , "ntdll.dll" );
    if ( NtdllBase ) {
        printf( "[+] ntdll.dll base address: %p\n" , NtdllBase );
    } else {
        printf( "[-] ntdll.dll not found\n" );
    }
    
    PVOID Kernel32Base = ModuleEnum::GetModuleBaseAddress( ProcessHandle , "kernel32.dll" );
    if ( Kernel32Base ) {
        printf( "[+] kernel32.dll base address: %p\n" , Kernel32Base );
    } else {
        printf( "[-] kernel32.dll not found\n" );
    }
    
    CloseHandle( ProcessHandle );
    
    printf( "\n[+] Done!\n" );
    
    return 0;
}
