#include<Windows.h>
#include<winternl.h>
#include<cstdio>

//
// ============================================================
//  LdrEnumerateLoadedModules
//  Undocumented ntdll export — takes a callback that fires
//  once per loaded module in the current process.
// ============================================================
//

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef VOID
(NTAPI* PLDR_ENUM_CALLBACK)(
    _In_    PMY_LDR_DATA_TABLE_ENTRY ModuleInformation,
    _In_    PVOID                    Parameter,
    _Inout_ BOOLEAN* Stop
    );

typedef NTSTATUS
(NTAPI* PFN_LDR_ENUMERATE_LOADED_MODULES)(
    _In_opt_ ULONG              ReservedFlag,
    _In_     PLDR_ENUM_CALLBACK EnumProc,
    _In_opt_ PVOID              Context
    );

//
// ============================================================
//  Callback — fires once per module
// ============================================================
//

VOID
NTAPI
ModuleEnumCallback(
    _In_    PMY_LDR_DATA_TABLE_ENTRY ModuleInfo,
    _In_    PVOID                    Parameter,
    _Inout_ BOOLEAN* Stop
)
{
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Stop);

    if (ModuleInfo->BaseDllName.Buffer == NULL)
    {
        return;
    }

    printf(
        "  Base: %p  Size: 0x%-8X  Name: %ws\n",
        ModuleInfo->DllBase,
        ModuleInfo->SizeOfImage,
        ModuleInfo->BaseDllName.Buffer
    );
}

INT
main(
    VOID
)
{
    CONST PFN_LDR_ENUMERATE_LOADED_MODULES LdrEnumerateLoadedModules =
        (PFN_LDR_ENUMERATE_LOADED_MODULES)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "LdrEnumerateLoadedModules"
        );

    if (LdrEnumerateLoadedModules == NULL)
    {
        printf("[-] Failed to resolve LdrEnumerateLoadedModules\n");
        return 1;
    }

    printf("[*] Enumerating modules via LdrEnumerateLoadedModules...\n\n");

    NTSTATUS Status = LdrEnumerateLoadedModules(
        0,                    // reserved — must be 0
        ModuleEnumCallback,
        NULL                  // context passed to callback
    );

    if (Status != 0)
    {
        printf("[-] LdrEnumerateLoadedModules failed: 0x%08X\n", Status);
        return 1;
    }

    return 0;
}
