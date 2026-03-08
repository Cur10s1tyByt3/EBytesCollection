#include<Windows.h>
#include<winternl.h>
#include<cstdio>

//
// ============================================================
//  RtlQueryProcessDebugInformation structures
// ============================================================
//

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _RTL_DEBUG_INFORMATION {
    HANDLE                SectionHandleClient;
    PVOID                 ViewBaseClient;
    PVOID                 ViewBaseTarget;
    ULONG_PTR             ViewBaseDelta;
    HANDLE                EventPairClient;
    HANDLE                EventPairTarget;
    HANDLE                TargetProcessHandle;
    PVOID                 TargetThreadHandle;
    ULONG_PTR             Flags;
    SIZE_T                OffsetFree;
    SIZE_T                CommitSize;
    SIZE_T                ViewSize;
    PRTL_PROCESS_MODULES  Modules;         // offset into the shared section
    PVOID                 BackTraces;
    PVOID                 Heaps;
    PVOID                 Locks;
    PVOID                 SpecificHeap;
    HANDLE                TargetProcessHandle2;
    PVOID                 VerifierOptions;
    PVOID                 ProcessVerifierOptions;
    PVOID                 Reserved[4];
} RTL_DEBUG_INFORMATION, * PRTL_DEBUG_INFORMATION;

//
// Classes passed to RtlQueryProcessDebugInformation.
// OR these together to request multiple data types at once.
//
#define PDI_MODULES     0x01    // populate Modules field
#define PDI_BACKTRACE   0x02    // populate BackTraces field
#define PDI_HEAPS       0x04    // populate Heaps field
#define PDI_HEAP_TAGS   0x08
#define PDI_HEAP_BLOCKS 0x10
#define PDI_LOCKS       0x20    // populate Locks field

typedef PRTL_DEBUG_INFORMATION
(NTAPI* PFN_RTL_CREATE_QUERY_DEBUG_BUFFER)(
    _In_opt_ ULONG  MaximumCommit,
    _In_     BOOLEAN UseEventPair
    );

typedef NTSTATUS
(NTAPI* PFN_RTL_QUERY_PROCESS_DEBUG_INFORMATION)(
    _In_    HANDLE                  UniqueProcessId,
    _In_    ULONG                   Flags,
    _Inout_ PRTL_DEBUG_INFORMATION  Buffer
    );

typedef NTSTATUS
(NTAPI* PFN_RTL_DESTROY_QUERY_DEBUG_BUFFER)(
    _In_ PRTL_DEBUG_INFORMATION Buffer
    );

INT
main(
    VOID
)
{
    CONST HMODULE Ntdll = GetModuleHandleA("ntdll.dll");

    CONST PFN_RTL_CREATE_QUERY_DEBUG_BUFFER RtlCreateQueryDebugBuffer =
        (PFN_RTL_CREATE_QUERY_DEBUG_BUFFER)GetProcAddress(
            Ntdll,
            "RtlCreateQueryDebugBuffer"
        );

    CONST PFN_RTL_QUERY_PROCESS_DEBUG_INFORMATION RtlQueryProcessDebugInformation =
        (PFN_RTL_QUERY_PROCESS_DEBUG_INFORMATION)GetProcAddress(
            Ntdll,
            "RtlQueryProcessDebugInformation"
        );

    CONST PFN_RTL_DESTROY_QUERY_DEBUG_BUFFER RtlDestroyQueryDebugBuffer =
        (PFN_RTL_DESTROY_QUERY_DEBUG_BUFFER)GetProcAddress(
            Ntdll,
            "RtlDestroyQueryDebugBuffer"
        );

    if (!RtlCreateQueryDebugBuffer ||
        !RtlQueryProcessDebugInformation ||
        !RtlDestroyQueryDebugBuffer)
    {
        printf("[-] Failed to resolve Rtl debug functions\n");
        return 1;
    }

    //
    // Allocate the shared debug buffer.
    // First arg is max commit size — 0 lets ntdll choose a default.
    //
    PRTL_DEBUG_INFORMATION DebugBuffer = RtlCreateQueryDebugBuffer(0, FALSE);
    if (DebugBuffer == NULL)
    {
        printf("[-] RtlCreateQueryDebugBuffer failed\n");
        return 1;
    }

    //
    // Query module information for the current process.
    // Pass the PID as a handle — ntdll accepts the numeric PID here.
    //
    NTSTATUS Status = RtlQueryProcessDebugInformation(
        (HANDLE)(ULONG_PTR)GetCurrentProcessId(),
        PDI_MODULES,
        DebugBuffer
    );

    if (Status != 0)
    {
        printf("[-] RtlQueryProcessDebugInformation failed: 0x%08X\n", Status);
        RtlDestroyQueryDebugBuffer(DebugBuffer);
        return 1;
    }

    CONST PRTL_PROCESS_MODULES Modules = DebugBuffer->Modules;

    printf("[*] Enumerating modules via RtlQueryProcessDebugInformation...\n\n");
    printf("[+] Total modules: %d\n\n", Modules->NumberOfModules);

    for (ULONG i = 0; i < Modules->NumberOfModules; i++)
    {
        CONST PRTL_PROCESS_MODULE_INFORMATION Mod = &Modules->Modules[i];

        //
        // OffsetToFileName points into FullPathName where the
        // bare filename starts — avoids a manual string scan.
        //
        CONST LPCSTR FileName = (LPCSTR)Mod->FullPathName + Mod->OffsetToFileName;

        printf(
            "  [%3d] Base: %p  Size: 0x%-8X  Name: %s\n",
            i,
            Mod->ImageBase,
            Mod->ImageSize,
            FileName
        );

        printf(
            "        Path: %s\n\n",
            Mod->FullPathName
        );
    }

    //
    // Always destroy the debug buffer to release the shared section.
    //
    RtlDestroyQueryDebugBuffer(DebugBuffer);

    return 0;
}
