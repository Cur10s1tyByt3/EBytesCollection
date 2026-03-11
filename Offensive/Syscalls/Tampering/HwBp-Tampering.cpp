// credits to rad9800 this is rewritten engine, 
#include<Windows.h>
#include<stdio.h>
#include<string.h>

#pragma warning(push)

#if !defined(_M_X64)
#error This code only supports x64 builds.
#endif

#define MAX_BREAKPOINT_ARGUMENT_OVERRIDES 16

typedef enum _DRX
{
    Dr0 = 0,
    Dr1,
    Dr2,
    Dr3
} DRX, *PDRX;

typedef
VOID
(CALLBACK* PHARDWARE_BREAKPOINT_CALLBACK)(
    _Inout_ PCONTEXT ThreadCtx,
    _In_opt_ PVOID   UserContext
    );

typedef struct _FUNCTION_ARGUMENT_OVERRIDE
{
    DWORD     ParameterIndex;
    ULONG_PTR Value;
} FUNCTION_ARGUMENT_OVERRIDE, *PFUNCTION_ARGUMENT_OVERRIDE;

typedef struct _HARDWARE_BREAKPOINT_ENTRY
{
    BOOL                          Active;
    DRX                           Register;
    ULONG_PTR                     Address;
    PHARDWARE_BREAKPOINT_CALLBACK Callback;
    PVOID                         CallbackContext;
    DWORD                         ArgumentOverrideCount;
    FUNCTION_ARGUMENT_OVERRIDE    ArgumentOverrides[MAX_BREAKPOINT_ARGUMENT_OVERRIDES];
} HARDWARE_BREAKPOINT_ENTRY, *PHARDWARE_BREAKPOINT_ENTRY;

static PVOID g_Veh = NULL;
static HARDWARE_BREAKPOINT_ENTRY g_HardwareBreakpointTable[4] = { 0 };

_Function_class_(PVECTORED_EXCEPTION_HANDLER)
DECLSPEC_NOINLINE
static
LONG
CALLBACK
ExceptionHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
);

static
PHARDWARE_BREAKPOINT_ENTRY
GetHardwareBreakpointEntry(
    _In_ DRX Register
)
{
    if (static_cast<DWORD>(Register) >= RTL_NUMBER_OF(g_HardwareBreakpointTable))
    {
        return NULL;
    }

    return &g_HardwareBreakpointTable[static_cast<DWORD>(Register)];
}

static
ULONG_PTR
SetDr7Bits(
    _In_ ULONG_PTR CurrentDr7,
    _In_ INT       StartingBitPosition,
    _In_ INT       NumberOfBitsToModify,
    _In_ ULONG_PTR NewValue
)
{
    CONST ULONG_PTR Mask =
        ((static_cast<ULONG_PTR>(1) << NumberOfBitsToModify) - 1);

    return
        (CurrentDr7 & ~(Mask << StartingBitPosition)) |
        (NewValue   <<  StartingBitPosition);
}

_Success_(return != FALSE)
static
BOOL
SetHardwareBreakpoint(
    _In_ PVOID Address,
    _In_ DRX   Register
)
{
    CONTEXT ThreadCtx = { 0 };
    ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    CONST HANDLE Thread = GetCurrentThread();

    if (!GetThreadContext(Thread, &ThreadCtx))
    {
        return FALSE;
    }

    switch (Register)
    {
        case Dr0:
            ThreadCtx.Dr0 = reinterpret_cast<DWORD_PTR>(Address);
            break;

        case Dr1:
            ThreadCtx.Dr1 = reinterpret_cast<DWORD_PTR>(Address);
            break;

        case Dr2:
            ThreadCtx.Dr2 = reinterpret_cast<DWORD_PTR>(Address);
            break;

        case Dr3:
            ThreadCtx.Dr3 = reinterpret_cast<DWORD_PTR>(Address);
            break;

        default:
            return FALSE;
    }

    ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, Register * 2, 1, 1);

    if (!SetThreadContext(Thread, &ThreadCtx))
    {
        return FALSE;
    }

    return TRUE;
}

_Success_(return != FALSE)
static
BOOL
RemoveHardwareBreakpoint(
    _In_ DRX Register
)
{
    CONTEXT ThreadCtx = { 0 };
    ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    CONST HANDLE Thread = GetCurrentThread();

    if (!GetThreadContext(Thread, &ThreadCtx))
    {
        return FALSE;
    }

    switch (Register)
    {
        case Dr0:
            ThreadCtx.Dr0 = 0;
            break;

        case Dr1:
            ThreadCtx.Dr1 = 0;
            break;

        case Dr2:
            ThreadCtx.Dr2 = 0;
            break;

        case Dr3:
            ThreadCtx.Dr3 = 0;
            break;

        default:
            return FALSE;
    }

    ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, Register * 2, 1, 0);

    if (!SetThreadContext(Thread, &ThreadCtx))
    {
        return FALSE;
    }

    return TRUE;
}

_Success_(return != FALSE)
static
BOOL
InitializeHardwareBreakpointEngine(
    VOID
)
{
    if (g_Veh == NULL)
    {
        g_Veh = AddVectoredExceptionHandler(1, ExceptionHandler);
    }

    return (g_Veh != NULL);
}

_Success_(return != FALSE)
static
BOOL
ShutdownHardwareBreakpointEngine(
    VOID
)
{
    if (g_Veh != NULL)
    {
        if (RemoveVectoredExceptionHandler(g_Veh) == 0)
        {
            return FALSE;
        }

        g_Veh = NULL;
    }

    ZeroMemory(g_HardwareBreakpointTable, sizeof(g_HardwareBreakpointTable));
    return TRUE;
}

static
ULONG_PTR
GetInstructionPointer(
    _In_ PCONTEXT ThreadCtx
)
{
    return static_cast<ULONG_PTR>(ThreadCtx->Rip);
}

static
VOID
SetInstructionPointer(
    _Inout_ PCONTEXT ThreadCtx,
    _In_    ULONG_PTR Value
)
{
    ThreadCtx->Rip = static_cast<DWORD64>(Value);
}

static
ULONG_PTR
GetStackPointer(
    _In_ PCONTEXT ThreadCtx
)
{
    return static_cast<ULONG_PTR>(ThreadCtx->Rsp);
}

static
ULONG_PTR
GetFunctionArgument(
    _In_ PCONTEXT ThreadCtx,
    _In_ DWORD    ParameterIndex
)
{
    switch (ParameterIndex)
    {
        case 1:
            return static_cast<ULONG_PTR>(ThreadCtx->Rcx);

        case 2:
            return static_cast<ULONG_PTR>(ThreadCtx->Rdx);

        case 3:
            return static_cast<ULONG_PTR>(ThreadCtx->R8);

        case 4:
            return static_cast<ULONG_PTR>(ThreadCtx->R9);

        default:
            break;
    }

    return *reinterpret_cast<PULONG_PTR>(
        ThreadCtx->Rsp + (ParameterIndex * sizeof(PVOID))
        );
}

static
VOID
SetFunctionArgument(
    _Inout_ PCONTEXT  ThreadCtx,
    _In_    ULONG_PTR Value,
    _In_    DWORD     ParameterIndex
)
{
    switch (ParameterIndex)
    {
        case 1:
            //
            // For syscalls, the first parameter is in R10, not RCX.
            // Check if we're at a syscall instruction by looking at RIP.
            //
            {
                PBYTE InstructionPtr = reinterpret_cast<PBYTE>(ThreadCtx->Rip);
                if (InstructionPtr[0] == 0x0F && InstructionPtr[1] == 0x05)
                {
                    // This is a syscall instruction we ->  use R10
                    ThreadCtx->R10 = static_cast<DWORD64>(Value);
                }
                else
                {
                    // Regular function call we - >  use RCX
                    ThreadCtx->Rcx = static_cast<DWORD64>(Value);
                }
            }
            return;

        case 2:
            ThreadCtx->Rdx = static_cast<DWORD64>(Value);
            return;

        case 3:
            ThreadCtx->R8 = static_cast<DWORD64>(Value);
            return;

        case 4:
            ThreadCtx->R9 = static_cast<DWORD64>(Value);
            return;

        default:
            break;
    }

    *reinterpret_cast<PULONG_PTR>(
        ThreadCtx->Rsp + (ParameterIndex * sizeof(PVOID))
        ) = Value;
}

static
VOID
SetReturnValue(
    _Inout_ PCONTEXT ThreadCtx,
    _In_    ULONG_PTR Value
)
{
    ThreadCtx->Rax = static_cast<DWORD64>(Value);
}

static
VOID
ContinueExecution(
    _Inout_ PCONTEXT ThreadCtx
)
{
    //
    // Set RF so the instruction we just trapped on does not immediately fault again.
    //
    ThreadCtx->EFlags |= (1UL << 16);
}

static
BOOL
IsHardwareBreakpointEnabled(
    _In_ PCONTEXT ThreadCtx,
    _In_ DRX      Register
)
{
    return
        ((ThreadCtx->Dr7 &
          (static_cast<DWORD_PTR>(1) << (static_cast<DWORD>(Register) * 2))) != 0);
}

static
BOOL
HasHardwareBreakpointFired(
    _In_ PCONTEXT ThreadCtx,
    _In_ DRX      Register
)
{
    return
        ((ThreadCtx->Dr6 &
          (static_cast<DWORD_PTR>(1) << static_cast<DWORD>(Register))) != 0);
}

static
ULONG_PTR
GetHardwareBreakpointAddress(
    _In_ PCONTEXT ThreadCtx,
    _In_ DRX      Register
)
{
    switch (Register)
    {
        case Dr0:
            return static_cast<ULONG_PTR>(ThreadCtx->Dr0);

        case Dr1:
            return static_cast<ULONG_PTR>(ThreadCtx->Dr1);

        case Dr2:
            return static_cast<ULONG_PTR>(ThreadCtx->Dr2);

        case Dr3:
            return static_cast<ULONG_PTR>(ThreadCtx->Dr3);

        default:
            return 0;
    }
}

_Success_(return != FALSE)
static
BOOL
GetTriggeredHardwareBreakpoint(
    _In_  PCONTEXT  ThreadCtx,
    _Out_ PDRX      Register,
    _Out_ PULONG_PTR Address
)
{
    for (DWORD i = 0; i < RTL_NUMBER_OF(g_HardwareBreakpointTable); i++)
    {
        CONST DRX CurrentRegister = static_cast<DRX>(i);

        if (IsHardwareBreakpointEnabled(ThreadCtx, CurrentRegister) &&
            HasHardwareBreakpointFired(ThreadCtx, CurrentRegister))
        {
            *Register = CurrentRegister;
            *Address = GetHardwareBreakpointAddress(ThreadCtx, CurrentRegister);
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
ApplyFunctionArgumentOverrides(
    _Inout_ PCONTEXT ThreadCtx,
    _In_reads_(ArgumentOverrideCount) CONST FUNCTION_ARGUMENT_OVERRIDE* ArgumentOverrides,
    _In_ DWORD ArgumentOverrideCount
)
{
    for (DWORD i = 0; i < ArgumentOverrideCount; i++)
    {
        SetFunctionArgument(
            ThreadCtx,
            ArgumentOverrides[i].Value,
            ArgumentOverrides[i].ParameterIndex
        );
    }
}

_Success_(return != FALSE)
static
BOOL
RegisterHardwareBreakpointAction(
    _In_ PVOID Address,
    _In_ DRX   Register,
    _In_reads_opt_(ArgumentOverrideCount) CONST FUNCTION_ARGUMENT_OVERRIDE* ArgumentOverrides,
    _In_ DWORD ArgumentOverrideCount,
    _In_opt_ PHARDWARE_BREAKPOINT_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext
)
{
    PHARDWARE_BREAKPOINT_ENTRY Entry = GetHardwareBreakpointEntry(Register);

    if (Entry == NULL ||
        Address == NULL ||
        ArgumentOverrideCount > MAX_BREAKPOINT_ARGUMENT_OVERRIDES)
    {
        return FALSE;
    }

    if (!InitializeHardwareBreakpointEngine())
    {
        return FALSE;
    }

    ZeroMemory(Entry, sizeof(*Entry));

    Entry->Active = TRUE;
    Entry->Register = Register;
    Entry->Address = reinterpret_cast<ULONG_PTR>(Address);
    Entry->Callback = Callback;
    Entry->CallbackContext = CallbackContext;
    Entry->ArgumentOverrideCount = ArgumentOverrideCount;

    if (ArgumentOverrides != NULL && ArgumentOverrideCount != 0)
    {
        CopyMemory(
            Entry->ArgumentOverrides,
            ArgumentOverrides,
            sizeof(FUNCTION_ARGUMENT_OVERRIDE) * ArgumentOverrideCount
        );
    }

    if (!SetHardwareBreakpoint(Address, Register))
    {
        ZeroMemory(Entry, sizeof(*Entry));
        return FALSE;
    }

    return TRUE;
}

_Success_(return != FALSE)
static
BOOL
UnregisterHardwareBreakpointAction(
    _In_ DRX Register
)
{
    PHARDWARE_BREAKPOINT_ENTRY Entry = GetHardwareBreakpointEntry(Register);

    if (Entry == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Entry, sizeof(*Entry));
    return RemoveHardwareBreakpoint(Register);
}

_Function_class_(PVECTORED_EXCEPTION_HANDLER)
DECLSPEC_NOINLINE
static
LONG
CALLBACK
ExceptionHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    PCONTEXT Ctx = NULL;
    DRX HitRegister = Dr0;
    ULONG_PTR BreakpointAddress = 0;
    PHARDWARE_BREAKPOINT_ENTRY Entry = NULL;
    ULONG_PTR InstructionPointer = 0;
    ULONG_PTR ExceptionAddress = 0;

    if (ExceptionInfo == NULL ||
        ExceptionInfo->ExceptionRecord == NULL ||
        ExceptionInfo->ContextRecord == NULL)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    Ctx = ExceptionInfo->ContextRecord;

    if (!GetTriggeredHardwareBreakpoint(Ctx, &HitRegister, &BreakpointAddress))
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    Entry = GetHardwareBreakpointEntry(HitRegister);
    if (Entry == NULL || !Entry->Active)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InstructionPointer = GetInstructionPointer(Ctx);
    ExceptionAddress =
        reinterpret_cast<ULONG_PTR>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

    if (Entry->Address != BreakpointAddress ||
        Entry->Address != InstructionPointer ||
        Entry->Address != ExceptionAddress)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (Entry->ArgumentOverrideCount != 0)
    {
        ApplyFunctionArgumentOverrides(
            Ctx,
            Entry->ArgumentOverrides,
            Entry->ArgumentOverrideCount
        );
    }

    if (Entry->Callback != NULL)
    {
        Entry->Callback(Ctx, Entry->CallbackContext);
    }

    Ctx->Dr6 = 0;
    ContinueExecution(Ctx);

    return EXCEPTION_CONTINUE_EXECUTION;
}

//
// NTDLL function pointer types for POC, if u need more of these, feel free to define them manualyl lol... these are just for PoC
//
typedef LONG NTSTATUS;

typedef struct _NT_ALLOCATE_VIRTUAL_MEMORY_PATCH
{
    HANDLE   ProcessHandle;
    PVOID*   BaseAddress;
    ULONG_PTR ZeroBits;
    PSIZE_T  RegionSize;
    ULONG    AllocationType;
    ULONG    Protect;
} NT_ALLOCATE_VIRTUAL_MEMORY_PATCH, *PNT_ALLOCATE_VIRTUAL_MEMORY_PATCH;

typedef struct _NT_PROTECT_VIRTUAL_MEMORY_PATCH
{
    HANDLE   ProcessHandle;
    PVOID*   BaseAddress;
    PSIZE_T  NumberOfBytesToProtect;
    ULONG    NewAccessProtection;
    PULONG   OldAccessProtection;
} NT_PROTECT_VIRTUAL_MEMORY_PATCH, *PNT_PROTECT_VIRTUAL_MEMORY_PATCH;

typedef
NTSTATUS
(NTAPI* PFN_NT_ALLOCATE_VIRTUAL_MEMORY)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef
NTSTATUS
(NTAPI* PFN_NT_PROTECT_VIRTUAL_MEMORY)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    PSIZE_T   NumberOfBytesToProtect,
    ULONG     NewAccessProtection,
    PULONG    OldAccessProtection
);

static
PVOID
FindSyscallInstruction(
    _In_ PVOID FunctionAddress
)
{
    //
    // x64: Look for the syscall instruction (0x0F 0x05)...  ( feel free to imporve :0 )
    //
    CONST BYTE SyscallPattern[2] = { 0x0F, 0x05 };
    PBYTE Scan = static_cast<PBYTE>(FunctionAddress);

    for (SIZE_T i = 0; i < 23; i++)
    {
        if (Scan[i] == SyscallPattern[0] && Scan[i + 1] == SyscallPattern[1])
        {
            return static_cast<PVOID>(&Scan[i]);
        }
    }

    return NULL;
}

_Success_(return != FALSE)
static
BOOL
RegisterNtAllocateVirtualMemoryBreakpoint(
    _In_ PVOID WatchAddress,
    _In_ DRX   Register,
    _In_ CONST NT_ALLOCATE_VIRTUAL_MEMORY_PATCH* Patch
)
{
    FUNCTION_ARGUMENT_OVERRIDE ArgumentOverrides[6] = { 0 };

    if (Patch == NULL)
    {
        return FALSE;
    }

    ArgumentOverrides[0].ParameterIndex = 1;
    ArgumentOverrides[0].Value =
        reinterpret_cast<ULONG_PTR>(Patch->ProcessHandle);

    ArgumentOverrides[1].ParameterIndex = 2;
    ArgumentOverrides[1].Value =
        reinterpret_cast<ULONG_PTR>(Patch->BaseAddress);

    ArgumentOverrides[2].ParameterIndex = 3;
    ArgumentOverrides[2].Value =
        static_cast<ULONG_PTR>(Patch->ZeroBits);

    ArgumentOverrides[3].ParameterIndex = 4;
    ArgumentOverrides[3].Value =
        reinterpret_cast<ULONG_PTR>(Patch->RegionSize);

    ArgumentOverrides[4].ParameterIndex = 5;
    ArgumentOverrides[4].Value =
        static_cast<ULONG_PTR>(Patch->AllocationType);

    ArgumentOverrides[5].ParameterIndex = 6;
    ArgumentOverrides[5].Value =
        static_cast<ULONG_PTR>(Patch->Protect);

    return RegisterHardwareBreakpointAction(
        WatchAddress,
        Register,
        ArgumentOverrides,
        RTL_NUMBER_OF(ArgumentOverrides),
        NULL,
        NULL
    );
}

_Success_(return != FALSE)
static
BOOL
RegisterNtProtectVirtualMemoryBreakpoint(
    _In_ PVOID WatchAddress,
    _In_ DRX   Register,
    _In_ CONST NT_PROTECT_VIRTUAL_MEMORY_PATCH* Patch
)
{
    FUNCTION_ARGUMENT_OVERRIDE ArgumentOverrides[5] = { 0 };

    if (Patch == NULL)
    {
        return FALSE;
    }

    ArgumentOverrides[0].ParameterIndex = 1;
    ArgumentOverrides[0].Value =
        reinterpret_cast<ULONG_PTR>(Patch->ProcessHandle);

    ArgumentOverrides[1].ParameterIndex = 2;
    ArgumentOverrides[1].Value =
        reinterpret_cast<ULONG_PTR>(Patch->BaseAddress);

    ArgumentOverrides[2].ParameterIndex = 3;
    ArgumentOverrides[2].Value =
        reinterpret_cast<ULONG_PTR>(Patch->NumberOfBytesToProtect);

    ArgumentOverrides[3].ParameterIndex = 4;
    ArgumentOverrides[3].Value =
        static_cast<ULONG_PTR>(Patch->NewAccessProtection);

    ArgumentOverrides[4].ParameterIndex = 5;
    ArgumentOverrides[4].Value =
        reinterpret_cast<ULONG_PTR>(Patch->OldAccessProtection);

    return RegisterHardwareBreakpointAction(
        WatchAddress,
        Register,
        ArgumentOverrides,
        RTL_NUMBER_OF(ArgumentOverrides),
        NULL,
        NULL
    );
}

static
VOID
TestNtAllocateVirtualMemory(
    VOID
)
{
    printf("\n=== Testing NtAllocateVirtualMemory ===\n");

    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (Ntdll == NULL)
    {
        printf("Failed to get ntdll.dll handle\n");
        return;
    }

    PVOID ProcAddr = GetProcAddress(Ntdll, "NtAllocateVirtualMemory");
    if (ProcAddr == NULL)
    {
        printf("Failed to get NtAllocateVirtualMemory address\n");
        return;
    }

    PFN_NT_ALLOCATE_VIRTUAL_MEMORY NtAllocateVirtualMemory =
        reinterpret_cast<PFN_NT_ALLOCATE_VIRTUAL_MEMORY>(ProcAddr);

    PVOID SyscallAddr = FindSyscallInstruction(ProcAddr);
    if (SyscallAddr == NULL)
    {
        printf("Failed to find syscall instruction\n");
        return;
    }

    printf("NtAllocateVirtualMemory: 0x%p\n", ProcAddr);
    printf("Syscall instruction: 0x%p\n", SyscallAddr);

    SIZE_T RegionSize = 4096;
    PVOID BaseAddress = NULL;

    NT_ALLOCATE_VIRTUAL_MEMORY_PATCH Patch = { 0 };
    Patch.ProcessHandle = GetCurrentProcess();  // replace with Handle(-1) if u want ... 
    Patch.BaseAddress = &BaseAddress;
    Patch.ZeroBits = 0;
    Patch.RegionSize = &RegionSize;
    Patch.AllocationType = MEM_COMMIT | MEM_RESERVE;
    Patch.Protect = PAGE_EXECUTE_READWRITE;

    if (!RegisterNtAllocateVirtualMemoryBreakpoint(SyscallAddr, Dr0, &Patch))
    {
        printf("Failed to register hardware breakpoint\n");
        return;
    }

    printf("Hardware breakpoint registered at syscall\n");

    NTSTATUS Status = NtAllocateVirtualMemory(NULL, NULL, 0, NULL, 0, 0);

    printf("[NtAllocateVirtualMemory] Status: 0x%lx\n", Status);
    printf("[NtAllocateVirtualMemory] Allocated at: 0x%p\n", BaseAddress);
    printf("[NtAllocateVirtualMemory] Region size: %zu bytes\n", RegionSize);

    if (BaseAddress != NULL && Status == 0)
    {
        memcpy(BaseAddress, "HWBP Test!", 11);
        printf("Wrote test data to allocated memory\n");
        printf("Memory content: %s\n", static_cast<char*>(BaseAddress));
    }

    UnregisterHardwareBreakpointAction(Dr0);

    if (BaseAddress != NULL)
    {
        SIZE_T FreeSize = 0;
        VirtualFree(BaseAddress, FreeSize, MEM_RELEASE);
        printf("Memory freed\n");
    }
}

static
VOID
TestNtProtectVirtualMemory(
    VOID
)
{
    printf("\n=== Testing NtProtectVirtualMemory ===\n");

    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (Ntdll == NULL)
    {
        printf("Failed to get ntdll.dll handle\n");
        return;
    }

    PVOID ProcAddr = GetProcAddress(Ntdll, "NtProtectVirtualMemory");
    if (ProcAddr == NULL)
    {
        printf("Failed to get NtProtectVirtualMemory address\n");
        return;
    }

    PFN_NT_PROTECT_VIRTUAL_MEMORY NtProtectVirtualMemory =
        reinterpret_cast<PFN_NT_PROTECT_VIRTUAL_MEMORY>(ProcAddr);

    PVOID SyscallAddr = FindSyscallInstruction(ProcAddr);
    if (SyscallAddr == NULL)
    {
        printf("Failed to find syscall instruction\n");
        return;
    }

    printf("NtProtectVirtualMemory: 0x%p\n", ProcAddr);
    printf("Syscall instruction: 0x%p\n", SyscallAddr);

    PVOID TestMem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (TestMem == NULL)
    {
        printf("Failed to allocate test memory\n");
        return;
    }

    printf("Allocated test memory at: 0x%p\n", TestMem);

    SIZE_T ProtectSize = 4096;
    ULONG OldProtect = 0;

    NT_PROTECT_VIRTUAL_MEMORY_PATCH Patch = { 0 };
    Patch.ProcessHandle = GetCurrentProcess(); // replace with Handle(-1) if u want ... 
    Patch.BaseAddress = &TestMem;
    Patch.NumberOfBytesToProtect = &ProtectSize;
    Patch.NewAccessProtection = PAGE_EXECUTE_READ;
    Patch.OldAccessProtection = &OldProtect;

    if (!RegisterNtProtectVirtualMemoryBreakpoint(SyscallAddr, Dr1, &Patch))
    {
        printf("Failed to register hardware breakpoint\n");
        VirtualFree(TestMem, 0, MEM_RELEASE);
        return;
    }

    printf("Hardware breakpoint registered at syscall\n");

    NTSTATUS Status = NtProtectVirtualMemory(NULL, NULL, NULL, 0, NULL);

    printf("[NtProtectVirtualMemory] Status: 0x%lx\n", Status);
    printf("[NtProtectVirtualMemory] Old protection: 0x%lx\n", OldProtect);
    printf("[NtProtectVirtualMemory] New protection: PAGE_EXECUTE_READ\n");

    UnregisterHardwareBreakpointAction(Dr1);

    VirtualFree(TestMem, 0, MEM_RELEASE);
    printf("Memory freed\n");
}

INT
wmain(
    _In_ INT     Argc,
    _In_ PWSTR*  Argv
)
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    printf("========================================\n");
    printf("Hardware Breakpoint Syscall Hook POC\n");
    printf("========================================\n");

    TestNtAllocateVirtualMemory();
    TestNtProtectVirtualMemory();

    ShutdownHardwareBreakpointEngine();

    printf("\n========================================\n");
    printf("Press Enter to exit...\n");
    getchar();

    return 0;
}

#pragma warning(pop)
