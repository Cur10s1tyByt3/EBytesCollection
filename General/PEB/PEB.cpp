#include<Windows.h>
#include<winternl.h>
#include<cstdio>

//
// ============================================================
//  NtQueryInformationProcess
// ============================================================
//

typedef NTSTATUS
(NTAPI* PFN_NT_QUERY_INFORMATION_PROCESS)(
    _In_      HANDLE ProcessHandle,
    _In_      ULONG  ProcessInformationClass,
    _Out_     PVOID  ProcessInformation,
    _In_      ULONG  ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// ============================================================
//  Correctly laid out PROCESS_BASIC_INFORMATION
// ============================================================
//

typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

//
// ============================================================
//  64-bit structures
// ============================================================
//

typedef struct _MY_LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY64, * PMY_LDR_DATA_TABLE_ENTRY64;

typedef struct _MY_PEB_LDR_DATA64 {
    ULONG      Length;
    BOOL       Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA64, * PMY_PEB_LDR_DATA64;

typedef struct _MY_PEB64 {
    BYTE               Reserved[2];
    BYTE               BeingDebugged;
    BYTE               Reserved2[1];
    PVOID              Reserved3[2];
    PMY_PEB_LDR_DATA64 Ldr;
} MY_PEB64, * PMY_PEB64;

//
// ============================================================
//  32-bit (WOW64) structures all pointers are DWORD 
//  ( we talked in EAT hooking about DWORD's Limits )
// ============================================================
//

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Buffer;
} UNICODE_STRING32;

typedef struct _MY_LDR_DATA_TABLE_ENTRY32 {
    DWORD            InLoadOrderLinks[2];
    DWORD            InMemoryOrderLinks[2];
    DWORD            InInitializationOrderLinks[2];
    DWORD            DllBase;
    DWORD            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY32, * PMY_LDR_DATA_TABLE_ENTRY32;

typedef struct _MY_PEB_LDR_DATA32 {
    ULONG Length;
    BOOL  Initialized;
    DWORD SsHandle;
    DWORD InLoadOrderModuleList[2];
    DWORD InMemoryOrderModuleList[2];
    DWORD InInitializationOrderModuleList[2];
} MY_PEB_LDR_DATA32, * PMY_PEB_LDR_DATA32;

typedef struct _MY_PEB32 {
    BYTE  Reserved[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    DWORD Reserved3[2];
    DWORD Ldr;
} MY_PEB32, * PMY_PEB32;

//
// ============================================================
//  Local PEB
// ============================================================
//

VOID
EnumerateLocalPeb(
    VOID
)
{
    //
    // Obtain the PEB via TEB cast to our full struct since
    // winternl.h only exposes an incomplete stub.
    //
    CONST PMY_PEB64 Peb = (PMY_PEB64)NtCurrentTeb()->ProcessEnvironmentBlock;

    printf("[Local PEB] Address: %p | BeingDebugged: %d\n", Peb, Peb->BeingDebugged);

    CONST PLIST_ENTRY Head = &Peb->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY Current = Head->Flink; Current != Head; Current = Current->Flink)
    {
        CONST PMY_LDR_DATA_TABLE_ENTRY64 Entry =
            CONTAINING_RECORD(Current, MY_LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);

        if (Entry->BaseDllName.Buffer == NULL)
        {
            continue;
        }

        printf("  Base: %p  Name: %ws\n", Entry->DllBase, Entry->BaseDllName.Buffer);
    }
}

//
// ============================================================
//  Remote PEB 64-bit target
// ============================================================
//

VOID
EnumerateRemotePeb64(
    _In_ HANDLE                           ProcessHandle,
    _In_ PFN_NT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess
)
{
    //
    // Query ProcessBasicInformation (class 0).
    // PebBaseAddress sits at offset 8 in this struct
    //
    MY_PROCESS_BASIC_INFORMATION Pbi{ };
    ULONG  ReturnLength = 0;
    SIZE_T BytesRead = 0;

    NTSTATUS Status = NtQueryInformationProcess(
        ProcessHandle,
        0,
        &Pbi,
        sizeof(Pbi),
        &ReturnLength
    );

    if (Status != 0)
    {
        printf("[-] NtQueryInformationProcess failed: 0x%08X\n", Status);
        return;
    }

    printf("[*] Remote PebBaseAddress: %p\n", Pbi.PebBaseAddress);

    MY_PEB64 Peb{ };

    if (ReadProcessMemory(ProcessHandle, Pbi.PebBaseAddress, &Peb, sizeof(Peb), &BytesRead) == FALSE)
    {
        printf("[-] ReadProcessMemory (PEB64) failed: %d\n", GetLastError());
        return;
    }

    printf("[Remote PEB64] Address: %p | BeingDebugged: %d\n",
        Pbi.PebBaseAddress, Peb.BeingDebugged);

    MY_PEB_LDR_DATA64 Ldr{ };

    if (ReadProcessMemory(ProcessHandle, Peb.Ldr, &Ldr, sizeof(Ldr), &BytesRead) == FALSE)
    {
        printf("[-] ReadProcessMemory (LDR64) failed: %d\n", GetLastError());
        return;
    }

    CONST PVOID Head = &((PMY_PEB_LDR_DATA64)Peb.Ldr)->InLoadOrderModuleList;
    PLIST_ENTRY Current = Ldr.InLoadOrderModuleList.Flink;

    while (Current != Head)
    {
        MY_LDR_DATA_TABLE_ENTRY64 Entry{ };

        if (ReadProcessMemory(
            ProcessHandle,
            CONTAINING_RECORD(Current, MY_LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks),
            &Entry,
            sizeof(Entry),
            &BytesRead) == FALSE)
        {
            break;
        }

        if (Entry.BaseDllName.Buffer != NULL && Entry.BaseDllName.Length > 0)
        {
            WCHAR Name[MAX_PATH]{ };

            ReadProcessMemory(
                ProcessHandle,
                Entry.BaseDllName.Buffer,
                Name,
                Entry.BaseDllName.Length,
                &BytesRead
            );

            printf("  Base: %p  Name: %ws\n", Entry.DllBase, Name);
        }

        //
        // Advance via the local Flink copy never chase the remote pointer directly.
        //
        Current = Entry.InLoadOrderLinks.Flink;
    }
}

//
// ============================================================
//  Remote PEB WOW64 (32-bit target)
// ============================================================
//

VOID
EnumerateRemotePeb32(
    _In_ HANDLE                           ProcessHandle,
    _In_ PFN_NT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess
)
{
    //
    // Query ProcessWow64Information (class 26) to get the 32-bit PEB address.
    // This returns a PVOID whose numeric value is a 32-bit address.
    //
    PVOID  Peb32Address = NULL;
    SIZE_T BytesRead = 0;

    NtQueryInformationProcess(ProcessHandle, 26, &Peb32Address, sizeof(PVOID), NULL);

    if (Peb32Address == NULL)
    {
        printf("[-] Failed to get WOW64 PEB address\n");
        return;
    }

    MY_PEB32 Peb{ };

    if (ReadProcessMemory(ProcessHandle, Peb32Address, &Peb, sizeof(Peb), &BytesRead) == FALSE)
    {
        printf("[-] ReadProcessMemory (PEB32) failed: %d\n", GetLastError());
        return;
    }

    printf("[Remote PEB32] Address: %p | BeingDebugged: %d\n",
        Peb32Address, Peb.BeingDebugged);

    MY_PEB_LDR_DATA32 Ldr{ };

    if (ReadProcessMemory(
        ProcessHandle,
        (PVOID)(ULONG_PTR)Peb.Ldr,
        &Ldr,
        sizeof(Ldr),
        &BytesRead) == FALSE)
    {
        printf("[-] ReadProcessMemory (LDR32) failed: %d\n", GetLastError());
        return;
    }

    //
    // The list head is the remote address of InLoadOrderModuleList
    // inside the remote LDR structure.
    //
    CONST DWORD Head = Peb.Ldr + offsetof(MY_PEB_LDR_DATA32, InLoadOrderModuleList);
    DWORD       Current = Ldr.InLoadOrderModuleList[0];

    while (Current != Head)
    {
        MY_LDR_DATA_TABLE_ENTRY32 Entry{ };

        if (ReadProcessMemory(
            ProcessHandle,
            (PVOID)(ULONG_PTR)Current,
            &Entry,
            sizeof(Entry),
            &BytesRead) == FALSE)
        {
            break;
        }

        if (Entry.BaseDllName.Buffer != 0 && Entry.BaseDllName.Length > 0)
        {
            WCHAR Name[MAX_PATH]{ };

            ReadProcessMemory(
                ProcessHandle,
                (PVOID)(ULONG_PTR)Entry.BaseDllName.Buffer,
                Name,
                Entry.BaseDllName.Length,
                &BytesRead
            );

            printf("  Base: %08X  Name: %ws\n", Entry.DllBase, Name);
        }

        Current = Entry.InLoadOrderLinks[0];
    }
}

//
// ============================================================
//  Dispatcher detects WOW64 and routes accordingly
// ============================================================
//

VOID
EnumerateRemotePeb(
    _In_ DWORD ProcessId
)
{
    CONST HANDLE ProcessHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        ProcessId
    );

    if (ProcessHandle == NULL)
    {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        return;
    }

    CONST PFN_NT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess =
        (PFN_NT_QUERY_INFORMATION_PROCESS)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQueryInformationProcess"
        );

    //
    // Detect whether the target is WOW64 (32-bit) and route to the
    // correct enumeration path.
    //
    BOOL IsWow64 = FALSE;
    IsWow64Process(ProcessHandle, &IsWow64);

    printf("[*] PID %d | Architecture: %s\n",
        ProcessId, IsWow64 ? "WOW64 (32-bit)" : "64-bit");

    if (IsWow64 == TRUE)
    {
        EnumerateRemotePeb32(ProcessHandle, NtQueryInformationProcess);
    }
    else
    {
        EnumerateRemotePeb64(ProcessHandle, NtQueryInformationProcess);
    }

    CloseHandle(ProcessHandle);
}

//
// ============================================================
//  Entry point
// ============================================================
//

INT
main(
    _In_     INT    Argc,
    _In_opt_ CHAR** Argv
)
{
    EnumerateLocalPeb();

    if (Argc > 1)
    {
        EnumerateRemotePeb((DWORD)atoi(Argv[1]));
    }

    return 0;
}
