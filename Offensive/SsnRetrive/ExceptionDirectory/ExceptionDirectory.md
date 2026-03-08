# Exception Directory SSN Retrieval

Retrieves System Service Numbers (SSNs) by walking the .pdata exception directory in ntdll.dll. This method is hook-immune because it never reads stub bytes — it only walks the RUNTIME_FUNCTION table and matches RVAs against the Export Address Table.

## What It Does

Every Zw* function in ntdll has a syscall stub:

```asm
mov r10, rcx
mov eax, <SSN>
syscall
ret
```

The SSN is the syscall ID. Knowing it lets you invoke syscalls directly without going through ntdll, bypassing usermode hooks placed by EDR products.

## How It Works

On x64, Windows uses table-based exception handling stored in the .pdata section (IMAGE_DIRECTORY_ENTRY_EXCEPTION). This section contains an array of RUNTIME_FUNCTION structures:

```cpp
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;  // RVA of function start
    DWORD EndAddress;    // RVA of function end
    DWORD UnwindData;    // RVA of UNWIND_INFO
} RUNTIME_FUNCTION;
```

The .pdata table is sorted by BeginAddress in ascending order at link time. Windows assigns syscall numbers in the same ascending order. We walk the table, match each BeginAddress against ntdll's Export Address Table, and increment a counter for every Zw* function. The counter gives us the SSN.

**Why the sorting matters:** The linker sorts .pdata by BeginAddress for performance — when an exception occurs, the OS does a binary search to find the UNWIND_INFO. This sorting is guaranteed by the PE specification and matches the order Windows uses to assign syscall numbers.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (ExceptionDir_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table now contains all Zw* functions with SSNs
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X at %p\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn,
        Table.Entries[i].Address);
}
```

The tool dumps all syscalls to stdout showing function name, SSN, and address. Extend this to build a lookup table or integrate into a syscall wrapper library.

## x64 Only

This method only works on x64. x86 uses stack-based SEH instead of table-based exception handling, so there's no .pdata section. The code includes a compile-time check and returns an error on x86 builds.
