# GuardCF SSN Retrieval

This tool retrieves System Service Numbers (SSNs) by reading the Control Flow Guard function table from ntdll.dll.

## What It Does

System Service Numbers are the syscall IDs that ntdll uses to invoke kernel functions. Every Zw* function in ntdll has a stub that looks like:

```asm
mov r10, rcx
mov eax, <SSN>
syscall
ret
```

The SSN is the number in the `mov eax` instruction. Knowing the SSN lets you invoke syscalls directly without going through ntdll, which is useful for bypassing usermode hooks placed by EDR products.

## Why GuardCF Method Matters

Traditional SSN retrieval methods read the stub bytes directly from ntdll and parse out the `mov eax` instruction. This breaks when an EDR hooks the function with a JMP (0xE9) at the start of the stub — the SSN bytes are overwritten.

GuardCF bypasses this entirely. Control Flow Guard is a Windows security feature that maintains a sorted list of every valid indirect call target in a module. This list is stored in IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable and contains the RVA of every function that can be called via a function pointer.

We walk the CFG table, match each RVA against the Export Address Table, and increment a counter for every Zw* function we find. Since the CFG table is sorted by RVA and syscalls are assigned in ascending order, the counter gives us the SSN.

## How It Works

**Load Config Directory** — The IMAGE_LOAD_CONFIG_DIRECTORY is a data directory (index 10) that contains security and optimization metadata. One field is GuardCFFunctionTable, which points to an array of IMAGE_CFG_ENTRY structures. Each entry has an RVA and flags indicating the function's CFG properties.

**CFG Table Walk** — We iterate the CFG table until we hit an entry with RVA == 0 (the terminator). For each entry, we check if the RVA matches any export in ntdll's EAT.

**EAT Matching** — The Export Address Table has three parallel arrays: AddressOfNames (RVAs to name strings), AddressOfNameOrdinals (ordinal indices), and AddressOfFunctions (RVAs to function entry points). We walk AddressOfNames looking for functions that start with "Zw", then check if the function's RVA matches the current CFG entry's RVA.

**SSN Assignment** — When we find a match, we store the current counter value as the SSN and increment the counter. Since the CFG table is sorted by RVA and Windows assigns syscall numbers in ascending RVA order, this gives us the correct SSN for each function.

**Lookup** — The tool builds a table of all Zw* functions with their SSNs and addresses. You can look up a function by name using GuardCF_LookUpByName, which does a linear search through the table.

## Limitations

This method only works on Windows 10+ with CFG-compiled binaries. Older versions of ntdll don't have a GuardCFFunctionTable. You can check if it exists by verifying LoadCfg->GuardCFFunctionTable != 0.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (GuardCF_DumpAll(&Table) == FALSE)
{
    printf("[-] GuardCF failed\n");
    return 1;
}

// Look up a specific function
SSN_ENTRY Entry = GuardCF_LookUpByName("ZwCreateFile", &Table);
if (Entry.Address != NULL)
{
    printf("ZwCreateFile: SSN 0x%04X at %p\n", Entry.Ssn, Entry.Address);
}
```

The tool dumps a few common syscalls (ZwCreateFile, ZwOpenProcess, etc.) to demonstrate the lookup. You can extend this to dump all syscalls or integrate it into a syscall wrapper library.
