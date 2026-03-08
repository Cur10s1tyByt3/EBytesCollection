# FreshyCalls SSN Retrieval

Sorts Nt* exports by virtual address — the sorted index is the SSN. Never reads stub bytes, making it completely hook-immune. The kernel assigns SSNs in ascending VA order at build time, so the sorted position IS the SSN.

## What It Does

Instead of reading stub bytes or scanning for patterns, FreshyCalls collects all Nt* exports from ntdll's EAT, sorts them by virtual address in ascending order, and assigns SSNs based on position. The lowest address gets SSN 0, the next gets SSN 1, and so on.

## How It Works

**Export Collection** — Walk ntdll's Export Address Table looking for functions that start with "Nt". Skip "Ntdll" prefixed functions (like NtdllDefWindowProc_A) — those are loader internals, not syscalls.

**Address Sorting** — Build an array of (name, address) pairs and sort by address using qsort. The comparison function casts addresses to ULONG_PTR and returns -1/0/1 based on ordering.

**SSN Assignment** — After sorting, the array index is the SSN. The first entry (lowest address) is SSN 0, the second is SSN 1, etc.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (FreshyCalls_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table contains all Nt* functions sorted by address
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X at %p\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn,
        Table.Entries[i].Address);
}
```

The tool dumps all syscalls in ascending address order with their calculated SSNs.
