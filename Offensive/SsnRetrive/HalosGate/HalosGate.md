# Halo's Gate SSN Retrieval

Hell's Gate with neighbor scanning for hooked stubs. When a function starts with a JMP hook (0xE9), scans up to 8 adjacent exports in either direction to find an unhooked neighbor, then calculates the hooked SSN based on the distance.

## What It Does

Hell's Gate fails when EDR hooks a stub with a JMP. Halo's Gate detects the hook and searches nearby functions. Since Windows assigns SSNs in EAT address order, consecutive syscalls differ by exactly 1. If we find an unhooked neighbor 3 slots away with SSN 0x0055, the hooked function's SSN is 0x0055 ± 3.

## How It Works

**Hook Detection** — Check if the first byte of the stub is 0xE9 (JMP rel32). If so, the function is hooked.

**Neighbor Scan** — Search up to 8 slots in both directions (±1, ±2, ±3, ... ±8). For each neighbor, try to read its SSN using the Hell's Gate pattern scan.

**SSN Calculation** — When we find an unhooked neighbor at distance `Delta` in direction `Dir`:
```cpp
HookedSSN = NeighborSSN - (Dir * Delta)
```

If the neighbor is 3 slots forward (+3) with SSN 0x0058, the hooked SSN is 0x0058 - 3 = 0x0055.

**Fallback** — If the stub isn't hooked (first byte != 0xE9), use normal Hell's Gate pattern scanning.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (HalosGate_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table contains all Zw* functions including hooked ones
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X at %p\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn,
        Table.Entries[i].Address);
}
```

The tool successfully retrieves SSNs even when functions are hooked, as long as at least one neighbor within 8 slots is unhooked.


