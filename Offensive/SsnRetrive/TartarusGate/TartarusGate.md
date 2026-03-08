# Tartarus Gate SSN Retrieval

Halo's Gate with detection of mid-stub hooks. Some EDR products patch the stub after `mov r10, rcx` instead of at byte 0, producing `4C 8B D1 E9 ...` (mov then JMP). Tartarus detects both hook positions and falls back to neighbor scanning for either.

## What It Does

Extends Halo's Gate to catch a second hook pattern. Standard hooks replace byte 0 with 0xE9 (JMP). Some EDRs let the first instruction execute, then hook at byte 3:

```asm
mov r10, rcx    ; 4C 8B D1 (bytes 0-2)
jmp <detour>    ; E9 ... (byte 3+)
```

This preserves the register setup before redirecting. Tartarus checks both positions and uses neighbor scanning if either is hooked.

## How It Works

**Hook Detection** — Check two positions:
1. Byte 0 == 0xE9 (standard hook)
2. Bytes 0-2 == `4C 8B D1` AND byte 3 == 0xE9 (mid-stub hook)

**Neighbor Scan** — If either hook is detected, scan up to 8 adjacent exports to find an unhooked neighbor and calculate the SSN based on distance.

**Fallback** — If no hook is detected, use normal Hell's Gate pattern scanning.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (TartarusGate_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table contains all Zw* functions including those with mid-stub hooks
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X at %p\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn,
        Table.Entries[i].Address);
}
```

The tool successfully retrieves SSNs even when EDR products use mid-stub hooking techniques.
