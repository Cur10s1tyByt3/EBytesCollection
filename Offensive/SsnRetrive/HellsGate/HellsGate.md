# Hell's Gate SSN Retrieval

Retrieves System Service Numbers (SSNs) by reading stub bytes directly from ntdll.dll. This is the original Hell's Gate technique — fast and simple, but breaks when stubs are hooked by EDR products.

## What It Does

Every Zw* function in ntdll has a syscall stub:

```asm
mov r10, rcx      ; 4C 8B D1
mov eax, <SSN>    ; B8 [lo] [hi] 00 00
syscall           ; 0F 05
ret               ; C3
```

The SSN is embedded in the `mov eax` instruction at bytes 4-5 of the pattern. We scan the stub looking for the byte sequence `4C 8B D1 B8 [lo] [hi] 00 00`, extract the two SSN bytes, and return the 16-bit value.

## How It Works

**Export Table Walk** — We get ntdll's base address via GetModuleHandleA (ntdll is always loaded before any user code runs). Walk the Export Address Table looking for functions that start with "Zw".

**Stub Scan** — For each Zw* function, read the first 32 bytes looking for the syscall pattern. We scan up to 32 bytes to handle potential padding or alignment bytes at the start of the function.

**Hook Detection** — Before scanning for the pattern, we check for common hook signatures:
- `0xE9` (JMP rel32) — EDR redirects to their own code
- `0x0F 0x05` (syscall) — stub might be modified
- `0xC3` (ret) — stub might be gutted

If we find any of these before the pattern, we skip the function and return FALSE.

**SSN Extraction** — When we find the pattern, bytes 4-5 contain the SSN in little-endian format. We combine them: `(hi << 8) | lo`.

## Hook Detection

The tool checks for three hook indicators:

1. **JMP (0xE9)** — Most EDR products hook by overwriting the first 5 bytes with a JMP to their detour function. If we see 0xE9 before the syscall pattern, the stub is hooked.

2. **Syscall (0x0F 0x05)** — If we hit a syscall instruction before finding the pattern, the stub layout is unexpected and might be modified.

3. **Ret (0xC3)** — If we hit a return before the pattern, the stub has been gutted or replaced.

If any of these appear, we skip the function. The tool will miss hooked functions but won't return incorrect SSNs.

## Usage

```cpp
SSN_TABLE Table = { 0 };

if (HellsGate_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table contains all unhooked Zw* functions with SSNs
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X at %p\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn,
        Table.Entries[i].Address);
}
```

The tool dumps all successfully scanned syscalls. If EDR hooks are present, some functions will be missing from the output.


