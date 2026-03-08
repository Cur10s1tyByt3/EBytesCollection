# NtOsKrnl aka EbyteGate SSN Retrieval

Retrieves SSNs by scanning ntoskrnl.exe stub bytes from disk. Maps the kernel image as a data file and scans each Zw* export for `MOV EAX, imm32` (0xB8) to extract the SSN. Useful as a cross-validation source since the kernel image on disk is untouched by EDR hooks.

## What It Does

Instead of scanning ntdll.dll in memory (which EDR products hook), this method loads ntoskrnl.exe from `C:\Windows\System32\` as a data file and scans its export stubs. The kernel image on disk is never modified by usermode hooks, so the SSNs are always clean.

## How It Works

**Stub Scanning** — For each Zw* export, scan the first 32 bytes looking for 0xB8 (MOV EAX, imm32). The 4 bytes following 0xB8 are the SSN. If we hit 0xE9 (JMP) first, the stub is invalid or hooked — skip it.

**Export Walk** — Walk ntoskrnl.exe's Export Address Table looking for functions starting with "Zw". For each one, scan the stub and extract the SSN.
**X86** - Ins't supported 🫰
## Usage

```cpp
SSN_TABLE Table = { 0 };

if (NtOsKrnl_DumpAll(&Table) == FALSE)
{
    printf("[-] Failed\n");
    return 1;
}

// Table contains SSNs from ntoskrnl.exe on disk
for (DWORD i = 0; i < Table.Count; i++)
{
    printf("%s: SSN 0x%04X\n",
        Table.Entries[i].Name,
        Table.Entries[i].Ssn);
}
```

The tool dumps all successfully scanned syscalls from the kernel image.

## Incomplete Results

This method won't retrieve every possible syscall. Some syscalls exist in ntdll.dll but not in ntoskrnl.exe's export table, and vice versa. The kernel exports Zw* variants for internal use, but not all of them map 1:1 to ntdll's Nt*/Zw* exports. Some SSNs will be missing from the output.
