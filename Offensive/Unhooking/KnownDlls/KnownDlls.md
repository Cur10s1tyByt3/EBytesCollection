# KnownDlls Unhooking

Unhooks ntdll.dll by pulling a clean copy from the `\KnownDlls` object directory instead of reading from disk. The `\KnownDlls\ntdll.dll` section object is pre-loaded at boot before any EDR injects, so the bytes are guaranteed clean.

## What It Does

EDR products hook ntdll.dll by modifying the .text section in memory. Traditional unhooking reads ntdll.dll from `C:\Windows\System32\` and restores .text, but EDR can hook file reads or replace the on-disk file. KnownDlls bypasses this by opening the section object Windows uses internally.
> Note; Every good av will detect this! >:D
## Usage

```cpp
if (KnownDlls_Unhook() == FALSE)
{
    printf("[-] Unhooking failed\n");
    return 1;
}

// ntdll.dll is now unhooked - all syscall stubs are clean
```

The function returns TRUE on success. After unhooking, all ntdll functions point to the original unhooked code.
