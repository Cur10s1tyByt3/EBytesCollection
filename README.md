# FunStuff

A personal collection of source code focused on **Windows internals**, **general security research**, and **offensive tooling**. Topics range from PE structure parsing and process enumeration to hooking techniques and syscall tampering.

> These are older projects shared as-is. Code quality and documentation may vary.
> https://t.me/ebytelabs
---

## Table of Contents

- [General](#general)
- [Hooking](#hooking)
- [Offensive](#offensive)

---

## General

General Windows internals utilities and research tools.

### Cryptography
| Project | Description |
|---|---|
| `Bcrypt` | BCrypt API usage examples |
| `DPapi` | DPAPI (Data Protection API) usage |

### Memory
| Project | Description |
|---|---|
| `MemoryScanning/CodeCaves` | Finding executable code caves in memory |
| `MemoryScanning/MemScan` | General memory scanning |
| `MemoryScanning/SignatureScan` | Signature-based memory scanning |

### PE (Portable Executable)
| Project | Description |
|---|---|
| `PE/EAT` | Export Address Table parsing |
| `PE/IAT` | Import Address Table parsing |
| `PE/Modules/EnumClassic` | Classic module enumeration |
| `PE/Modules/LdrEnumLoadedModules` | Module enumeration via `LdrEnumerateLoadedModules` |
| `PE/Modules/RtlQueryProcessDebugInformation` | Module enumeration via `RtlQueryProcessDebugInformation` |

### Thread Enumeration
| Project | Description |
|---|---|
| `PE/ThreadEnumeration/NtGetNextThread` | Thread enumeration via `NtGetNextThread` |
| `PE/ThreadEnumeration/NtQueryInfoThread` | Thread enumeration via `NtQueryInformationThread` |
| `PE/ThreadEnumeration/T_NtQuerySysInfo` | Thread enumeration via `NtQuerySystemInformation` |

### Process Enumeration
| Project | Description |
|---|---|
| `ProcessEnumeration/CreateToolHelp32` | Enumeration via `CreateToolhelp32Snapshot` |
| `ProcessEnumeration/EnumProc` | Enumeration via `EnumProcesses` |
| `ProcessEnumeration/NtQuerySys` | Enumeration via `NtQuerySystemInformation` |

### Miscellaneous
| Project | Description |
|---|---|
| `BinInt3Nopper` | NOP out `INT3` breakpoints in binaries |
| `Cupcake` | PE Parser |
| `DriverEnumeration` | Enumerate loaded kernel drivers |
| `FirmwareTableEnum` | Enumerate firmware tables |
| `HandleEnumeration` | Enumerate system/process handles |
| `NamedPipe` | Named pipe communication examples |
| `PEB` | Process Environment Block inspection |
| `ToyDebugger` | Minimal debugger implementation |
| `WMI` | WMI querying examples |

---

## Hooking

Various hooking techniques targeting different interception points.

| Project | Description |
|---|---|
| `EAT/EatHook.cpp` | Export Address Table hook implementation |
| `EAT/Patchless` | Patchless EAT hooking |
| `HwBp` | Hardware breakpoint-based hooks |
| `IAT/IatHook.cpp` | Import Address Table hook implementation |
| `IAT/Patchless` | Patchless IAT hooking |
| `INT3` | INT3 software breakpoint hooks |
| `Inline` | Inline / trampoline hooks |
| `PageGuard` | PAGE_GUARD exception-based hooks |
| `VTable` | Virtual table (vtable) hooks |

---

## Offensive

Offensive security tooling and evasion techniques.

### DLL
| Project | Description |
|---|---|
| `DLL/ManualMapping` | Manual DLL mapping (no LoadLibrary) |
| `DLL/Proxying` | DLL proxying / DLL hijacking |

### Syscalls & Tampering
| Project | Description |
|---|---|
| `SsnRetrieve` | SSN (System Service Number) retrieval |
| `Syscalls/HwBp-Tampering.cpp` | Syscall argument tampering via hardware breakpoints |

### Unhooking
| Project | Description |
|---|---|
| `Unhooking/KnownDlls` | Unhooking via `\KnownDlls` section objects |
| `Unhooking/Text` | Unhooking by restoring `.text` section from disk |

### WiFi
| Project | Description |
|---|---|
| `WifiExtract/Extract.cpp` | Extract saved WiFi credentials |
| `WifiExtract/Impersonate` | Token impersonation for credential access |

---

## Disclaimer

This code is intended for **educational and research purposes only**. Use responsibly and only on systems you own or have explicit permission to test.

### Credits:
Rad9800
Dk0m
CodeReversing
