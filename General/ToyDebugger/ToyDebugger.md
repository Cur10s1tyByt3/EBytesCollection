# FunStuff - Toy Debugger 

Tiny Windows toy debugger that attaches to a running process and prints a stream of debug events. Right now it focuses on the stuff you actually want to see first: process attach, thread creation, exceptions, DLL loads and unloads, output debug strings, process exit, plus quick thread and module snapshots.

## What It Does
This code is like year old, just rewritten ... 
The debugger takes a single argument: either a process name like `notepad.exe` or a numeric PID. It resolves the target, attaches with `DebugActiveProcess`, disables kill-on-exit so the debuggee does not die just because the debugger exits, prints an initial thread/module inventory, and then sits in a basic debug loop until the target process exits.

DLL loads are logged from `LOAD_DLL_DEBUG_EVENT`. If Windows gives us a usable file handle for the image, the debugger asks `GetFinalPathNameByHandleW` for the path. If not, it falls back to trying the image name pointer from the debug event. It also tries to match the module base against a Toolhelp snapshot so you get a module name and size when that lookup works.

Exceptions, create-process, create-thread, unload-DLL, output-debug-string, and exit events are also printed. For threads, the debugger tries to grab the live control context and prints `EIP/ESP/EBP` for x86 or WOW64 targets and `RIP/RSP/RBP` for native x64 targets. Breakpoints and single-step exceptions are continued with `DBG_CONTINUE`; everything else falls back to `DBG_EXCEPTION_NOT_HANDLED` so the target keeps its normal behavior.

## Usage

```bat
FunStuff.exe notepad.exe
FunStuff.exe 1234
```

If the attach succeeds, the debugger prints a line for each event until the process exits or the debug loop fails.

## Limitations

This is a toy debugger, not a full one. There is no symbol resolution, no breakpoint management UI, no disassembly, no memory browser, and no multi-process session management.

The DLL path recovery and thread-context capture are both best effort. Some debug events do not give enough information to reconstruct a nice module path every time, and some threads may be gone or inaccessible by the time the debugger asks for context, so you will occasionally see `<unknown>` or `<unavailable>`.

Attaching to other processes may require the right integrity level or administrator privileges depending on the target.
