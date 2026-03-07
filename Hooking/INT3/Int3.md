# INT3 Software Breakpoint Hooking

INT3 hooking is the same technique debuggers use to set breakpoints. You write a single byte (`0xCC`) to the start of a function, catch the exception when it fires, redirect to your hook, modify parameters or behavior, then restore the original byte. Simple, lightweight, and works on any function.

## How Debuggers Set Breakpoints

When you click "set breakpoint" in a debugger like OllyDbg, IDA, or x64dbg, here's what happens:

```
Original Function:
[48 83 EC 38] [45 33 DB] [rest of function...]
 ^
 First byte

Debugger replaces first byte with 0xCC:
[CC] [83 EC 38] [45 33 DB] [rest of function...]
 ^
 INT3 instruction
```

When the CPU hits `0xCC`, it generates an `EXCEPTION_BREAKPOINT`. The debugger catches it, shows you the breakpoint, lets you inspect variables, then restores the original byte and continues.

## INT3 for Hooking

We can use the same technique for hooking:

```
1. Save original byte
2. Write 0xCC to function start
3. Register VEH to catch EXCEPTION_BREAKPOINT
4. When exception fires:
   - Check if address matches our hook
   - Modify CPU registers (parameters)
   - Restore original byte
   - Adjust RIP/EIP to re-execute the instruction
   - Continue execution
```

## The Flow

```
Original Function:              After INT3 Installed:
+------------------+            +------------------+
| 48 83 EC 38      |            | CC (INT3)        | <-- Breakpoint!
| 45 33 DB         |            | 83 EC 38         |
| 44 39 1D ...     |            | 45 33 DB         |
| ...              |            | 44 39 1D ...     |
+------------------+            +------------------+
                                        |
                                        | Exception fires
                                        v
                                +------------------+
                                | VEH Handler      |
                                | - Check address  |
                                | - Modify params  |
                                | - Restore byte   |
                                | - Adjust RIP     |
                                +------------------+
                                        |
                                        v
                                +------------------+
                                | Original Func    |
                                | Executes with    |
                                | modified params  |
                                +------------------+
```

## Why 0xCC?

`0xCC` is the opcode for `INT 3` (interrupt 3), a special one-byte instruction designed for debugging. It's perfect for breakpoints because:

- **Only 1 byte** - can replace any instruction without overwriting others
- **Generates EXCEPTION_BREAKPOINT** - easy to catch with VEH
- **Hardware-supported** - the CPU knows how to handle it
- **Fast** - no page protection changes needed
- **Special case** - normal INT instructions are 2 bytes (`CD 03`), but INT 3 has its own 1-byte opcode

The Intel manual says: "The INT3 instruction uses a one-byte opcode (CC) and is intended for calling the debug exception handler with a breakpoint exception. This one-byte form is valuable because it can be used to replace the first byte of any instruction with a breakpoint, including other one-byte instructions, without overwriting other code."

## Modifying Function Parameters

The real power of INT3 hooking is modifying function parameters before the original function executes. On x64 Windows, the calling convention passes the first 4 parameters in registers:

**x64 Windows Fastcall:**
- 1st parameter: `RCX`
- 2nd parameter: `RDX`
- 3rd parameter: `R8`
- 4th parameter: `R9`
- 5th+ parameters: Stack

**x86 (32-bit):**
- All parameters: Stack (ESP + offsets)

Example for MessageBoxA on x64:
```cpp
int MessageBoxA( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );
//               RCX       RDX           R8               R9
```

In the exception handler, you can modify these registers:
```cpp
// Original parameters
LPCSTR OriginalText = (LPCSTR)ExceptionInfo->ContextRecord->Rdx;
LPCSTR OriginalCaption = (LPCSTR)ExceptionInfo->ContextRecord->R8;

// Modify them
ExceptionInfo->ContextRecord->Rdx = (DWORD64)"Hooked!";
ExceptionInfo->ContextRecord->R8 = (DWORD64)"INT3 Hook";

// When the original function executes, it sees the modified parameters
```

This is incredibly powerful - you can intercept any function call and change what it does without writing a full hook function.

## Vectored Exception Handling (VEH)

VEH is Windows' way of letting you catch exceptions before they reach the normal exception handlers. You register a callback that gets called for every exception in your process.

```cpp
PVOID AddVectoredExceptionHandler(
    ULONG First,                    // 1 = first, 0 = last
    PVECTORED_EXCEPTION_HANDLER Handler
);
```

The `First` parameter controls priority:
- **1 (nonzero)** - Handler is called first in the chain
- **0** - Handler is called last in the chain

Multiple handlers form a chain. Each handler can either handle the exception (`EXCEPTION_CONTINUE_EXECUTION`) or pass it to the next handler (`EXCEPTION_CONTINUE_SEARCH`).

Your handler gets an `EXCEPTION_POINTERS` structure with:
- `ExceptionRecord` - what exception happened, where it happened
- `ContextRecord` - CPU registers (RIP, RAX, RBX, RCX, RDX, R8, R9, etc.)

Return values:
- `EXCEPTION_CONTINUE_EXECUTION (0xFFFFFFFF)` - I handled it, continue from current RIP
- `EXCEPTION_CONTINUE_SEARCH (0x0)` - Not mine, let other handlers try

## The Exception Handler

```cpp
LONG WINAPI ExceptionHandler( EXCEPTION_POINTERS* ExceptionInfo ) {
    // Check if it's a breakpoint exception
    if ( ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT )
        return EXCEPTION_CONTINUE_SEARCH;
    
    // Check if it's our breakpoint
    void* ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    if ( ExceptionAddress != TargetFunction )
        return EXCEPTION_CONTINUE_SEARCH;
    
    // Call our hook
    HookFunction( );
    
    // Restore original byte
    WriteOriginalByte( );
    
    // Adjust RIP to re-execute the instruction
    #ifdef _WIN64
        ExceptionInfo->ContextRecord->Rip = (DWORD64)TargetFunction;
    #else
        ExceptionInfo->ContextRecord->Eip = (DWORD)TargetFunction;
    #endif
    
    // Continue execution
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

## Why Adjust RIP?

When `INT3` fires, the CPU has already moved past it. The instruction pointer (RIP on x64, EIP on x86) points to the next byte after the `0xCC`. We need to move it back to the start of the function so the original instruction executes.

```
Before INT3:
RIP -> [CC] [83 EC 38] ...

After INT3 exception:
       [CC] [83 EC 38] ...
              ^
              RIP is here (moved forward by 1 byte)

After we restore and adjust:
RIP -> [48] [83 EC 38] ...
       ^
       Back to start, original byte restored
```

**Important:** Windows automatically decrements EIP/RIP to point to the `0xCC` when `EXCEPTION_BREAKPOINT` occurs. So when your handler receives the exception, RIP already points to the breakpoint location. You don't need to subtract 1 - just set it to the function address.

## FlushInstructionCache - Why It Matters

After modifying code in memory, you MUST call `FlushInstructionCache`. Here's why:

Modern CPUs cache instructions for performance. When you write `0xCC` to memory, the CPU's instruction cache might still have the old instruction cached. If you don't flush, the CPU might execute the cached instruction instead of your breakpoint.

```cpp
FlushInstructionCache( GetCurrentProcess( ) , TargetAddress , 1 );
```

According to Microsoft: "Applications should call FlushInstructionCache if they generate or modify code in memory. The CPU cannot detect the change, and may execute the old code it cached."

This is critical for self-modifying code, JIT compilers, and hooking. Without it, your breakpoint might not fire, or worse - you might get unpredictable behavior.

## One-Shot vs Persistent Hooks

**One-shot** - Hook fires once, then the original byte stays restored (our implementation):
```cpp
// Just restore the byte, don't reinstall
RestoreOriginalByte( );
// Hook is gone after first hit
```

**Persistent** - Hook fires every time (requires trap flag):
```cpp
// After handling breakpoint:
// 1. Restore original byte
RestoreOriginalByte( );

// 2. Set trap flag to single-step
ExceptionInfo->ContextRecord->EFlags |= 0x100;  // Trap flag (bit 8)

// 3. Return EXCEPTION_CONTINUE_EXECUTION
// CPU will execute ONE instruction, then fire EXCEPTION_SINGLE_STEP

// 4. In EXCEPTION_SINGLE_STEP handler:
if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
    // Reinstall the breakpoint
    *(unsigned char*)TargetAddress = 0xCC;
    FlushInstructionCache( GetCurrentProcess( ) , TargetAddress , 1 );
    
    // Clear trap flag
    ExceptionInfo->ContextRecord->EFlags &= ~0x100;
    
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

The trap flag (TF) is bit 8 of the EFLAGS register. When set, the CPU generates an `EXCEPTION_SINGLE_STEP` after executing one instruction. This lets you:
1. Execute the original instruction (with breakpoint removed)
2. Catch the single-step exception
3. Reinstall the breakpoint
4. Continue normally

This is how debuggers implement persistent breakpoints. It's trickier because you need to handle two exception types, but it allows the hook to fire on every call.

## Example Output

```
[*] Installing INT3 hook on MessageBoxA...
[+] Target Address: 00007FFC6698D900
[+] Original Byte: 48
[+] VEH Handler: 000001C956EF0000
[+] INT3 hook installed!

[*] Testing MessageBoxA...
[*] EXCEPTION_BREAKPOINT at 00007FFC6698D900
[*] MessageBoxA hooked via INT3!
[*] Restoring original byte and continuing...
```


[*] Testing MessageBoxA again (hook should be gone)...
[MessageBox appears with original text - hook was one-shot]
```
