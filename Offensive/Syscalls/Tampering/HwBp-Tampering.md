# Hardware Breakpoint Argument Rewriting

Using Windows hardware breakpoints and a vectored exception handler to rewrite function arguments at execution time.

## What It Does

Registers a vectored exception handler, programs one of the CPU debug registers (`Dr0` through `Dr3`) to break on a target instruction, and then rewrites function arguments from the exception `CONTEXT` before execution continues.

The project includes a small proof-of-concept around a generic breakpoint engine. It tracks active breakpoint slots, detects which slot fired, applies argument overrides, and resumes execution cleanly. The sample in `Main.cpp` uses this engine to test argument patching against native call sites in a local lab setup.

## How It Works

The code uses the Windows thread-context APIs to access the processor debug registers. When a breakpoint is registered, it captures the current thread context with `GetThreadContext`, writes the target address into one of the debug-address registers (`Dr0` through `Dr3`), updates `Dr7` to enable that slot, and pushes the modified context back with `SetThreadContext`.

To receive control when a breakpoint fires, the program installs a vectored exception handler with `AddVectoredExceptionHandler`. When the processor hits a hardware execution breakpoint, Windows raises `EXCEPTION_SINGLE_STEP` and passes an `EXCEPTION_POINTERS` structure containing both the exception record and the thread `CONTEXT`.

The handler inspects the debug-status bits to determine which breakpoint slot fired, verifies that the current instruction pointer matches the registered address, and looks up the matching entry in the breakpoint table. Each entry can contain a callback and a list of argument overrides.

Argument rewriting is done directly against the exception `CONTEXT`. For register-passed arguments the code updates the appropriate general-purpose registers. For stack-passed arguments it writes the replacement values into the stack locations referenced by the saved stack pointer. This allows the target call to continue with new arguments without changing the original call site in source code.

After the argument updates are applied, the handler sets the resume flag in `EFlags` so the processor does not immediately trap again on the same instruction. It then returns `EXCEPTION_CONTINUE_EXECUTION`, which resumes the interrupted thread with the modified register and stack state.

The engine is intentionally small and table-driven. `FUNCTION_ARGUMENT_OVERRIDE` describes one replacement argument, `HARDWARE_BREAKPOINT_ENTRY` describes one active breakpoint slot, and `RegisterHardwareBreakpointAction` ties a target address to a breakpoint register, optional argument overrides, and an optional callback.

### Credits : Rad9800 and his repo tampering syscall :) https://github.com/rad9800/TamperingSyscalls/
