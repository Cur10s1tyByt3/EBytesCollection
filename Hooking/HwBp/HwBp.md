# Hardware Breakpoint Hooking

Hardware breakpoints are another way to hook functions. No code modification, no memory page tricks - just pure CPU debug register magic. The x86/x64 architecture gives you 4 debug registers (Dr0-Dr3) that can trigger exceptions when code executes at specific addresses. Set one to your target function, catch the exception, redirect execution. Done.

## Debug Registers

The CPU has dedicated hardware for debugging:

**Dr0, Dr1, Dr2, Dr3** - Address registers (hold the breakpoint addresses)
**Dr6** - Debug status register (tells you which breakpoint fired)
**Dr7** - Debug control register (enables/disables breakpoints and sets conditions)

```
Dr7 Layout (simplified):
Bits 0-7:   Enable flags (L0, G0, L1, G1, L2, G2, L3, G3)
Bits 16-31: Condition and length fields for each breakpoint

Dr6 Layout (simplified):
Bits 0-3:   Breakpoint hit flags (B0, B1, B2, B3)
Bit 14:     Single-step flag
```

## How It Works

1. **Set Dr0-Dr3** to your target function address
2. **Enable the breakpoint** in Dr7 (set the corresponding enable bit)
3. **Install VEH** to catch `EXCEPTION_SINGLE_STEP`
4. **When breakpoint fires**, Dr6 tells you which one
5. **Redirect execution** to your hook function
6. **Set resume flag** (EFlags |= 0x10000) to continue

Unlike software breakpoints, hardware breakpoints don't modify memory. The CPU itself watches for execution at the specified address and triggers an exception. Zero footprint in the target code.

## The 4 Breakpoint Limit

You get exactly 4 hardware breakpoints. That's it. Dr0, Dr1, Dr2, Dr3. If you need more, you're out of luck. This is a hard CPU limitation, not a Windows thing. The upside? These 4 are incredibly powerful and nearly impossible to detect without checking debug registers directly.

## Setting a Hardware Breakpoint

```cpp
CONTEXT Ctx = { 0 };
Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext( GetCurrentThread( ) , &Ctx );

// Set Dr0 to target address
Ctx.Dr0 = (DWORD_PTR)TargetAddress;

// Enable Dr0 breakpoint (bit 0 of Dr7)
Ctx.Dr7 |= ( 1ULL << 0 );

// Set condition to "execution" (bits 16-17 = 00)
Ctx.Dr7 &= ~( 3ULL << 16 );

// Set length to 1 byte (bits 18-19 = 00)
Ctx.Dr7 &= ~( 3ULL << 18 );

SetThreadContext( GetCurrentThread( ) , &Ctx );
```

The condition field determines when the breakpoint fires:
- `00` = Execution (what we want for hooking)
- `01` = Data write
- `10` = I/O read/write
- `11` = Data read/write

## Exception Handling

When a hardware breakpoint fires, you get `EXCEPTION_SINGLE_STEP` (not `EXCEPTION_BREAKPOINT` like you might expect). Check Dr6 to see which breakpoint triggered:

```cpp
if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
    // Check if Dr0 breakpoint fired (bit 0 of Dr6)
    if ( ExceptionInfo->ContextRecord->Dr6 & 0x1 ) {
        // Redirect to hook
        ExceptionInfo->ContextRecord->Rip = (DWORD64)HookFunction;
        
        // Set resume flag to continue execution
        ExceptionInfo->ContextRecord->EFlags |= 0x10000;
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}
```

The resume flag (bit 16 of EFlags) is critical. Without it, you'll loop infinitely on the same breakpoint. Setting it tells the CPU "I handled this, move on."


## The Resume Flag

This is the most important part. When a hardware breakpoint fires, you MUST set the resume flag:

```cpp
ExceptionInfo->ContextRecord->EFlags |= 0x10000;
```

Without this, the CPU thinks the breakpoint is still active and will trigger again immediately. Infinite loop. The resume flag tells the CPU "I've handled this exception, clear the breakpoint condition and continue."

## Finding Free Debug Registers

Since you only get 4, you need to check which ones are available:

```cpp
DWORD FindFreeDrIndex( PCONTEXT Ctx ) {
    for ( DWORD i = 0; i < 4; i++ ) {
        // Check if enable bit is set in Dr7
        if ( !( Ctx->Dr7 & ( 1ULL << ( i * 2 ) ) ) )
            return i;
    }
    return (DWORD)-1; // All in use
}
```

This checks the local enable bits (bits 0, 2, 4, 6) in Dr7. If a bit is clear, that debug register is free.

## Example Output

```
[*] Installing hardware breakpoint hook on MessageBoxA...
[+] Target Address: 00007FFE12345678
[+] Using Dr0
[+] Hardware breakpoint hook installed!

[*] Testing MessageBoxA...
[*] Hardware breakpoint triggered at 00007FFE12345678
[*] MessageBoxA hooked via hardware breakpoint!
```

## The Bottom Line

Hardware breakpoints are the precision tool of function hooking. Four shots, make them count. No memory modification, no performance overhead, just pure CPU-level interception. The catch? They're easy to detect if someone knows to look. But if you're up against integrity checks and need stealth, hardware breakpoints are your best friend.

Perfect for targeted hooking where you need surgical precision and can't afford to touch the code. Just remember - you only get 4, and everyone can see them if they check the right registers.
