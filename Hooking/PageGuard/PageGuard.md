# PAGE_GUARD Software Breakpoint Hooking

Software breakpoints using PAGE_GUARD are a slick way to hook functions without modifying any code. Instead of patching bytes or messing with import tables, you just mark a memory page as "guarded" and let Windows do the heavy lifting. When code on that page executes, boom - exception fires, you handle it, redirect execution.

## How PAGE_GUARD Works

Windows has this neat feature called guard pages. Mark a page with `PAGE_GUARD` and any access (read, write, execute) triggers a `STATUS_GUARD_PAGE_VIOLATION` exception. The catch? It's one-shot. Once the exception fires, Windows automatically removes the `PAGE_GUARD` flag. You gotta restore it yourself if you want it to keep working.

```
Normal Execution:
1. Code calls function at 0x1000
2. CPU jumps to 0x1000
3. Function executes

With PAGE_GUARD:
1. Code calls function at 0x1000
2. CPU tries to execute 0x1000
3. PAGE_GUARD triggers STATUS_GUARD_PAGE_VIOLATION
4. Your VEH catches it
5. You redirect to your hook
6. PAGE_GUARD flag is removed (one-shot!)
```

## The Single-Step Dance

Here's the tricky part. When `STATUS_GUARD_PAGE_VIOLATION` fires, Windows strips the `PAGE_GUARD` flag from the entire page. If you just restore it immediately, you'll trigger another exception on the same instruction - infinite loop. The solution? Single-stepping.

**The Process:**
1. `STATUS_GUARD_PAGE_VIOLATION` fires
2. Check if it's your target address
3. Redirect execution to your hook
4. Set trap flag (`EFlags |= 0x100`) to enable single-step mode
5. Return `EXCEPTION_CONTINUE_EXECUTION`
6. Next instruction executes
7. `EXCEPTION_SINGLE_STEP` fires
8. Restore `PAGE_GUARD` on the page
9. Clear trap flag (happens automatically)
10. Continue execution

This ensures the PAGE_GUARD gets restored after moving past the guarded instruction.

## The Performance Hit

Software breakpoints are slow. Like, really slow. Every instruction on the guarded page triggers two exceptions:
1. `STATUS_GUARD_PAGE_VIOLATION` - when you hit the page
2. `EXCEPTION_SINGLE_STEP` - to restore the guard

If your target function is on a page with lots of other code, you're gonna feel it. A 4KB page can hold hundreds of instructions. If any of them execute, your exception handler fires. This is why PAGE_GUARD hooking is best for functions that don't get called constantly.

## Implementation Details

### Setting the Guard Page

```cpp
MEMORY_BASIC_INFORMATION PageInfo{};
VirtualQuery( TargetAddress , &PageInfo , sizeof( PageInfo ) );

DWORD OldProtect;
VirtualProtect( PageInfo.BaseAddress , PageInfo.RegionSize , 
                PageInfo.Protect | PAGE_GUARD , &OldProtect );
```

You can't just set `PAGE_GUARD` - you gotta OR it with the existing protection. Otherwise you'll lose execute permissions and crash.

### Vectored Exception Handler

```cpp
AddVectoredExceptionHandler( 1 , ExceptionHandler );
```

The `1` means "first in chain". Your handler gets called before anyone else's. This is crucial because if another handler returns `EXCEPTION_CONTINUE_EXECUTION`, yours never fires.

### Redirecting Execution

```cpp
#if defined(_M_ARM64) || defined(__aarch64__)
    ExceptionInfo->ContextRecord->Pc = (DWORD64)HookFunction;
#elif defined(_M_ARM) || defined(__arm__)
    ExceptionInfo->ContextRecord->Pc = (DWORD)HookFunction;
#elif defined(_WIN64) || defined(__x86_64__)
    ExceptionInfo->ContextRecord->Rip = (DWORD64)HookFunction;
#else
    ExceptionInfo->ContextRecord->Eip = (DWORD)HookFunction;
#endif
```

Modify the instruction pointer in the exception context. When you return `EXCEPTION_CONTINUE_EXECUTION`, the CPU resumes at your hook function instead of the original. On ARM/ARM64, use `Pc` (Program Counter) instead of `Rip`/`Eip`.

### The Trap Flag

```cpp
ExceptionInfo->ContextRecord->EFlags |= 0x100;
```

Bit 8 of EFlags is the trap flag. Set it and the CPU enters single-step mode - one instruction, then `EXCEPTION_SINGLE_STEP`. This is how we get control back to restore the PAGE_GUARD.

## Example Output

```
[*] Installing PAGE_GUARD hook on MessageBoxA...
[+] Target Address: 00007FFE12345678
[+] Page Base: 00007FFE12345000
[+] Page Size: 4096 bytes
[+] Original Protection: 0x20 (PAGE_EXECUTE_READ)
[+] PAGE_GUARD hook installed!

[*] Testing MessageBoxA...
[*] PAGE_GUARD triggered at 00007FFE12345678
[*] MessageBoxA hooked via PAGE_GUARD!
```

## The Bottom Line

PAGE_GUARD hooking is a clever technique that trades performance for stealth and flexibility. It's perfect for scenarios where code integrity matters more than speed. The two-exception dance (guard violation + single step) keeps the hook alive without touching any code bytes. Just remember - it's slow, detectable, and affects an entire page. Use it wisely.
