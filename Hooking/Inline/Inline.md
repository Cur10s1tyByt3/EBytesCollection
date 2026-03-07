# Inline Hooking with Trampolines

Inline hooking is the classic way to intercept function calls. You overwrite the first few bytes of a function with a jump to your hook, execute your code, then jump to a "trampoline" that holds the stolen bytes and returns to the original function. Simple, effective, and works on any function you can write to.
> THIS IS POC, DONT USE IN PRODUCTION USE MinHook/Detours etc, way more reliable.
## The Problem with Basic Inline Hooks

If you just overwrite the start of a function with a jump, you lose those original instructions. They're gone. You can redirect to your hook, but you can't call the original function anymore because you destroyed it. That's where trampolines come in.

## What's a Trampoline?

A trampoline is a small chunk of dynamically allocated executable memory that holds:
1. The original instructions you overwrote (the "stolen bytes")
2. A jump back to the rest of the original function

```
Original Function:
[JMP to hook] [NOP] [NOP] [rest of function...]
                              ^
Trampoline:                   |
[stolen bytes] [JMP back] ----+
```

When you want to call the original function, you call the trampoline instead. It executes the stolen bytes, then jumps back to continue the original function as if nothing happened.

## x86 vs x64 Jumps

**x86 (32-bit) - 5 byte relative jump:**
```
E9 XX XX XX XX    jmp rel32
```
Offset is relative to the next instruction. Range: ±2GB

**x64 (64-bit) - 12 byte absolute jump:**
```
48 B8 XX XX XX XX XX XX XX XX    mov rax, imm64
FF E0                              jmp rax
```
Can jump anywhere in 64-bit address space.

Why not use relative jumps on x64? Because functions can be more than 2GB apart in memory. Absolute jumps always work.

## Instruction Length Disassembly

You can't just copy 5 or 12 bytes. Instructions are variable length on x86/x64 (1-15 bytes). If you split an instruction in half, you'll crash. You need to disassemble until you have enough complete instructions.

```cpp
size_t GetMinimumHookSize( void* Address , size_t MinSize ) {
    size_t TotalSize = 0;
    while ( TotalSize < MinSize ) {
        size_t InstrLen = GetInstructionLength( Current );
        TotalSize += InstrLen;
        Current += InstrLen;
    }
    return TotalSize;
}
```

This ensures you only copy complete instructions. If you need 12 bytes but the first 3 instructions are 14 bytes total, you copy all 14.

## The Stolen Bytes Problem

When you relocate instructions to the trampoline, some might break. Specifically:

**RIP-relative addressing (x64):**
```
cmp [rip + 0x1000], r11d
```
This reads from an address relative to the instruction pointer. If you copy it to the trampoline, RIP changes and it reads from the wrong place. This is extremely common in x64 function prologues.

**Relative jumps/calls:**
```
call 0x12345678    ; relative offset
```
Same problem - the offset is relative to the current location.

**The Solutions:**

1. **Full disassembler with instruction fixing** - Detect RIP-relative instructions and recalculate offsets. Complex but proper, we have MinHook, Detours and one engine i forgot...

2. **Unhook/Rehook pattern** - Temporarily remove the hook, call the original, reinstall the hook:
```cpp
int WINAPI HookFunc( ... ) {
    RemoveHook( );
    int Result = OriginalFunc( ... );
    InstallHook( );
    return Result;
}
```
Simple and works for most cases. Slight performance overhead but avoids the relocation problem entirely.

3. **Hook functions with simple prologues** - Some functions start with simple instructions like `push rbp; mov rbp, rsp` that don't use RIP-relative addressing. These work fine with basic trampolines.

## Creating the Trampoline

```cpp
// Allocate executable memory
void* Trampoline = VirtualAlloc( nullptr , Size , 
                                 MEM_COMMIT | MEM_RESERVE , 
                                 PAGE_EXECUTE_READWRITE );

// Copy stolen bytes
memcpy( Trampoline , OriginalBytes , StolenSize );

// Add jump back to original function
void* ReturnAddr = (char*)OriginalFunc + StolenSize;

#ifdef _WIN64
    // mov rax, ReturnAddr; jmp rax
    Trampoline[StolenSize + 0] = 0x48;
    Trampoline[StolenSize + 1] = 0xB8;
    *(DWORD64*)&Trampoline[StolenSize + 2] = (DWORD64)ReturnAddr;
    Trampoline[StolenSize + 10] = 0xFF;
    Trampoline[StolenSize + 11] = 0xE0;
#else
    // jmp rel32
    Trampoline[StolenSize + 0] = 0xE9;
    *(DWORD*)&Trampoline[StolenSize + 1] = 
        (DWORD)( ReturnAddr - ( Trampoline + StolenSize + 5 ) );
#endif
```

## Installing the Hook

```cpp
// Save original bytes
memcpy( OriginalBytes , TargetFunc , StolenSize );

// Make target writable
DWORD OldProtect;
VirtualProtect( TargetFunc , StolenSize , PAGE_EXECUTE_READWRITE , &OldProtect );

// Write jump to hook
#ifdef _WIN64
    // mov rax, HookFunc; jmp rax
    Target[0] = 0x48;
    Target[1] = 0xB8;
    *(DWORD64*)&Target[2] = (DWORD64)HookFunc;
    Target[10] = 0xFF;
    Target[11] = 0xE0;
    
    // NOP out remaining bytes
    for ( size_t i = 12; i < StolenSize; i++ )
        Target[i] = 0x90;
#else
    // jmp rel32
    Target[0] = 0xE9;
    *(DWORD*)&Target[1] = (DWORD)( HookFunc - ( Target + 5 ) );
    
    // NOP out remaining bytes
    for ( size_t i = 5; i < StolenSize; i++ )
        Target[i] = 0x90;
#endif

// Restore protection
VirtualProtect( TargetFunc , StolenSize , OldProtect , &OldProtect );
```

## Why NOP the Extra Bytes?

If you steal 14 bytes but your jump is only 12, you have 2 bytes left over. Those bytes are now in the middle of your jump instruction from the CPU's perspective. If any code tries to jump to those bytes (unlikely but possible), it'll execute garbage. NOPs (0x90) are safe - they do nothing.

## Calling the Original Function

**Option 1: Unhook/Rehook Pattern (Recommended)**
```cpp
int WINAPI HookMessageBoxA( HWND H , LPCSTR T , LPCSTR C , UINT U ) {
    printf( "[*] Hooked!\n" );
    
    // Temporarily remove hook
    RemoveHook( );
    int Result = MessageBoxA( H , "Modified" , "Title" , U );
    // Reinstall hook
    InstallHook( );
    
    return Result;
}
```

This avoids the RIP-relative instruction problem by calling the original function directly. Simple and reliable.

**Option 2: Trampoline (Advanced)**
```cpp
int WINAPI HookMessageBoxA( HWND H , LPCSTR T , LPCSTR C , UINT U ) {
    printf( "[*] Hooked!\n" );
    
    // Call trampoline to execute original function
    return TrampolineMessageBoxA( H , "Modified" , "Title" , U );
}
```

Only works if the stolen bytes don't contain RIP-relative instructions. Requires instruction fixing for full reliability.
