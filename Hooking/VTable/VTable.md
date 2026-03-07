# VTable Hooking with Shadow VTable

So you wanna hook virtual functions? VTable hooking is one of the cleanest ways to intercept C++ virtual method calls without touching the actual code. This implementation uses a "shadow vtable" approach which is way stealthier than patching the original vtable in place.

## What's a VTable?

When you declare virtual functions in C++, the compiler generates a virtual function table (vtable) - basically an array of function pointers. Each object with virtual functions has a pointer to its class's vtable as the first member. When you call a virtual function, the program looks up the function address in the vtable and jumps to it.

```
Object Layout:
+------------------+
| vptr -> VTable   |  <-- Points to vtable
+------------------+
| member1          |
| member2          |
+------------------+

VTable Layout:
+------------------+
| RTTI pointer     |  <-- Type info (at offset -1)
+------------------+
| Function 0       |  <-- vptr points here
| Function 1       |
| Function 2       |
+------------------+
```

## How Shadow VTable Hooking Works

Instead of modifying the original vtable (which anti-cheat can detect), we:

1. **Copy the entire vtable** to a new memory region (the "shadow")
2. **Modify our copy** to point to our hook function
3. **Swap the object's vptr** to point to our shadow vtable

This is way harder to detect because:
- Original vtable stays untouched
- Each hooked object gets its own shadow (doesn't affect other instances)
- Memory protection on original vtable never changes

## VTable Scanner

The tricky part is figuring out where the vtable ends. There's no size field, so we scan until we hit something that's not a valid function pointer.

### Validation Checks

Our scanner uses multiple heuristics to reliably detect vtable boundaries:

**1. Pointer Alignment**
```cpp
if ( (DWORD_PTR)Entry % sizeof( void* ) != 0 )
    return FALSE;
```
Function pointers are always pointer-aligned (4 bytes on x86, 8 on x64).

**2. Memory Region Validation**
```cpp
MEMORY_BASIC_INFORMATION Mbi{};
VirtualQuery( Entry , &Mbi , sizeof( Mbi ) );
```
We check that:
- Memory is committed (`MEM_COMMIT`)
- It's part of a module image (`MEM_IMAGE`)
- It has execute permissions (`PAGE_EXECUTE*`)

**3. VTable Region Consistency**
```cpp
if ( CurrentMbi.BaseAddress != FirstMbi.BaseAddress )
    break;
```
All vtable entries should be in the same memory region. If we cross into a different region, we've hit the boundary.

**4. RTTI Detection**
```cpp
void* RttiPtr = VTableBase[-1];
```
MSVC stores a pointer to type_info at offset -1 from the vtable. We can validate this to confirm we're looking at a real vtable.

### Why This Matters

Without proper validation, you might:
- Read past the vtable into random data
- Hook the wrong function index
- Crash when calling invalid pointers
- Get detected by anti-cheat scanning for invalid vtables

## Usage

```cpp
BaseClass* Obj = new DerivedClass{ };

// Hook the Name() function at index 2
void* OriginalName = nullptr;
FunStuff::VTableHook::Install( Obj , 2 , HookName , &OriginalName );

// Call goes through our hook
Obj->Name( );

// Restore original vtable
FunStuff::VTableHook::Remove( );
```

## Detection Vectors

Even shadow vtables can be detected:

**1. VTable Location Check**
Anti-cheat can verify vtables are in the module's .rdata section. Our shadow is in heap memory, which is suspicious.

**2. Multiple Objects Comparison**
If you hook one object but not others of the same class, comparing their vptrs reveals the hook.

**3. Memory Scanning**
Scanning for executable memory regions that aren't part of loaded modules can find shadow vtables.

**4. Integrity Checks**
Some games checksum their vtables at startup and verify them periodically.

## Research Sources

- MSVC vtable layout includes RTTI pointer at offset -1
- VirtualQuery is safer than deprecated IsBadCodePtr
- Vtables reside in MEM_IMAGE regions with read-only protection
- Shadow vtables are common in game hacking but detectable
- Alignment and region consistency are reliable boundary indicators
