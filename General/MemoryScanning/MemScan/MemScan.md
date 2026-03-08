
# Memory Scanning for Values and Strings

Scanning process memory for specific DWORD values and strings.

## What It Does

Enumerates all committed memory regions in a process and scans them for specific values. You can search for DWORD values like integers or pointers, or you can search for strings. The scanner returns all addresses where the target value or string is found.

## How It Works

The code has three main parts. First it enumerates all memory regions in the process. Then it scans those regions for DWORD values. Then it scans those regions for strings. Each part is a separate function.

GetProcessMemoryRegions walks the entire virtual address space of the process using VirtualQueryEx. This function queries information about a memory region at a specific address. It returns a MEMORY_BASIC_INFORMATION structure that describes the region including its base address, size, state, protection, and type.

The enumeration loop starts at address NULL and keeps calling VirtualQueryEx. After each call it advances the base address by the region size to move to the next region. This continues until VirtualQueryEx fails which means you've reached the end of the address space.

The code only collects committed regions. Memory can be in three states: free, reserved, or committed. Free means no memory is allocated. Reserved means the address range is reserved but no physical memory is backing it. Committed means physical memory is allocated and you can read and write it. Only committed regions have actual data so those are the only ones worth scanning.

ScanForDword takes the list of regions and scans each one for a specific DWORD value. For each region it allocates a buffer, reads the region into the buffer with ReadProcessMemory, then scans the buffer byte by byte looking for the target value. When it finds a match it records the address and continues scanning.

The scan advances by sizeof(DWORD) each iteration because DWORDs are 4 bytes and typically aligned on 4 byte boundaries. This is faster than checking every byte and usually sufficient for finding DWORD values.

ScanForString works similarly but scans for strings instead of DWORDs. It reads each region into a buffer then slides through the buffer one byte at a time comparing the target string with the buffer contents using lstrcmpA. When it finds a match it records the address.

The string scan advances by 1 byte each iteration because strings can start at any byte offset. It checks if the string at the current offset matches the target string. The loop stops when it reaches the end of the buffer minus the string length to avoid reading past the end.

## VirtualQueryEx

This function queries information about a memory region. You pass it a process handle and an address and it fills a MEMORY_BASIC_INFORMATION structure with details about the region containing that address.

The structure tells you the base address of the region, the size of the region, the allocation base which is where the original allocation started, the allocation protection which is the initial protection flags, the current state which is free, reserved, or committed, the current protection which is the current access rights, and the type which is private, mapped, or image.

By calling VirtualQueryEx repeatedly and advancing the address you can walk the entire address space and enumerate all regions. This is how memory scanners and debuggers discover what memory exists in a process.

## Memory States

MEM_FREE means the address range is not allocated. You can't read or write it. MEM_RESERVE means the address range is reserved but no physical memory backs it. You can't read or write it yet. MEM_COMMIT means physical memory is allocated and you can read and write it according to the protection flags.

The code checks if the state is MEM_COMMIT before adding the region to the list. This filters out free and reserved regions which have no data to scan.

## Memory Protection

Each region has protection flags that control access. PAGE_NOACCESS means you can't access it at all. PAGE_READONLY means you can read but not write. PAGE_READWRITE means you can read and write. PAGE_EXECUTE means you can execute code. PAGE_EXECUTE_READ means you can execute and read. PAGE_EXECUTE_READWRITE means you can do everything.

The code doesn't filter by protection. It scans all committed regions regardless of protection. This means it scans code, data, stack, heap, everything. If you only want to scan writable memory you could check the protection flags and skip regions that aren't writable.

## ReadProcessMemory

This function reads memory from a process into a local buffer. It works for both the current process and remote processes. For the current process you could also just cast the address to a pointer and read directly but ReadProcessMemory is safer because it handles invalid addresses gracefully.

The code reads the entire region into a buffer before scanning. This is faster than reading during the scan because ReadProcessMemory has overhead. Reading once and scanning the local buffer is more efficient.

## DWORD Scanning

The DWORD scanner looks for 4 byte integer values. It advances by 4 bytes each iteration and compares the DWORD at the current offset with the target value. If they match it records the address.

This is useful for finding specific values in memory. For example if you're debugging and you know a variable has value 1234 you can scan for 1234 and find all locations where that value exists. Game hacks use this to find health values, ammo counts, or other game variables.

The scan is aligned to DWORD boundaries which means it only checks addresses that are multiples of 4. This is usually fine because compilers align DWORDs on 4 byte boundaries for performance. If you need to find unaligned DWORDs you could advance by 1 byte instead of 4.

## String Scanning

The string scanner looks for null terminated strings. It advances by 1 byte each iteration and uses lstrcmpA to compare the string at the current offset with the target string. lstrcmpA compares until it hits a null terminator or finds a mismatch.

This is useful for finding strings in memory. For example you can find where a DLL name is stored, where error messages are located, or where configuration strings are kept. Reverse engineers use this to find interesting strings that reveal what the program does.

The scan is byte by byte because strings can start at any offset. This is slower than the DWORD scan but necessary for finding strings.

## Multiple Results

Both scanners can find multiple matches. They keep scanning even after finding a match and store all results up to MaxResults. This is important because the same value or string often appears many times in memory.

For example the value 0 appears millions of times in memory. The string VirtualAlloc might appear in multiple DLLs or in the IAT of multiple modules. The scanner finds all of them and lets you decide which ones are relevant.

## Buffer Allocation

For each region the code allocates a buffer with HeapAlloc, reads the region into the buffer, scans the buffer, then frees the buffer with HeapFree. This is done for every region.

An optimization would be to allocate one large buffer and reuse it for all regions. You'd allocate a buffer the size of the largest region then reuse it for smaller regions. This would reduce allocation overhead.

## Address Calculation

When a match is found the code calculates the address by adding the region base address and the offset within the buffer. The region base is where the region starts in the process address space. The offset is where the match was found in the buffer. Adding them gives you the actual address in the process.

## Example Usage

The example scans for the DWORD value 4 and the string VirtualAlloc. The value 4 is chosen arbitrarily to demonstrate DWORD scanning. It will find many matches because 4 is a common value. The string VirtualAlloc is chosen because it appears in the IAT of most programs that use memory allocation.

You can change the target value or string to search for whatever you want. Scan for specific integers, pointers, function names, error messages, or any other data.

## Performance

Memory scanning is slow because you're reading and searching through potentially gigabytes of memory. The current process might have hundreds of regions totaling hundreds of megabytes. Reading and scanning all of that takes time.

For better performance you could filter regions by protection or type. For example only scan writable regions if you're looking for variables. Only scan private regions if you're looking for heap data. Only scan image regions if you're looking for code or strings in modules.

## Remote Process Scanning

The code uses ReadProcessMemory which works for remote processes. If you pass a handle to another process it will scan that process's memory. You need PROCESS_VM_READ permission to read remote process memory.

This is useful for analyzing other processes, finding values in games, or monitoring what other programs are doing. Game hacks use this to scan game memory from an external process.

## Region Count Limit

The code has a limit of 4096 regions. This is usually enough for most processes. If a process has more regions the enumeration will stop at 4096. You could increase the limit or make it dynamic by reallocating the array as needed.

## Result Count Limit

Both scanners have a limit of 1024 results. If more matches are found the scanning stops at 1024. You could increase the limit or make it dynamic. For common values like 0 or 1 you'll hit the limit quickly.

## Why Scan Memory

Memory scanning is used for debugging, reverse engineering, game hacking, and security analysis. You can find where specific values are stored, locate strings and data structures, discover hidden functionality, or analyze how a program uses memory.

Cheat Engine and similar tools use memory scanning to find game variables. Debuggers use it to search for values during debugging. Security researchers use it to find sensitive data or analyze malware behavior.
