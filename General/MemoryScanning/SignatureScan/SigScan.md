# Signature Scanning (Pattern Scanning)

Scanning memory for byte patterns with wildcard support.

## What It Does

Searches through a region of memory looking for a specific sequence of bytes. You provide a pattern like "4C 8B D1 B8 ?? ?? ?? ??" where ?? means any byte can match. The scanner finds all locations where the pattern matches and returns their addresses.

## How It Works

The code takes a byte pattern as a string with space separated hex values. First it parses this string into two arrays. One array contains the actual byte values and the other array contains flags indicating which bytes are wildcards. A wildcard is represented by ?? in the pattern string.

The parsing loop uses strtok to split the pattern string on spaces. For each token it checks if it's ?? and if so marks that position as a wildcard. Otherwise it converts the hex string to a byte value using strtoul with base 16. This builds up the pattern byte array and wildcard mask array.

Once the pattern is parsed the code reads the entire target memory region into a local buffer using ReadProcessMemory. This is faster than reading byte by byte during the scan. The buffer contains a copy of the memory you want to search.

Then it slides the pattern across the buffer one byte at a time. For each position it compares the pattern bytes with the buffer bytes. If a pattern byte is marked as a wildcard it always matches. If it's not a wildcard it must match exactly. If all bytes in the pattern match then you found a match and you record the address.

The address is calculated by taking the start address of the region and adding the offset where the match was found. The results are stored in an array and the count is returned. The caller can then use these addresses to do whatever they need.

## Pattern Format

The pattern is a string of space separated hex bytes. Each byte is two hex digits like 4C or B8 or FF. Wildcards are represented by ?? which means that byte can be anything. For example "4C 8B D1 B8 ?? ?? ?? ??" means the first four bytes must be exactly 4C 8B D1 B8 but the next four bytes can be anything.

Wildcards are useful when you're looking for code patterns where some bytes vary. For example syscall stubs in ntdll have a consistent structure but the syscall number changes. So you use wildcards for the syscall number bytes and concrete values for the rest.

## Why Signature Scanning

Signature scanning is used for finding code patterns in memory. This is useful for reverse engineering, game hacking, malware analysis, and security research. You can find function prologues, specific instructions, or unique byte sequences that identify code you're interested in.

For example if you want to find all syscall stubs in ntdll you can scan for the syscall instruction pattern. If you want to find a specific function without using exports you can scan for its unique byte sequence. If you want to detect certain code patterns for security analysis you can scan for them.

Game hacks use signature scanning to find game functions and data structures. The addresses change between game versions but the code patterns stay similar so you use wildcards for the parts that change. Security tools use signature scanning to detect malware patterns or suspicious code.

## ReadProcessMemory

The code reads the entire region into a buffer before scanning. This is much faster than reading during the scan because ReadProcessMemory has overhead. Reading once and scanning the local buffer is more efficient than making thousands of ReadProcessMemory calls.

The downside is memory usage. If you're scanning a large region you need a large buffer. The code uses HeapAlloc to allocate the buffer. For very large regions you might need to scan in chunks instead of reading everything at once.

## Sliding Window

The scan uses a sliding window approach. It starts at offset 0 and checks if the pattern matches. Then it moves to offset 1 and checks again. Then offset 2 and so on. For each offset it compares all the pattern bytes with the buffer bytes at that offset.

The loop goes from 0 to RegionSize minus PatternLen. This ensures you don't read past the end of the buffer. If the region is 1000 bytes and the pattern is 10 bytes you check offsets 0 through 990.

## Wildcard Matching

The inner loop compares pattern bytes with buffer bytes. If the wildcard flag is set for a byte it skips the comparison and continues. This makes that byte always match. If the wildcard flag is not set it compares the bytes and if they don't match it breaks out and moves to the next offset.

This is why wildcards are powerful. You can match patterns where some bytes are variable. Without wildcards you could only find exact byte sequences which is too restrictive for most use cases.

## Multiple Results

The code can find multiple matches. It keeps scanning even after finding a match and stores all results up to MaxResults. This is useful when the pattern appears multiple times in the region. For example there are hundreds of syscall stubs in ntdll so you want to find all of them not just the first one.

The Results array is filled with addresses and MatchCount tracks how many were found. The caller can loop through the results and process each match.

## Example Pattern

The example pattern "4C 8B D1 B8 ?? ?? ?? ?? F6" matches syscall stubs in ntdll on 64 bit Windows. The pattern is:

4C 8B D1 is mov r10, rcx which saves the first parameter. B8 is mov eax followed by four wildcard bytes for the syscall number. F6 is part of the test instruction that follows.

This pattern is specific enough to match syscall stubs but uses wildcards for the syscall number which varies for each function. By scanning for this pattern you can find all syscall stubs in ntdll.

## GetModuleInformation

The code uses GetModuleInformation to get the base address and size of ntdll. This tells you where the module is loaded and how big it is. You need this to know what region to scan. The MODULEINFO structure has lpBaseOfDll which is the base address and SizeOfImage which is the size in bytes.

You could scan any module by changing the GetModuleHandleA parameter. Or you could scan arbitrary memory regions by specifying the start address and size directly.

## Pattern Length Limit

The code has a limit of 256 bytes for the pattern. This is usually more than enough. Most code patterns are 10 to 30 bytes. If you need longer patterns you can increase the array sizes.

## strtok Parsing

The pattern parsing uses strtok which modifies the string. That's why the code copies the pattern to PatternCopy first. strtok replaces spaces with null terminators as it tokenizes the string. Each call to strtok returns the next token until there are no more tokens.

The parsing loop builds up the PatternBytes and Wildcard arrays in parallel. The index PatternLen tracks how many bytes are in the pattern.

## Hex String Conversion

The code uses strtoul with base 16 to convert hex strings to byte values. strtoul parses a string as an unsigned long with the specified base. Base 16 means hexadecimal. So "4C" becomes 0x4C which is 76 in decimal.
