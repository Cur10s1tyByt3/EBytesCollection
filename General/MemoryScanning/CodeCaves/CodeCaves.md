# Code Cave Finder

Finding unused space in PE sections for code injection.

## What It Does

Scans all sections of a PE file looking for sequences of null bytes. These sequences are called code caves and they're unused space where you can inject code or data. The finder reports the location, size, and section name of each cave.

## How It Works

The code starts with the base address of a loaded PE image. It navigates to the NT headers and gets the section table. The section table is an array of IMAGE_SECTION_HEADER structures, one for each section in the PE file.

For each section it gets the PointerToRawData which is the file offset where the section data starts and the SizeOfRawData which is how many bytes the section occupies. It calculates the section base address by adding the PointerToRawData to the image base.

Then it walks through the section byte by byte looking for null bytes. When it finds a null byte it increments a counter. When it finds a non null byte it checks if the counter is greater than the minimum cave size. If it is then you found a code cave. It records the cave information and resets the counter.

The cave information includes a pointer to the section header, the section name copied from the header, the size of the cave in bytes, the raw address which is the file offset, and the virtual address which is where the cave would be in memory when the image is loaded.

The virtual address is calculated by adding the cave offset to the preferred image base from the optional header. This gives you the address where the cave will be when the module is loaded at its preferred base. If the module is relocated the actual address will be different but the offset from the base stays the same.

After scanning all sections the function returns the count of caves found. The caller can loop through the results and use the caves for whatever purpose.

## Code Caves

A code cave is a sequence of unused bytes in a PE section. These bytes are typically null padding added by the compiler or linker to align sections or fill space. The bytes aren't used by the program so you can overwrite them with your own code or data without breaking anything.

Code caves are useful for code injection. Instead of allocating new memory with VirtualAlloc you can use existing unused space in the target module. This is stealthier because you're not creating new memory regions that security software might detect.

The size of a cave determines what you can fit in it. A 64 byte cave can hold a small shellcode stub. A 256 byte cave can hold more complex code. Larger caves are rare but when you find them they're valuable.

## Section Scanning

The code scans every section in the PE file. Sections are named regions like .text for code, .data for initialized data, .rdata for read only data, .bss for uninitialized data, and .rsrc for resources. Each section has different characteristics and protection flags.

The section header contains the section name, virtual address, virtual size, raw data pointer, raw data size, characteristics, and other fields. The code uses PointerToRawData and SizeOfRawData to know where to scan.

## Null Byte Detection

The scanner looks for consecutive null bytes. It walks through the section and increments a counter for each null byte. When it hits a non null byte it checks if the counter exceeds the minimum size. If it does that's a cave.

This approach finds caves of any size. You specify the minimum size to filter out small caves that aren't useful. The example uses 64 bytes as the minimum but you can adjust this based on your needs.

## Raw Address vs Virtual Address

The raw address is the file offset where the cave is located. This is useful if you're patching a file on disk. The virtual address is where the cave will be in memory when the module is loaded. This is useful if you're injecting into a running process.

The virtual address is calculated as ImageBase plus the cave offset. The ImageBase comes from the optional header and is the preferred load address. On 64 bit systems this is typically a high address like 0x140000000. On 32 bit systems it's typically 0x400000 for executables and 0x10000000 for DLLs.

If the module is relocated due to ASLR or base conflicts the actual load address will be different. You'd need to adjust the virtual address by the relocation delta. But the offset from the base stays the same so you can always calculate the real address.

## Section Names

Section names are stored as 8 byte arrays in the section header. They're not null terminated if the name is exactly 8 characters. The code copies the name and adds a null terminator to make it a proper C string.

Common section names are .text, .data, .rdata, .bss, .rsrc, .reloc, and .idata. Some compilers use different names or add custom sections. The name helps you understand what the section is for and whether it's safe to use caves in it.

## IMAGE_FIRST_SECTION

This macro calculates the address of the first section header. The section table immediately follows the optional header. The macro adds the size of the optional header to the NT headers address to get the section table address.

The section table is an array so you can iterate through it by incrementing the section pointer. The NumberOfSections field in the file header tells you how many sections there are.

## Why Minimum Size

Small caves aren't useful for most purposes. A 5 byte cave can't hold much code. A 10 byte cave might hold a short jump. A 64 byte cave can hold a decent shellcode stub. By filtering out small caves you focus on the useful ones.

The minimum size is a parameter so you can adjust it. If you only need to inject a few bytes you can lower the minimum. If you need to inject a large payload you can raise it.

## Cave Characteristics

Not all caves are equal. Caves in the .text section are executable but might be in read only memory. Caves in the .data section are writable but not executable. Caves in the .rdata section are read only. You need to consider the section characteristics when choosing a cave.

The code doesn't check section characteristics. It just finds caves. You'd need to check the Characteristics field in the section header to see if the section is executable, writable, or read only. Then choose caves that match your needs.

## Padding and Alignment

Compilers and linkers add padding for alignment. Sections are typically aligned to 512 byte or 4096 byte boundaries. If a section is 1000 bytes it might be padded to 4096 bytes leaving 3096 bytes of null padding. That's a large code cave.

Functions are also aligned. If a function is 50 bytes it might be padded to 64 bytes leaving 14 bytes of null padding. These small caves add up and the scanner finds them all.

## False Positives

The scanner looks for null bytes but not all null bytes are caves. Some data structures contain null bytes as part of their data. Some code contains null bytes in immediate values or padding. The scanner can't distinguish between intentional nulls and padding nulls.

In practice this isn't a big problem. Most caves are in padding at the end of sections or between functions. If you inject into a false positive you might corrupt data or code but you can test the cave first to make sure it's safe.

## Injection Use Case

Once you find a cave you can inject code into it. You'd write your shellcode to the cave address, modify the entry point or a function to jump to your cave, execute your code, then jump back. This is a common code injection technique.

The advantage of using caves is you don't need to allocate new memory. The cave already exists in the target module. This is stealthier and avoids creating suspicious memory regions.

## File Patching

If you're patching a file on disk you use the raw address. You open the file, seek to the raw address, write your code, and save the file. When the file is loaded your code will be at the virtual address.

This is how some packers and protectors work. They find caves in the original executable, inject their code into the caves, and modify the entry point to run their code first.

## Memory Patching

If you're patching a running process you use the virtual address. You open the process, change the memory protection to writable with VirtualProtectEx, write your code to the virtual address with WriteProcessMemory, restore the protection, and flush the instruction cache with FlushInstructionCache.

This is how some game hacks and DLL injectors work. They find caves in loaded modules, inject their code, and hook functions to redirect execution to their code.

## Section Iteration

The code iterates through sections by incrementing the section pointer. The section table is a contiguous array so you can treat it like a C array. The loop goes from 0 to NumberOfSections and increments the section pointer each iteration.

## Cave Offset Calculation

When a cave is found the offset is calculated as PointerToRawData plus the current index minus the cave size. The current index is where the non null byte was found. The cave size is how many null bytes preceded it. Subtracting the cave size gives you the start of the cave.

This offset is both the raw address and the offset from the image base. You add it to the preferred image base to get the virtual address.

## Buffer Limit

The code has a limit of 512 caves. If more caves are found the scanning stops at 512. Most executables have fewer than 512 caves so this is usually enough. You could increase the limit or make it dynamic if needed.

---

That's code cave finding. Scan PE sections for sequences of null bytes, record their location and size, and report them for potential code injection use.
