# Import Address Table (IAT) Parser

Parsing the Import Address Table of a loaded PE image to see all imported functions and their resolved addresses.

## What It Does

Walks through the IAT of a loaded module and prints every imported function. For each function it shows the function name, which DLL it comes from, and the actual memory address where that function is located. This lets you see exactly what external functions a module uses and where they're resolved to in memory.

## How It Works

The code starts with the base address of a loaded PE image. In this case it uses GetModuleHandleA(NULL) which returns the base address of the current executable. From the base address you can navigate the PE structure to find the import directory.

First you read the DOS header which is at the very start of the PE file. The DOS header has an e_lfanew field that points to the NT headers. The NT headers contain the optional header which has a data directory array. Index 1 of this array is IMAGE_DIRECTORY_ENTRY_IMPORT which gives you the RVA and size of the import directory.

The import directory is an array of IMAGE_IMPORT_DESCRIPTOR structures. Each descriptor represents one DLL that the module imports from. The array is terminated by a zeroed descriptor. Each descriptor has a Name field which is an RVA pointing to the DLL name string. It also has OriginalFirstThunk and FirstThunk fields which point to arrays of thunk data.

OriginalFirstThunk points to the Import Name Table which contains the names or ordinals of the imported functions. FirstThunk points to the Import Address Table which contains the actual resolved addresses of those functions. Before the module is loaded both arrays contain the same data but after loading FirstThunk is overwritten by the loader with the real function addresses.

You walk both arrays in parallel. For each entry you check if it's imported by name or by ordinal. If the high bit is not set it's imported by name so you follow the AddressOfData RVA to an IMAGE_IMPORT_BY_NAME structure which contains the function name. If the high bit is set it's imported by ordinal so you mask off the high bit to get the ordinal number.

The code prints the DLL name, then loops through all the functions imported from that DLL, showing the function name or ordinal and the resolved address from the IAT. Then it moves to the next import descriptor and repeats until it hits the null terminator.

## PE Structure Navigation

A PE file has a specific structure. At offset 0 is the DOS header which starts with MZ. The DOS header has e_lfanew which points to the NT headers. The NT headers start with the signature PE followed by the file header and optional header. The optional header contains the data directory array which has entries for imports, exports, resources, relocations, and other things.

Each data directory entry has a VirtualAddress which is an RVA and a Size. An RVA is a relative virtual address meaning it's an offset from the image base. To convert an RVA to an actual pointer you add it to the base address. So if the import directory RVA is 0x2000 and the base is 0x400000 the import directory is at 0x402000.

## IMAGE_IMPORT_DESCRIPTOR

This structure describes one imported DLL. The important fields are:

OriginalFirstThunk is an RVA to the Import Name Table. This table contains the names or ordinals of the functions being imported. This table is not modified by the loader so it always contains the original data.

FirstThunk is an RVA to the Import Address Table. This table initially contains the same data as OriginalFirstThunk but the loader overwrites it with the actual function addresses when the module is loaded. This is what the code uses to call imported functions.

Name is an RVA to a null terminated string containing the DLL name like kernel32.dll or ntdll.dll.

TimeDateStamp and ForwarderChain are used for binding and forwarding but usually not relevant for basic IAT parsing.

## Thunk Data

Both the Import Name Table and Import Address Table are arrays of IMAGE_THUNK_DATA structures. This structure is a union that can hold different types of data. Before loading it holds either an RVA to an IMAGE_IMPORT_BY_NAME structure or an ordinal value. After loading the IAT thunks hold function pointers.

The high bit of the thunk determines if it's an ordinal import. If IMAGE_ORDINAL_FLAG is set then the low bits contain the ordinal number. If the flag is not set then the value is an RVA to an IMAGE_IMPORT_BY_NAME structure.

## IMAGE_IMPORT_BY_NAME

This structure contains a function name. It has a Hint field which is a suggested index into the export table of the target DLL. The loader can use this hint to speed up the lookup but it's not required. After the hint comes the Name field which is a null terminated string containing the function name like CreateFileW or NtQuerySystemInformation.

## Import by Ordinal

Some functions are imported by ordinal instead of by name. An ordinal is just a number that identifies the function in the export table. Importing by ordinal is slightly faster because the loader doesn't need to do a string comparison but it's fragile because ordinals can change between versions. Most modern code imports by name.

When you see an ordinal import the code prints Ordinal followed by the number. You can look up what function that ordinal corresponds to by checking the export table of the target DLL but that requires parsing the exports which this code doesn't do.

## Why Parse the IAT

Parsing the IAT is useful for several reasons. You can see what functions a module uses which helps with reverse engineering. You can detect IAT hooking where malware or security software modifies the function pointers to redirect calls. You can resolve function addresses without calling GetProcAddress. You can analyze dependencies and see what DLLs a module requires.

Security tools parse the IAT to detect hooks. If a function pointer in the IAT doesn't point to the expected DLL it might be hooked. Malware sometimes hooks the IAT to intercept API calls. Debuggers use the IAT to set breakpoints on imported functions.

## IAT Hooking

IAT hooking is a technique where you modify the function pointers in the IAT to redirect calls to your own code. For example if a program calls CreateFileW you can change the IAT entry for CreateFileW to point to your hook function. Your hook can do whatever it wants then call the real CreateFileW. This is a common technique for API monitoring, DLL injection, and malware.

The IAT is writable by default so hooking it is easy. You just change the memory protection to writable, overwrite the function pointer, and restore the protection. Some security software uses IAT hooks to monitor API calls. Some malware uses IAT hooks to hide its activity or bypass security checks.

## OriginalFirstThunk vs FirstThunk

OriginalFirstThunk is the Import Name Table and FirstThunk is the Import Address Table. Before the module is loaded both contain the same data which is either RVAs to IMAGE_IMPORT_BY_NAME structures or ordinal values. The loader walks OriginalFirstThunk to get the function names or ordinals, resolves them to addresses, and writes the addresses into FirstThunk.

After loading OriginalFirstThunk still contains the original data but FirstThunk contains function pointers. This is why you walk both in parallel. You use OriginalFirstThunk to get the function name and FirstThunk to get the resolved address.

Some packed or obfuscated executables might not have OriginalFirstThunk. In that case you can only see the resolved addresses in FirstThunk but not the function names. This makes analysis harder which is why malware sometimes strips OriginalFirstThunk.

## GetModuleHandleA(NULL)

This returns the base address of the current executable. It's equivalent to the ImageBase value in the PE optional header. You can also pass a DLL name to GetModuleHandleA to get the base of a loaded DLL. Once you have the base you can parse the IAT of that module.

The code parses its own IAT but you could easily modify it to parse any loaded module. Just pass a different base address to ParseIat. You could enumerate all loaded modules with EnumProcessModules and parse the IAT of each one.

## RVA to Pointer Conversion

Throughout the code you see Base + SomeRva. This converts an RVA to an actual pointer. An RVA is relative to the image base so you add the base to get the absolute address. For example if the import directory RVA is 0x2000 and the base is 0x140000000 the import directory pointer is 0x140002000.

This only works for loaded images where the RVAs are already mapped into memory. If you're parsing a PE file on disk you need to convert RVAs to file offsets using the section headers which is more complex.

## Null Termination

The import descriptor array is terminated by a zeroed descriptor. The code checks if ImportDesc->Name is 0 to detect the end. Similarly the thunk arrays are terminated by a zero thunk. The code checks if OrgThunk->u1.AddressOfData is 0 to detect the end of the function list for a DLL.

This is a common pattern in PE structures. Arrays are terminated by a zeroed entry rather than having an explicit count field. You walk the array until you hit the terminator.

---

That's IAT parsing. Navigate the PE structure, walk the import descriptors, walk the thunk arrays, and print the function names and addresses.
