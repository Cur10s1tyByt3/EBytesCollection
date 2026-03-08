# Export Address Table (EAT) Parser

Parsing the Export Address Table of a loaded PE image to see all exported functions and their addresses.

## What It Does

Walks through the EAT of a loaded DLL and prints every exported function. For each function it shows the function name, the ordinal number, and the actual memory address where that function is located. This lets you see what functions a DLL exposes and where they're located in memory.

## How It Works

The code starts with the base address of a loaded module. In this case it uses GetModuleHandleA to get the base of kernel32.dll. From the base address you navigate the PE structure to find the export directory.

First you read the DOS header at the start of the PE file. The e_lfanew field points to the NT headers. The NT headers contain the optional header which has a data directory array. Index 0 of this array is IMAGE_DIRECTORY_ENTRY_EXPORT which gives you the RVA of the export directory.

The export directory is an IMAGE_EXPORT_DIRECTORY structure. This structure contains three important arrays. AddressOfFunctions is an array of RVAs pointing to the actual function code. AddressOfNames is an array of RVAs pointing to function name strings. AddressOfNameOrdinals is an array of indices that map names to functions.

The way it works is you loop through the AddressOfNames array. For each name you look up the corresponding index in AddressOfNameOrdinals. That index tells you which entry in AddressOfFunctions contains the RVA for that function. You add the RVA to the base address to get the actual function pointer.

The export directory also has a Base field which is the starting ordinal number. Ordinals are sequential numbers that identify functions. The actual ordinal for a function is Base plus the index in the AddressOfFunctions array. The code calculates this and prints it along with the function name and address.

## IMAGE_EXPORT_DIRECTORY

This structure describes the exports of a DLL. The important fields are:

Name is an RVA to a string containing the DLL name. This is the internal name of the DLL which might be different from the filename.

Base is the starting ordinal number. Ordinals start at this value and increment for each function. Usually Base is 1 but it can be any value.

NumberOfFunctions is the total count of exported functions including those exported only by ordinal.

NumberOfNames is the count of functions that have names. Some functions might only be exported by ordinal so NumberOfNames can be less than NumberOfFunctions.

AddressOfFunctions is an RVA to an array of DWORDs. Each DWORD is an RVA to a function. The array has NumberOfFunctions entries.

AddressOfNames is an RVA to an array of DWORDs. Each DWORD is an RVA to a function name string. The array has NumberOfNames entries.

AddressOfNameOrdinals is an RVA to an array of WORDs. Each WORD is an index into the AddressOfFunctions array. The array has NumberOfNames entries.

## Three Parallel Arrays

The export table uses three parallel arrays to map names to functions. This design is a bit confusing at first but it's efficient.

AddressOfNames contains RVAs to name strings. If you want to find a function by name you search this array for the matching name. The index where you find the name is important.

AddressOfNameOrdinals contains indices. You use the index from AddressOfNames to look up the corresponding entry in AddressOfNameOrdinals. This gives you an index into AddressOfFunctions.

AddressOfFunctions contains RVAs to the actual functions. You use the index from AddressOfNameOrdinals to look up the function RVA in this array. Add the RVA to the base to get the function pointer.

So the lookup is Names[i] gives you the name, Ordinals[i] gives you the function index, Functions[Ordinals[i]] gives you the function RVA.

## Why Three Arrays

You might wonder why not just have one array with name and address pairs. The reason is ordinals. Some functions are exported only by ordinal without a name. The AddressOfFunctions array has entries for all functions but the AddressOfNames array only has entries for named functions. The AddressOfNameOrdinals array maps between them.

This design lets you export functions by ordinal only which saves space in the export table. It also lets you have multiple names point to the same function by having multiple name entries with the same ordinal index.

## Ordinal Calculation

The ordinal for a function is Base plus the index in AddressOfFunctions. So if Base is 1 and a function is at index 0 in AddressOfFunctions its ordinal is 1. If another function is at index 5 its ordinal is 6.

When you import a function by ordinal you specify the ordinal number. The loader subtracts Base to get the index then looks up the function in AddressOfFunctions. This is faster than importing by name because there's no string comparison.

## Export Forwarding

The code doesn't handle export forwarding. A forwarded export is when a function in one DLL is actually implemented in another DLL. The export table contains a string like NTDLL.RtlAllocateHeap instead of a function RVA. You can detect forwarding by checking if the function RVA falls within the export directory itself. If it does it's a forwarder string not a real function.

Forwarding is common in Windows. For example kernel32.dll forwards many functions to kernelbase.dll. The code would print these as addresses but they're actually strings. Handling forwarding requires checking the RVA range and parsing the forwarder string.

## Why Parse the EAT

Parsing the EAT is useful for several reasons. You can see what functions a DLL provides which helps with reverse engineering. You can resolve function addresses without calling GetProcAddress. You can detect EAT hooking where the function RVAs are modified to redirect calls. You can analyze DLL dependencies and see what functions are available.

Security tools parse the EAT to detect hooks. If a function RVA points outside the DLL it might be hooked. Malware sometimes hooks the EAT to intercept API calls. Debuggers use the EAT to resolve function names from addresses.

## EAT Hooking

EAT hooking is a technique where you modify the function RVAs in the export table to redirect calls to your own code. This is less common than IAT hooking because it affects all processes that import the function not just one process. But it's more powerful for the same reason.

To hook the EAT you change the memory protection of the export directory to writable, overwrite the function RVA, and restore the protection. Your hook function can do whatever it wants then call the real function. Some rootkits use EAT hooks to hide their presence system wide.

## GetProcAddress Implementation

GetProcAddress works by parsing the EAT. When you call GetProcAddress with a function name it searches the AddressOfNames array for a matching name. When it finds the name it uses the corresponding entry in AddressOfNameOrdinals to get the function index. Then it looks up the function RVA in AddressOfFunctions and adds it to the base to get the function pointer.

If you pass an ordinal to GetProcAddress instead of a name it skips the name lookup and goes straight to AddressOfFunctions using the ordinal minus Base as the index.

## Named vs Unnamed Exports

NumberOfNames tells you how many functions have names. NumberOfFunctions tells you the total count. If NumberOfFunctions is greater than NumberOfNames then some functions are exported only by ordinal.

The code only prints named exports because it loops through AddressOfNames. To print unnamed exports you would need to loop through AddressOfFunctions and check which indices are not referenced by AddressOfNameOrdinals. Those are the ordinal only exports.

## Module Name

The Name field in the export directory contains the internal name of the DLL. This is usually the same as the filename but not always. For example kernel32.dll might have an internal name of KERNEL32 without the extension. This name is what you see in import tables when other modules import from this DLL.

## RVA to Pointer Conversion

Throughout the code you see Base + SomeRva. This converts an RVA to an actual pointer. An RVA is relative to the image base so you add the base to get the absolute address. This only works for loaded images where the RVAs are already mapped into memory.

## Parsing Other DLLs

The code parses kernel32.dll but you can parse any loaded DLL by changing the GetModuleHandleA parameter. Try ntdll.dll to see low level NT functions. Try user32.dll to see GUI functions. Try your own DLL to see what you're exporting.

You could also enumerate all loaded modules with EnumProcessModules and parse the EAT of each one to get a complete picture of all available functions in the process.

## Export Directory Location

The export directory is at index 0 in the data directory array. Index 1 is imports, index 2 is resources, index 5 is relocations, etc. Each entry has a VirtualAddress which is an RVA and a Size. If the VirtualAddress is 0 that directory doesn't exist. Not all PE files have exports. Only DLLs and some executables export functions.
