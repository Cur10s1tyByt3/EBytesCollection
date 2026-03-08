# Module Enumeration via RtlQueryProcessDebugInformation

Enumerating loaded modules using undocumented ntdll debug functions.

## What It Does

Uses RtlQueryProcessDebugInformation from ntdll to query module information for a process. This undocumented API returns detailed information about loaded modules including base address, size, full path, and load order. It's more powerful than the documented APIs and can query multiple types of debug information at once.

## How It Works

The code resolves three functions from ntdll. RtlCreateQueryDebugBuffer allocates a shared memory buffer for the debug information. RtlQueryProcessDebugInformation fills the buffer with the requested information. RtlDestroyQueryDebugBuffer frees the buffer when you're done.

First you call RtlCreateQueryDebugBuffer with a maximum commit size and a flag indicating whether to use event pairs. Passing 0 for the size lets ntdll choose a default. Passing FALSE for the event pair flag is typical. The function returns a pointer to an RTL_DEBUG_INFORMATION structure which contains the buffer and metadata.

Then you call RtlQueryProcessDebugInformation with the target process ID, flags indicating what information you want, and the debug buffer. The flags are PDI_MODULES for modules, PDI_HEAPS for heaps, PDI_LOCKS for locks, and others. You can OR multiple flags together to request multiple types of information at once.

The function fills the debug buffer with the requested information. For modules it populates the Modules field which points to an RTL_PROCESS_MODULES structure. This structure has a NumberOfModules count and an array of RTL_PROCESS_MODULE_INFORMATION entries.

Each module entry contains the image base address, image size, full path, offset to the filename within the path, load order index, init order index, and other fields. The code loops through the entries and prints the base, size, filename, and full path.

Finally you call RtlDestroyQueryDebugBuffer to free the shared memory buffer. This is important to avoid leaking resources.

## RtlCreateQueryDebugBuffer

This function allocates a shared memory section for debug information. The first parameter is the maximum commit size. Passing 0 lets ntdll choose a reasonable default based on what you're querying. The second parameter is a boolean indicating whether to use event pairs for synchronization. Passing FALSE is typical.

The function returns a pointer to an RTL_DEBUG_INFORMATION structure. This structure contains handles to the shared section, pointers to the mapped views, and fields for the various types of debug information. If the function fails it returns NULL.

## RtlQueryProcessDebugInformation

This function queries debug information for a process. The first parameter is the process ID cast to a HANDLE. This is unusual because most APIs take a real process handle but this function accepts the numeric PID directly.

The second parameter is a flags value indicating what information you want. PDI_MODULES requests module information. PDI_HEAPS requests heap information. PDI_LOCKS requests lock information. You can OR multiple flags together to request multiple types at once.

The third parameter is the debug buffer returned by RtlCreateQueryDebugBuffer. The function fills the appropriate fields in the buffer based on the flags.

The function returns an NTSTATUS value. 0 means success. Non zero means failure. Common failures are STATUS_ACCESS_DENIED if you don't have permission or STATUS_INVALID_PARAMETER if you pass bad values.

## RtlDestroyQueryDebugBuffer

This function frees the debug buffer and releases the shared memory section. You must call this when you're done with the buffer to avoid leaking resources. The function takes the debug buffer pointer and cleans everything up.

## RTL_DEBUG_INFORMATION Structure

This structure contains the debug buffer and metadata. The important fields are Modules which points to module information, Heaps which points to heap information, Locks which points to lock information, and BackTraces which points to stack trace information.

The structure also contains handles to the shared section, pointers to the mapped views in both the client and target process, and size information. Most of these fields are internal and you don't need to touch them.

## RTL_PROCESS_MODULES Structure

This structure contains the module list. It has a NumberOfModules field indicating how many modules are in the list and a flexible array member Modules containing the actual entries. You loop from 0 to NumberOfModules and access each entry.

## RTL_PROCESS_MODULE_INFORMATION Structure

This structure describes one loaded module. The important fields are ImageBase which is the base address, ImageSize which is the size in bytes, FullPathName which is the full path as a char array, and OffsetToFileName which is the offset into FullPathName where the filename starts.

The structure also has LoadOrderIndex and InitOrderIndex which indicate the module's position in the load order and initialization order lists. LoadCount indicates how many times the module is loaded. Flags contains various flags about the module.

## OffsetToFileName

This field is clever. Instead of storing the filename separately it stores an offset into the FullPathName array where the filename starts. For example if FullPathName is C:\Windows\System32\kernel32.dll then OffsetToFileName is 20 which points to kernel32.dll.

This saves space and avoids string duplication. To get the filename you just add the offset to the FullPathName pointer. The code does this to print just the filename without the path.

## Process ID as Handle

The function takes the process ID as a HANDLE type but you pass the numeric PID. This is unusual because most Windows APIs require a real process handle from OpenProcess. But this function accepts the PID directly which is more convenient.

You cast the PID to ULONG_PTR then to HANDLE to satisfy the type system. The function internally converts it back to a PID and uses it to query the process.

## PDI Flags

The flags control what information is queried. PDI_MODULES requests module information. PDI_HEAPS requests heap information. PDI_HEAP_TAGS requests heap tag information. PDI_HEAP_BLOCKS requests heap block information. PDI_LOCKS requests lock information. PDI_BACKTRACE requests stack trace information.

You can OR multiple flags together to request multiple types at once. For example PDI_MODULES | PDI_HEAPS requests both modules and heaps. The function fills the corresponding fields in the debug buffer.

## Shared Memory Section

The debug buffer uses a shared memory section. This is a region of memory that's mapped into both the calling process and the target process. The function queries information from the target process and writes it into the shared section where the calling process can read it.

This is more efficient than copying data back and forth. The shared section is created by RtlCreateQueryDebugBuffer and destroyed by RtlDestroyQueryDebugBuffer.

## Why Use This API

There are several ways to enumerate modules. EnumProcessModules is the documented API. Walking the PEB is another way. LdrEnumerateLoadedModules is an undocumented alternative. RtlQueryProcessDebugInformation is yet another option.

The advantage of RtlQueryProcessDebugInformation is it can query multiple types of information at once. You can get modules, heaps, locks, and more in a single call. It also works for remote processes not just the current process.

The disadvantage is it's undocumented and more complex. You need to manage the debug buffer and understand the structures. For simple module enumeration the other APIs are easier.

## Undocumented but Stable

These functions are undocumented but they've been in ntdll since Windows NT. They're used internally by debugging tools and system utilities. The signatures and behavior have been consistent across Windows versions.

Tools like Process Hacker and WinDbg use these functions to query process information. They're reliable in practice even though Microsoft doesn't officially support them.

## Full Path vs Filename

The FullPathName field contains the complete path to the module. For system modules this is typically a native NT path like \SystemRoot\System32\kernel32.dll. For user modules it might be a DOS path like C:\Program Files\App\module.dll.

The OffsetToFileName field lets you extract just the filename without parsing the path. This is useful when you only care about the module name not the full path.

## Load Order and Init Order

The LoadOrderIndex field indicates the module's position in the load order list. The first module loaded has index 0, the second has index 1, and so on. This is the same order as the InLoadOrderModuleList in the PEB.

The InitOrderIndex field indicates the module's position in the initialization order list. This is the order in which module entry points are called. The main executable is not in this list so its init order index is 0.

## Module Flags

The Flags field contains various flags about the module. These flags indicate things like whether the module is a DLL, whether it's been initialized, whether it's being unloaded, and other state information. The exact flag values are not documented.

## Querying Remote Processes

The code queries the current process but you can query remote processes by passing a different PID. You don't need to open a handle to the process. Just pass the PID and the function handles the rest.

This is useful for analyzing other processes without needing PROCESS_QUERY_INFORMATION or PROCESS_VM_READ permissions. The function works at a lower level and can access process information that the documented APIs can't.

## Heap and Lock Information

The code only requests module information but you can also request heap and lock information by using different flags. PDI_HEAPS gives you information about all heaps in the process. PDI_LOCKS gives you information about critical sections and other locks.

This is useful for debugging memory issues or analyzing lock contention. The structures for heaps and locks are more complex and not shown in this example.

## Error Handling

The code checks if the functions resolve successfully and if the calls succeed. If RtlCreateQueryDebugBuffer returns NULL or if RtlQueryProcessDebugInformation returns a non zero status the code prints an error and exits.

Always check return values when using undocumented APIs. They might fail in unexpected ways or on different Windows versions.

---

That's module enumeration via RtlQueryProcessDebugInformation. Create a debug buffer, query the information, read the results, and destroy the buffer.
