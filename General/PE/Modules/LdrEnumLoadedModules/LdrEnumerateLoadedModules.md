# Module Enumeration via LdrEnumerateLoadedModules

Enumerating loaded modules using an undocumented ntdll function.

## What It Does

Uses the undocumented LdrEnumerateLoadedModules function from ntdll to enumerate all modules loaded in the current process. For each module it prints the base address, size, and name. This is an alternative to the documented EnumProcessModules API.

## How It Works

The code resolves LdrEnumerateLoadedModules from ntdll.dll using GetProcAddress. This function is exported by ntdll but not documented by Microsoft. It takes a callback function and calls that callback once for each loaded module in the process.

You pass three parameters to LdrEnumerateLoadedModules. The first is a reserved flag that must be 0. The second is a pointer to your callback function. The third is a context pointer that gets passed to your callback. The context can be anything you want or NULL if you don't need it.

When you call LdrEnumerateLoadedModules it walks the loader data structures internally and calls your callback for each module. The callback receives a pointer to an LDR_DATA_TABLE_ENTRY structure which contains information about the module. This is the same structure you'd get by manually walking the PEB loader lists.

The callback also receives the context pointer you passed and a stop flag. If you set the stop flag to TRUE the enumeration stops immediately. Otherwise it continues until all modules are enumerated.

The LDR_DATA_TABLE_ENTRY structure contains the module base address, entry point, size, full path, and base name. The code prints the base address, size, and base name for each module.

## LdrEnumerateLoadedModules

This is an undocumented function exported by ntdll.dll. It's been present since Windows XP and is used internally by Windows. The function signature takes a reserved flag, a callback function pointer, and a context pointer.

The reserved flag must be 0. Passing any other value might cause the function to fail or behave unexpectedly. The callback is called once per module. The context is passed through to your callback and can be used to pass state or data.

The function returns an NTSTATUS value. 0 means success. Non zero means failure. Common failure codes are STATUS_INVALID_PARAMETER if you pass bad parameters or STATUS_ACCESS_DENIED if you don't have permission.

## Callback Function

The callback has a specific signature. It takes a pointer to an LDR_DATA_TABLE_ENTRY, a context pointer, and a pointer to a BOOLEAN stop flag. The callback is called once for each loaded module.

Inside the callback you can do whatever you want with the module information. Print it, store it, analyze it, whatever. The code just prints the base address, size, and name.

The stop flag lets you terminate the enumeration early. If you set it to TRUE the function stops calling your callback and returns. This is useful if you're searching for a specific module and want to stop once you find it.

## LDR_DATA_TABLE_ENTRY

This structure describes a loaded module. It's part of the loader data structures maintained by ntdll. The structure contains several LIST_ENTRY fields that link it into various lists, the DllBase which is the base address, the EntryPoint which is the entry point address, the SizeOfImage which is the module size in bytes, and UNICODE_STRING fields for the full path and base name.

The InLoadOrderLinks field links the entry into the load order list. The InMemoryOrderLinks field links it into the memory order list. The InInitializationOrderLinks field links it into the initialization order list. These are the same lists you'd walk if you manually enumerated modules via the PEB.

The FullDllName contains the full path like C:\Windows\System32\kernel32.dll. The BaseDllName contains just the filename like kernel32.dll. Both are UNICODE_STRING structures with a Length, MaximumLength, and Buffer pointer.

## Why Use This Function

There are several ways to enumerate modules. EnumProcessModules is the documented API. Walking the PEB loader lists manually is another way. LdrEnumerateLoadedModules is a third way.

The advantage of LdrEnumerateLoadedModules is it's simple and does the work for you. You don't need to walk the lists manually or deal with the PEB. You just provide a callback and the function handles everything.

The disadvantage is it's undocumented. Microsoft doesn't guarantee it will exist in future Windows versions or that the signature won't change. In practice it's been stable for decades but there's always a risk with undocumented APIs.

## UNICODE_STRING

The module names are UNICODE_STRING structures. This is a Windows kernel structure with a Length field in bytes, a MaximumLength field, and a Buffer pointer to the wide string. The Length is the actual string length in bytes not including the null terminator.

To print a UNICODE_STRING you use the Buffer pointer with %ws format specifier. The code checks if Buffer is NULL before printing to avoid crashes on malformed entries.

## Module Base and Size

The DllBase field is the base address where the module is loaded in memory. This is the same value you'd get from GetModuleHandle. The SizeOfImage field is the size of the module in bytes. This is the virtual size from the PE optional header.

These values are useful for memory scanning, code analysis, or calculating address ranges. If you want to scan a module for patterns you use the base and size to define the region.

## Callback Context

The context parameter lets you pass data to your callback. For example you could pass a pointer to a structure where you want to store the results. Or you could pass a search string if you're looking for a specific module.

The code passes NULL because it just prints the modules and doesn't need any context. But you could easily extend it to collect modules into an array by passing a pointer to the array as context.

## Stop Flag

The stop flag lets you terminate enumeration early. If you're searching for a specific module you can set stop to TRUE once you find it. This avoids wasting time enumerating the rest of the modules.

The code doesn't use the stop flag because it wants to enumerate all modules. But if you only needed the first module or a specific module you could use the flag to optimize.

## Module Order

The modules are enumerated in load order. The first module is the main executable. Then come the DLLs in the order they were loaded. This is the same order as the InLoadOrderModuleList in the PEB.

If you need a different order you'd need to walk the PEB lists manually. The InMemoryOrderModuleList is sorted by base address. The InInitializationOrderModuleList is sorted by initialization order.

## NULL Checks

The code checks if BaseDllName.Buffer is NULL before printing. Some entries might have NULL names especially for special modules or if the loader data is corrupted. Checking prevents crashes.

## UNREFERENCED_PARAMETER

The callback uses UNREFERENCED_PARAMETER macros to suppress compiler warnings about unused parameters. The Parameter and Stop parameters aren't used in this simple example but they're part of the callback signature so they must be present.
