# DLL Proxy Generator

This tool generates proxy DLL export forwarding code by walking the Export Address Table (EAT) of a target DLL and emitting linker pragmas for every named export. Took me about 2 hours to get the path handling and forwarder logic right.

## What It Does

DLL proxying is a technique where you create a fake DLL with the same name as a legitimate system DLL, then forward all its exports to the real DLL (renamed with a suffix). This lets you intercept DLL loads — your proxy gets loaded first, runs your code in DllMain, then forwards all function calls to the real implementation.

## Why DLL Proxying Matters

Windows searches for DLLs in a specific order: application directory first, then system directories. If you drop a proxy version.dll in an application's folder, it loads instead of the real C:\Windows\System32\version.dll. Your DllMain runs with the application's privileges, and all the app's calls to version.dll functions still work because you're forwarding them.

This is used for DLL hijacking, persistence, and code injection. It's also how legitimate software does API hooking without modifying system files — the proxy sits between the application and the real DLL.

## How It Works

The tool loads the target DLL with DONT_RESOLVE_DLL_REFERENCES, which skips DllMain and import resolution. We only need the PE headers, not an initialized module. This is faster and safer than a full load — if the DLL has dependencies or crashes in DllMain, we don't care.

We locate the export directory via IMAGE_DIRECTORY_ENTRY_EXPORT in the data directory array. The export directory contains three parallel arrays: AddressOfNames (RVAs to function name strings), AddressOfNameOrdinals (ordinal indices), and AddressOfFunctions (RVAs to function entry points).

For each named export, we emit a linker pragma that tells the linker to create an export in our proxy DLL that forwards to the real DLL. The syntax is:

```cpp
#pragma comment(linker, "/export:FunctionName=RealDll_suffix.FunctionName")
```

When an application calls FunctionName in your proxy DLL, the loader automatically redirects it to RealDll_suffix.FunctionName without any runtime overhead. This is a linker-level forward, not a runtime thunk.

## Forwarder Chains

Some DLLs have forwarder exports — instead of pointing to code, the export RVA points to a string like "NTDLL.RtlAllocateHeap". The loader resolves this recursively. If you skip forwarders when generating the proxy, you silently drop exports and break the ABI.

The tool proxies every named export including forwarders. Forwarder chains work fine: YourProxy.Func -> OrigDll.Func -> RealImpl. The loader handles the recursion.

## Path Handling

The tool builds the forwarder target by stripping the directory and extension from the input path, then appending the suffix. For example:

```
Input : C:\Windows\System32\version.dll
Suffix: _orig
Output: version_orig
```

The output file is always saved as `proxied.h` in the same directory as the running exe. This is intentional — you typically run the tool from your project directory, and the output goes straight into your source tree.

## Usage

```
ProxyDll.exe <dll_path> <suffix>
```

Example:
```
ProxyDll.exe C:\Windows\System32\version.dll _orig
```

This generates `proxied.h` containing:
```cpp
#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
// ... etc for all exports
```

To use it:

1. Run the tool to generate `proxied.h`
2. Create a new DLL project with the same name as the target (e.g., version.dll)
3. Include `proxied.h` in your source
4. Add your payload code to DllMain
5. Compile your proxy DLL
6. Rename the original DLL to match the suffix (e.g., version.dll -> version_orig.dll)
7. Drop your proxy DLL in the application directory

When the application loads, your DllMain runs first, then all function calls forward to the real DLL.

## Why DONT_RESOLVE_DLL_REFERENCES

Loading a DLL normally (LoadLibraryA) runs DllMain and resolves imports. If the DLL has dependencies that aren't present, or if DllMain crashes, the load fails. DONT_RESOLVE_DLL_REFERENCES skips all that — it just maps the file into memory and returns a handle to the headers.

This is safe because we only need to read the export table, which is part of the PE headers. We never call any code in the DLL.

## Ordinal-Only Exports

The tool only proxies named exports. Some DLLs have ordinal-only exports (no name, just a number). These are rare in modern Windows DLLs, but if you need to proxy them, you'd emit:

```cpp
#pragma comment(linker, "/export:@123=RealDll.@123,@123,NONAME")
```

The tool doesn't do this because ordinal-only exports are uncommon and the syntax is more complex. If you hit a DLL with ordinal exports, you'll need to add that logic.
