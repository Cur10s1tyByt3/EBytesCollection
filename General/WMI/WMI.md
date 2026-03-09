# FunStuff

Evasive WMI library with compile-time string obfuscation. Every WQL query, namespace path, and property name is XOR'd at compile time so static analysis tools won't find WMI-related strings in your binary.

## The Problem with Classic WMI Libraries

Most WMI wrappers are built for sysadmin tools and IT automation. They prioritize convenience over stealth. When you use a typical WMI library, your binary contains plaintext strings like "SELECT * FROM Win32_Process" and "ROOT\\CIMV2" sitting in the .rdata section. Any defender with a hex editor can see exactly what you're querying.

The other issue is that WMI itself is heavily monitored. Windows Event Tracing logs WMI queries through the Microsoft-Windows-WMI-Activity provider. Sysmon can track WmiEventConsumer creation. Defenders watch for suspicious WQL patterns like "SELECT * FROM AntiVirusProduct" or "SELECT * FROM Win32_Process WHERE Name='explorer.exe'". Your obfuscated binary might pass static analysis, but the WMI query itself gets logged by the OS.

## What This Does Differently

This library uses compile-time XOR encoding for all strings. The ENCODE_STR macro runs at compile time via constexpr templates. Each string literal gets a unique key derived from __COUNTER__, gets XOR'd into a byte array, and the plaintext never appears in the binary. At runtime, the Decode() method XORs the bytes on the stack to recover the original string only when needed.

The key generation is intentionally simple so you can replace it. Right now it's just `Key = ((Seed * 167 + 29) & 0xFF) ?: 0xA5` which stops basic string scanners but won't resist targeted analysis. You should swap this for something stronger like ChaCha20, or at minimum use __TIME__ and __DATE__ macros to make each build unique.

The code includes function pointer typedefs for all COM and OLE APIs. These are set up for dynamic resolution so you can load ole32.dll and oleaut32.dll manually without touching the IAT. Right now it still uses static linking because the manual mapping code isn't implemented yet, but the infrastructure is there. You just need to add a PE loader that maps the DLLs into memory and resolves exports without calling LoadLibrary or GetProcAddress.

Format strings for printf are also obfuscated via the WMILITE_PRINT macro. This encodes the format string at compile time and decodes it at runtime, so even your debug output doesn't leak information in the binary.

## How It Works

When you write `ENCODE_STR(Query, L"SELECT Caption FROM Win32_OperatingSystem")`, the preprocessor expands this to a constexpr template call that runs at compile time. The WmiLite_EncodeWideLiteral function takes your string literal and the XOR key, creates a WMI_ENCODED_LITERAL struct with the XOR'd bytes, and returns it as a compile-time constant. The compiler emits the encoded bytes into the binary's data section.

At runtime, the macro declares a stack buffer and calls the Decode() method which XORs each byte with the key to recover the original string. The plaintext exists in memory only during the function call, then gets overwritten when the stack frame is destroyed. This doesn't stop memory scanners or EDR hooks from seeing the decoded string, but it does prevent static analysis tools from finding it in the binary.

The WMI query flow is standard COM. Initialize COM with CoInitializeEx, create a WbemLocator object with CoCreateInstance, connect to the namespace with ConnectServer, set the proxy blanket with CoSetProxyBlanket for authentication, then execute queries with ExecQuery. The difference is that all the string parameters are decoded from XOR'd buffers at runtime instead of being plaintext constants.

For remote connections, WmiLite_InitializeRemote takes a hostname, namespace, username, password, and domain. It builds a UNC path like \\\\hostname\\ROOT\\CIMV2, allocates BSTRs for the credentials, and passes them to ConnectServer. If credentials are provided, it stores them in the context and uses CoSetProxyBlanket with a COAUTHIDENTITY structure to authenticate the proxy. The credentials are scrubbed with RtlSecureZeroMemory when the context is destroyed.

## Usage

```cpp
WMI_CONTEXT Context;
WCHAR Value[256];

if (WmiLite_Initialize(&Context) == FALSE)
{
    return 1;
}

ENCODE_STR(Query, L"SELECT Caption FROM Win32_OperatingSystem");
ENCODE_STR(Property, L"Caption");

if (WmiLite_QueryFirstString(&Context, Query, Property, Value, 256))
{
    printf("[+] %ws\n", Value);
}

WmiLite_Shutdown(&Context);
```

The ENCODE_STR calls happen at compile time. At runtime, Query and Property are stack buffers containing the decoded strings. WmiLite_QueryFirstString allocates BSTRs for the WQL language identifier and query text, calls ExecQuery with WBEM_FLAG_FORWARD_ONLY to minimize memory usage, pulls the first result with Next, extracts the property with Get, and copies the BSTR value to your output buffer.

## What You Should Add

The XOR encoding is weak. Replace WmiLite_MakeObfKey with something that uses __TIME__ or __DATE__ to make each build unique

Manual mapping for ole32.dll and oleaut32.dll would eliminate the IAT entries. Write a PE loader that reads the DLL from disk, maps sections into memory with VirtualAlloc, processes relocations, resolves imports, and calls DllMain. Then resolve CoInitializeEx, CoCreateInstance, and the other APIs by walking the export table manually. This avoids LoadLibrary and GetProcAddress which are heavily hooked.

## Disclaimer

For authorized red team and penetration testing only. Unauthorized access to computer systems is illegal.
