# FunStuff

Lazy-loaded DPAPI wrapper with a custom export walker. It loads `crypt32.dll` at runtime, resolves `CryptProtectData` and `CryptUnprotectData` by walking the PE export table instead of calling WinAPI `GetProcAddress`, and wraps the basic protect/unprotect flow in a single-file demo.

## What This Does Differently

This version keeps the project tiny, but it is organized like a real wrapper instead of a disposable snippet. The runtime loads `crypt32.dll` once, caches the DPAPI entry points it cares about, and calls them through a small `FUNSTUFF_DPAPI_RUNTIME` table after the first lookup.

The export lookup is manual. `FunStuff_CustomGetProcAddress` parses the DOS header, NT headers, and export directory itself, resolves functions by name or ordinal, and follows forwarded exports when it has to. `GetProcAddress` is not part of that path anymore.

The cleanup path is also less lazy than the average sample. `FunStuff_Dpapi_FreeBlob` scrubs returned buffers with `RtlSecureZeroMemory` before calling `LocalFree`, and `FunStuff_Dpapi_FreeDescription` handles the optional description string returned by `CryptUnprotectData` so callers do not leak memory every time they decrypt something.

## How It Works

When the first DPAPI helper runs, `FunStuff_Dpapi_EnsureLoaded` calls `LoadLibraryW( L"crypt32.dll" )`, resolves `CryptProtectData` and `CryptUnprotectData`, and stores both pointers in `g_FunStuffDpapiApi`. After that, the rest of the wrapper calls the cached function pointers directly.

`FunStuff_Dpapi_Protect` takes plaintext bytes, optional entropy, an optional description string, and a flags value. It builds the input `DATA_BLOB`s, forces `CRYPTPROTECT_UI_FORBIDDEN` so the demo stays non-interactive, and hands everything off to `CryptProtectData`. The encrypted blob that comes back is owned by the caller until `FunStuff_Dpapi_FreeBlob` is used.

`FunStuff_Dpapi_Unprotect` does the reverse. It takes a protected blob, optional entropy, and optional flags, calls `CryptUnprotectData`, and returns both the recovered plaintext blob and the optional description string. If the caller does not want the description, the wrapper frees it immediately instead of leaking it.

The demo in `main()` encrypts `"FunStuff DPAPI demo"` with optional entropy, prints the resulting protected blob as hex, decrypts it, prints the description string, prints the recovered plaintext, and verifies that the bytes match the original input.

## Usage

```cpp
CONST BYTE Plaintext[] = "FunStuff DPAPI demo";
CONST BYTE OptionalEntropy[] = "FunStuff entropy";
DATA_BLOB ProtectedData = { 0 };

if ( FunStuff_Dpapi_Protect(
        Plaintext,
        ( DWORD )( sizeof( Plaintext ) - 1 ),
        OptionalEntropy,
        ( DWORD )( sizeof( OptionalEntropy ) - 1 ),
        L"FunStuff DPAPI blob",
        0,
        &ProtectedData ) == FALSE )
{
    return 1;
}

printf( "[+] DPAPI blob: " );
FunStuff_Dpapi_PrintHex( ProtectedData.pbData, ProtectedData.cbData );
printf( "\n" );
```

That is the protect side. The matching unprotect path takes the encrypted blob and the same optional entropy, then gives you back a plaintext `DATA_BLOB` plus the original description string if you ask for it.

If you just run `main()`, the sample already does the full round trip and frees everything at the end.

# Why ? 
> Many people asked me, Evilbytecode why do u reinvent the wheel ?
- Its beacuse i want to make it atleast something unique, if u have skill u can make it into a header easily, and also to teach people, this repository is dedicated to offensive/general dev, that means if someone decides to use this they also should have it reliable and no random crashes, or debugging some weird ass codes lol. i have to frick with this bs so u dont have to :) ... and no im not recoding this all , like almost all of those codes are my old projects which i just like copy and modify and put here :)
## What You Should Add

Right now this is still a single-file demo. Split it into a header and source file, expose a small public API.
