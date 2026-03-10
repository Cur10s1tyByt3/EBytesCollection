# FunStuff

Lazy-loaded BCrypt wrapper with a custom export walker. It loads `bcrypt.dll` at runtime, resolves the `BCrypt*` entry points by walking the PE export table instead of calling WinAPI `GetProcAddress`, and wraps hashing, HMAC, RNG, FIPS checks, and AES-GCM-256 behind small helper functions.

## The Problem with Classic BCrypt Wrappers

Most CNG examples are written like textbook code. They link `bcrypt.lib` directly or call `LoadLibraryW` and `GetProcAddress` in the most obvious way possible. That means your binary either imports `BCryptOpenAlgorithmProvider`, `BCryptHashData`, `BCryptEncrypt`, and `BCryptGenRandom` through the IAT, or it advertises a dead-simple lazy loader that every reverser has seen a thousand times.

The other issue is that a lot of sample code treats CNG state like disposable junk. People skip the `BCRYPT_OBJECT_LENGTH` query, guess buffer sizes, forget to validate AES-GCM tag lengths, and leave key objects or hash state sitting on the heap after cleanup. The code works until it doesn't, and when it breaks it usually breaks in annoying ways.

Then there is the quality problem. Most "minimal" examples show a single hash call and stop there. They do not give you a reusable runtime table, they do not unify cleanup, and they definitely do not show a full AES-GCM path with nonce, AAD, tag handling, decrypt verification, and secure buffer teardown.

## What This Does Differently

This wrapper loads `bcrypt.dll` once and caches every function pointer it needs in a `FUNSTUFF_BCRYPT_RUNTIME` struct. The interesting part is `FunStuff_CustomGetProcAddress`. Instead of handing symbol lookup back to kernel32, it parses the module's DOS header, NT headers, and export directory itself, resolves names and ordinals, and follows forwarded exports when necessary.

The hashing path is wrapped properly. `FunStuff_Bcrypt_InitializeHashEx` opens the provider, queries `BCRYPT_OBJECT_LENGTH` and `BCRYPT_HASH_LENGTH`, allocates the backing state buffer, and creates the hash handle. `FunStuff_Bcrypt_ShutdownHash` destroys the hash, zeroes the heap buffer with `RtlSecureZeroMemory`, frees it, and closes the provider so callers get one cleanup path instead of five half-correct ones.

The AES path is also stricter than the usual copy-paste sample. `FunStuff_Bcrypt_AesGcmCrypt256` enforces a 32-byte key, requires a nonce, validates the requested tag length against `BCRYPT_AUTH_TAG_LENGTH`, sets `BCRYPT_CHAIN_MODE_GCM` before key creation, and uses `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` for both encrypt and decrypt. If the output length is wrong, it fails instead of pretending everything is fine.

This is still intentionally simple. It does not do compile-time string obfuscation. It does not manually map `bcrypt.dll`. It still calls `LoadLibraryW` to bring the module in. The goal here is a small, readable runtime wrapper around CNG, not a giant crypto framework.

## How It Works

When the first crypto helper runs, `FunStuff_Bcrypt_EnsureLoaded` calls `LoadLibraryW( L"bcrypt.dll" )`, resolves the exports it cares about, and stores them in `g_FunStuffBcryptApi`. After that, the rest of the code calls through cached function pointers only. If any required export is missing, the loader bails out early and frees the module.

For hashing and HMAC, the flow is straight CNG. Open the algorithm provider, query the object and digest sizes, allocate the object buffer, create the hash, stream bytes through `BCryptHashData`, finish with `BCryptFinishHash`, then tear the whole thing down through a single cleanup routine. The one-shot helpers `FunStuff_Bcrypt_HashBuffer` and `FunStuff_Bcrypt_HmacBuffer` exist so callers do not have to manage that state manually unless they want to.

For AES-GCM-256, the wrapper opens the AES provider, flips the chaining mode to GCM, validates the requested tag size, allocates the key object buffer, and creates a symmetric key from the caller's 32-byte key material. It fills out `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` with the nonce, AAD, and tag, then calls either `BCryptEncrypt` or `BCryptDecrypt`. The heap-backed key object is scrubbed before being freed.

The demo in `main()` exercises the whole surface. It computes a SHA-256 digest, computes an HMAC-SHA256 value, checks whether FIPS mode is enabled, generates random bytes, encrypts a sample string with AES-GCM-256, decrypts it, and verifies that the plaintext matches.

## Usage

```cpp
CONST BYTE DemoText[] = "FunStuff BCrypt demo";
BYTE Digest[64] = { 0 };
ULONG DigestLength = 0;

if ( FunStuff_Bcrypt_HashBuffer(
        BCRYPT_SHA256_ALGORITHM,
        DemoText,
        ( ULONG )( sizeof( DemoText ) - 1 ),
        Digest,
        sizeof( Digest ),
        &DigestLength ) == FALSE )
{
    return 1;
}

printf( "[+] SHA256: " );
FunStuff_Bcrypt_PrintHex( Digest, DigestLength );
printf( "\n" );
```

That is the one-shot digest path. The same pattern exists for HMAC through `FunStuff_Bcrypt_HmacBuffer`, and the AES-GCM helpers take a 32-byte key, a nonce, optional AAD, an input buffer, an output buffer of matching size, and a caller-supplied authentication tag buffer.

If you want the full example, just run `main()`. The current demo already shows SHA-256, HMAC-SHA256, FIPS mode querying, random generation, AES-GCM encryption, AES-GCM tag output, AES-GCM decryption, and plaintext verification in one place.

## What You Should Add

Right now this is a single-file wrapper. Split it into a header and source file, remove the `static` qualifiers from the public helpers, and add real test vectors for SHA-256, HMAC-SHA256, and AES-GCM so changes can be verified automatically instead of by eyeballing demo output.

Key handling is still minimal. Add higher-level helpers for key derivation, nonce generation policy, and secure buffer ownership so callers are less likely to misuse raw `BYTE*` parameters. The crypto primitives are fine; the ergonomics are what need work next.

The loader story is only half-custom. Export resolution is manual now, but module loading still goes through `LoadLibraryW`. If reducing obvious runtime resolution behavior matters to you, that is the next gap. If maintainability matters more, leave it alone and focus on tests and API cleanup.

## API Functions

`FunStuff_CustomGetProcAddress` walks a loaded module's export table and resolves an export by name or ordinal. It also handles forwarded exports.

`FunStuff_Bcrypt_EnsureLoaded` lazy-loads `bcrypt.dll`, resolves the required CNG entry points, and caches them in the global runtime table.

`FunStuff_Bcrypt_GetFipsMode` calls `BCryptGetFipsAlgorithmMode` when the export is available and reports whether the system is running in FIPS mode.

`FunStuff_Bcrypt_HashBuffer` performs a one-shot hash for any algorithm ID accepted by BCrypt, such as `BCRYPT_SHA256_ALGORITHM`.

`FunStuff_Bcrypt_HmacBuffer` does the same for HMAC by opening the algorithm provider with `BCRYPT_ALG_HANDLE_HMAC_FLAG`.

`FunStuff_Bcrypt_GenRandom` wraps `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` and fills a caller-supplied buffer with random bytes.

`FunStuff_Bcrypt_AesGcmEncrypt256` encrypts a buffer with AES-GCM using a 32-byte key and writes the authentication tag back to the caller.

`FunStuff_Bcrypt_AesGcmDecrypt256` decrypts a buffer with AES-GCM and fails if authentication or buffer validation does not pass.

`FunStuff_Bcrypt_RunDemo` exercises the wrapper end to end and is what `main()` currently calls.

You do not need `bcrypt.lib` here because the code resolves the CNG exports at runtime.

## Limitations
- NO AES-CBC, AES-CTR, SHA-512, PBKDF2, or key import/export helpers
