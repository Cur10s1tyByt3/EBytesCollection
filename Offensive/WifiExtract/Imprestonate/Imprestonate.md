# WiFi Password Extraction via DPAPI Decryption

Extracting WiFi passwords by reading and decrypting DPAPI-protected profile XML files directly from disk.

## What It Does

Reads WiFi profile XML files from the Windows WLAN service directory, decrypts DPAPI-encrypted passwords by impersonating SYSTEM, and extracts the plaintext passwords. This works for all saved WiFi networks on the system including those with encrypted passwords.

## How It Works

Windows stores WiFi profiles as XML files in C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces. Each wireless interface has a GUID subdirectory containing XML files for each saved network. The XML contains all the network settings including the password in the keyMaterial tag.

When the password is protected the keyMaterial is DPAPI encrypted. DPAPI is Data Protection API which encrypts data using keys derived from the user or machine context. WiFi passwords are encrypted by SYSTEM so they can only be decrypted when running as SYSTEM.

The code first enables SeDebugPrivilege which allows opening handles to system processes. Then it finds winlogon.exe which always runs as SYSTEM. It opens winlogon, duplicates its token, and uses SetThreadToken to impersonate SYSTEM on the current thread.

Once impersonating SYSTEM it enumerates the interface directories and finds all XML profile files. For each file it reads the XML, checks if the password is protected, and if so extracts the hex-encoded DPAPI blob from keyMaterial. It converts the hex to binary, calls CryptUnprotectData to decrypt it, and gets the plaintext password.

After processing all profiles it calls RevertToSelf to stop impersonating SYSTEM and returns to the original user context.

## Token Impersonation

The key technique here is token impersonation. Windows uses tokens to represent security contexts. Each process and thread has a token that determines what permissions it has. By duplicating the token from a SYSTEM process and applying it to your thread you temporarily gain SYSTEM privileges.

The code uses winlogon.exe as the source because it's always running as SYSTEM and is accessible with SeDebugPrivilege. You open the process with PROCESS_QUERY_INFORMATION, open its token with OpenProcessToken, duplicate the token with DuplicateTokenEx as an impersonation token, and apply it with SetThreadToken.

Once the thread token is set all operations on that thread run with SYSTEM privileges. This includes file access, registry access, and DPAPI decryption. After you're done you call RevertToSelf to remove the impersonation and return to your original token.

## SeDebugPrivilege

This privilege allows opening handles to any process on the system including protected processes. Normally you can only open processes running under your user account. With SeDebugPrivilege you can open system processes like winlogon.

The privilege is available to administrators but not enabled by default. You enable it by opening your process token, looking up the privilege LUID with LookupPrivilegeValueW, and calling AdjustTokenPrivileges to enable it.

Once enabled you can open winlogon and duplicate its token. Without this privilege OpenProcess would fail with access denied.

## DPAPI Decryption

DPAPI encrypts data using keys derived from the user password or machine key. The encryption is tied to the security context so only the same user or machine can decrypt it. WiFi passwords are encrypted by SYSTEM using the machine key.

CryptUnprotectData takes an encrypted blob and decrypts it. The function checks the current thread token to determine the security context. If you're running as the same user or machine that encrypted the data it succeeds. Otherwise it fails with NTE_BAD_KEY_STATE.

This is why impersonation is necessary. The passwords were encrypted by SYSTEM so you must be SYSTEM to decrypt them. By impersonating SYSTEM your thread has the right context and CryptUnprotectData succeeds.

## Hex Encoding

The keyMaterial in the XML is hex-encoded not base64. Each byte is represented as two hex digits. The code uses CryptStringToBinaryW with CRYPT_STRING_HEX to convert the hex string to binary.

First it calls with a NULL buffer to get the required size. Then it allocates a buffer and calls again to do the conversion. The result is the raw DPAPI blob ready for decryption.

## XML Parsing

The code uses a simple XML parser that searches for tags. It builds the open and close tags by wrapping the tag name in angle brackets. Then it uses wcsstr to find the open tag, advances past it, finds the close tag, and copies the content between them.

This works for the flat structure of WiFi profile XML. The important tags are protected which indicates if the password is encrypted, and keyMaterial which contains the password or encrypted blob.

## UTF-8 to UTF-16 Conversion

The XML files are UTF-8 encoded. The code reads the raw bytes and converts them to UTF-16 using MultiByteToWideChar. This is necessary because the rest of the code uses wide string functions like wcsstr and wsprintfW.

The conversion takes the UTF-8 bytes, calculates how many wide characters are needed, allocates a buffer, and does the conversion. The result is a null-terminated wide string.

## Profile Directory Structure

The profiles are organized by interface GUID. Each wireless adapter has a unique GUID. Under the Interfaces directory there's a subdirectory for each GUID. Inside each GUID directory are XML files named with the profile GUID.

The code enumerates the interface directories with FindFirstFileW and FindNextFileW. For each interface it enumerates the XML files. This finds all profiles for all interfaces.

## Protected vs Plaintext

The protected tag indicates if the password is encrypted. If it's true the keyMaterial is DPAPI encrypted. If it's false or missing the keyMaterial is plaintext.

The code checks this tag and handles both cases. For encrypted passwords it decrypts them. For plaintext passwords it just extracts them directly.

## Administrator Requirement

The code requires administrator privileges for two reasons. First SeDebugPrivilege is only available to administrators. Second accessing the WLAN profiles directory requires elevated permissions.

You must run the executable as administrator. Right click and choose Run as administrator or run from an elevated command prompt.

## Why This Works

Windows stores WiFi passwords on disk so it can reconnect automatically. The passwords are encrypted to protect them from unauthorized access. But if you have administrator privileges you can impersonate SYSTEM and decrypt them.

This is by design. Administrators have full control over the system. If an attacker gains admin access they can do anything including extracting WiFi passwords. The security model assumes that admin access means game over.

## Comparison to WLAN API

The previous approach used WlanGetProfile with WLAN_PROFILE_GET_PLAINTEXT_KEY. That works for the current user's profiles without elevation. This approach reads the files directly and decrypts them with SYSTEM privileges. It works for all profiles on the system regardless of which user created them.

The WLAN API approach is simpler and doesn't require impersonation. This approach is more powerful but more complex. Use the API approach for user profiles and this approach for system-wide extraction.

## Security Implications

Any program running with administrator privileges can extract all WiFi passwords on the system. This is a common post-exploitation technique. Once an attacker has admin access they can steal all saved WiFi passwords.

The defense is to prevent unauthorized admin access. Use strong passwords, enable UAC, keep software updated, and use security software. If an attacker gets admin they can do much worse than steal WiFi passwords.

## Token Duplication

DuplicateTokenEx creates a copy of a token. The copy can have different access rights and type. The code duplicates the winlogon token as an impersonation token with TOKEN_ALL_ACCESS.

An impersonation token is used with SetThreadToken to impersonate a security context. A primary token is used with CreateProcessAsUser to create a process. The code needs impersonation so it specifies TokenImpersonation.

The security impersonation level is SecurityImpersonation which allows the thread to impersonate the token on the local system. Higher levels like SecurityDelegation allow impersonation across network boundaries.

---

That's WiFi password extraction via DPAPI decryption. Impersonate SYSTEM by duplicating the winlogon token, read the profile XML files from disk, decrypt the DPAPI blobs, and extract the plaintext passwords.
