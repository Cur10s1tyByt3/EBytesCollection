#include <Windows.h>
#include <cstdio>
#include <wlanapi.h>
#pragma comment(lib, "wlanapi.lib")

//
// ============================================================
//  WifiData — holds profile name, XML, and interface name
// ============================================================
//

typedef struct _WIFI_DATA {
    WCHAR InterfaceName[256];
    WCHAR ProfileName[256];
    WCHAR XmlData[8192];
} WIFI_DATA, * PWIFI_DATA;

//
// ============================================================
//  GetWifiDataWithPasswords
//  Enumerates all WLAN interfaces and profiles, retrieving
//  plaintext credentials from each profile's XML blob.
// ============================================================
//

DWORD
GetWifiDataWithPasswords(
    _Out_ PWIFI_DATA Results,
    _In_  DWORD      MaxResults
)
{
    HANDLE WlanHandle = NULL;
    DWORD  NegVersion = 0;
    DWORD  ResultCount = 0;

    //
    // Open a handle to the WLAN API.
    // Client version 1 = XP, 2 = Vista+.
    //
    if (WlanOpenHandle(2, NULL, &NegVersion, &WlanHandle) != ERROR_SUCCESS)
    {
        printf("[-] WlanOpenHandle failed: %d\n", GetLastError());
        return 0;
    }

    //
    // Enumerate all wireless interfaces on the machine.
    //
    PWLAN_INTERFACE_INFO_LIST InterfaceList = NULL;

    if (WlanEnumInterfaces(WlanHandle, NULL, &InterfaceList) != ERROR_SUCCESS)
    {
        printf("[-] WlanEnumInterfaces failed: %d\n", GetLastError());
        WlanCloseHandle(WlanHandle, NULL);
        return 0;
    }

    for (DWORD i = 0; i < InterfaceList->dwNumberOfItems; i++)
    {
        CONST PWLAN_INTERFACE_INFO InterfaceInfo =
            &InterfaceList->InterfaceInfo[i];

        GUID InterfaceGuid = InterfaceInfo->InterfaceGuid;

        //
        // Retrieve all saved profiles for this interface.
        //
        PWLAN_PROFILE_INFO_LIST ProfileList = NULL;

        if (WlanGetProfileList(WlanHandle, &InterfaceGuid, NULL, &ProfileList) != ERROR_SUCCESS)
        {
            continue;
        }

        for (DWORD x = 0; x < ProfileList->dwNumberOfItems && ResultCount < MaxResults; x++)
        {
            CONST PWLAN_PROFILE_INFO ProfileInfo =
                &ProfileList->ProfileInfo[x];

            LPWSTR  ProfileXml = NULL;
            DWORD   ProfileFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD   GrantedAccess = 0;

            //
            // WLAN_PROFILE_GET_PLAINTEXT_KEY (0x4) requests the password
            // in plaintext inside the XML blob
            //
            if (WlanGetProfile(
                WlanHandle,
                &InterfaceGuid,
                ProfileInfo->strProfileName,
                NULL,
                &ProfileXml,
                &ProfileFlags,
                &GrantedAccess) != ERROR_SUCCESS)
            {
                continue;
            }

            PWIFI_DATA Entry = &Results[ResultCount];

            //
            // Copy interface description, profile name, and XML blob
            // into our result structure.
            //
            RtlCopyMemory(
                Entry->InterfaceName,
                InterfaceInfo->strInterfaceDescription,
                sizeof(Entry->InterfaceName)
            );

            RtlCopyMemory(
                Entry->ProfileName,
                ProfileInfo->strProfileName,
                sizeof(Entry->ProfileName)
            );

            if (ProfileXml != NULL)
            {
                RtlCopyMemory(
                    Entry->XmlData,
                    ProfileXml,
                    min((lstrlenW(ProfileXml) + 1) * sizeof(WCHAR),
                        sizeof(Entry->XmlData))
                );

                WlanFreeMemory(ProfileXml);
            }

            ResultCount++;
        }

        WlanFreeMemory(ProfileList);
    }

    WlanFreeMemory(InterfaceList);
    WlanCloseHandle(WlanHandle, NULL);

    return ResultCount;
}

VOID
ExtractXmlValue(
    _In_  LPCWSTR Xml,
    _In_  LPCWSTR Tag,
    _Out_ WCHAR* OutBuffer,
    _In_  DWORD   BufferSize
)
{
    //
    // Build open and close tag strings, then extract content between them.
    //
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
    if (Length >= BufferSize)
    {
        Length = BufferSize - 1;
    }

    RtlCopyMemory(OutBuffer, Start, Length * sizeof(WCHAR));
    OutBuffer[Length] = L'\0';
}

INT
main(
    VOID
)
{
    CONST PWIFI_DATA Results = (PWIFI_DATA)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(WIFI_DATA) * 256
    );

    if (Results == NULL)
    {
        printf("[-] HeapAlloc failed\n");
        return 1;
    }

    CONST DWORD Count = GetWifiDataWithPasswords(Results, 256);

    printf("[+] Found %d saved profiles\n\n", Count);

    for (DWORD i = 0; i < Count; i++)
    {
        WCHAR Ssid[256] = { 0 };
        WCHAR Auth[256] = { 0 };
        WCHAR Encryption[256] = { 0 };
        WCHAR Password[256] = { 0 };
        WCHAR KeyType[256] = { 0 };

        ExtractXmlValue(Results[i].XmlData, L"name", Ssid, 256);
        ExtractXmlValue(Results[i].XmlData, L"authentication", Auth, 256);
        ExtractXmlValue(Results[i].XmlData, L"encryption", Encryption, 256);
        ExtractXmlValue(Results[i].XmlData, L"keyType", KeyType, 256);
        ExtractXmlValue(Results[i].XmlData, L"keyMaterial", Password, 256);

        printf("  Interface  : %ws\n", Results[i].InterfaceName);
        printf("  SSID       : %ws\n", Ssid);
        printf("  Auth       : %ws\n", Auth);
        printf("  Encryption : %ws\n", Encryption);
        printf("  Key Type   : %ws\n", KeyType);
        printf("  Password   : %ws\n", Password);
        printf("  --------------------------------\n\n");
    }

    HeapFree(GetProcessHeap(), 0, Results);
    return 0;
}
