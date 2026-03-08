#define WIN32_NO_STATUS
#include<Windows.h>
#undef WIN32_NO_STATUS
#include<ntstatus.h>
#include<winternl.h>
#include<cstdio>

//
// ============================================================
//  SMBIOS raw table fetch via NtQuerySystemInformation
//  class 0x4C (SystemFirmwareTableInformation).
//
//  ProviderSignature 'RSMB' = Raw SMBIOS data directly from
//  the firmware — no abstraction layer.
// ============================================================
//

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
    SystemFirmwareTable_Enumerate = 0,
    SystemFirmwareTable_Get = 1
} SYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG                          ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION   Action;
    ULONG                          TableID;
    ULONG                          TableBufferLength;
    UCHAR                          TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;

//
// Raw SMBIOS data layout returned inside TableBuffer.
//
typedef struct _RAW_SMBIOS_DATA {
    BYTE   Used20CallingMethod;
    BYTE   MajorVersion;
    BYTE   MinorVersion;
    BYTE   DmiRevision;
    DWORD  Length;
    BYTE   SMBIOSTableData[1];
} RAW_SMBIOS_DATA, * PRAW_SMBIOS_DATA;

//
// Every SMBIOS structure starts with this header.
//
typedef struct _SMBIOS_HEADER {
    BYTE  Type;
    BYTE  Length;
    WORD  Handle;
} SMBIOS_HEADER, * PSMBIOS_HEADER;

//
// Type 1 — System Information (contains UUID).
//
typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Header;
    BYTE          Manufacturer;
    BYTE          ProductName;
    BYTE          Version;
    BYTE          SerialNumber;
    BYTE          UUID[16];
    BYTE          WakeUpType;
    BYTE          SKUNumber;
    BYTE          Family;
} SMBIOS_TYPE1, * PSMBIOS_TYPE1;

typedef NTSTATUS
(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
    );

//
// ============================================================
//  GetSmbiosInfo
//  Allocates a buffer and fetches the raw SMBIOS table.
//  Caller must HeapFree the returned pointer.
// ============================================================
//

PSYSTEM_FIRMWARE_TABLE_INFORMATION
GetSmbiosInfo(
    VOID
)
{
    CONST PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );

    if (NtQuerySystemInformation == NULL)
    {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        return NULL;
    }

    ULONG BufferSize = 65536;

    PSYSTEM_FIRMWARE_TABLE_INFORMATION Info =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            BufferSize
        );

    if (Info == NULL)
    {
        return NULL;
    }

    //
    // 'RSMB' = 0x52534D42 — requests raw SMBIOS table from firmware.
    // TableID 0 = first/only table for RSMB provider.
    //
    Info->ProviderSignature = 'RSMB';
    Info->Action = SystemFirmwareTable_Get;
    Info->TableID = 0;
    Info->TableBufferLength = BufferSize;

    NTSTATUS Status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)0x4C,
        Info,
        BufferSize,
        &BufferSize
    );

    if (!NT_SUCCESS(Status))
    {
        printf("[-] NtQuerySystemInformation failed: 0x%08X\n", Status);
        HeapFree(GetProcessHeap(), 0, Info);
        return NULL;
    }

    return Info;
}

//
// ============================================================
//  ParseUUID
//  Extracts UUID from SMBIOS Type 1 structure and formats
//  it as a standard XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX string.
//
//  Per SMBIOS spec, first three components are little-endian,
//  last two are big-endian.
// ============================================================
//

VOID
ParseUUID(
    _In_  CONST BYTE* UUID,
    _Out_ WCHAR* OutBuffer,
    _In_  DWORD       BufferSize
)
{
    wsprintfW(
        OutBuffer,
        L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        //
        // First component — 4 bytes little-endian (reversed).
        //
        UUID[3], UUID[2], UUID[1], UUID[0],
        //
        // Second component — 2 bytes little-endian.
        //
        UUID[5], UUID[4],
        //
        // Third component — 2 bytes little-endian.
        //
        UUID[7], UUID[6],
        //
        // Fourth and fifth components — big-endian (as-is).
        //
        UUID[8], UUID[9],
        UUID[10], UUID[11], UUID[12],
        UUID[13], UUID[14], UUID[15]
    );
}

//
// ============================================================
//  GetStringFromSmbios
//  SMBIOS string table lives after the formatted structure.
//  Strings are 1-indexed null-terminated sequences.
// ============================================================
//

LPCSTR
GetStringFromSmbios(
    _In_ PSMBIOS_HEADER Header,
    _In_ BYTE           StringIndex
)
{
    if (StringIndex == 0)
    {
        return "<not present>";
    }

    //
    // String table starts immediately after the formatted structure area.
    //
    LPCSTR StringPtr = (LPCSTR)Header + Header->Length;
    BYTE   Index = 1;

    while (*StringPtr != '\0')
    {
        if (Index == StringIndex)
        {
            return StringPtr;
        }

        //
        // Advance past this null-terminated string.
        //
        StringPtr += lstrlenA(StringPtr) + 1;
        Index++;
    }

    return "<not found>";
}

INT
main(
    VOID
)
{
    PSYSTEM_FIRMWARE_TABLE_INFORMATION Info = GetSmbiosInfo();

    if (Info == NULL)
    {
        return 1;
    }

    //
    // TableBuffer contains the RAW_SMBIOS_DATA header followed
    // by the actual SMBIOS structures.
    //
    CONST PRAW_SMBIOS_DATA RawData = (PRAW_SMBIOS_DATA)Info->TableBuffer;

    printf(
        "[+] SMBIOS version: %d.%d  DMI revision: %d  Table size: %d bytes\n\n",
        RawData->MajorVersion,
        RawData->MinorVersion,
        RawData->DmiRevision,
        RawData->Length
    );

    //
    // Walk every SMBIOS structure in the table.
    //
    PBYTE  Current = RawData->SMBIOSTableData;
    PBYTE  End = Current + RawData->Length;

    while (Current < End)
    {
        CONST PSMBIOS_HEADER Header = (PSMBIOS_HEADER)Current;

        //
        // Type 127 = end-of-table sentinel.
        //
        if (Header->Type == 127)
        {
            break;
        }

        if (Header->Type == 1)
        {
            //
            // Type 1 — System Information.
            //
            CONST PSMBIOS_TYPE1 Type1 = (PSMBIOS_TYPE1)Header;

            WCHAR UuidStr[64] = { 0 };
            ParseUUID(Type1->UUID, UuidStr, 64);

            printf("[+] System Information (Type 1)\n");
            printf("  Manufacturer : %s\n", GetStringFromSmbios(Header, Type1->Manufacturer));
            printf("  Product Name : %s\n", GetStringFromSmbios(Header, Type1->ProductName));
            printf("  Version      : %s\n", GetStringFromSmbios(Header, Type1->Version));
            printf("  Serial Number: %s\n", GetStringFromSmbios(Header, Type1->SerialNumber));
            printf("  UUID         : %ws\n", UuidStr);
            printf("\n");
        }

        //
        // Advance past the formatted area to the string table.
        // String table ends with a double null terminator.
        //
        PBYTE StringTable = Current + Header->Length;

        while (*(WORD*)StringTable != 0)
        {
            StringTable++;
        }

        Current = StringTable + 2;
    }

    HeapFree(GetProcessHeap(), 0, Info);
    return 0;
}
