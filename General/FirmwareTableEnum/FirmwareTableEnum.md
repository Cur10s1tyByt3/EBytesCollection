# SMBIOS Information Extraction

Extracting hardware information from the SMBIOS firmware tables using NtQuerySystemInformation.

## What It Does

Queries the raw SMBIOS tables from the system firmware and parses them to extract hardware information like manufacturer, product name, serial number, and UUID. SMBIOS is System Management BIOS which is a standard for exposing hardware information to the operating system.

## How It Works

The code uses NtQuerySystemInformation with information class 0x4C which is SystemFirmwareTableInformation. This class allows querying firmware tables including ACPI tables and SMBIOS tables. You specify a provider signature to indicate which type of table you want.

The provider signature RSMB means Raw SMBIOS. This gives you the raw SMBIOS data directly from the firmware without any abstraction. The data is a binary blob containing SMBIOS structures laid out according to the SMBIOS specification.

The code allocates a buffer, fills in the request structure with the RSMB provider signature and action SystemFirmwareTable_Get, and calls NtQuerySystemInformation. The function fills the buffer with the raw SMBIOS data.

The returned data starts with a RAW_SMBIOS_DATA header containing the SMBIOS version and table length. After the header comes the actual SMBIOS structures. Each structure starts with a header containing the type, length, and handle. After the header comes type-specific data. After the data comes a string table.

The code walks through the structures by reading the header, processing the type-specific data, skipping past the string table, and advancing to the next structure. It looks for Type 1 which is System Information and extracts the manufacturer, product name, version, serial number, and UUID.

## SMBIOS Structure

SMBIOS is a standard defined by the DMTF. The firmware exposes hardware information as a table of structures. Each structure has a type indicating what kind of information it contains. Common types are BIOS information, system information, baseboard information, processor information, memory information, and many others.

Each structure has a fixed format area followed by a variable string table. The fixed area contains numeric fields and string indices. The string table contains null-terminated strings. String indices in the fixed area are 1-based offsets into the string table.

The structures are packed end to end in memory. To walk them you read the header to get the length, skip past the fixed area, skip past the string table which ends with a double null, and you're at the next structure. Type 127 is the end-of-table marker.

## SystemFirmwareTableInformation

This is information class 0x4C for NtQuerySystemInformation. It allows querying firmware tables. You pass a SYSTEM_FIRMWARE_TABLE_INFORMATION structure with the provider signature, action, table ID, and buffer.

The provider signature is a four character code. RSMB is raw SMBIOS. FIRM is ACPI firmware. ACPI is ACPI tables. Each provider exposes different tables.

The action is either enumerate or get. Enumerate lists available table IDs. Get retrieves a specific table. The code uses get with table ID 0 which is the main SMBIOS table.

## RSMB Provider

RSMB stands for Raw System Management BIOS. This provider gives you the raw SMBIOS data exactly as it appears in firmware. The data format follows the SMBIOS specification published by DMTF.

The returned data starts with a RAW_SMBIOS_DATA structure containing metadata about the SMBIOS version and table size. The SMBIOSTableData field is a flexible array containing the actual structures.

## SMBIOS Type 1

Type 1 is System Information. This structure contains identifying information about the system including manufacturer, product name, version, serial number, UUID, wake-up type, SKU number, and family.

The UUID is particularly interesting. It's a 16 byte unique identifier for the system. The UUID format follows RFC 4122 but with a quirk. The first three components are little-endian and the last two are big-endian. This is a historical artifact of how different firmware vendors implemented it.

## UUID Parsing

The code parses the UUID by reversing the byte order of the first three components and keeping the last two as-is. The result is formatted as a standard UUID string with dashes.

For example if the raw bytes are 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 the formatted UUID is 04030201-0605-0807-090A-0B0C0D0E0F10. Notice the first three groups are reversed but the last two are not.

## String Table

After each SMBIOS structure comes a string table. The table is a sequence of null-terminated strings. The end of the table is marked by a double null. String indices in the structure are 1-based so index 1 is the first string, index 2 is the second, and so on. Index 0 means no string.

The code walks the string table by starting at the end of the fixed structure area and advancing past each null-terminated string until it finds the requested index or hits the double null.

## Structure Walking

To walk the structures you start at the beginning of the table and keep advancing until you hit the end or find type 127. For each structure you read the header to get the type and length. You process the type-specific data. Then you skip past the string table by scanning for the double null. Then you advance to the next structure.

The string table scan looks for a WORD value of 0 which is two consecutive null bytes. This marks the end of the string table. You advance past it by 2 bytes to get to the next structure.

## Information Class 0x4C

This is SystemFirmwareTableInformation. It's an undocumented information class but it's been stable since Windows Vista. The documented API is GetSystemFirmwareTable but it's just a wrapper around NtQuerySystemInformation with this class.

The advantage of using NtQuerySystemInformation directly is you have more control and can see exactly what's happening. The disadvantage is it's undocumented and requires manual structure definitions.

## SMBIOS Version

The RAW_SMBIOS_DATA header contains the SMBIOS version as major and minor numbers. Common versions are 2.4, 2.7, 3.0, and 3.2. The version determines which structures and fields are available. Newer versions add new structure types and fields.

The DMI revision is related but different. DMI is Desktop Management Interface which was the predecessor to SMBIOS. The revision indicates compatibility with DMI.

## Other SMBIOS Types

The code only parses Type 1 but there are many other types. Type 0 is BIOS information. Type 2 is baseboard information. Type 4 is processor information. Type 17 is memory device information. Type 32 is system boot information. There are over 40 defined types.

Each type has its own structure layout. To parse them you need to define the structure and cast the header pointer to that type. Then you can access the fields and extract the strings.

## Why Query SMBIOS

SMBIOS information is useful for hardware inventory, system identification, and compatibility checking. The UUID is often used as a unique machine identifier. The serial number and manufacturer are used for asset tracking. The processor and memory information are used for system profiling.

Security tools use SMBIOS to detect virtual machines. VMs often have telltale values in the manufacturer or product name fields. Malware uses this to detect if it's running in a sandbox.

## Virtual Machine Detection

Many VMs have obvious SMBIOS values. VMware sets the manufacturer to VMware Inc. VirtualBox sets it to innotek GmbH. QEMU sets it to QEMU. Hyper-V sets it to Microsoft Corporation with product name Virtual Machine.

By checking these strings you can detect if you're running in a VM. This is a common anti-analysis technique used by malware. It's also used by legitimate software to adjust behavior in virtualized environments.

## Serial Number

The serial number is supposed to be unique per system. In practice it's often not set or is set to a default value. Some manufacturers use it properly and some don't. It's more reliable on enterprise hardware than consumer hardware.

The serial number can be used for asset tracking or license enforcement. Some software uses it as part of a hardware fingerprint to tie licenses to specific machines.

## Manufacturer and Product Name

These strings identify the system vendor and model. For example a Dell laptop might have manufacturer Dell Inc and product name Latitude 7490. A custom built PC might have manufacturer To Be Filled By O.E.M.

These values come from the firmware and are set by the manufacturer. They're useful for identifying the hardware platform and looking up specifications or drivers.

## Handle Field

Each SMBIOS structure has a handle which is a unique identifier within the table. Handles are used to reference structures from other structures. For example a memory device structure might reference a physical memory array structure by handle.

The code doesn't use handles but they're part of the header. If you're parsing relationships between structures you need to track handles.

## Length Field

The length field in the header indicates the size of the fixed format area. It doesn't include the string table. To skip to the next structure you advance by the length then scan past the string table.

Different versions of the same structure type can have different lengths. Newer SMBIOS versions add fields to the end of structures. The length tells you which version you're dealing with.

## End of Table

Type 127 marks the end of the table. When you encounter it you stop walking. Some tables might have padding or garbage after type 127 so you should stop when you see it rather than relying on the table length.

## Buffer Size

The code allocates a 64KB buffer which is usually enough for SMBIOS tables. Most tables are a few KB. If the table is larger the call fails and you need a bigger buffer. You could query the size first then allocate exactly what's needed but 64KB is a safe default.

## No Special Privileges

Querying SMBIOS doesn't require administrator privileges. Any user can do it. The information is considered public and is exposed through various APIs. This makes it easy to gather hardware information without elevation.

---

That's SMBIOS information extraction. Query the raw firmware tables via NtQuerySystemInformation, parse the SMBIOS structures, extract the strings, and display the hardware information.
