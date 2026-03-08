# WiFi Password Extraction

Extracting saved WiFi passwords from Windows using the WLAN API.

## What It Does

Enumerates all wireless interfaces on the system, retrieves all saved WiFi profiles, and extracts the plaintext passwords from the profile XML. This shows the SSID, authentication type, encryption type, and password for every WiFi network the system has connected to.

## How It Works

The code uses the Windows WLAN API to interact with the wireless subsystem. First it opens a handle to the WLAN service with WlanOpenHandle. This handle is used for all subsequent WLAN operations.

Then it enumerates all wireless interfaces on the machine with WlanEnumInterfaces. Most machines have one WiFi adapter but some have multiple. The function returns a list of interface information structures containing the interface GUID and description.

For each interface it retrieves the list of saved profiles with WlanGetProfileList. A profile is a saved WiFi network configuration. Every network you've connected to has a profile stored on the system. The function returns a list of profile names.

For each profile it retrieves the full profile XML with WlanGetProfile. The key part is passing the WLAN_PROFILE_GET_PLAINTEXT_KEY flag which tells the API to include the password in plaintext in the XML. Without this flag the password is encrypted or omitted. This flag requires administrator privileges.

The XML contains all the profile details including the SSID, authentication type, encryption type, and password. The code parses the XML to extract these values using a simple tag search function. It looks for tags like name, authentication, encryption, keyType, and keyMaterial.

The keyMaterial tag contains the actual password in plaintext. The code extracts this and prints it along with the other information. After processing all profiles it frees the memory and closes the WLAN handle.

## WlanOpenHandle

This function opens a handle to the WLAN service. The first parameter is the client version. Version 1 is for Windows XP. Version 2 is for Windows Vista and later. The code uses version 2 which works on all modern Windows versions.

The second parameter is reserved and must be NULL. The third parameter receives the negotiated version which tells you what version the service is using. The fourth parameter receives the WLAN handle.

The function returns ERROR_SUCCESS on success or an error code on failure. Common failures are ERROR_SERVICE_NOT_ACTIVE if the WLAN service isn't running or ERROR_ACCESS_DENIED if you don't have permission.

## WlanEnumInterfaces

This function enumerates all wireless interfaces on the system. It takes the WLAN handle, a reserved parameter that must be NULL, and a pointer to receive the interface list.

The function allocates a WLAN_INTERFACE_INFO_LIST structure and fills it with information about each interface. The structure has a dwNumberOfItems field indicating how many interfaces there are and an array of WLAN_INTERFACE_INFO structures.

Each interface info structure contains the interface GUID, description, and state. The GUID is used to identify the interface in other WLAN API calls. The description is a human readable name like Intel WiFi Adapter. The state indicates whether the interface is connected, disconnected, or in some other state.

## WlanGetProfileList

This function retrieves the list of saved profiles for an interface. It takes the WLAN handle, the interface GUID, a reserved parameter that must be NULL, and a pointer to receive the profile list.

The function allocates a WLAN_PROFILE_INFO_LIST structure and fills it with information about each profile. The structure has a dwNumberOfItems field and an array of WLAN_PROFILE_INFO structures.

Each profile info structure contains the profile name and flags. The profile name is the SSID of the network. The flags indicate things like whether the profile is a group policy profile or a user profile.

## WlanGetProfile

This function retrieves the full XML configuration for a profile. It takes the WLAN handle, the interface GUID, the profile name, a reserved parameter that must be NULL, a pointer to receive the XML string, a pointer to flags, and a pointer to receive the granted access mask.

The flags parameter is both input and output. On input you pass WLAN_PROFILE_GET_PLAINTEXT_KEY to request the password in plaintext. On output the function tells you what flags were honored. The granted access mask tells you what permissions you have on the profile.

The function allocates a wide string containing the profile XML and returns it. You must free this string with WlanFreeMemory when you're done. The XML contains all the profile settings in a structured format.

## WLAN_PROFILE_GET_PLAINTEXT_KEY

This flag is the key to extracting passwords. Without it the password is encrypted or omitted from the XML. With it the password appears in plaintext in the keyMaterial tag. 

The flag value is 0x4. You pass it in the flags parameter to WlanGetProfile. The function includes the plaintext password in the XML for profiles that the current user has access to.

## Profile XML Format

The profile XML is a structured document containing all the network settings. It has tags like name for the SSID, SSIDConfig for SSID configuration, connectionType for the connection type, connectionMode for the connection mode, MSM for media specific module settings, security for security settings, authEncryption for authentication and encryption types, and sharedKey for the password.

The sharedKey section contains keyType which is usually passPhrase for WPA/WPA2 networks and keyMaterial which is the actual password. The code extracts these values by searching for the tags in the XML.

## ExtractXmlValue

This helper function extracts the content between XML tags. It takes the XML string, the tag name, an output buffer, and the buffer size. It builds the open and close tags by wrapping the tag name in angle brackets. Then it searches for the open tag, advances past it, searches for the close tag, and copies the content between them into the output buffer.

This is a simple XML parser that works for the flat structure of WiFi profile XML. It doesn't handle nested tags or attributes but it's sufficient for extracting the values we need.

## Authentication Types

The authentication tag indicates the security protocol. Common values are open for open networks, WPA2PSK for WPA2 Personal, WPA2 for WPA2 Enterprise, and WPA3SAE for WPA3. The authentication type determines how the password is used.

## Encryption Types

The encryption tag indicates the encryption algorithm. Common values are none for open networks, TKIP for older WPA networks, AES for WPA2 and WPA3, and GCMP256 for WPA3. The encryption type determines how data is encrypted over the air.

## Key Types

The keyType tag indicates the format of the password. Common values are networkKey for WEP keys, passPhrase for WPA/WPA2 passphrases, and sometimes other values for enterprise networks. Most home networks use passPhrase.

## User Permissions

The WLAN API returns plaintext passwords for profiles that the current user created or has access to. You don't need administrator privileges to extract passwords for your own profiles. If you're logged in as the user who connected to the networks you can retrieve the passwords.

Profiles created by other users or system profiles might require elevated privileges depending on the profile permissions. But for typical user profiles no elevation is needed.

## WlanFreeMemory

The WLAN API allocates memory for the returned structures and strings. You must free this memory with WlanFreeMemory when you're done. The function takes a pointer to the memory and frees it. Forgetting to free memory causes leaks.

The code frees the profile XML after copying it to the result structure. It frees the profile list after processing all profiles. It frees the interface list after processing all interfaces.

## WlanCloseHandle

This function closes the WLAN handle and releases resources. You must call it when you're done with the WLAN API. The function takes the WLAN handle and a reserved parameter that must be NULL.

## Why This Works

Windows stores WiFi profiles in the registry and on disk. The profiles contain all the information needed to connect to the network including the password. The WLAN API provides access to these profiles. With administrator privileges you can retrieve the plaintext passwords.

This is by design. Administrators need to be able to view and manage WiFi settings including passwords. The WLAN API provides this capability. Security tools and password managers use this API to backup and restore WiFi settings.

## Security Implications

Any program running under a user account can extract WiFi passwords for that user's profiles. This is a common technique used by malware and information stealers. If malware runs under your user account it can steal all your saved WiFi passwords.

This is by design. Users need to be able to view their own WiFi passwords to share them or reconfigure devices. The WLAN API provides this access. The security model assumes that if code is running as your user it already has access to your data.

## Multiple Interfaces

Some machines have multiple WiFi adapters. Laptops might have a built in adapter and a USB adapter. Desktops might have multiple USB adapters. The code handles this by enumerating all interfaces and processing profiles for each one.

Each interface has its own set of profiles. A profile on one interface is independent of profiles on other interfaces. The code collects profiles from all interfaces into a single result list.

## Profile Storage

The code stores results in a WIFI_DATA structure containing the interface name, profile name, and XML data. This structure is allocated on the heap and filled by the enumeration function. The main function then parses the XML and prints the results.

The structure uses fixed size buffers which is simple but limits the size of the data. The XML buffer is 8192 wide characters which is enough for typical profiles. If a profile is larger it gets truncated.

## Error Handling

The code checks return values from WLAN API functions and continues on error. If WlanGetProfileList fails for an interface it skips that interface. If WlanGetProfile fails for a profile it skips that profile. This ensures the code processes as many profiles as possible even if some fail.

## Use Cases

This technique is used by password recovery tools, system administration utilities, and security auditing tools. It's also used by malware and post exploitation frameworks to steal credentials.

Legitimate uses include backing up WiFi settings before reinstalling Windows, migrating settings to a new machine, or auditing what networks a system has connected to.

---

That's WiFi password extraction. Use the WLAN API to enumerate interfaces and profiles, request plaintext passwords with the right flag, parse the XML to extract the passwords, and print the results.
