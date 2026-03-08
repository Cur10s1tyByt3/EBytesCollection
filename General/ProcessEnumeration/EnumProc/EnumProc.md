# Process Enumeration Helper

A simple utility function that finds a process ID by its executable name using the Windows API.

## What This Does

This code provides a helper function `GetProcessIdFromName()` that searches through all running processes and returns the PID of the first one matching the given name. It's a common building block for tools that need to interact with other processes.

## How It Works

### The Function Breakdown

```
GetProcessIdFromName("notepad.exe")
         |
         v
    EnumProcesses() -----> Get all PIDs into array
         |
         v
    Loop through each PID
         |
         v
    OpenProcess() --------> Get handle to process
         |
         v
    EnumProcessModules() -> Get main module (the .exe)
         |
         v
    GetModuleBaseNameA() -> Get the executable name
         |
         v
    Compare with target name
         |
         v
    Return PID if match
```

### Step-by-Step

1. **EnumProcesses()** - Grabs all running process IDs into a buffer
   - Takes a DWORD array to fill with PIDs
   - Returns how many bytes were written
   - We divide bytes by sizeof(DWORD) to get the count

2. **OpenProcess()** - Opens each process with query rights
   - `PROCESS_QUERY_INFORMATION` - lets us ask questions about the process
   - `PROCESS_VM_READ` - lets us read its memory (needed for module info)
   - Returns NULL if we don't have permission (skip it)

3. **EnumProcessModules()** - Gets the main executable module
   - First module is always the main .exe
   - We only ask for one module (sizeof(MainModule))
   - This is way faster than enumerating all DLLs

4. **GetModuleBaseNameA()** - Extracts just the filename
   - Returns "notepad.exe" not "C:\Windows\System32\notepad.exe"
   - ANSI version (A suffix) for simple char strings

5. **lstrcmpA()** - Case-insensitive string comparison
   - Returns 0 if strings match
   - Windows API string compare function

## Usage Example

```cpp
CONST DWORD Id = GetProcessIdFromName("Notepad.exe");
printf("[+] notepad PID: %d\n", Id);
```

Output:
```
[+] notepad PID: 12345
```

## Permissions

You need these rights to enumerate processes:

- **SeDebugPrivilege** - Optional but helps access more processes
- **PROCESS_QUERY_INFORMATION** - Required to query process info
- **PROCESS_VM_READ** - Required to read module information

Without admin rights, you can only query processes running under your user account. System processes and other users' processes will be skipped (OpenProcess returns NULL).

## Error Handling

> Always check the return value:

```cpp
DWORD pid = GetProcessIdFromName("target.exe");
if (pid == 0)
{
    printf("[-] Process not found or access denied\n");
    return -1;
}
```

