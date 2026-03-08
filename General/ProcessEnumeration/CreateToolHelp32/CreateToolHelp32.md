# Process Enumeration via CreateToolhelp32Snapshot

Finding a process ID by name using the Toolhelp API.

## What It Does

Takes a snapshot of all running processes and walks through them to find one matching the given name. Returns the PID.

## How It Works

```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
         |
         v
    Snapshot of all processes
         |
         v
    Process32Next() in a loop
         |
         v
    Compare szExeFile with target name
         |
         v
    Return th32ProcessID
```

