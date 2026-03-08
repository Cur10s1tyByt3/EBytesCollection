
# Kernel Driver Enumeration

Enumerating all loaded kernel drivers using the Psapi functions.

## What It Does

Gets a list of all kernel mode drivers currently loaded in the system. For each driver it shows the base address where it's loaded in kernel memory, the driver name, and the full file path. This only works if you run with administrator privileges.

## How It Works

The code uses three Psapi functions to enumerate drivers. First it calls EnumDeviceDrivers which fills an array with the base addresses of all loaded drivers. Each driver is loaded at a specific address in kernel memory and this function gives you those addresses. The function takes a buffer, the buffer size in bytes, and returns how many bytes were actually needed. You divide the bytes by sizeof(LPVOID) to get the count of drivers.

Once you have the base addresses you can query information about each driver. GetDeviceDriverBaseNameA takes a base address and returns just the filename like ntoskrnl.exe or win32k.sys. GetDeviceDriverFileNameA takes a base address and returns the full path like SystemRoot\system32\ntoskrnl.exe. Note that the paths use NT path format not DOS path format so you see SystemRoot instead of C:\Windows.

The code loops through all the base addresses and calls both name functions for each one. It prints the base address, the short name, and the full path. If a base address is NULL it skips it because that means the enumeration failed for that entry which happens when you don't have admin rights.

## Why Administrator Rights

Kernel drivers run in kernel mode which is a privileged execution level. Regular user mode code can't directly access kernel memory or kernel structures. The Psapi functions need to query kernel information to get the driver list so they require administrator privileges. If you run without admin the functions will fail or return partial results with NULL entries.

## EnumDeviceDrivers

This function is the core of driver enumeration. You pass it an array of LPVOID pointers and it fills the array with base addresses. The function signature takes the buffer, the buffer size in bytes, and a pointer to receive the bytes needed. If your buffer is too small it still succeeds but only fills what fits and tells you the real size needed in BytesNeeded.

The return value is TRUE on success or FALSE on failure. If it fails you check GetLastError to see why. Common errors are access denied if you're not admin or invalid parameter if you pass bad pointers.

## GetDeviceDriverBaseNameA

This function takes a driver base address and returns just the filename. For example if the driver is loaded from C:\Windows\System32\drivers\ntfs.sys it returns ntfs.sys. This is useful when you just want to identify the driver without caring about the full path.

The function takes the base address, a buffer to receive the name, and the buffer size. It returns the number of characters copied or 0 on failure. If it fails the code sets the name to unknown so you still get output.

## GetDeviceDriverFileNameA

This function takes a driver base address and returns the full NT path. NT paths use a different format than regular Windows paths. Instead of C:\Windows you see SystemRoot. Instead of C:\Program Files you might see \Device\HarddiskVolume2\Program Files. This is the native kernel path format.

The function signature is the same as GetDeviceDriverBaseNameA. It takes the base address, a buffer, and the buffer size. Returns the number of characters copied or 0 on failure.

## Driver Base Addresses

Each driver is loaded at a specific address in kernel virtual memory. The base address is where the driver's PE image starts in memory. This is similar to how user mode DLLs have base addresses but these are in kernel space not user space. Typical kernel addresses are in the high range like 0xFFFFF80000000000 on 64 bit systems.
