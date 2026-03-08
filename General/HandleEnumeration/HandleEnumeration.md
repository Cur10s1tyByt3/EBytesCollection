# System-Wide Handle Enumeration

Enumerating all open handles across every process on the system using NtQuerySystemInformation.

## What It Does

Queries Windows for a complete list of every open handle in every process. This includes file handles, registry keys, mutexes, events, threads, processes, and everything else that uses a handle. Then it prints them all out with their owner PID, type, handle value, and access rights.

## How It Works

The code uses NtQuerySystemInformation with information class 16 which is SystemHandleInformation. This is an undocumented class that returns a massive list of every handle in the entire system. The list includes handles from all processes including system processes and other users' processes.

The tricky part is that you don't know how big the buffer needs to be ahead of time. The number of handles changes constantly as processes open and close things. So the code uses a retry loop. It calls NtQuerySystemInformation with a buffer and if the buffer is too small Windows returns STATUS_INFO_LENGTH_MISMATCH and tells you the required size in the ReturnLength parameter. Then you reallocate the buffer to that size and try again. You keep doing this until the call succeeds.

The buffer reallocation uses HeapReAlloc which grows the buffer without losing the data. On the first iteration Buffer is NULL so we use HeapAlloc to create it. On subsequent iterations we use HeapReAlloc to grow it. This keeps happening until the buffer is big enough and NtQuerySystemInformation returns success.

Once you have the data it's a SYSTEM_HANDLE_INFORMATION structure. This structure has a NumberOfHandles field telling you how many handles are in the list and then a flexible array member called Handles that contains all the entries. Each entry is a SYSTEM_HANDLE_TABLE_ENTRY_INFO structure with info about one handle.

The code loops through all the entries and prints them. Each entry tells you the PID of the process that owns the handle, the object type index which is a number representing what kind of object it is, the handle value which is the actual handle number, and the granted access mask which tells you what permissions the handle has.

## SYSTEM_HANDLE_TABLE_ENTRY_INFO Structure

Each handle entry has these fields. UniqueProcessId is the PID of the process that owns the handle. CreatorBackTraceIndex is used for debugging and usually not interesting. ObjectTypeIndex is a number representing the type of object like file, registry key, mutex, event, thread, process, etc. The exact mapping of numbers to types is system dependent and not documented. HandleAttributes contains flags about the handle like whether it's inheritable or protected from closing. HandleValue is the actual handle value that the process uses. Object is the kernel pointer to the object which is only useful in kernel mode. GrantedAccess is the access mask showing what permissions the handle has.

## Why Information Class 16

NtQuerySystemInformation has over 200 information classes. Class 16 is SystemHandleInformation which returns all handles system wide. There's also class 64 which is SystemExtendedHandleInformation that returns more detailed info but it's only available on newer Windows versions. Class 16 works on all Windows versions going back to NT.

## The Retry Loop

The loop keeps calling NtQuerySystemInformation until it succeeds. Each time it fails with STATUS_INFO_LENGTH_MISMATCH it updates BufferSize to the required size and reallocates the buffer. This pattern is necessary because the handle count changes constantly. Between the time you query the size and the time you query the data new handles might be created so you need to be ready to retry.

The HeapReAlloc call is a bit tricky. On the first iteration Buffer is NULL so we need to use HeapAlloc to create it. On subsequent iterations Buffer is valid so we use HeapReAlloc to grow it. The ternary operator handles this by checking if Buffer is NULL and calling the appropriate function.

## Flexible Array Member

The SYSTEM_HANDLE_INFORMATION structure has Handles[1] at the end. This is a flexible array member. It's declared as size 1 but actually contains NumberOfHandles entries. This is an old C trick for variable length structures. You allocate enough memory for the structure plus all the extra entries and then index into the array normally. Windows fills in all the entries and you just loop through them.

## Object Type Index

The ObjectTypeIndex field is a number but what does each number mean? That's not documented and it changes between Windows versions. On Windows 10 type 2 might be File and type 5 might be Event but on Windows 7 the numbers are different. If you want to know the actual type name you need to query each object individually using NtQueryObject which is slow and can hang on certain object types. Most tools just show the number or have a hardcoded mapping for specific Windows versions.

## Access Rights

The GrantedAccess field is a bitmask of permissions. For files it includes things like read, write, delete, execute. For processes it includes things like terminate, suspend, query information. The exact bits depend on the object type. You can look up the access masks in the Windows SDK headers for each object type.
