# Thread Enumeration via NtGetNextThread

Enumerating threads in a process using the undocumented NtGetNextThread function.

## What It Does

Enumerates all threads in a process using an iterator pattern. Instead of taking a snapshot like CreateToolhelp32Snapshot this function walks through threads one at a time. Each call returns the next thread handle until there are no more threads.

## How It Works

The code resolves NtGetNextThread from ntdll.dll using GetProcAddress. This function is exported but not documented by Microsoft. It's been stable since Windows Vista and is used internally by Windows.

You start by calling NtGetNextThread with a NULL thread handle. This returns a handle to the first thread in the process. Then you call it again passing the previous thread handle. This returns the next thread. You keep calling it until it returns STATUS_NO_MORE_ENTRIES which means you've enumerated all threads.

Each call gives you a new thread handle with the access rights you requested. The code requests THREAD_QUERY_INFORMATION which allows querying thread information. You can use this handle with other thread APIs like GetThreadId, GetThreadTimes, or SuspendThread.

After getting each thread handle the code calls GetThreadId to get the thread ID and prints it. Then it closes the previous handle and saves the new one. This continues until the enumeration is complete.

## NtGetNextThread

This is an undocumented ntdll function that enumerates threads. The signature takes a process handle, the current thread handle, desired access rights, handle attributes, flags, and a pointer to receive the new thread handle.

The process handle identifies which process to enumerate threads from. The current thread handle is the iterator position. Pass NULL to start at the beginning. Pass a thread handle to get the next thread after that one.

The desired access parameter specifies what access rights the returned handle should have. Common values are THREAD_QUERY_INFORMATION for querying, THREAD_SUSPEND_RESUME for suspending, or THREAD_ALL_ACCESS for everything.

The handle attributes and flags parameters are reserved and should be 0. The function returns STATUS_SUCCESS if it found another thread or STATUS_NO_MORE_ENTRIES if there are no more threads.

## Iterator Pattern

Unlike CreateToolhelp32Snapshot which takes a snapshot at a point in time, NtGetNextThread is an iterator. It walks the live thread list in the kernel. If threads are created or destroyed during enumeration you might see them or miss them depending on timing.

The iterator pattern is more efficient because it doesn't need to allocate a snapshot buffer. It just walks the kernel data structures directly. But it's less consistent because the thread list can change between calls.

## Thread Handles

Each call to NtGetNextThread returns a new thread handle. You're responsible for closing these handles when you're done. The code closes the previous handle before getting the next one to avoid leaking handles.

The handles have the access rights you requested. If you request THREAD_QUERY_INFORMATION you can query the thread but not suspend it. If you request THREAD_ALL_ACCESS you can do anything.

## GetThreadId

This function takes a thread handle and returns the thread ID. Thread IDs are numeric identifiers that are unique system-wide at any given time. They can be reused after a thread exits but while the thread is alive the ID is unique.

Thread IDs are used to identify threads in debugging tools, performance monitors, and other system utilities. The ID is what you see in Task Manager or Process Explorer.

## Why Use This Function

There are several ways to enumerate threads. CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD is the documented way. NtQuerySystemInformation with SystemProcessInformation returns thread information. NtGetNextThread is a third option.

The advantage of NtGetNextThread is it's simple and efficient. You don't need to allocate a snapshot buffer or parse complex structures. You just call it in a loop and get thread handles.

The disadvantage is it's undocumented. Microsoft doesn't guarantee it will exist in future Windows versions or that the signature won't change. In practice it's been stable for over a decade but there's always a risk with undocumented APIs.

## Undocumented but Stable

NtGetNextThread has been in ntdll since Windows Vista. It's used internally by Windows components and debugging tools. The signature and behavior have been consistent across all Windows versions from Vista to Windows 11.

Many low level tools use undocumented ntdll functions because they're more powerful or convenient than the documented APIs. Process Hacker, x64dbg, and other tools rely on these functions.

## STATUS_NO_MORE_ENTRIES

This is the return value when there are no more threads to enumerate. It's defined in ntstatus.h as 0x8000001A. The code checks for STATUS_SUCCESS which is 0 to know if the call succeeded.

When you get STATUS_NO_MORE_ENTRIES you stop the loop and close the last thread handle. This is the normal end of enumeration.

## Process Handle

You need a process handle with PROCESS_QUERY_INFORMATION access to enumerate threads. The code opens the current process but you could open any process you have permission to access.

For remote processes you need appropriate permissions. System processes and processes running as other users might require administrator privileges or SeDebugPrivilege.

## Thread Access Rights

The desired access parameter determines what you can do with the returned thread handles. THREAD_QUERY_INFORMATION lets you query thread information like ID, times, and priority. THREAD_SUSPEND_RESUME lets you suspend and resume the thread. THREAD_TERMINATE lets you terminate the thread.

The code only needs to query the thread ID so it requests THREAD_QUERY_INFORMATION. If you wanted to suspend threads or read their context you'd need different access rights.

## Handle Cleanup

The code closes each thread handle after printing the information. This is important to avoid handle leaks. If you enumerate threads in a loop without closing handles you'll eventually run out of handles.

The pattern is to close the previous handle before getting the next one. At the end of the loop you close the last handle. This ensures all handles are cleaned up.

## Current Process

The code enumerates threads in the current process by using GetCurrentProcessId and opening a handle to itself. This is safe and doesn't require special permissions.

You could easily modify it to enumerate threads in another process by changing the PID. Just make sure you have permission to open that process.

## Thread Creation and Destruction

If threads are created or destroyed while you're enumerating you might see them or miss them. The iterator walks the live list so it reflects the current state at each call.

This is usually not a problem. Thread creation and destruction are relatively rare events. Most processes have a stable set of threads. But if you're enumerating a process that's actively creating and destroying threads you might see inconsistent results.

## Use Cases

Thread enumeration is useful for debugging, profiling, and system monitoring. You can see what threads a process has, suspend or resume them, read their context, or analyze their behavior.

Security tools enumerate threads to detect suspicious activity. Malware might create hidden threads or inject threads into other processes. By enumerating threads you can detect these anomalies.

Debuggers enumerate threads to show the thread list and allow switching between threads. Performance tools enumerate threads to measure CPU usage per thread.

---

That's thread enumeration via NtGetNextThread. Resolve the function from ntdll, call it in a loop starting with NULL, get thread handles, and close them when done.
