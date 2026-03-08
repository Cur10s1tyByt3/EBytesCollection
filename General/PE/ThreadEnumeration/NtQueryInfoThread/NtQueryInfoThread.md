# Thread Enumeration with NtQueryInformationThread

Combining thread enumeration with detailed per-thread queries using NtGetNextThread and NtQueryInformationThread.

## What It Does

Enumerates threads using NtGetNextThread and queries detailed information for each thread using NtQueryInformationThread. This combines the iterator pattern with per-thread queries to get the TEB address, Win32 start address, priority, and affinity mask. The Win32 start address is the actual function pointer passed to CreateThread, not the kernel wrapper.

## How It Works

The code resolves two functions from ntdll. NtGetNextThread enumerates threads using an iterator pattern. NtQueryInformationThread queries information about a specific thread.

It loops through threads using NtGetNextThread. For each thread it makes two queries. First it queries class 0 which is ThreadBasicInformation. This returns a THREAD_BASIC_INFORMATION structure containing the exit status, TEB address, client ID, affinity mask, and priority.

Second it queries class 9 which is ThreadQuerySetWin32StartAddress. This returns the actual Win32 start address which is the function pointer passed to CreateThread. This is different from the start address returned by NtQuerySystemInformation which always points to RtlUserThreadStart.

After getting the information it prints the thread ID, TEB address, Win32 start address, priority, and affinity mask. Then it closes the previous thread handle and continues to the next thread.

## NtQueryInformationThread

This is an undocumented ntdll function that queries information about a thread. The signature takes a thread handle, an information class, a buffer to receive the information, the buffer size, and an optional pointer to receive the bytes written.

The information class determines what information is returned. Class 0 is basic information. Class 9 is Win32 start address. There are many other classes for different types of information.

The function returns STATUS_SUCCESS on success or an error code on failure. Common errors are STATUS_INVALID_HANDLE if the handle is invalid or STATUS_INFO_LENGTH_MISMATCH if the buffer is too small.

## ThreadBasicInformation

This is information class 0. It returns a THREAD_BASIC_INFORMATION structure containing basic information about the thread. The structure has ExitStatus which is the thread's exit code if it's terminated, TebBaseAddress which is the address of the Thread Environment Block, ClientId which contains the process ID and thread ID, AffinityMask which indicates which CPUs the thread can run on, Priority which is the current dynamic priority, and BasePriority which is the base priority.

This information is useful for understanding the thread's state and configuration. The TEB address is particularly interesting because it gives you access to thread-local storage and other per-thread data.

## ThreadQuerySetWin32StartAddress

This is information class 9. It returns the Win32 start address which is the actual function pointer passed to CreateThread. When you call CreateThread you pass a function pointer. That pointer is stored in the thread's kernel structure and can be retrieved with this query.

This is different from the start address returned by NtQuerySystemInformation. That API returns the kernel-side entry point which is always RtlUserThreadStart. RtlUserThreadStart is a wrapper in ntdll that sets up the thread environment and then calls the actual Win32 start address.

By querying class 9 you skip past the wrapper and get the real function pointer. This is useful for identifying what code the thread is running.

## Affinity Mask

The affinity mask is a bitmask indicating which CPUs the thread can run on. Each bit represents one CPU. If bit 0 is set the thread can run on CPU 0. If bit 1 is set it can run on CPU 1. And so on.

By default threads can run on any CPU so the affinity mask has all bits set. You can restrict a thread to specific CPUs by setting the affinity mask with SetThreadAffinityMask. This is useful for performance tuning or isolating threads.

The code prints the affinity mask in hex. On a 4-core system the default mask is 0xF which is binary 1111 meaning all 4 CPUs.

## Priority

The Priority field is the current dynamic priority. The scheduler adjusts this based on thread behavior. Threads that are I/O bound get priority boosts. Threads that are CPU bound get priority penalties. The dynamic priority fluctuates but stays within a range determined by the base priority.

The BasePriority field is the base priority set when the thread was created. This doesn't change unless you explicitly set it with SetThreadPriority. Normal user threads have base priority around 8. Real-time threads have priority 16 or higher.

## Win32 Start Address vs Kernel Start Address

When you create a thread with CreateThread you pass a function pointer. That's the Win32 start address. But the kernel doesn't call that function directly. Instead it calls RtlUserThreadStart which is a wrapper in ntdll.

RtlUserThreadStart sets up the thread environment, initializes thread-local storage, sets up exception handling, and then calls your function. When your function returns RtlUserThreadStart cleans up and terminates the thread.

NtQuerySystemInformation returns the kernel start address which is always RtlUserThreadStart. NtQueryInformationThread with class 9 returns the Win32 start address which is your actual function. This is more useful for identifying what the thread is doing.

## Why Query Both Classes

Class 0 gives you the TEB address, affinity, and priority. Class 9 gives you the Win32 start address. You need both to get a complete picture of the thread.

The code makes two separate queries because there's no single class that returns all this information. You could query additional classes to get even more information like thread times, thread state, or thread context.

## Thread Handles

NtGetNextThread returns thread handles with the access rights you requested. The code requests THREAD_QUERY_INFORMATION which allows querying thread information. This is sufficient for NtQueryInformationThread.

If you wanted to suspend the thread or read its context you'd need different access rights like THREAD_SUSPEND_RESUME or THREAD_GET_CONTEXT.

## Client ID

The ClientId structure in THREAD_BASIC_INFORMATION contains UniqueProcess and UniqueThread. UniqueProcess is the process ID. UniqueThread is the thread ID. These are the same values you'd get from GetProcessId and GetThreadId.

The code prints the thread ID from ClientId.UniqueThread. It casts it to ULONG_PTR for printing because thread IDs are pointer-sized values.

## Exit Status

The ExitStatus field in THREAD_BASIC_INFORMATION is the thread's exit code. If the thread is still running this is STATUS_PENDING which is 0x103. If the thread has exited this is the value passed to ExitThread or returned from the thread function.

The code doesn't print the exit status but you could add it. It's useful for determining if a thread has exited and what its exit code was.

## Use Cases

This technique is useful for analyzing thread behavior, detecting thread injection, or profiling thread activity. By getting the Win32 start address you can identify what code each thread is running. By getting the TEB address you can read thread-local data.

Security tools use this to detect malicious threads. If a thread's start address is in an unexpected module or at an unusual location it might be injected code. By analyzing all threads you can detect anomalies.

Debuggers use this to show detailed thread information. Process Explorer shows the start address and TEB for each thread using similar techniques.

## Comparison to Other Methods

CreateToolhelp32Snapshot gives you basic thread information like thread ID and priority. NtQuerySystemInformation gives you start addresses and states but the start address is always RtlUserThreadStart. NtQueryInformationThread gives you the real Win32 start address and TEB address.

Use CreateToolhelp32Snapshot for simple enumeration. Use NtQuerySystemInformation for system-wide snapshots. Use NtQueryInformationThread for detailed per-thread information.

## Information Classes

NtQueryInformationThread supports many information classes. Class 0 is basic information. Class 9 is Win32 start address. Other classes include thread times, thread state, thread context, thread description, and many more.

Each class returns different information. Some classes are documented, some are not. The code uses two of the most useful classes but you could query others to get additional information.

## No Special Privileges

Querying thread information doesn't require special privileges for threads in your own process. For threads in other processes you need THREAD_QUERY_INFORMATION access which might require administrator privileges or SeDebugPrivilege depending on the target process.

## Undocumented but Stable

NtQueryInformationThread is undocumented but has been stable since Windows NT. The information classes and structures have remained consistent across Windows versions. New classes have been added but existing ones haven't changed.

Many tools rely on this API because it's the most detailed way to get thread information. It's widely used and unlikely to change in breaking ways.

## Handle Cleanup

The code closes each thread handle after processing. This is important to avoid handle leaks. The pattern is to close the previous handle before getting the next one. At the end of the loop it closes the last handle.

---

That's thread enumeration with deep information. Use NtGetNextThread to enumerate threads, query ThreadBasicInformation for TEB and priority, query ThreadQuerySetWin32StartAddress for the real start address, and print all the details.
