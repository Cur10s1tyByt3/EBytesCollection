# Thread Enumeration via NtQuerySystemInformation

Enumerating threads using NtQuerySystemInformation with SystemProcessInformation class.

## What It Does

Queries detailed information about all processes and their threads system-wide using NtQuerySystemInformation. For a target process it displays each thread's ID, start address, state, and context switch count. This gives you low-level thread information that's not available through documented APIs.

## How It Works

The code resolves NtQuerySystemInformation from ntdll and calls it with information class 5 which is SystemProcessInformation. This returns a linked list of SYSTEM_PROCESS_INFORMATION structures, one for each process on the system. Each structure contains process information followed by an array of SYSTEM_THREAD_INFORMATION structures for that process's threads.

The function doesn't know how much buffer space is needed ahead of time so it uses a retry loop. It starts with a buffer and calls the function. If it returns STATUS_INFO_LENGTH_MISMATCH the buffer is too small. It grows the buffer by 64KB and tries again. This continues until the call succeeds.

Once it has the data it walks the linked list of process entries. Each entry has a NextEntryOffset field pointing to the next entry. When NextEntryOffset is 0 you've reached the end. The code searches for the target PID and when it finds it, it loops through the Threads array and prints information about each thread.

For each thread it prints the thread ID from ClientId.UniqueThread, the start address which is the kernel-side entry point, the thread state which indicates what the thread is doing, and the context switch count which shows how many times the thread has been scheduled.

## SystemProcessInformation

This is information class 5 for NtQuerySystemInformation. It returns a snapshot of all processes and threads on the system. The data is a linked list of variable-size structures. Each structure contains process info followed by thread info.

This is the same class used for process enumeration but here we're focusing on the thread information. Each process entry has a NumberOfThreads field and a Threads array containing that many SYSTEM_THREAD_INFORMATION structures.

## SYSTEM_THREAD_INFORMATION

This structure contains detailed information about a thread. The important fields are KernelTime and UserTime which show CPU time spent in kernel and user mode, CreateTime which shows when the thread was created, StartAddress which is the thread's entry point, ClientId which contains the process ID and thread ID, Priority and BasePriority which show scheduling priority, ContextSwitches which counts how many times the thread has been scheduled, ThreadState which indicates the current state, and WaitReason which explains why the thread is waiting if it's in a wait state.

The thread state is a number from 0 to 7. 0 is initialized, 1 is ready, 2 is running, 3 is standby, 4 is terminated, 5 is wait, 6 is transition, and 7 is unknown. Most threads are either running or waiting.

## Start Address

The StartAddress field is the kernel-side entry point for the thread. For user-mode threads this is typically RtlUserThreadStart which is a wrapper in ntdll that calls the actual thread function. The actual user-mode start address is not directly available through this API.

The start address is useful for identifying what code the thread is running. You can look up the address in the module list to see which DLL or executable it belongs to. This helps identify the purpose of the thread.

## Thread State

The ThreadState field indicates what the thread is currently doing. Running means it's executing on a CPU. Ready means it's ready to run but waiting for a CPU. Standby means it's selected to run next. Wait means it's blocked waiting for something. Terminated means it's exited. Transition means it's transitioning between states.

Most threads spend most of their time in the wait state. They're blocked waiting for events, I/O, synchronization objects, or other resources. When something happens they transition to ready and eventually to running.

## Context Switches

The ContextSwitches field counts how many times the thread has been scheduled on a CPU. Each time the scheduler switches from one thread to another it increments this counter. A high count indicates the thread is active and frequently scheduled. A low count indicates the thread is mostly idle.

Context switches have overhead because the CPU must save the old thread's state and load the new thread's state. Too many context switches can hurt performance. Monitoring this counter helps identify scheduling issues.

## Wait Reason

The WaitReason field explains why a thread is in the wait state. Common reasons are waiting for an executive object like a mutex or event, waiting for a page to be read from disk, waiting for a free page, waiting for I/O to complete, or waiting for a user request.

The code doesn't print the wait reason but you could add it. The field is only meaningful when ThreadState is 5 (wait). Otherwise it's undefined.

## Linked List Walking

The process entries are linked together with NextEntryOffset. This field contains the number of bytes from the start of the current entry to the start of the next entry. To advance you add NextEntryOffset to the current pointer. When NextEntryOffset is 0 you've reached the end.

This is a common pattern in Windows kernel structures. Variable-size structures are linked with offsets rather than pointers. This makes the data relocatable and easier to pass between kernel and user mode.

## Buffer Growth

The code doesn't know how much buffer space is needed so it uses a retry loop. It starts with 0 bytes and grows by 64KB each iteration. The function returns STATUS_INFO_LENGTH_MISMATCH and updates BufferSize with the required size. The code allocates that size and tries again.

In practice the buffer size is usually a few hundred KB depending on how many processes and threads are running. The retry loop ensures the buffer is always big enough even if processes are created between calls.

## Why Use This API

There are several ways to enumerate threads. CreateToolhelp32Snapshot is the documented way. NtGetNextThread is an iterator. NtQuerySystemInformation is a snapshot of everything.

The advantage of NtQuerySystemInformation is you get detailed information about all threads in one call. You get start addresses, states, context switches, and timing information. This is useful for system monitoring and analysis.

The disadvantage is it's overkill if you only need threads for one process. You get data for every process on the system. It's also undocumented so there's no guarantee it won't change.

## Thread ID

The ClientId structure contains UniqueProcess and UniqueThread. UniqueThread is the thread ID. Thread IDs are unique system-wide at any given time but can be reused after a thread exits.

The code casts UniqueThread to ULONG_PTR then to DWORD for printing. On 64-bit systems thread IDs are 64-bit values but in practice they fit in 32 bits.

## Process ID Matching

The code searches for the target PID by comparing Entry->UniqueProcessId with TargetPid. When it finds a match it processes that entry's threads and breaks out of the loop.

You could easily modify this to enumerate threads for all processes by removing the PID check and processing every entry.

## System Process

The first entry in the list is the system idle process with PID 0. Its ImageName.Buffer is NULL so the code prints system instead. This process represents idle CPU time and has one thread per CPU core.

## Timing Information

The SYSTEM_THREAD_INFORMATION structure contains KernelTime, UserTime, and CreateTime. These are LARGE_INTEGER values representing 100-nanosecond intervals. You can use them to calculate CPU usage per thread or determine how long a thread has been running.

The code doesn't print timing information but you could add it. Divide the time values by 10000000 to get seconds.

## Priority

The Priority field is the current dynamic priority. The BasePriority field is the base priority set when the thread was created. The scheduler adjusts the dynamic priority based on thread behavior but the base priority stays constant.

Priority values range from 0 to 31. Higher values get more CPU time. Normal user threads have base priority around 8. Real-time threads have priority 16 or higher.

## No Special Privileges

Querying system information doesn't require special privileges. Any user can call NtQuerySystemInformation and get data about all processes and threads. The information is considered public.

This makes it easy to monitor the system without elevation. Security tools use this to detect suspicious threads or analyze system behavior.

## Snapshot Consistency

The data is a snapshot taken at the moment of the call. If threads are created or destroyed after the call they won't appear in the data. This is different from NtGetNextThread which walks the live thread list.

For most purposes the snapshot is more useful because it's consistent. You see all threads that existed at one point in time. With an iterator you might miss threads or see duplicates if the list changes during enumeration.

## Performance

Querying all processes and threads is relatively expensive. The kernel must walk its internal data structures and copy everything to user mode. The buffer can be several hundred KB.

Don't call this in a tight loop. If you need to monitor threads continuously use a slower refresh rate like once per second. For one-time enumeration the performance is fine.

## Use Cases

This technique is used by system monitoring tools, performance analyzers, and debuggers. Task Manager uses similar APIs to show thread information. Process Explorer shows detailed thread data including start addresses and states.

Security tools use this to detect suspicious threads. Malware might inject threads into other processes or create hidden threads. By enumerating all threads you can detect these anomalies.

## Undocumented but Stable

NtQuerySystemInformation with class 5 has been stable since Windows NT. The structure layout has remained consistent across all Windows versions. New fields have been added to the end but the existing fields haven't changed.

Many tools rely on this API because it's the most powerful way to get process and thread information. It's undocumented but widely used and unlikely to change in breaking ways.

---

That's thread enumeration via NtQuerySystemInformation. Query the system process list, walk the linked list, find the target process, and print information about its threads.
