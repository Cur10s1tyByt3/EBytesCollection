# CrossAssemblyExec

A proof of concept demonstrating the execution of a managed function from an assembly separate from the one in which it is defined.

## What It Does

This project serves a functional demonstration for cross-assembly execution of managed functions. This technique has potential for usage in code obfuscation and anti-analysis for .NET programs.

## How It Works

The code first queries the bytes of the current executing assembly and calls the `Assembly.Load` function to load the assembly reflectively (this is just for ease of demonstration, the code can be easily modified to load a different assembly.) It then creates a string array with one element, and uses the `Unsafe.As` function from `System.Runtime.CompilerServices` to perform an unchecked type conversion, allowing an `Action` to be placed into the string array in the place of a string. The entry point of the assembly is then executed by a call to `MethodBase.Invoke` with the mutated string array passed as the sole argument. The `Main` function is then executed a second time, this time casting the string array to an object array, before getting the first element and casting it to an `Action` and calling it and therefore executing a function from the original assembly by way of the reflectively loaded one.
