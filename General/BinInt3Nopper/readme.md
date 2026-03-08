# INT3 Instruction Nopping in PE Files

Patching all INT3 (0xCC) breakpoint instructions to NOP (0x90) in the code section of PE executables.

A standalone tool that nops stubbed branches with INT3 instructions, which are commonly used by obfuscators and protectors to break disassemblers and analysis tools.

## What It Does

Scans the .text section of a PE file for all INT3 instructions and replaces them with NOP instructions. INT3 is the x86 software breakpoint instruction used by debuggers. Replacing them with NOPs removes breakpoints and can bypass certain anti-debugging techniques.

## How It Works

The code memory-maps the input PE file with read-write access. It parses the PE headers to locate the .text section which contains executable code. Then it scans every byte in that section looking for 0xCC which is the opcode for INT3. When it finds one it replaces it with 0x90 which is the opcode for NOP. After patching all INT3s it writes the modified file to the output path.

Memory mapping is used instead of reading the entire file into a buffer because it allows in-place modification. The file is mapped into the process address space and changes to the mapped memory are automatically reflected in the file. After unmapping the changes are persisted.
