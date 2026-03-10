# Cupcake Parser

Parse Portable Executable files on Windows and print sections, imports, exports, code caves, entropy, and RWX sections.

## Why The Name

The name started as a joke because the tool began as a small PE parser and immediately tried to grow into something way bigger. It felt like one of those projects that looks harmless on the outside, then you cut into it and realize it has five layers, too much frosting, and somehow an entire extra feature set hiding in the middle, this is unfinished...

So `Cupcake Parser` stuck. It sounds cute, but it still tears apart binaries for breakfast.

## What It Does

Reads a PE file from disk and walks the major PE structures manually. The program can print high-level header information, enumerate sections, list imports and exports, look for long runs of null bytes that may be usable as code caves, calculate entropy, and identify sections that are marked read, write, and execute at the same time.

If no path is provided, it defaults to `C:\Windows\System32\kernel32.dll`.

## How It Works

The code starts by opening the target file with `CreateFileW`, reading the full file into memory, and then treating that buffer as a raw PE image. It validates the DOS header first and then locates the NT headers through `e_lfanew`.

Once the NT headers are found, the program extracts the file header, optional header data, and the first section header. From there it walks all section headers and stores them in a list so later routines can query them easily.

Exports are parsed by reading the export directory, then resolving the name table, function table, and ordinal table. For each named export the code converts the RVA into a file offset, reads the symbol name, and stores the RVA and ordinal.

Imports are parsed by walking the import descriptor array. For each imported DLL, the code resolves the thunk data and reads either the imported function name or ordinal. The import table is handled for both PE32 and PE32+ so the same parser works in x86 and x64 builds.

Code caves are found by scanning each section's raw data for long runs of `0x00` bytes. When a run is at least the configured minimum size, the code records the raw offset, virtual address, section name, and size.

Entropy is calculated by counting byte frequency across either the whole file or a single section and applying the standard Shannon entropy formula. This gives a quick way to spot highly packed, compressed, or encrypted regions.

RWX sections are identified by checking the section characteristics for `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE`, and `IMAGE_SCN_MEM_EXECUTE`. A section with all three flags is usually worth looking at more closely.

## Command Line

The Cupcake parser supports selective output flags so you can print only the parts you care about.

- `-all`, `--all`: Show everything
- `--headers`: Show PE summary and header information
- `--sections`: Show section list
- `--imports`: Show imports
- `--exports`: Show exports
- `--caves`: Show code caves
- `--entropy`: Show file entropy and section entropy
- `--rwx`: Show RWX sections

If no output flags are passed, the program behaves like `-all`.

## Run

Print everything for the default target:

```bat
FunStuff.exe -all
```

Print only sections and entropy for a specific file:

```bat
FunStuff.exe --sections --entropy C:\Windows\System32\kernel32.dll
```

Print only imports and exports:

```bat
FunStuff.exe --imports --exports C:\Windows\System32\user32.dll
```

## Notes

- The parser works on raw PE files from disk, not mapped images in memory.
- Import parsing supports both 32-bit and 64-bit PE files.
- The current code cave threshold is `300` bytes.
- Verbose output is intentional, especially when `-all` is used on large system DLLs.
- The parser implementation lives in the `Cupcake` namespace in `Main.cpp`.
- Unfinished...
