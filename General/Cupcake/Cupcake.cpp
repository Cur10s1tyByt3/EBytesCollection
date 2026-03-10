#define NOMINMAX
#include<Windows.h>
#include<stdio.h>
#include<wchar.h>

#include<algorithm>
#include<array>
#include<cmath>
#include<memory>
#include<string>
#include<vector>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4514)
#pragma warning(disable: 4710)
#pragma warning(disable: 4711)
#define CUPCAKE_FORCEINLINE __forceinline
#define CUPCAKE_NOINLINE __declspec(noinline)
#else
#define CUPCAKE_FORCEINLINE inline
#define CUPCAKE_NOINLINE
#endif

namespace Cupcake
{

    typedef struct _PE_HEADERS
    {
        PIMAGE_DOS_HEADER     DosHdr;
        PVOID                 NtHdr;
        IMAGE_FILE_HEADER     FileHdr;
        WORD                  OptionalMagic;
        DWORD                 SizeOfHeaders;
        DWORD                 AddressOfEntryPoint;
        ULONGLONG             ImageBase;
        IMAGE_DATA_DIRECTORY  ExportDirectory;
        IMAGE_DATA_DIRECTORY  ImportDirectory;
        PIMAGE_SECTION_HEADER FirstSection;
    } PE_HEADERS, * PPE_HEADERS;

    typedef std::vector<PIMAGE_SECTION_HEADER> PE_SECTIONS;

    typedef struct _PE_IMPORT_FUNCTION
    {
        std::string Name;
        ULONGLONG   Address;
    } PE_IMPORT_FUNCTION, * PPE_IMPORT_FUNCTION;

    typedef struct _PE_IMPORT_ENTRY
    {
        std::string                    Dll;
        std::vector<PE_IMPORT_FUNCTION> Imports;
    } PE_IMPORT_ENTRY, * PPE_IMPORT_ENTRY;

    typedef struct _PE_EXPORT
    {
        std::string Name;
        DWORD       Address;
        WORD        Ordinal;
    } PE_EXPORT, * PPE_EXPORT;

    typedef struct _CODE_CAVE
    {
        PIMAGE_SECTION_HEADER Section;
        std::string           SectionName;
        DWORD                 Size;
        DWORD                 RawAddress;
        ULONGLONG             VirtualAddress;
    } CODE_CAVE, * PCODE_CAVE;

    typedef struct _PE
    {
        std::unique_ptr<BYTE[]> Buffer;
        DWORD                   Size;
        PE_HEADERS              Headers;
        PE_SECTIONS             Sections;
        std::vector<PE_IMPORT_ENTRY> Imports;
        std::vector<PE_EXPORT>  Exports;
    } PE, * PPE;

    typedef struct _OUTPUT_OPTIONS
    {
        BOOL ShowHeaders;
        BOOL ShowSections;
        BOOL ShowImports;
        BOOL ShowExports;
        BOOL ShowCaves;
        BOOL ShowEntropy;
        BOOL ShowRwx;
    } OUTPUT_OPTIONS, * POUTPUT_OPTIONS;

    template<typename T>
    static
        CUPCAKE_FORCEINLINE
        T
        RvaToVa(
            _In_ ULONG_PTR PeBase,
            _In_ SIZE_T    Offset
        )
    {
        return reinterpret_cast<T>(PeBase + Offset);
    }

    static
        std::string
        ByteStringToString(
            _In_reads_(Length) const BYTE* Buffer,
            _In_ SIZE_T Length
        )
    {
        std::string Result;

        for (SIZE_T Index = 0; Index < Length; Index++)
        {
            if (Buffer[Index] == '\0')
            {
                break;
            }

            Result.push_back(static_cast<char>(Buffer[Index]));
        }

        return Result;
    }

    static
        DWORD
        RvaToFileOffset(
            _In_ const PE_HEADERS& Headers,
            _In_ DWORD             Rva
        )
    {
        if (Rva < Headers.SizeOfHeaders)
        {
            return Rva;
        }

        PIMAGE_SECTION_HEADER Section = Headers.FirstSection;

        for (WORD Index = 0; Index < Headers.FileHdr.NumberOfSections; Index++)
        {
            const DWORD SectionAddress = Section->VirtualAddress;
            const DWORD SectionSize =
                std::max(Section->Misc.VirtualSize, Section->SizeOfRawData);

            if (Rva >= SectionAddress && Rva < SectionAddress + SectionSize)
            {
                return (Rva - SectionAddress + Section->PointerToRawData);
            }

            Section++;
        }

        return 0;
    }

    static
        BOOL
        CUPCAKE_NOINLINE
        ReadPeFile(
            _In_  PCWSTR FilePath,
            _Out_ std::unique_ptr<BYTE[]>* Buffer,
            _Out_ PDWORD Size
        )
    {
        HANDLE FileHandle = INVALID_HANDLE_VALUE;
        LARGE_INTEGER FileSize = {};
        DWORD BytesRead = 0;

        *Buffer = nullptr;
        *Size = 0;

        FileHandle = CreateFileW(
            FilePath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (FileHandle == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }

        if (!GetFileSizeEx(FileHandle, &FileSize) ||
            FileSize.QuadPart <= 0 ||
            FileSize.QuadPart > MAXDWORD)
        {
            CloseHandle(FileHandle);
            return FALSE;
        }

        *Size = static_cast<DWORD>(FileSize.QuadPart);
        *Buffer = std::make_unique<BYTE[]>(*Size);

        if (!*Buffer)
        {
            CloseHandle(FileHandle);
            return FALSE;
        }

        if (!ReadFile(FileHandle, Buffer->get(), *Size, &BytesRead, NULL) ||
            BytesRead != *Size)
        {
            Buffer->reset();
            *Size = 0;
            CloseHandle(FileHandle);
            return FALSE;
        }

        CloseHandle(FileHandle);
        return TRUE;
    }

    static
        BOOL
        ParsePe(
            _In_  PCWSTR FilePath,
            _Out_ PPE   ParsedPe
        )
    {
        ULONG_PTR PeBase = 0;
        PIMAGE_DOS_HEADER DosHdr = NULL;
        PIMAGE_FILE_HEADER FileHdr = NULL;
        WORD OptionalMagic = 0;
        DWORD NtSignature = 0;

        *ParsedPe = PE{};

        if (!ReadPeFile(FilePath, &ParsedPe->Buffer, &ParsedPe->Size))
        {
            return FALSE;
        }

        PeBase = reinterpret_cast<ULONG_PTR>(ParsedPe->Buffer.get());
        DosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(PeBase);

        if (ParsedPe->Size < sizeof(IMAGE_DOS_HEADER) ||
            DosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return FALSE;
        }

        if (DosHdr->e_lfanew <= 0 ||
            static_cast<DWORD>(DosHdr->e_lfanew) > ParsedPe->Size - sizeof(DWORD))
        {
            return FALSE;
        }

        NtSignature = *reinterpret_cast<PDWORD>(PeBase + DosHdr->e_lfanew);
        if (NtSignature != IMAGE_NT_SIGNATURE)
        {
            return FALSE;
        }

        FileHdr = reinterpret_cast<PIMAGE_FILE_HEADER>(
            PeBase + DosHdr->e_lfanew + sizeof(DWORD)
            );

        OptionalMagic = *reinterpret_cast<PWORD>(
            reinterpret_cast<PBYTE>(FileHdr) + sizeof(IMAGE_FILE_HEADER)
            );

        ParsedPe->Headers.DosHdr = DosHdr;
        ParsedPe->Headers.NtHdr = reinterpret_cast<PVOID>(PeBase + DosHdr->e_lfanew);
        ParsedPe->Headers.FileHdr = *FileHdr;
        ParsedPe->Headers.OptionalMagic = OptionalMagic;
        ParsedPe->Headers.FirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<PBYTE>(FileHdr) +
            sizeof(IMAGE_FILE_HEADER) +
            FileHdr->SizeOfOptionalHeader
            );

        if (OptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 NtHdr =
                reinterpret_cast<PIMAGE_NT_HEADERS64>(ParsedPe->Headers.NtHdr);

            ParsedPe->Headers.ImageBase =
                static_cast<ULONGLONG>(NtHdr->OptionalHeader.ImageBase);
            ParsedPe->Headers.AddressOfEntryPoint =
                NtHdr->OptionalHeader.AddressOfEntryPoint;
            ParsedPe->Headers.SizeOfHeaders =
                NtHdr->OptionalHeader.SizeOfHeaders;
            ParsedPe->Headers.ExportDirectory =
                NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            ParsedPe->Headers.ImportDirectory =
                NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
        else if (OptionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 NtHdr =
                reinterpret_cast<PIMAGE_NT_HEADERS32>(ParsedPe->Headers.NtHdr);

            ParsedPe->Headers.ImageBase =
                static_cast<ULONGLONG>(NtHdr->OptionalHeader.ImageBase);
            ParsedPe->Headers.AddressOfEntryPoint =
                NtHdr->OptionalHeader.AddressOfEntryPoint;
            ParsedPe->Headers.SizeOfHeaders =
                NtHdr->OptionalHeader.SizeOfHeaders;
            ParsedPe->Headers.ExportDirectory =
                NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            ParsedPe->Headers.ImportDirectory =
                NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
        else
        {
            return FALSE;
        }

        for (WORD Index = 0; Index < FileHdr->NumberOfSections; Index++)
        {
            ParsedPe->Sections.push_back(&ParsedPe->Headers.FirstSection[Index]);
        }

        if (ParsedPe->Headers.ExportDirectory.VirtualAddress != 0)
        {
            const DWORD ExportOffset =
                RvaToFileOffset(ParsedPe->Headers, ParsedPe->Headers.ExportDirectory.VirtualAddress);

            if (ExportOffset != 0 && ExportOffset < ParsedPe->Size)
            {
                PIMAGE_EXPORT_DIRECTORY ExportDir =
                    RvaToVa<PIMAGE_EXPORT_DIRECTORY>(PeBase, ExportOffset);

                const DWORD NameTableOffset =
                    RvaToFileOffset(ParsedPe->Headers, ExportDir->AddressOfNames);
                const DWORD FunctionTableOffset =
                    RvaToFileOffset(ParsedPe->Headers, ExportDir->AddressOfFunctions);
                const DWORD OrdinalTableOffset =
                    RvaToFileOffset(ParsedPe->Headers, ExportDir->AddressOfNameOrdinals);

                if (NameTableOffset != 0 &&
                    FunctionTableOffset != 0 &&
                    OrdinalTableOffset != 0)
                {
                    PDWORD AddressOfNames = RvaToVa<PDWORD>(PeBase, NameTableOffset);
                    PDWORD AddressOfFunctions = RvaToVa<PDWORD>(PeBase, FunctionTableOffset);
                    PWORD AddressOfNameOrds = RvaToVa<PWORD>(PeBase, OrdinalTableOffset);

                    for (DWORD Index = 0; Index < ExportDir->NumberOfNames; Index++)
                    {
                        const DWORD NameOffset =
                            RvaToFileOffset(ParsedPe->Headers, AddressOfNames[Index]);
                        const WORD OrdinalIndex = AddressOfNameOrds[Index];

                        if (NameOffset == 0 || OrdinalIndex >= ExportDir->NumberOfFunctions)
                        {
                            continue;
                        }

                        ParsedPe->Exports.push_back(
                            PE_EXPORT{
                                std::string(
                                    reinterpret_cast<LPCSTR>(PeBase + NameOffset)
                                ),
                                AddressOfFunctions[OrdinalIndex],
                                static_cast<WORD>(ExportDir->Base + OrdinalIndex)
                            }
                        );
                    }
                }
            }
        }

        if (ParsedPe->Headers.ImportDirectory.VirtualAddress != 0)
        {
            const DWORD ImportOffset =
                RvaToFileOffset(ParsedPe->Headers, ParsedPe->Headers.ImportDirectory.VirtualAddress);

            if (ImportOffset != 0 && ImportOffset < ParsedPe->Size)
            {
                PIMAGE_IMPORT_DESCRIPTOR ImportDir =
                    RvaToVa<PIMAGE_IMPORT_DESCRIPTOR>(PeBase, ImportOffset);

                while (ImportDir->Name != 0)
                {
                    const DWORD NameOffset =
                        RvaToFileOffset(ParsedPe->Headers, ImportDir->Name);

                    if (NameOffset == 0)
                    {
                        ImportDir++;
                        continue;
                    }

                    PE_IMPORT_ENTRY Entry = {};
                    Entry.Dll = reinterpret_cast<LPCSTR>(PeBase + NameOffset);

                    const DWORD OriginalThunkRva =
                        (ImportDir->OriginalFirstThunk != 0) ?
                        ImportDir->OriginalFirstThunk :
                        ImportDir->FirstThunk;

                    const DWORD OriginalThunkOffset =
                        RvaToFileOffset(ParsedPe->Headers, OriginalThunkRva);
                    const DWORD FirstThunkOffset =
                        RvaToFileOffset(ParsedPe->Headers, ImportDir->FirstThunk);

                    if (OriginalThunkOffset == 0 || FirstThunkOffset == 0)
                    {
                        ParsedPe->Imports.push_back(std::move(Entry));
                        ImportDir++;
                        continue;
                    }

                    if (ParsedPe->Headers.OptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        PIMAGE_THUNK_DATA64 OriginalThunk =
                            RvaToVa<PIMAGE_THUNK_DATA64>(PeBase, OriginalThunkOffset);
                        PIMAGE_THUNK_DATA64 FirstThunk =
                            RvaToVa<PIMAGE_THUNK_DATA64>(PeBase, FirstThunkOffset);

                        while (OriginalThunk->u1.AddressOfData != 0)
                        {
                            PE_IMPORT_FUNCTION Function = {};
                            Function.Address = FirstThunk->u1.Function;

                            if (IMAGE_SNAP_BY_ORDINAL64(OriginalThunk->u1.Ordinal))
                            {
                                char OrdinalName[32] = {};
                                sprintf_s(
                                    OrdinalName,
                                    "#%llu",
                                    IMAGE_ORDINAL64(OriginalThunk->u1.Ordinal)
                                );

                                Function.Name = OrdinalName;
                            }
                            else
                            {
                                const DWORD ImportByNameOffset = RvaToFileOffset(
                                    ParsedPe->Headers,
                                    static_cast<DWORD>(OriginalThunk->u1.AddressOfData)
                                );

                                if (ImportByNameOffset != 0)
                                {
                                    PIMAGE_IMPORT_BY_NAME ImportByName =
                                        RvaToVa<PIMAGE_IMPORT_BY_NAME>(PeBase, ImportByNameOffset);

                                    Function.Name =
                                        reinterpret_cast<LPCSTR>(ImportByName->Name);
                                }
                            }

                            Entry.Imports.push_back(std::move(Function));
                            OriginalThunk++;
                            FirstThunk++;
                        }
                    }
                    else
                    {
                        PIMAGE_THUNK_DATA32 OriginalThunk =
                            RvaToVa<PIMAGE_THUNK_DATA32>(PeBase, OriginalThunkOffset);
                        PIMAGE_THUNK_DATA32 FirstThunk =
                            RvaToVa<PIMAGE_THUNK_DATA32>(PeBase, FirstThunkOffset);

                        while (OriginalThunk->u1.AddressOfData != 0)
                        {
                            PE_IMPORT_FUNCTION Function = {};
                            Function.Address = FirstThunk->u1.Function;

                            if (IMAGE_SNAP_BY_ORDINAL32(OriginalThunk->u1.Ordinal))
                            {
                                char OrdinalName[32] = {};
                                sprintf_s(
                                    OrdinalName,
                                    "#%lu",
                                    IMAGE_ORDINAL32(OriginalThunk->u1.Ordinal)
                                );

                                Function.Name = OrdinalName;
                            }
                            else
                            {
                                const DWORD ImportByNameOffset = RvaToFileOffset(
                                    ParsedPe->Headers,
                                    OriginalThunk->u1.AddressOfData
                                );

                                if (ImportByNameOffset != 0)
                                {
                                    PIMAGE_IMPORT_BY_NAME ImportByName =
                                        RvaToVa<PIMAGE_IMPORT_BY_NAME>(PeBase, ImportByNameOffset);

                                    Function.Name =
                                        reinterpret_cast<LPCSTR>(ImportByName->Name);
                                }
                            }

                            Entry.Imports.push_back(std::move(Function));
                            OriginalThunk++;
                            FirstThunk++;
                        }
                    }

                    ParsedPe->Imports.push_back(std::move(Entry));
                    ImportDir++;
                }
            }
        }

        return TRUE;
    }

    static
        PIMAGE_SECTION_HEADER
        CUPCAKE_FORCEINLINE
        FindSection(
            _In_ const PE& ParsedPe,
            _In_ const char* SectionName
        )
    {
        for (PIMAGE_SECTION_HEADER Section : ParsedPe.Sections)
        {
            if (ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME) == SectionName)
            {
                return Section;
            }
        }

        return NULL;
    }

    static
        double
        CalcEntropy(
            _In_reads_bytes_(Size) const BYTE* Buffer,
            _In_ SIZE_T Size
        )
    {
        std::array<DWORD, 256> Frequency = {};
        double Entropy = 0.0;

        if (Buffer == NULL || Size == 0)
        {
            return 0.0;
        }

        for (SIZE_T Index = 0; Index < Size; Index++)
        {
            Frequency[Buffer[Index]]++;
        }

        for (DWORD Count : Frequency)
        {
            if (Count == 0)
            {
                continue;
            }

            const double Probability =
                static_cast<double>(Count) / static_cast<double>(Size);

            Entropy += -Probability * std::log2(Probability);
        }

        return Entropy;
    }

    static
        double
        Entropy(
            _In_ const PE& ParsedPe,
            _In_ PIMAGE_SECTION_HEADER Section
        )
    {
        if (Section == NULL || Section->PointerToRawData >= ParsedPe.Size)
        {
            return 0.0;
        }

        const DWORD AvailableBytes = ParsedPe.Size - Section->PointerToRawData;
        const DWORD SectionSize = std::min(Section->SizeOfRawData, AvailableBytes);
        const BYTE* Buffer = ParsedPe.Buffer.get() + Section->PointerToRawData;

        return CalcEntropy(Buffer, SectionSize);
    }

    static
        double
        Entropy(
            _In_ const PE& ParsedPe
        )
    {
        return CalcEntropy(ParsedPe.Buffer.get(), ParsedPe.Size);
    }

    static
        std::vector<CODE_CAVE>
        CodeCaves(
            _In_ const PE& ParsedPe,
            _In_ DWORD     MinimumSize
        )
    {
        std::vector<CODE_CAVE> Result;

        for (PIMAGE_SECTION_HEADER Section : ParsedPe.Sections)
        {
            if (Section->PointerToRawData >= ParsedPe.Size || Section->SizeOfRawData == 0)
            {
                continue;
            }

            const DWORD AvailableBytes = ParsedPe.Size - Section->PointerToRawData;
            const DWORD SectionSize = std::min(Section->SizeOfRawData, AvailableBytes);
            const BYTE* SectionData = ParsedPe.Buffer.get() + Section->PointerToRawData;
            DWORD FreeBytes = 0;

            for (DWORD Index = 0; Index < SectionSize; Index++)
            {
                if (SectionData[Index] == 0x00)
                {
                    FreeBytes++;
                    continue;
                }

                if (FreeBytes >= MinimumSize)
                {
                    const DWORD CaveOffset = Index - FreeBytes;

                    Result.push_back(
                        CODE_CAVE{
                            Section,
                            ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME),
                            FreeBytes,
                            Section->PointerToRawData + CaveOffset,
                            ParsedPe.Headers.ImageBase +
                                Section->VirtualAddress +
                                CaveOffset
                        }
                    );
                }

                FreeBytes = 0;
            }

            if (FreeBytes >= MinimumSize)
            {
                const DWORD CaveOffset = SectionSize - FreeBytes;

                Result.push_back(
                    CODE_CAVE{
                        Section,
                        ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME),
                        FreeBytes,
                        Section->PointerToRawData + CaveOffset,
                        ParsedPe.Headers.ImageBase +
                            Section->VirtualAddress +
                            CaveOffset
                    }
                );
            }
        }

        return Result;
    }

    static
        std::vector<PIMAGE_SECTION_HEADER>
        RwxSections(
            _In_ const PE& ParsedPe
        )
    {
        std::vector<PIMAGE_SECTION_HEADER> Result;

        for (PIMAGE_SECTION_HEADER Section : ParsedPe.Sections)
        {
            const DWORD ReadFlag = Section->Characteristics & IMAGE_SCN_MEM_READ;
            const DWORD WriteFlag = Section->Characteristics & IMAGE_SCN_MEM_WRITE;
            const DWORD ExecuteFlag = Section->Characteristics & IMAGE_SCN_MEM_EXECUTE;

            if (ReadFlag == IMAGE_SCN_MEM_READ &&
                WriteFlag == IMAGE_SCN_MEM_WRITE &&
                ExecuteFlag == IMAGE_SCN_MEM_EXECUTE)
            {
                Result.push_back(Section);
            }
        }

        return Result;
    }

    static
        VOID
        CUPCAKE_NOINLINE
        PrintUsage(
            _In_ PCWSTR ProgramName
        )
    {
        wprintf(
            L"Cupcake Parser\n"
            L"Usage  : %ls [options] [pe_path]\n"
            L"Options:\n"
            L"  -all, --all      Show everything\n"
            L"  --headers        Show PE summary/header information\n"
            L"  --sections       Show sections\n"
            L"  --imports        Show imports\n"
            L"  --exports        Show exports\n"
            L"  --caves          Show code caves\n"
            L"  --entropy        Show entropy information\n"
            L"  --rwx            Show RWX sections\n"
            L"\n"
            L"Example: %ls --sections --imports C:\\Windows\\System32\\kernel32.dll\n"
            L"         %ls -all\n",
            ProgramName,
            ProgramName,
            ProgramName
        );
    }

    static
        VOID
        CUPCAKE_FORCEINLINE
        EnableAllOutput(
            _Out_ POUTPUT_OPTIONS Options
        )
    {
        Options->ShowHeaders = TRUE;
        Options->ShowSections = TRUE;
        Options->ShowImports = TRUE;
        Options->ShowExports = TRUE;
        Options->ShowCaves = TRUE;
        Options->ShowEntropy = TRUE;
        Options->ShowRwx = TRUE;
    }

    static
        BOOL
        CUPCAKE_FORCEINLINE
        HasAnyOutputOption(
            _In_ const OUTPUT_OPTIONS& Options
        )
    {
        return
            Options.ShowHeaders ||
            Options.ShowSections ||
            Options.ShowImports ||
            Options.ShowExports ||
            Options.ShowCaves ||
            Options.ShowEntropy ||
            Options.ShowRwx;
    }

    static
        BOOL
        CUPCAKE_FORCEINLINE
        IsFlag(
            _In_ PCWSTR Argument
        )
    {
        return (Argument != NULL && Argument[0] == L'-');
    }

    static
        BOOL
        ParseArguments(
            _In_  INT             Argc,
            _In_reads_(Argc) PWSTR* Argv,
            _Out_ POUTPUT_OPTIONS Options,
            _Out_ PCWSTR* FilePath
        )
    {
        *Options = OUTPUT_OPTIONS{};
        *FilePath = L"C:\\Windows\\System32\\kernel32.dll";

        for (INT Index = 1; Index < Argc; Index++)
        {
            PCWSTR Argument = Argv[Index];

            if (!IsFlag(Argument))
            {
                *FilePath = Argument;
                continue;
            }

            if (_wcsicmp(Argument, L"-all") == 0 ||
                _wcsicmp(Argument, L"--all") == 0)
            {
                EnableAllOutput(Options);
            }
            else if (_wcsicmp(Argument, L"--headers") == 0)
            {
                Options->ShowHeaders = TRUE;
            }
            else if (_wcsicmp(Argument, L"--sections") == 0)
            {
                Options->ShowSections = TRUE;
            }
            else if (_wcsicmp(Argument, L"--imports") == 0)
            {
                Options->ShowImports = TRUE;
            }
            else if (_wcsicmp(Argument, L"--exports") == 0)
            {
                Options->ShowExports = TRUE;
            }
            else if (_wcsicmp(Argument, L"--caves") == 0)
            {
                Options->ShowCaves = TRUE;
            }
            else if (_wcsicmp(Argument, L"--entropy") == 0)
            {
                Options->ShowEntropy = TRUE;
            }
            else if (_wcsicmp(Argument, L"--rwx") == 0)
            {
                Options->ShowRwx = TRUE;
            }
            else
            {
                wprintf(L"[-] Unknown option: %ls\n", Argument);
                return FALSE;
            }
        }

        if (!HasAnyOutputOption(*Options))
        {
            EnableAllOutput(Options);
        }

        return TRUE;
    }

} // namespace Cupcake

INT
wmain(
    _In_ INT    Argc,
    _In_ PWSTR* Argv
)
{
    Cupcake::PE ParsedPe = {};
    Cupcake::OUTPUT_OPTIONS Options = {};
    PCWSTR FilePath = NULL;

    if (!Cupcake::ParseArguments(Argc, Argv, &Options, &FilePath))
    {
        Cupcake::PrintUsage(Argv[0]);
        return 1;
    }

    if (!Cupcake::ParsePe(FilePath, &ParsedPe))
    {
        wprintf(L"[-] Failed to parse PE file: %ls\n", FilePath);
        return 1;
    }

    if (Options.ShowHeaders)
    {
        wprintf(L"[*] PE Path: %ls\n", FilePath);
        printf("[*] Pe Buffer Address: 0x%p\n", ParsedPe.Buffer.get());
        printf("[*] Pe File Size: %lu\n", ParsedPe.Size);
        printf("[*] AddressOfEntryPoint: 0x%08lx\n", ParsedPe.Headers.AddressOfEntryPoint);
        printf("[*] ImageBase: 0x%llx\n", ParsedPe.Headers.ImageBase);
        printf("[*] Sections: %zu\n", ParsedPe.Sections.size());
        printf("[*] Imports : %zu DLL(s)\n", ParsedPe.Imports.size());
        printf("[*] Exports : %zu\n", ParsedPe.Exports.size());
        printf("\n");
    }

    if (Options.ShowSections)
    {
        for (PIMAGE_SECTION_HEADER Section : ParsedPe.Sections)
        {
            if (Options.ShowEntropy)
            {
                printf(
                    "[*] Section: %s (VA: 0x%08lx, Raw: 0x%08lx, Entropy: %.4f)\n",
                    Cupcake::ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME).c_str(),
                    Section->VirtualAddress,
                    Section->PointerToRawData,
                    Cupcake::Entropy(ParsedPe, Section)
                );
            }
            else
            {
                printf(
                    "[*] Section: %s (VA: 0x%08lx, Raw: 0x%08lx)\n",
                    Cupcake::ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME).c_str(),
                    Section->VirtualAddress,
                    Section->PointerToRawData
                );
            }
        }

        printf("\n");
    }

    if (Options.ShowImports)
    {
        for (const Cupcake::PE_IMPORT_ENTRY& ImportEntry : ParsedPe.Imports)
        {
            printf("[%s]\n", ImportEntry.Dll.c_str());

            for (const Cupcake::PE_IMPORT_FUNCTION& ImportFunction : ImportEntry.Imports)
            {
                printf(
                    "\tName: %s, RVA: 0x%llx\n",
                    ImportFunction.Name.c_str(),
                    ImportFunction.Address
                );
            }
        }

        printf("\n");
    }

    if (Options.ShowExports)
    {
        for (const Cupcake::PE_EXPORT& Export : ParsedPe.Exports)
        {
            printf(
                "Name: %s, RVA: 0x%08lx, Ordinal: %u\n",
                Export.Name.c_str(),
                Export.Address,
                Export.Ordinal
            );
        }

        printf("\n");
    }

    if (Options.ShowCaves)
    {
        const std::vector<Cupcake::CODE_CAVE> ActualCodeCaves = Cupcake::CodeCaves(ParsedPe, 300);

        for (const Cupcake::CODE_CAVE& Cave : ActualCodeCaves)
        {
            printf(
                "[*] Code Cave Found, Section: %s, Size: %lu Bytes, Raw: 0x%08lx, VA: 0x%llx\n",
                Cave.SectionName.c_str(),
                Cave.Size,
                Cave.RawAddress,
                Cave.VirtualAddress
            );
        }

        if (ActualCodeCaves.empty())
        {
            printf("[*] No code caves >= 300 bytes found\n");
        }

        printf("\n");
    }

    if (Options.ShowRwx)
    {
        const std::vector<PIMAGE_SECTION_HEADER> ActualRwxSections = Cupcake::RwxSections(ParsedPe);

        for (PIMAGE_SECTION_HEADER Section : ActualRwxSections)
        {
            printf(
                "[*] RWX Section: %s (VA: 0x%08lx)\n",
                Cupcake::ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME).c_str(),
                Section->VirtualAddress
            );
        }

        if (ActualRwxSections.empty())
        {
            printf("[*] No RWX sections found\n");
        }

        printf("\n");
    }

    if (Options.ShowEntropy)
    {
        printf("[*] Pe Entropy: %.4f\n", Cupcake::Entropy(ParsedPe));

        if (!Options.ShowSections)
        {
            for (PIMAGE_SECTION_HEADER Section : ParsedPe.Sections)
            {
                printf(
                    "[*] Section Entropy: %s -> %.4f\n",
                    Cupcake::ByteStringToString(Section->Name, IMAGE_SIZEOF_SHORT_NAME).c_str(),
                    Cupcake::Entropy(ParsedPe, Section)
                );
            }
        }

        printf("\n");
    }

    if (Options.ShowHeaders)
    {
        if (Cupcake::FindSection(ParsedPe, ".text") != NULL)
        {
            printf("[*] Found .text section\n");
        }
        else
        {
            printf("[*] .text section not found\n");
        }
    }

    return 0;
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
