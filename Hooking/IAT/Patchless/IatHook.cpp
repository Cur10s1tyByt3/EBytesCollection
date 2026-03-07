#include <Windows.h>

#include <cstdio>


namespace FunStuff {

  struct PeImage {
    PVOID ImageBase;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    #ifdef _WIN64
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader;
    #else
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader;
    #endif
    IMAGE_FILE_HEADER FileHeader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
  };

  struct VehHookState {
    PVOID OriginalFunction;
    PVOID HookFunction;
    DWORD DrIndex;
    BOOL IsActive;
    BOOL IsExecuting;
  };

  class EatHook {
    private: static VehHookState State;
    static PVOID VehHandle;

    static DWORD FindFreeDrIndex(PCONTEXT Ctx);
    static BOOL SetHardwareBreakpoint(PVOID Address, DWORD DrIndex);
    static BOOL RemoveHardwareBreakpoint(DWORD DrIndex);
    static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS Info);

    public: static BOOL Install(LPCSTR Module, LPCSTR Proc, PVOID HookFunc, PVOID * OutOriginal);
    static BOOL Remove();

    template < typename Ret,
    typename...Args >
    static Ret CallOriginal(Args...args);
  };

  PeImage ParsePeImage(LPCSTR ImageName);
  DWORD_PTR GetInstructionPointer(PCONTEXT Ctx);
  void SetInstructionPointer(PCONTEXT Ctx, DWORD_PTR Address);

}

FunStuff::VehHookState FunStuff::EatHook::State {};
PVOID FunStuff::EatHook::VehHandle = nullptr;

FunStuff::PeImage FunStuff::ParsePeImage(LPCSTR ImageName) {
  PVOID ImageBase = GetModuleHandleA(ImageName);
  DWORD_PTR PeBase = (DWORD_PTR) ImageBase;
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER) ImageBase;

  #ifdef _WIN64
  PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(PeBase + Dos -> e_lfanew);
  PIMAGE_OPTIONAL_HEADER64 OptionalHeader = & NtHeaders -> OptionalHeader;
  #else
  PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(PeBase + Dos -> e_lfanew);
  PIMAGE_OPTIONAL_HEADER32 OptionalHeader = & NtHeaders -> OptionalHeader;
  #endif

  IMAGE_FILE_HEADER FileHeader = NtHeaders -> FileHeader;
  
  PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(PeBase + 
    OptionalHeader -> DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  
  PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(PeBase + 
    OptionalHeader -> DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  return PeImage {
    ImageBase,
    Dos,
    NtHeaders,
    OptionalHeader,
    FileHeader,
    ImportDescriptor,
    ExportDirectory
  };
}

DWORD_PTR FunStuff::GetInstructionPointer(PCONTEXT Ctx) {
  #if defined(_M_X64) || defined(__x86_64__)
  return Ctx -> Rip;
  #elif defined(_M_IX86) || defined(__i386__)
  return Ctx -> Eip;
  #elif defined(_M_ARM64) || defined(__aarch64__)
  return Ctx -> Pc;
  #elif defined(_M_ARM) || defined(__arm__)
  return Ctx -> Pc;
  #else
  return 0;
  #endif
}

void FunStuff::SetInstructionPointer(PCONTEXT Ctx, DWORD_PTR Address) {
  #if defined(_M_X64) || defined(__x86_64__)
  Ctx -> Rip = Address;
  #elif defined(_M_IX86) || defined(__i386__)
  Ctx -> Eip = (DWORD) Address;
  #elif defined(_M_ARM64) || defined(__aarch64__)
  Ctx -> Pc = Address;
  #elif defined(_M_ARM) || defined(__arm__)
  Ctx -> Pc = (DWORD) Address;
  #endif
}

DWORD FunStuff::EatHook::FindFreeDrIndex(PCONTEXT Ctx) {
  for (DWORD i = 0; i < 4; i++) {
    if (!(Ctx -> Dr7 & (1ULL << (i * 2))))
      return i;
  }
  return (DWORD) - 1;
}

BOOL FunStuff::EatHook::SetHardwareBreakpoint(PVOID Address, DWORD DrIndex) {
  HANDLE Thread = GetCurrentThread();
  CONTEXT Ctx = {
    0
  };
  Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  if (!GetThreadContext(Thread, & Ctx))
    return FALSE;

  switch (DrIndex) {
  case 0:
    Ctx.Dr0 = (DWORD_PTR) Address;
    break;
  case 1:
    Ctx.Dr1 = (DWORD_PTR) Address;
    break;
  case 2:
    Ctx.Dr2 = (DWORD_PTR) Address;
    break;
  case 3:
    Ctx.Dr3 = (DWORD_PTR) Address;
    break;
  default:
    return FALSE;
  }

  Ctx.Dr7 |= (1ULL << (DrIndex * 2));
  Ctx.Dr7 &= ~(3ULL << (16 + DrIndex * 4));
  Ctx.Dr7 &= ~(3ULL << (18 + DrIndex * 4));

  return SetThreadContext(Thread, & Ctx);
}

BOOL FunStuff::EatHook::RemoveHardwareBreakpoint(DWORD DrIndex) {
  HANDLE Thread = GetCurrentThread();
  CONTEXT Ctx = {
    0
  };
  Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  if (!GetThreadContext(Thread, & Ctx))
    return FALSE;

  Ctx.Dr7 &= ~(1ULL << (DrIndex * 2));

  switch (DrIndex) {
  case 0:
    Ctx.Dr0 = 0;
    break;
  case 1:
    Ctx.Dr1 = 0;
    break;
  case 2:
    Ctx.Dr2 = 0;
    break;
  case 3:
    Ctx.Dr3 = 0;
    break;
  default:
    return FALSE;
  }

  return SetThreadContext(Thread, & Ctx);
}

LONG CALLBACK FunStuff::EatHook::VectoredHandler(PEXCEPTION_POINTERS Info) {
  if (Info -> ExceptionRecord -> ExceptionCode != EXCEPTION_SINGLE_STEP)
    return EXCEPTION_CONTINUE_SEARCH;

  DWORD_PTR CurrentIp = GetInstructionPointer(Info -> ContextRecord);

  if (State.IsActive && !State.IsExecuting) {
    if (CurrentIp == (DWORD_PTR) State.OriginalFunction) {
      printf("[*] VEH Triggered for %p\n", State.OriginalFunction);
      SetInstructionPointer(Info -> ContextRecord, (DWORD_PTR) State.HookFunction);
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

BOOL FunStuff::EatHook::Install(LPCSTR Module, LPCSTR Proc, PVOID HookFunc, PVOID * OutOriginal) {
  PeImage Pe = ParsePeImage(NULL);
  DWORD_PTR Base = (DWORD_PTR) Pe.ImageBase;
  auto ImportDescriptor = Pe.ImportDescriptor;

  while (ImportDescriptor->Name) {
    LPCSTR LibName = (LPCSTR)(Base + ImportDescriptor->Name);
    
    if (_strcmpi(LibName, Module) == 0) {
      auto OrigThunk = (PIMAGE_THUNK_DATA)(Base + ImportDescriptor->OriginalFirstThunk);
      auto Thunk = (PIMAGE_THUNK_DATA)(Base + ImportDescriptor->FirstThunk);

      while (OrigThunk->u1.AddressOfData) {
        auto ByName = (PIMAGE_IMPORT_BY_NAME)(Base + OrigThunk->u1.AddressOfData);
        
        if (_strcmpi(ByName->Name, Proc) == 0) {
          PVOID Address = (PVOID)Thunk->u1.Function;
          * OutOriginal = Address;
          printf("[+] IAT Original Address: %p\n", Address);

          CONTEXT Ctx = { 0 };
          Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
          GetThreadContext(GetCurrentThread(), & Ctx);

          DWORD DrIndex = FindFreeDrIndex( & Ctx);
          if (DrIndex == (DWORD) - 1)
            return FALSE;

          if (!SetHardwareBreakpoint(Address, DrIndex))
            return FALSE;

          State.OriginalFunction = Address;
          State.HookFunction = HookFunc;
          State.DrIndex = DrIndex;
          State.IsActive = TRUE;
          State.IsExecuting = FALSE;

          if (!VehHandle) {
            VehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
            if (!VehHandle)
              return FALSE;
          }

          return TRUE;
        }
        
        OrigThunk++;
        Thunk++;
      }
    }
    
    ImportDescriptor++;
  }

  return FALSE;
}

BOOL FunStuff::EatHook::Remove() {
  if (!State.IsActive)
    return FALSE;

  if (!RemoveHardwareBreakpoint(State.DrIndex))
    return FALSE;

  State.IsActive = FALSE;
  return TRUE;
}

template < typename Ret, typename...Args >
  Ret FunStuff::EatHook::CallOriginal(Args...args) {
    RemoveHardwareBreakpoint(State.DrIndex);
    typedef Ret( * FuncType)(Args...);
    Ret Result = ((FuncType) State.OriginalFunction)(args...);
    SetHardwareBreakpoint(State.OriginalFunction, State.DrIndex);
    return Result;
  }

typedef int(WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

int WINAPI HookedMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) {
  printf( "[*] MessageBoxA hooked via VEH!\n" );
  auto Result = FunStuff::EatHook::CallOriginal < int > (hWnd, "Hooked via VEH!", lpCaption, uType);
  return Result;
}

int main() {
  printf( "[*] Loading user32.dll...\n" );
  HMODULE User32 = LoadLibraryA( "user32.dll" );
  if ( !User32 ) {
    printf( "[-] Failed to load user32.dll\n" );
    return -1;
  }

  PVOID OriginalFunc = nullptr;

  printf( "[*] Installing MessageBoxA IAT hook...\n" );
  if (!FunStuff::EatHook::Install("user32.dll", "MessageBoxA", HookedMessageBoxA, & OriginalFunc)) {
    printf("[-] Failed to hook MessageBoxA\n");
    return -1;
  }

  printf("[+] MessageBoxA hooked!\n\n");
  printf("[*] Testing MessageBoxA...\n");
  MessageBoxA(nullptr, "Hello World!", "Test", MB_OK);

  printf( "\n[*] Press any key to unhook...\n" );
  getchar( );

  if ( FunStuff::EatHook::Remove( ) )
    printf( "[+] IAT hook removed!\n" );

  return 0;
}
