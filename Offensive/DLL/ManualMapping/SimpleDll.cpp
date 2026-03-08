#include <Windows.h>

#pragma comment(linker, "/ENTRY:DllMain")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma strict_gs_check(off)

BOOL APIENTRY DllMain(
    _In_ HMODULE Module,
    _In_ DWORD   Reason,
    _In_ LPVOID  Reserved
)
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Reserved);

    if (Reason == DLL_PROCESS_ATTACH)
    {
        MessageBoxA(
            NULL,
            "SimpleDll loaded from memory!\nDllMain called successfully.",
            "Memory DLL Loader Test >:3",
            MB_OK | MB_ICONINFORMATION
        );
    }

    return TRUE;
}

extern "C" __declspec(dllexport)
INT TestFunction(
    _In_ INT A,
    _In_ INT B
)
{
    return A + B;
}
