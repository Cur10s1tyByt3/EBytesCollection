#include<Windows.h>
#include<stdio.h>
#include<wchar.h>

static CONST WCHAR g_PipeName[] = L"\\\\.\\pipe\\FunStuff";

static
VOID
PrintUsage(
    _In_ PCWSTR ProgramName
)
{
    wprintf(
        L"Usage  : %ls <server|client>\n"
        L"Example: %ls server\n"
        L"         %ls client\n",
        ProgramName,
        ProgramName,
        ProgramName
    );
}

static
INT
RunServer(
    VOID
)
{
    CONST HANDLE Pipe = CreateNamedPipeW(
        g_PipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        0,
        0,
        0,
        NULL
    );

    if (Pipe == INVALID_HANDLE_VALUE)
    {
        printf("[oopsies] Server pipe creation failed: %lu\n", GetLastError());
        return 1;
    }

    __try
    {
        printf("[emmm] Waiting for client(s)\n");

        BOOL Result = ConnectNamedPipe(Pipe, NULL);
        if (!Result)
        {
            CONST DWORD Error = GetLastError();
            if (Error != ERROR_PIPE_CONNECTED)
            {
                printf("[oopsies] ConnectNamedPipe failed: %lu\n", Error);
                return 1;
            }
        }

        printf("[yayyy] Client connected\n");

        CHAR Data[] = "*** Hello from the pipe server ***";
        DWORD BytesWritten = 0;

        Result = WriteFile(
            Pipe,
            Data,
            static_cast<DWORD>(strlen(Data)),
            &BytesWritten,
            NULL
        );

        if (!Result)
        {
            printf("[oopsies] WriteFile failed: %lu\n", GetLastError());
            return 1;
        }

        printf("[yayyy] bytes written: %lu\n", BytesWritten);

        FlushFileBuffers(Pipe);
        DisconnectNamedPipe(Pipe);
    }
    __finally
    {
        CloseHandle(Pipe);
    }

    return 0;
}

static
INT
RunClient(
    VOID
)
{
    CONST HANDLE Pipe = CreateFileW(
        g_PipeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (Pipe == INVALID_HANDLE_VALUE)
    {
        printf("[oopsies] Client connection failed: %lu\n", GetLastError());
        return 1;
    }

    __try
    {
        printf("[yayyy] Connected to server\n");

        CHAR Buffer[100] = { 0 };
        DWORD BytesRead = 0;

        CONST BOOL Result = ReadFile(
            Pipe,
            Buffer,
            static_cast<DWORD>(sizeof(Buffer) - 1),
            &BytesRead,
            NULL
        );

        if (!Result)
        {
            printf("[oopsies] ReadFile failed: %lu\n", GetLastError());
            return 1;
        }

        Buffer[BytesRead] = '\0';

        printf("[yayyy] bytes read: %lu\n", BytesRead);
        printf("%s\n", Buffer);
    }
    __finally
    {
        CloseHandle(Pipe);
    }

    return 0;
}

INT
wmain(
    _In_ INT    Argc,
    _In_ PWSTR* Argv
)
{
    if (Argc < 2)
    {
        PrintUsage(Argv[0]);
        return 1;
    }

    if (_wcsicmp(Argv[1], L"server") == 0)
    {
        return RunServer();
    }

    if (_wcsicmp(Argv[1], L"client") == 0)
    {
        return RunClient();
    }

    PrintUsage(Argv[0]);
    return 1;
}
