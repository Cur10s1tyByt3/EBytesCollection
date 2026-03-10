# Named Pipe Server And Client

Simple Windows named pipe communication using `CreateNamedPipe` and `CreateFile`.

## What It Does

Implements a tiny named pipe server and client in a single executable. The server creates a pipe at `\\.\pipe\crack`, waits for a client connection, and sends a short message through the pipe. The client connects to that same pipe, reads the message, and prints it to the console.

The program runs in one of two modes depending on the first command-line argument:

- `server`
- `client`

## How It Works

The code uses the Windows named pipe API for local inter-process communication. The server starts by calling `CreateNamedPipeW` to create a duplex byte-mode pipe named `\\.\pipe\crack`. This gives it a handle representing the server side of the pipe.

After the pipe is created, the server waits for a client by calling `ConnectNamedPipe`. This blocks until a client connects. Once the connection is established, the server writes a fixed string, `*** Hello from the pipe server ***`, into the pipe with `WriteFile`. It then flushes the buffers, disconnects the client, and closes the pipe handle.

The client uses `CreateFileW` to open the same pipe path, `\\.\pipe\FunStuff`, as if it were opening a file. If the server is already waiting on `ConnectNamedPipe`, the call succeeds and returns a handle to the client side of the pipe.

Once connected, the client calls `ReadFile` to read bytes from the pipe into a local buffer. After the read completes, the code null-terminates the buffer and prints both the number of bytes read and the received message.

The `wmain` entry point acts as a simple dispatcher. If the first argument is `server`, it runs the server code. If the first argument is `client`, it runs the client code. Any other input prints a usage message showing the expected command-line format.

## Run

Start the server in one terminal:

```bat
FunStuff.exe server
```

Start the client in another terminal:

```bat
FunStuff.exe client
```

Expected output looks roughly like this.

Server:

```text
[*] Waiting for client(s)
[*] Client connected
[*] bytes written: 34
```

Client:

```text
[*] Connected to server
[*] bytes read: 34
*** Hello from the pipe server ***
```

## Notes

- This demo uses byte-mode named pipes.
- The current server accepts a single client connection and then exits.
- The pipe name is hardcoded as `\\.\pipe\crack`.
- The server and client are both implemented in `Main.cpp`.
