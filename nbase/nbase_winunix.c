/***************************************************************************
 * nbase_winunix.h -- Background code that allows checking for input on    *
 * stdin on Windows without blocking.                                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#include <assert.h>

#include "nbase.h"

#include "nbase_winunix.h"

/*
This code makes it possible to check for input on stdin on Windows without
blocking. There are two obstacles that need to be overcome. The first is that
select on Windows works for sockets only, not stdin. The other is that the
Windows command shell doesn't echo typed characters to the screen unless the
program is actively reading from stdin (which would normally mean blocking).

The strategy is to create a background thread that constantly reads from stdin.
The thread blocks while reading, which lets characters be echoed. The thread
writes each block of data into an anonymous pipe. We juggle file descriptors and
Windows file handles to make the rest of the program think that the other end of
the pipe is stdin. Only the thread keeps a reference to the real stdin. Windows
has a PeekNamedPipe function that we use to check for input in the pipe without
blocking.

Call win_stdin_start_thread to start the thread and win_stdin_ready for the
non-blocking input check. Any other operations on stdin (read, scanf, etc.)
should be transparent, except I noticed that eof(0) returns 1 when there is
nothing in the pipe, but will return 0 again if more is written to the pipe. Any
data buffered but not delivered to the program before starting the background
thread may be lost when the thread is started.
*/

/* The background thread that reads and buffers the true stdin. */
static HANDLE stdin_thread = NULL;

/* This is a copy of the true stdin file handle before any redirection. It is
   read by the thread. */
static HANDLE thread_stdin_handle = NULL;
/* The thread writes to this pipe and standard input is reassigned to be the
   read end of it. */
static HANDLE stdin_pipe_r = NULL, stdin_pipe_w = NULL;

/* This is the thread that reads from the true stdin (thread_stdin_handle) and
   writes to stdin_pipe_w, which is reassigned to be the stdin that the rest of
   the program sees. Once started, it never finishes except in case of error.
   win_stdin_start_thread is responsible for setting up thread_stdin_handle. */
static DWORD WINAPI win_stdin_thread_func(void *data) {
    DWORD n, nwritten;
    char buffer[BUFSIZ];

    for (;;) {
        if (ReadFile(thread_stdin_handle, buffer, sizeof(buffer), &n, NULL) == 0)
            break;
        if (n == -1 || n == 0)
            break;

        if (WriteFile(stdin_pipe_w, buffer, n, &nwritten, NULL) == 0)
            break;
        if (nwritten != n)
            break;
    }
    CloseHandle(thread_stdin_handle);
    CloseHandle(stdin_pipe_w);

    return 0;
}

/* Get the newline translation mode (_O_TEXT or _O_BINARY) of a file
   descriptor. _O_TEXT does CRLF-LF translation and _O_BINARY does none.
   Complementary to _setmode. */
static int _getmode(int fd)
{
    int mode;

    /* There is no standard _getmode function, but _setmode returns the
       previous value. Set it to a dummy value and set it back. */
    mode = _setmode(fd, _O_BINARY);
    _setmode(fd, mode);

    return mode;
}

/* Start the reader thread and do all the file handle/descriptor redirection.
   Returns nonzero on success, zero on error. */
int win_stdin_start_thread(void) {
    int stdin_fd;
    int stdin_fmode;

    assert(stdin_thread == NULL);
    assert(stdin_pipe_r == NULL);
    assert(stdin_pipe_w == NULL);
    assert(thread_stdin_handle == NULL);

    /* Create the pipe that win_stdin_thread_func writes to. We reassign the
       read end to be the new stdin that the rest of the program sees. */
    if (CreatePipe(&stdin_pipe_r, &stdin_pipe_w, NULL, 0) == 0)
        return 0;

    /* Make a copy of the stdin handle to be used by win_stdin_thread_func.  It
       will remain a reference to the the true stdin after we fake stdin to read
       from the pipe instead. */
    if (DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_INPUT_HANDLE),
                        GetCurrentProcess(), &thread_stdin_handle,
                        0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
        CloseHandle(stdin_pipe_r);
        CloseHandle(stdin_pipe_w);
        return 0;
    }

    /* Set the stdin handle to read from the pipe. */
    if (SetStdHandle(STD_INPUT_HANDLE, stdin_pipe_r) == 0) {
        CloseHandle(stdin_pipe_r);
        CloseHandle(stdin_pipe_w);
        CloseHandle(thread_stdin_handle);
        return 0;
    }
    /* Need to redirect file descriptor 0 also. _open_osfhandle makes a new file
       descriptor from an existing handle. */
    /* Remember the newline translation mode (_O_TEXT or _O_BINARY), and
       restore it in the new file descriptor. */
    stdin_fmode = _getmode(STDIN_FILENO);
    stdin_fd = _open_osfhandle((intptr_t) GetStdHandle(STD_INPUT_HANDLE), _O_RDONLY | stdin_fmode);
    if (stdin_fd == -1) {
        CloseHandle(stdin_pipe_r);
        CloseHandle(stdin_pipe_w);
        CloseHandle(thread_stdin_handle);
        return 0;
    }
    dup2(stdin_fd, STDIN_FILENO);

    /* Finally, start up the thread. We don't bother keeping a reference to it
       because it runs until program termination. From here on out all reads
       from the stdin handle or file descriptor 0 will be reading from the
       anonymous pipe that is fed by the thread. */
    stdin_thread = CreateThread(NULL, 0, win_stdin_thread_func, NULL, 0, NULL);
    if (stdin_thread == NULL) {
        CloseHandle(stdin_pipe_r);
        CloseHandle(stdin_pipe_w);
        CloseHandle(thread_stdin_handle);
        return 0;
    }

    return 1;
}

/* Check if input is available on stdin, once all the above has taken place. */
int win_stdin_ready(void) {
    DWORD n;

    assert(stdin_pipe_r != NULL);

    if (!PeekNamedPipe(stdin_pipe_r, NULL, 0, NULL, &n, NULL))
        return 1;

    return n > 0;
}
