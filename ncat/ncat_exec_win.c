/***************************************************************************
 * ncat_exec_win.c -- Windows-specific subprocess execution.               *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include <assert.h>

#include "ncat.h"

/* This structure holds information about a subprocess with redirected input
   and output handles. */
struct subprocess_info {
    HANDLE proc;
    struct fdinfo fdn;
    HANDLE child_in_r;
    HANDLE child_in_w;
    HANDLE child_out_r;
    HANDLE child_out_w;
};

/* A list of subprocesses, so we can kill them when the program exits. */
static HANDLE subprocesses[DEFAULT_MAX_CONNS];
static int subprocess_max_index = 0;
/* Prevent concurrent access to the subprocesses table by the main process and
   a thread. Protects subprocesses and subprocesses_max_index. */
static HANDLE subprocesses_mutex = NULL;

static int start_subprocess(char *cmdexec, struct subprocess_info *info);
static DWORD WINAPI subprocess_thread_func(void *data);

static int register_subprocess(HANDLE proc);
static int unregister_subprocess(HANDLE proc);
static int get_subprocess_slot(void);

/* Have we registered the termination handler yet? */
static int atexit_registered = 0;
static void terminate_subprocesses(void);
static void sigint_handler(int s);

/* This may be set with set_pseudo_sigchld_handler. It is called when a thread
   representing a child process ends. */
static void (*pseudo_sigchld_handler)(void) = NULL;
/* Simulates blocking of SIGCHLD while the handler runs. Also prevents
   concurrent modification of pseudo_sigchld_handler. */
static HANDLE pseudo_sigchld_mutex = NULL;

/* Run a child process, redirecting its standard file handles to a socket
   descriptor. Return the child's PID or -1 on error. */
int netrun(struct fdinfo *fdn, char *cmdexec)
{
    struct subprocess_info *info;
    HANDLE thread;
    int pid;

    info = (struct subprocess_info *) safe_malloc(sizeof(*info));
    info->fdn = *fdn;

    pid = start_subprocess(cmdexec, info);
    if (pid == -1) {
        free(info);
        close(info->fdn.fd);
        return -1;
    }

    /* Start up the thread to handle process I/O. */
    thread = CreateThread(NULL, 0, subprocess_thread_func, info, 0, NULL);
    if (thread == NULL) {
        if (o.verbose)
            logdebug("Error in CreateThread: %d\n", GetLastError());
        free(info);
        return -1;
    }
    CloseHandle(thread);

    return pid;
}

/* Run the given command line as if by exec. Doesn't return. */
void netexec(struct fdinfo *fdn, char *cmdexec)
{
    struct subprocess_info *info;
    int pid;
    DWORD ret;

    info = (struct subprocess_info *) safe_malloc(sizeof(*info));
    info->fdn = *fdn;

    pid = start_subprocess(cmdexec, info);
    if (pid == -1)
        ExitProcess(2);

    /* Run the subprocess thread function, but don't put it in a thread. Just
       run it and exit with its return value because we're simulating exec. */
    ExitProcess(subprocess_thread_func(info));
}

/* Set a pseudo-signal handler that is called when a thread representing a
   child process dies. This is only used on Windows. */
extern void set_pseudo_sigchld_handler(void (*handler)(void))
{
    if (pseudo_sigchld_mutex == NULL) {
        pseudo_sigchld_mutex = CreateMutex(NULL, FALSE, NULL);
        assert(pseudo_sigchld_mutex != NULL);
    }
    assert(WaitForSingleObject(pseudo_sigchld_mutex, INFINITE) == WAIT_OBJECT_0);
    pseudo_sigchld_handler = handler;
    assert(ReleaseMutex(pseudo_sigchld_mutex) != 0);
}

/* Run a command and redirect its input and output handles to a pair of
   anonymous pipes.  The process handle and pipe handles are returned in the
   info struct. Returns the PID of the new process, or -1 on error. */
static int run_command_redirected(char *cmdexec, struct subprocess_info *info) {
    /* Each named pipe we create has to have a unique name. */
    static int pipe_serial_no = 0;
    char pipe_name[32];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    /* Make the pipe handles inheritable. */
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* The child's input pipe is an ordinary blocking pipe. */
    if (CreatePipe(&info->child_in_r, &info->child_in_w, &sa, 0) == 0) {
        if (o.verbose)
            logdebug("Error in CreatePipe: %d\n", GetLastError());
        return -1;
    }

    /* Pipe names must have this special form. */
    Snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\ncat-%d", pipe_serial_no);
    if (o.debug > 1)
        logdebug("Creating named pipe \"%s\"\n", pipe_name);

    /* The output pipe has to be nonblocking, which requires this complicated
       setup. */
    info->child_out_r = CreateNamedPipe(pipe_name,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE, 1, 4096, 4096, 1000, &sa);
    if (info->child_out_r == 0) {
        if (o.verbose)
            logdebug("Error in CreateNamedPipe: %d\n", GetLastError());
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        return -1;
    }
    info->child_out_w = CreateFile(pipe_name,
        GENERIC_WRITE, 0, &sa, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (info->child_out_w == 0) {
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        CloseHandle(info->child_out_r);
        return -1;
    }
    pipe_serial_no++;

    /* Don't inherit our end of the pipes. */
    SetHandleInformation(info->child_in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(info->child_out_r, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = info->child_in_r;
    si.hStdOutput = info->child_out_w;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    memset(&pi, 0, sizeof(pi));

    if (CreateProcess(NULL, cmdexec, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == 0) {
        if (o.verbose)
            logdebug("Error in CreateProcess: %d\n", GetLastError());
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        CloseHandle(info->child_out_r);
        CloseHandle(info->child_out_w);
        return -1;
    }

    /* Close hThread here because we have no use for it. hProcess is closed in
       subprocess_info_close. */
    CloseHandle(pi.hThread);

    info->proc = pi.hProcess;

    return pi.dwProcessId;
}

static const char *get_shell(void)
{
    const char *comspec;

    comspec = getenv("COMSPEC");
    if (comspec == NULL)
        comspec = "cmd.exe";

    return comspec;
}

static void subprocess_info_close(struct subprocess_info *info)
{
#ifdef HAVE_OPENSSL
    if (info->fdn.ssl != NULL) {
        SSL_shutdown(info->fdn.ssl);
        SSL_free(info->fdn.ssl);
    }
#endif
    closesocket(info->fdn.fd);
    CloseHandle(info->proc);
    CloseHandle(info->child_in_r);
    CloseHandle(info->child_in_w);
    CloseHandle(info->child_out_r);
    CloseHandle(info->child_out_w);
}

/* Start a subprocess with run_command_redirected and register it with the
   termination handler. Takes care of o.shellexec. Returns the PID of the
   subprocess or -1 on error. */
static int start_subprocess(char *cmdexec, struct subprocess_info *info)
{
    char *cmdbuf;
    int pid;

    if (o.shellexec) {
        /* Run with cmd.exe. */
        const char *shell;
        size_t cmdlen;

        shell = get_shell();
        cmdlen = strlen(shell) + strlen(cmdexec) + 32;
        cmdbuf = (char *) safe_malloc(cmdlen);
        Snprintf(cmdbuf, cmdlen, "%s /C %s", shell, cmdexec);
    } else {
        cmdbuf = cmdexec;
    }

    if (o.debug)
        logdebug("Executing: %s\n", cmdbuf);

    pid = run_command_redirected(cmdbuf, info);

    if (cmdbuf != cmdexec)
        free(cmdbuf);

    if (pid == -1)
        return -1;

    if (register_subprocess(info->proc) == -1) {
        if (o.verbose)
            logdebug("Couldn't register subprocess with termination handler; not executing.\n");
        TerminateProcess(info->proc, 2);
        subprocess_info_close(info);
        return -1;
    }

    return pid;
}

/* Relay data between a socket and a process until the process dies or stops
   sending or receiving data. The socket descriptor and process pipe handles
   are in the data argument, which must be a pointer to struct subprocess_info.

   This function is a workaround for the fact that we can't just run a process
   after redirecting its input handles to a socket. If the process, for
   example, redirects its own stdin, it somehow confuses the socket and stdout
   stops working. This is exactly what ncat does (as part of the Windows stdin
   workaround), so it can't be ignored.

   This function can be invoked through CreateThread to simulate fork+exec, or
   called directly to simulate exec. It frees the subprocess_info struct and
   closes the socket and pipe handles before returning. Returns the exit code
   of the subprocess. */
static DWORD WINAPI subprocess_thread_func(void *data) {
    struct subprocess_info *info;
    char pipe_buffer[BUFSIZ];
    OVERLAPPED overlap = { 0 };
    HANDLE events[3];
    DWORD ret;
    int crlf_state = 0;

    info = (struct subprocess_info *) data;

    /* Three events we watch for: socket read, pipe read, and process end. */
    events[0] = (HANDLE) WSACreateEvent();
    WSAEventSelect(info->fdn.fd, events[0], FD_READ | FD_CLOSE);
    events[1] = info->child_out_r;
    events[2] = info->proc;

    /* To avoid blocking or polling, we use asynchronous I/O, or what Microsoft
       calls "overlapped" I/O, on the process pipe. WaitForMultipleObjects
       reports when the read operation is complete. */
    ReadFile(info->child_out_r, pipe_buffer, sizeof(pipe_buffer), NULL, &overlap);

    /* Loop until EOF or error. */
    for (;;) {
        DWORD n, nwritten;
        int i;

        i = WaitForMultipleObjects(3, events, FALSE, INFINITE);
        if (i == WAIT_OBJECT_0) {
            /* Read from socket, write to process. */
            char buffer[BUFSIZ];
            int pending;

            ResetEvent(events[0]);
            do {
                n = ncat_recv(&info->fdn, buffer, sizeof(buffer), &pending);
                if (n <= 0)
                    goto loop_end;
                if (WriteFile(info->child_in_w, buffer, n, &nwritten, NULL) == 0)
                    break;
                if (nwritten != n)
                    goto loop_end;
            } while (pending);
        } else if (i == WAIT_OBJECT_0 + 1) {
            char *crlf = NULL, *wbuf;
            /* Read from process, write to socket. */
            if (GetOverlappedResult(info->child_out_r, &overlap, &n, FALSE)) {
                int n_r;

                wbuf = pipe_buffer;
                n_r = n;
                if (o.crlf) {
                    if (fix_line_endings((char *) pipe_buffer, &n_r, &crlf, &crlf_state))
                        wbuf = crlf;
                }
                /* The above call to WSAEventSelect puts the socket in
                   non-blocking mode, but we want this send to block, not
                   potentially return WSAEWOULDBLOCK. We call block_socket, but
                   first we must clear out the select event. */
                WSAEventSelect(info->fdn.fd, events[0], 0);
                block_socket(info->fdn.fd);
                nwritten = ncat_send(&info->fdn, wbuf, n_r);
                if (crlf != NULL)
                    free(crlf);
                if (nwritten != n_r)
                    break;
                /* Restore the select event (and non-block the socket again.) */
                WSAEventSelect(info->fdn.fd, events[0], FD_READ | FD_CLOSE);
                /* Queue another ansychronous read. */
                ReadFile(info->child_out_r, pipe_buffer, sizeof(pipe_buffer), NULL, &overlap);
            } else {
                if (GetLastError() != ERROR_IO_PENDING)
                    /* Error or end of file. */
                    break;
            }
        } else if (i == WAIT_OBJECT_0 + 2) {
            /* The child died. There are no more writes left in the pipe
               because WaitForMultipleObjects guarantees events with lower
               indexes are handled first. */
            break;
        } else {
            break;
        }
    }

loop_end:

    WSACloseEvent(events[0]);

    assert(unregister_subprocess(info->proc) != -1);

    GetExitCodeProcess(info->proc, &ret);
    if (ret == STILL_ACTIVE) {
        DWORD rc;

        if (o.debug > 1)
            logdebug("Subprocess still running, terminating it.\n");
        rc = TerminateProcess(info->proc, 0);
        if (rc == 0) {
            if (o.debug > 1)
                logdebug("TerminateProcess failed with code %d.\n", rc);
        }
    }
    GetExitCodeProcess(info->proc, &ret);
    if (o.debug > 1)
        logdebug("Subprocess ended with exit code %d.\n", ret);

    shutdown(info->fdn.fd, 2);
    subprocess_info_close(info);
    free(info);

    assert(WaitForSingleObject(pseudo_sigchld_mutex, INFINITE) == WAIT_OBJECT_0);
    if (pseudo_sigchld_handler != NULL)
        pseudo_sigchld_handler();
    assert(ReleaseMutex(pseudo_sigchld_mutex) != 0);

    return ret;
}

/* Find a free slot in the subprocesses table. Update subprocesses_max_index to
   be one greater than the maximum index containing a non-NULL handle. (It is
   assumed that the index returned by this function will be filled by a
   handle.) */
static int get_subprocess_slot(void)
{
    int i, free_index, max_index;

    assert(WaitForSingleObject(subprocesses_mutex, INFINITE) == WAIT_OBJECT_0);

    free_index = -1;
    max_index = 0;
    for (i = 0; i < subprocess_max_index; i++) {
        HANDLE proc = subprocesses[i];
        DWORD ret;

        if (proc == NULL) {
            if (free_index == -1)
                free_index = i;
        } else {
            max_index = i + 1;
        }
    }
    if ((free_index == -1 || free_index == max_index)
        && max_index < sizeof(subprocesses) / sizeof(subprocesses[0]))
        free_index = max_index++;
    subprocess_max_index = max_index;

    assert(ReleaseMutex(subprocesses_mutex) != 0);

    return free_index;
}

/* Add a process to the list of processes to kill at program exit. Once you
   call this function, the process handle "belongs" to it and you shouldn't
   modify the handle until you call unregister_subprocess. Returns -1 on
   error. */
static int register_subprocess(HANDLE proc)
{
    int i, rc;

    if (subprocesses_mutex == NULL) {
        subprocesses_mutex = CreateMutex(NULL, FALSE, NULL);
        assert(subprocesses_mutex != NULL);
    }
    if (pseudo_sigchld_mutex == NULL) {
        pseudo_sigchld_mutex = CreateMutex(NULL, FALSE, NULL);
        assert(pseudo_sigchld_mutex != NULL);
    }

    assert(WaitForSingleObject(subprocesses_mutex, INFINITE) == WAIT_OBJECT_0);

    i = get_subprocess_slot();
    if (i == -1) {
        if (o.verbose)
            logdebug("No free process slots for termination handler.\n");
    } else {
        subprocesses[i] = proc;

        if (o.debug > 1)
            logdebug("Register subprocess %p at index %d.\n", proc, i);

        if (!atexit_registered) {
            /* We register both an atexit and a SIGINT handler because ^C
               doesn't seem to cause atexit handlers to be called. */
            atexit(terminate_subprocesses);
            signal(SIGINT, sigint_handler);
            atexit_registered = 1;
        }
    }

    assert(ReleaseMutex(subprocesses_mutex) != 0);

    return i;
}

/* Remove a process handle from the termination handler list. Returns -1 if the
   process was not already registered. */
static int unregister_subprocess(HANDLE proc)
{
    int i;

    assert(WaitForSingleObject(subprocesses_mutex, INFINITE) == WAIT_OBJECT_0);

    for (i = 0; i < subprocess_max_index; i++) {
        if (proc == subprocesses[i])
            break;
    }
    if (i < subprocess_max_index) {
        subprocesses[i] = NULL;
        if (o.debug > 1)
            logdebug("Unregister subprocess %p from index %d.\n", proc, i);
    } else {
        i = -1;
    }

    assert(ReleaseMutex(subprocesses_mutex) != 0);

    return i;
}

static void terminate_subprocesses(void)
{
    int i;

    if (o.debug)
        logdebug("Terminating subprocesses\n");

    assert(WaitForSingleObject(subprocesses_mutex, INFINITE) == WAIT_OBJECT_0);

    if (o.debug > 1)
        logdebug("max_index %d\n", subprocess_max_index);
    for (i = 0; i < subprocess_max_index; i++) {
        HANDLE proc = subprocesses[i];
        DWORD ret;

        if (proc == NULL)
            continue;
        GetExitCodeProcess(proc, &ret);
        if (ret == STILL_ACTIVE) {
            if (o.debug > 1)
                logdebug("kill index %d\n", i);
            TerminateProcess(proc, 0);
        }
        subprocesses[i] = NULL;
    }

    assert(ReleaseMutex(subprocesses_mutex) != 0);
}

static void sigint_handler(int s)
{
    terminate_subprocesses();
    ExitProcess(0);
}
