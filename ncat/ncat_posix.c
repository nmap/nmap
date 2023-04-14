/***************************************************************************
 * ncat_posix.c -- POSIX-specific functions.                               *
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

#include "ncat.h"

#ifdef HAVE_LUA
#include "ncat_lua.h"
#endif

char **cmdline_split(const char *cmdexec);

/* fork and exec a child process with netexec. Close the given file descriptor
   in the parent process. Return the child's PID or -1 on error. */
int netrun(struct fdinfo *info, char *cmdexec)
{
    int pid;

    errno = 0;
    pid = fork();
    if (pid == 0) {
        /* In the child process. */
        netexec(info, cmdexec);
    }

    Close(info->fd);

    if (pid == -1 && o.verbose)
        logdebug("Error in fork: %s\n", strerror(errno));

    return pid;
}

/* Call write in a loop until all the data is written or an error occurs. The
   return value is the number of bytes written. If it is less than size, then
   there was an error. */
static int write_loop(int fd, char *buf, size_t size)
{
    char *p;
    int n;

    p = buf;
    while (p - buf < size) {
        n = write(fd, p, size - (p - buf));
        if (n == -1) {
            if (errno == EINTR)
                continue;
            else
                break;
        }
        p += n;
    }

    return p - buf;
}

/* Run the given command line as if with exec. What we actually do is fork the
   command line as a subprocess, then loop, relaying data between the socket and
   the subprocess. This allows Ncat to handle SSL from the socket and give plain
   text to the subprocess, and also allows things like logging and line delays.
   Never returns. */
void netexec(struct fdinfo *info, char *cmdexec)
{
    int child_stdin[2];
    int child_stdout[2];
    int pid;
    int crlf_state;

    char buf[DEFAULT_TCP_BUF_LEN];
    int maxfd;

    if (o.debug) {
        switch (o.execmode) {
        case EXEC_SHELL:
            logdebug("Executing with shell: %s\n", cmdexec);
            break;
#ifdef HAVE_LUA
        case EXEC_LUA:
            logdebug("Executing as lua script: %s\n", cmdexec);
            break;
#endif
        default:
            logdebug("Executing: %s\n", cmdexec);
            break;
        }
    }

    if (pipe(child_stdin) == -1 || pipe(child_stdout) == -1)
        bye("Can't create child pipes: %s", strerror(errno));

    pid = fork();
    if (pid == -1)
        bye("Error in fork: %s", strerror(errno));
    if (pid == 0) {
        /* This is the child process. Exec the command. */
        close(child_stdin[1]);
        close(child_stdout[0]);

        /* We might have turned off SIGPIPE handling in ncat_listen.c. Since
           the child process SIGPIPE might mean that the connection got broken,
           ignoring it could result in an infinite loop if the code here
           ignores the error codes of read()/write() calls. So, just in case,
           let's restore SIGPIPE so that writing to a broken pipe results in
           killing the child process. */
        Signal(SIGPIPE, SIG_DFL);

        /* rearrange stdin and stdout */
        Dup2(child_stdin[0], STDIN_FILENO);
        Dup2(child_stdout[1], STDOUT_FILENO);

        setup_environment(info);

        switch (o.execmode) {
        char **cmdargs;

        case EXEC_SHELL:
            execl("/bin/sh", "sh", "-c", cmdexec, (void *) NULL);
            break;
#ifdef HAVE_LUA
        case EXEC_LUA:
            lua_run();
            break;
#endif
        default:
            cmdargs = cmdline_split(cmdexec);
            execv(cmdargs[0], cmdargs);
            break;
        }

        /* exec failed. */
        die("exec");
    }

    close(child_stdin[0]);
    close(child_stdout[1]);

    maxfd = child_stdout[0];
    if (info->fd > maxfd)
        maxfd = info->fd;

    /* This is the parent process. Enter a "caretaker" loop that reads from the
       socket and writes to the subprocess, and reads from the subprocess and
       writes to the socket. We exit the loop on any read error (or EOF). On a
       write error we just close the opposite side of the conversation. */
    crlf_state = 0;
    for (;;) {
        fd_set fds;
        int r, n_r;

        FD_ZERO(&fds);
        checked_fd_set(info->fd, &fds);
        checked_fd_set(child_stdout[0], &fds);

        r = fselect(maxfd + 1, &fds, NULL, NULL, NULL);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            else
                break;
        }
        if (checked_fd_isset(info->fd, &fds)) {
            int pending;

            do {
                n_r = ncat_recv(info, buf, sizeof(buf), &pending);
                if (n_r <= 0) {
                    /* return value can be 0 without meaning EOF in some cases such as SSL
                     * renegotiations that require read/write socket operations but do not
                     * have any application data. */
                    if(n_r == 0 && info->lasterr == 0) {
                        continue; /* Check pending */
                    }
                    goto loop_end;
                }
                r = write_loop(child_stdin[1], buf, n_r);
                if (r != n_r)
                  goto loop_end;
            } while (pending);
        }
        if (checked_fd_isset(child_stdout[0], &fds)) {
            char *crlf = NULL, *wbuf;
            n_r = read(child_stdout[0], buf, sizeof(buf));
            if (n_r <= 0)
                break;
            wbuf = buf;
            if (o.crlf) {
                if (fix_line_endings((char *) buf, &n_r, &crlf, &crlf_state))
                    wbuf = crlf;
            }
            r = ncat_send(info, wbuf, n_r);
            if (crlf != NULL)
                free(crlf);
            if (r <= 0)
                goto loop_end;
        }
    }
loop_end:

#ifdef HAVE_OPENSSL
    if (info->ssl != NULL) {
        SSL_shutdown(info->ssl);
        SSL_free(info->ssl);
    }
#endif
    close(info->fd);

    exit(0);
}

/*
 * Split a command line into an array suitable for handing to execv.
 *
 * A note on syntax: words are split on whitespace and '\' escapes characters.
 * '\\' will show up as '\' and '\ ' will leave a space, combining two
 * words.  Examples:
 * "ncat\ experiment -l -k" will be parsed as the following tokens:
 * "ncat experiment", "-l", "-k".
 * "ncat\\ -l -k" will be parsed as "ncat\", "-l", "-k"
 * See the test program, test/test-cmdline-split to see additional cases.
 */
char **cmdline_split(const char *cmdexec)
{
    const char *ptr;
    char *cur_arg, **cmd_args;
    int max_tokens = 0, arg_idx = 0, ptr_idx = 0;

    /* Figure out the maximum number of tokens needed */
    ptr = cmdexec;
    while (*ptr) {
        // Find the start of the token
        while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr))
            ptr++;
        if ('\0' == *ptr)
            break;
        max_tokens++;
        // Find the start of the whitespace again
        while (('\0' != *ptr) && !isspace((int) (unsigned char) *ptr))
            ptr++;
    }

    /* The line is not empty so we've got something to deal with */
    cmd_args = (char **) safe_malloc(sizeof(char *) * (max_tokens + 1));
    cur_arg = (char *) Calloc(sizeof(char), strlen(cmdexec) + 1);

    /* Get and copy the tokens */
    ptr = cmdexec;
    while (*ptr) {
        while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr))
            ptr++;
        if ('\0' == *ptr)
            break;

        while (('\0' != *ptr) && !isspace((int) (unsigned char) *ptr)) {
            if ('\\' == *ptr) {
                ptr++;
                if ('\0' == *ptr)
                    break;

                cur_arg[ptr_idx] = *ptr;
                ptr_idx++;
                ptr++;

                if ('\\' != *(ptr - 1)) {
                    while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr))
                        ptr++;
                }
            } else {
                cur_arg[ptr_idx] = *ptr;
                ptr_idx++;
                ptr++;
            }
        }
        cur_arg[ptr_idx] = '\0';

        cmd_args[arg_idx] = strdup(cur_arg);
        cur_arg[0] = '\0';
        ptr_idx = 0;
        arg_idx++;
    }

    cmd_args[arg_idx] = NULL;

    /* Clean up */
    free(cur_arg);

    return cmd_args;
}

int ncat_openlog(const char *logfile, int append)
{
    if (append)
        return Open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0664);
    else
        return Open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0664);
}

void set_lf_mode(void)
{
    /* Nothing needed. */
}

#ifdef HAVE_OPENSSL

#define NCAT_CA_CERTS_PATH (NCAT_DATADIR "/" NCAT_CA_CERTS_FILE)

int ssl_load_default_ca_certs(SSL_CTX *ctx)
{
    int rc;

    if (o.debug)
        logdebug("Using system default trusted CA certificates and those in %s.\n", NCAT_CA_CERTS_PATH);

    /* Load distribution-provided defaults, if any. */
    rc = SSL_CTX_set_default_verify_paths(ctx);
    ncat_assert(rc > 0);

    /* Also load the trusted certificates we ship. */
    rc = SSL_CTX_load_verify_locations(ctx, NCAT_CA_CERTS_PATH, NULL);
    if (rc != 1) {
        if (o.debug)
            logdebug("Unable to load trusted CA certificates from %s: %s\n",
                NCAT_CA_CERTS_PATH, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    return 0;
}
#endif

int setenv_portable(const char *name, const char *value)
{
    return setenv(name, value, 1);
}
