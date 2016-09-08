/***************************************************************************
 * ncat_posix.c -- POSIX-specific functions.                               *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
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
        FD_SET(info->fd, &fds);
        FD_SET(child_stdout[0], &fds);

        r = fselect(maxfd + 1, &fds, NULL, NULL, NULL);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            else
                break;
        }
        if (FD_ISSET(info->fd, &fds)) {
            int pending;

            do {
                n_r = ncat_recv(info, buf, sizeof(buf), &pending);
                if (n_r <= 0)
                    goto loop_end;
                write_loop(child_stdin[1], buf, n_r);
            } while (pending);
        }
        if (FD_ISSET(child_stdout[0], &fds)) {
            char *crlf = NULL, *wbuf;
            n_r = read(child_stdout[0], buf, sizeof(buf));
            if (n_r <= 0)
                break;
            wbuf = buf;
            if (o.crlf) {
                if (fix_line_endings((char *) buf, &n_r, &crlf, &crlf_state))
                    wbuf = crlf;
            }
            ncat_send(info, wbuf, n_r);
            if (crlf != NULL)
                free(crlf);
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
