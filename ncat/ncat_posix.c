/***************************************************************************
 * ncat_posix.c -- POSIX-specific functions.                               *
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
        if (o.shellexec)
            logdebug("Executing with shell: %s\n", cmdexec);
        else
            logdebug("Executing: %s\n", cmdexec);
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

        /* rearrange stdin and stdout */
        Dup2(child_stdin[0], STDIN_FILENO);
        Dup2(child_stdout[1], STDOUT_FILENO);

        if (o.shellexec) {
            execl("/bin/sh", "sh", "-c", cmdexec, (void *) NULL);
        } else {
            char **cmdargs;

            cmdargs = cmdline_split(cmdexec);
            execv(cmdargs[0], cmdargs);
        }

        /* exec failed.*/
        die("exec");
    }

    close(child_stdin[0]);
    close(child_stdout[1]);

    maxfd = child_stdout[0];
    if (info->fd > maxfd)
        maxfd = info->fd;

    /* This is the parent process. Enter a "caretaker" loop that reads from the
       socket and writes to the suprocess, and reads from the subprocess and
       writes to the socket. We exit the loop on any read error (or EOF). On a
       write error we just close the opposite side of the conversation. */
    crlf_state = 0;
    for (;;) {
        fd_set fds;
        int r, n_r, n_w;

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
                n_w = write_loop(child_stdin[1], buf, n_r);
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
            n_w = ncat_send(info, wbuf, n_r);
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
        while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr)) ptr++;
        if ('\0' == *ptr)     break;
        max_tokens++;
        // Find the start of the whitespace again
        while (('\0' != *ptr) && !isspace((int) (unsigned char) *ptr)) ptr++;
    }

    /* The line is not empty so we've got something to deal with */
    cmd_args = (char**)safe_malloc(sizeof(char*) * (max_tokens + 1));
    cur_arg = (char*)Calloc(sizeof(char), strlen(cmdexec));

    /* Get and copy the tokens */
    ptr = cmdexec;
    while (*ptr) {
        while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr)) ptr++;
        if ('\0' == *ptr)     break;

        while (('\0' != *ptr) && !isspace((int) (unsigned char) *ptr)) {
            if ('\\' == *ptr) {
                ptr++;
                if ('\0' == *ptr)   break;

                cur_arg[ptr_idx] = *ptr;
                ptr_idx++;
                ptr++;

                if ('\\' != *(ptr - 1)) {
                    while (('\0' != *ptr) && isspace((int) (unsigned char) *ptr)) ptr++;
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
    assert(SSL_CTX_set_default_verify_paths(ctx) > 0);

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
