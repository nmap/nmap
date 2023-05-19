/***************************************************************************
 * sys_wrap.c -- Error-checked wrappers around common functions.           *
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

#include <limits.h>

#include "sys_wrap.h"
#include "util.h"

void *Calloc(size_t nmemb, size_t size)
{
    void *ret;

    /* older libcs don't check for int overflow */
    smul(nmemb, size);

    ret = calloc(nmemb, size);
    if (ret == NULL)
        die("calloc");

    return ret;
}

int Close(int fd)
{
    if (close(fd) < 0)
        die("close");

    return 0;
}

int Connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
    if (connect(sockfd, serv_addr, addrlen) < 0)
        die("connect");

    return 0;
}

int Dup2(int oldfd, int newfd)
{
    int ret;

    ret = dup2(oldfd, newfd);
    if (ret < 0)
        die("dup2");

    return ret;
}

int Listen(int s, int backlog)
{
    if (listen(s, backlog) < 0)
        die("listen");

    return 0;
}

int Open(const char *pathname, int flags, mode_t mode)
{
    int ret;

    ret = open(pathname, flags, mode);
    if (ret < 0)
        die("open");

    return ret;
}

ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t ret;

    ret = read(fd, buf, count);
    if (ret < 0)
        die("read");

    return ret;
}

int Setsockopt(int s, int level, int optname, const void *optval,
                    socklen_t optlen)
{
    int ret;

    ret = setsockopt(s, level, optname, (const char *) optval, optlen);
    if (ret < 0)
        die("setsockopt");

    return ret;
}

sighandler_t Signal(int signum, sighandler_t handler)
{
    sighandler_t ret;

    ret = signal(signum, handler);
    if (ret == SIG_ERR)
        die("signal");

    return ret;
}


int Socket(int domain, int type, int protocol)
{
    int ret;

    ret = socket(domain, type, protocol);
    if (ret < 0)
        die("socket");

    return ret;
}

char *Strdup(const char *s)
{
    char *ret;

    ret = strdup(s);
    if (ret == NULL)
        die("strdup");

    return ret;
}

ssize_t Write(int fd, const void *buf, size_t count)
{
    ssize_t ret = write(fd, buf, count);

    if (ret < 0)         /* we don't bail if < count bytes written */
        die("write");

    return ret;
}
