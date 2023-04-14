/***************************************************************************
 * util.h                                                                  *
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

#ifndef UTIL_H_
#define UTIL_H_

#include "ncat_config.h"

#include "nbase.h"
#ifndef WIN32
#include <sys/types.h>
#include <netinet/in.h>
#endif

#include "sockaddr_u.h"

#if HAVE_SYS_UN_H
#include <sys/un.h>
#include <string.h>

#define NCAT_INIT_SUN(_Sock, _Source) do { \
  memset(_Sock, 0, sizeof(union sockaddr_u)); \
  (_Sock)->un.sun_family = AF_UNIX; \
  if (strlen(_Source) > sizeof((_Sock)->un.sun_path) - 1) \
    bye("Socket path length is too long. Max: %lu", sizeof((_Sock)->un.sun_path) - 1); \
  strncpy((_Sock)->un.sun_path, _Source, sizeof((_Sock)->un.sun_path) - 1); \
} while (0);

#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

/* add/multiply unsigned values safely */
size_t sadd(size_t, size_t);
size_t smul(size_t, size_t);

#ifdef WIN32
void windows_init();
#endif

void loguser(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void loguser_noprefix(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void logdebug(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void logtest(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));

/* handle errors */

#define ncat_assert(expr) \
do { \
        if (!(expr)) \
                bye("assertion failed: %s", #expr); \
} while (0)

void die(char *);

NORETURN void bye(const char *, ...)
     __attribute__ ((format (printf, 1, 2)));

/* zero out some memory, bzero() is deprecated */
void zmem(void *, size_t);

int strbuf_append(char **buf, size_t *size, size_t *offset, const char *s, size_t n);

int strbuf_append_str(char **buf, size_t *size, size_t *offset, const char *s);

int strbuf_sprintf(char **buf, size_t *size, size_t *offset, const char *fmt, ...)
     __attribute__ ((format (printf, 4, 5)));

int addr_is_local(const union sockaddr_u *su);

const char *socktop(const union sockaddr_u *su, socklen_t ss_len);
const char *inet_socktop(const union sockaddr_u *su);

unsigned short inet_port(const union sockaddr_u *su);

int do_listen(int, int, const union sockaddr_u *);


int do_connect(int);

unsigned char *buildsrcrte(struct in_addr dstaddr, struct in_addr routes[],
                  int numroutes, int ptr, size_t *len);

int allow_access(const union sockaddr_u *su);

void ms_to_timeval(struct timeval *tv, long ms)
    __attribute__ ((nonnull));

struct fdinfo {
    int fd;
    int lasterr;
    union sockaddr_u remoteaddr;
    socklen_t ss_len;
#ifdef HAVE_OPENSSL
    SSL *ssl;
#endif
};

typedef struct fd_list {
    struct fdinfo *fds;
    int nfds, maxfds, fdmax;
    int state; /* incremented each time the list is modified */
} fd_list_t;

int add_fdinfo(fd_list_t *, struct fdinfo *);
int add_fd(fd_list_t *fdl, int fd);
int rm_fd(fd_list_t *, int);
void free_fdlist(fd_list_t *);
void init_fdlist(fd_list_t *, int);
int get_maxfd(fd_list_t *);
struct fdinfo *get_fdinfo(const fd_list_t *, int);

int fix_line_endings(char *src, int *len, char **dst, int *state);

unsigned char *next_protos_parse(size_t *outlen, const char *in);

#endif
