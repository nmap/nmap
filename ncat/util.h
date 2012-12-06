/***************************************************************************
 * util.h                                                                  *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
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

#if HAVE_SYS_UN_H
#include <sys/un.h>
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

#include "sockaddr_u.h"

void loguser(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void loguser_noprefix(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void logdebug(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));

/* handle errors */
void die(char *);

void bye(const char *, ...)
     __attribute__ ((noreturn))
     __attribute__ ((format (printf, 1, 2)));

/* zero out some memory, bzero() is deprecated */
void zmem(void *, size_t);

int strbuf_append(char **buf, size_t *size, size_t *offset, const char *s, size_t n);

int strbuf_append_str(char **buf, size_t *size, size_t *offset, const char *s);

int strbuf_sprintf(char **buf, size_t *size, size_t *offset, const char *fmt, ...)
     __attribute__ ((format (printf, 4, 5)));

char *mkstr(const char *start, const char *end);

int addr_is_local(const union sockaddr_u *su);

const char *inet_socktop(const union sockaddr_u *su);

unsigned short inet_port(const union sockaddr_u *su);

int do_listen(int, int, const union sockaddr_u *);


int do_connect(int);

unsigned char *buildsrcrte(struct in_addr dstaddr, struct in_addr routes[],
                  int numroutes, int ptr, size_t *len);

int allow_access(const union sockaddr_u *su);

struct fdinfo {
    int fd;
    union sockaddr_u remoteaddr;
#ifdef HAVE_OPENSSL
    SSL *ssl;
#endif
};

typedef struct fd_list {
    struct fdinfo *fds;
    int nfds, maxfds, fdmax;
} fd_list_t;

int add_fdinfo(fd_list_t *, struct fdinfo *);
int add_fd(fd_list_t *fdl, int fd);
int rm_fd(fd_list_t *, int);
void free_fdlist(fd_list_t *);
void init_fdlist(fd_list_t *, int);
int get_maxfd(fd_list_t *);
struct fdinfo *get_fdinfo(const fd_list_t *, int);

int fix_line_endings(char *src, int *len, char **dst, int *state);

#endif
