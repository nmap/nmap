/***************************************************************************
 * ncat_core.h                                                             *
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

#ifndef NCAT_CORE_H
#define NCAT_CORE_H

#include "nsock.h"
#include "nbase.h"
#include "util.h"
#include "sockaddr_u.h"

/* Maximum size of the srcaddrs array. In this case two because we can only have
   a IPV4 INADDR_ANY and a IPV6 in6addr_any at most or a user defined address */
#define NUM_LISTEN_ADDRS 2

extern union sockaddr_u listenaddrs[NUM_LISTEN_ADDRS];
extern int num_listenaddrs;

extern union sockaddr_u srcaddr;
extern size_t srcaddrlen;

extern union sockaddr_u targetss;
extern size_t targetsslen;

enum exec_mode {
    EXEC_PLAIN,
    EXEC_SHELL,
    EXEC_LUA,
};

struct options {
    unsigned short portno;

    int verbose;
    int debug;
    char *target;
    int af;
    /* IPPROTO_TCP, IPPROTO_SCTP, or IPPROTO_UDP */
    int proto;
    int broker;
    int listen;
    int keepopen;
    int sendonly;
    int recvonly;
    int noshutdown;
    int telnet;
    int linedelay;
    int chat;
    int nodns;
    const char *normlog;
    const char *hexlog;
    int normlogfd;
    int hexlogfd;
    int append;
    int idletimeout;
    int crlf;
    /* Were any hosts specifically allowed? If so, deny all others. */
    int allow;
    int deny;
    struct addrset allowset;
    struct addrset denyset;
    int httpserver;
    int nsock_engine;
    /* Output messages useful for testing to stderr? */
    int test;

    /* Loose source-routing stuff */
    struct in_addr srcrtes[8];
    int numsrcrtes;
    int srcrteptr;

    /* Maximum number of simultaneous connections */
    int conn_limit;
    int conntimeout;

    /* When execmode == EXEC_LUA, cmdexec is the name of the file to run. */
    char *cmdexec;
    enum exec_mode execmode;
    char *proxy_auth;
    char *proxytype;
    char *proxyaddr;

    int ssl;
    char *sslcert;
    char *sslkey;
    int sslverify;
    char *ssltrustfile;
    char *sslciphers;
    int zerobyte;
};

extern struct options o;

/* The time the program was started, for exit statistics in connect mode. */
extern struct timeval start_time;

/* Initializes global options to their default values. */
void options_init(void);

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0.

   If the global o.nodns is true, then do not resolve any names with DNS. */
int resolve(const char *hostname, unsigned short port,
            struct sockaddr_storage *ss, size_t *sslen, int af);

int fdinfo_close(struct fdinfo *fdn);
int fdinfo_recv(struct fdinfo *fdn, char *buf, size_t size);
int fdinfo_send(struct fdinfo *fdn, const char *buf, size_t size);
int fdinfo_pending(struct fdinfo *fdn);

int ncat_recv(struct fdinfo *fdn, char *buf, size_t size, int *pending);
int ncat_send(struct fdinfo *fdn, const char *buf, size_t size);

/* Broadcast a message to all the descriptors in fds. Returns -1 if any of the
   sends failed. */
extern int ncat_broadcast(fd_set *fds, const fd_list_t *fdlist, const char *msg, size_t size);

/* Do telnet WILL/WONT DO/DONT negotiations */
extern void dotelnet(int s, unsigned char *buf, size_t bufsiz);

/* sleep(), usleep(), msleep(), Sleep() -- all together now, "portability".
 *
 * There is no upper or lower limit to the delayval, so if you pass in a short
 * length of time <100ms, then you're likely going to get odd results.
 * This is because the Linux timeslice is 10ms-200ms. So don't expect
 * it to return for at least that long.
 *
 * Block until the specified time has elapsed, then return 1.
 */
extern int ncat_delay_timer(int delayval);

/* Open a logfile for writing.
 * Return the open file descriptor. */
extern int ncat_openlog(const char *logfile, int append);

extern void ncat_log_send(const char *data, size_t len);

extern void ncat_log_recv(const char *data, size_t len);

extern int ncat_hostaccess(char *matchaddr, char *filename, char *remoteip);

/* Make it so that line endings read from a console are always \n (not \r\n).
   Defined in ncat_posix.c and ncat_win.c. */
extern void set_lf_mode(void);

extern int getaddrfamily(const char *addr);
extern int setenv_portable(const char *name, const char *value);
extern void setup_environment(struct fdinfo *fdinfo);

#endif
