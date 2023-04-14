/***************************************************************************
 * ncat_core.h                                                             *
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

#ifndef NCAT_CORE_H
#define NCAT_CORE_H

#include "nsock.h"
#include "nbase.h"
#include "util.h"
#include "sockaddr_u.h"

/* Maximum size of the srcaddrs array. In this case two because we can only have
   a IPV4 INADDR_ANY and a IPV6 in6addr_any at most or a user defined address */
#define NUM_LISTEN_ADDRS 2

/* Structure to store a linked list of resolved addresses. */
struct sockaddr_list {
    union sockaddr_u addr;
    size_t addrlen;
    struct sockaddr_list* next;
};

extern union sockaddr_u listenaddrs[NUM_LISTEN_ADDRS];
extern int num_listenaddrs;

extern union sockaddr_u srcaddr;
extern size_t srcaddrlen;

extern struct sockaddr_list *targetaddrs;

enum exec_mode {
    EXEC_PLAIN,
    EXEC_SHELL,
    EXEC_LUA,
};

/* Proxy DNS resolution options (mask bits) */
#define PROXYDNS_LOCAL  1
#define PROXYDNS_REMOTE 2

struct options {
    unsigned int portno;

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
    struct addrset *allowset;
    struct addrset *denyset;
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
    int proxydns;

    int ssl;
    char *sslcert;
    char *sslkey;
    int sslverify;
    char *ssltrustfile;
    char *sslciphers;
    char* sslservername;
    char *sslalpn;
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

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0.

   Resolve the hostname with DNS only if global o.proxydns includes PROXYDNS_LOCAL. */
int proxyresolve(const char *hostname, unsigned short port,
            struct sockaddr_storage *ss, size_t *sslen, int af);

/* Resolves the given hostname or IP address with getaddrinfo, and stores
   all results into a linked list.
   The rest of behavior is same as resolve(). */
int resolve_multi(const char *hostname, unsigned short port,
        struct sockaddr_list *sl, int af);

void free_sockaddr_list(struct sockaddr_list *sl);

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
