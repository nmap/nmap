/***************************************************************************
 * ncat_main.c -- main function: option parsing and checking, dispatching  *
 * to mode-specific functions.                                             *
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

#include "nsock.h"
#include "ncat.h"
#include "util.h"
#include "sys_wrap.h"

#include <getopt.h>

#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#ifndef WIN32
#include <netdb.h>
#endif
#include <fcntl.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef HAVE_LUA
#include "ncat_lua.h"
#endif

static int ncat_connect_mode(void);
static int ncat_listen_mode(void);

/* Determines if it's parsing HTTP or SOCKS by looking at defport */
static size_t parseproxy(char *str, struct sockaddr_storage *ss,
    size_t *sslen, unsigned short *portno)
{
    char *c = strrchr(str, ':'), *ptr;
    int rc;

    ptr = str;

    if (c)
        *c = 0;

    if (c && strlen((c + 1)))
        *portno = (unsigned short) atoi(c + 1);

    rc = resolve(ptr, *portno, ss, sslen, o.af);
    if (rc != 0) {
        loguser("Could not resolve proxy \"%s\": %s.\n", ptr, gai_strerror(rc));
        if (o.af == AF_INET6 && *portno)
            loguser("Did you specify the port number? It's required for IPv6.\n");
        exit(EXIT_FAILURE);
    }

    return *sslen;
}

/* These functions implement a simple linked list to hold allow/deny
   specifications until the end of option parsing. */
struct host_list_node {
    /* If false, then spec is the name of a file containing host patterns. */
    int is_filename;
    char *spec;
    struct host_list_node *next;
};

static void host_list_add_spec(struct host_list_node **list, char *spec)
{
    struct host_list_node *node = (struct host_list_node *) safe_malloc(sizeof(*node));
    node->is_filename = 0;
    node->spec = spec;
    node->next = *list;
    *list = node;
}

static void host_list_add_filename(struct host_list_node **list, char *filename)
{
    struct host_list_node *node = (struct host_list_node *) safe_malloc(sizeof(*node));
    node->is_filename = 1;
    node->spec = filename;
    node->next = *list;
    *list = node;
}

static void host_list_free(struct host_list_node *list)
{
    struct host_list_node *next;
    for ( ; list != NULL; list = next) {
        next = list->next;
        free(list);
    }
}

static void host_list_to_set(struct addrset *set, struct host_list_node *list)
{
    struct host_list_node *node;

    for (node = list; node != NULL; node = node->next) {
        if (node->is_filename) {
            FILE *fd;

            fd = fopen(node->spec, "r");
            if (fd == NULL)
                bye("can't open %s: %s.", node->spec, strerror(errno));
            if (!addrset_add_file(set, fd, o.af, !o.nodns))
                bye("error in hosts file %s.", node->spec);
            fclose(fd);
        } else {
            char *spec, *commalist;

            commalist = node->spec;
            while ((spec = strtok(commalist, ",")) != NULL) {
                commalist = NULL;
                if (!addrset_add_spec(set, spec, o.af, !o.nodns))
                    bye("error in host specification \"%s\".", node->spec);
            }
        }
    }
}

static void print_banner(void)
{
    loguser("Version %s ( %s )\n", NCAT_VERSION, NCAT_URL);
}

int main(int argc, char *argv[])
{
    /* We have to buffer the lists of hosts to allow and deny until after option
       parsing is done. Adding hosts to an addrset can require name resolution,
       which may differ as a result of options like -n and -6. */
    struct host_list_node *allow_host_list = NULL;
    struct host_list_node *deny_host_list = NULL;

	unsigned short proxyport = DEFAULT_PROXY_PORT;
    int srcport = -1;
    char *source = NULL;

    struct option long_options[] = {
        {"4",               no_argument,        NULL,         '4'},
        {"6",               no_argument,        NULL,         '6'},
#if HAVE_SYS_UN_H
        {"unixsock",        no_argument,        NULL,         'U'},
#endif
        {"crlf",            no_argument,        NULL,         'C'},
        {"g",               required_argument,  NULL,         'g'},
        {"G",               required_argument,  NULL,         'G'},
        {"exec",            required_argument,  NULL,         'e'},
        {"sh-exec",         required_argument,  NULL,         'c'},
#ifdef HAVE_LUA
        {"lua-exec",        required_argument,  NULL,         0},
        {"lua-exec-internal",required_argument, NULL,         0},
#endif
        {"max-conns",       required_argument,  NULL,         'm'},
        {"help",            no_argument,        NULL,         'h'},
        {"delay",           required_argument,  NULL,         'd'},
        {"listen",          no_argument,        NULL,         'l'},
        {"output",          required_argument,  NULL,         'o'},
        {"hex-dump",        required_argument,  NULL,         'x'},
        {"append-output",   no_argument,        NULL,         0},
        {"idle-timeout",    required_argument,  NULL,         'i'},
        {"keep-open",       no_argument,        NULL,         'k'},
        {"recv-only",       no_argument,        &o.recvonly,  1},
        {"source-port",     required_argument,  NULL,         'p'},
        {"source",          required_argument,  NULL,         's'},
        {"send-only",       no_argument,        &o.sendonly,  1},
        {"no-shutdown",     no_argument,        &o.noshutdown,1},
        {"broker",          no_argument,        NULL,         0},
        {"chat",            no_argument,        NULL,         0},
        {"talk",            no_argument,        NULL,         0},
        {"deny",            required_argument,  NULL,         0},
        {"denyfile",        required_argument,  NULL,         0},
        {"allow",           required_argument,  NULL,         0},
        {"allowfile",       required_argument,  NULL,         0},
        {"telnet",          no_argument,        NULL,         't'},
        {"udp",             no_argument,        NULL,         'u'},
        {"sctp",            no_argument,        NULL,         0},
        {"version",         no_argument,        NULL,         0},
        {"verbose",         no_argument,        NULL,         'v'},
        {"wait",            required_argument,  NULL,         'w'},
        {"nodns",           no_argument,        NULL,         'n'},
        {"proxy",           required_argument,  NULL,         0},
        {"proxy-type",      required_argument,  NULL,         0},
        {"proxy-auth",      required_argument,  NULL,         0},
        {"nsock-engine",    required_argument,  NULL,         0},
        {"test",            no_argument,        NULL,         0},
        {"ssl",             no_argument,        &o.ssl,       1},
#ifdef HAVE_OPENSSL
        {"ssl-cert",        required_argument,  NULL,         0},
        {"ssl-key",         required_argument,  NULL,         0},
        {"ssl-verify",      no_argument,        NULL,         0},
        {"ssl-trustfile",   required_argument,  NULL,         0},
        {"ssl-ciphers",     required_argument,  NULL,         0},
#else
        {"ssl-cert",        optional_argument,  NULL,         0},
        {"ssl-key",         optional_argument,  NULL,         0},
        {"ssl-verify",      no_argument,        NULL,         0},
        {"ssl-trustfile",   optional_argument,  NULL,         0},
        {"ssl-ciphers",     optional_argument,  NULL,         0},
#endif
        {0, 0, 0, 0}
    };

    gettimeofday(&start_time, NULL);
    /* Set default options. */
    options_init();

#ifdef WIN32
    windows_init();
#endif

    while (1) {
        /* handle command line arguments */
        int option_index;
        int c = getopt_long(argc, argv, "46UCc:e:g:G:i:km:hp:d:lo:x:ts:uvw:n:z",
                            long_options, &option_index);

        /* That's the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case '4':
            o.af = AF_INET;
            break;
        case '6':
#ifdef HAVE_IPV6
            o.af = AF_INET6;
#else
            bye("-6 chosen when IPv6 wasn't compiled in.");
#endif
            break;
#if HAVE_SYS_UN_H
        case 'U':
            o.af = AF_UNIX;
            break;
#endif
        case 'C':
            o.crlf = 1;
            break;
        case 'c':
            if (o.cmdexec != NULL)
                bye("Only one of --exec, --sh-exec, and --lua-exec is allowed.");
            o.cmdexec = optarg;
            o.execmode = EXEC_SHELL;
            break;
        case 'e':
            if (o.cmdexec != NULL)
                bye("Only one of --exec, --sh-exec, and --lua-exec is allowed.");
            o.cmdexec = optarg;
            o.execmode = EXEC_PLAIN;
            break;
        case 'g': {
            char *from = optarg;
            char *a = NULL;
            while (o.numsrcrtes < 8 && (a = strtok(from, ",")))
            {
                union sockaddr_u addr;
                size_t sslen;
                int rc;
                from = NULL;

                rc = resolve(a, 0, &addr.storage, &sslen, AF_INET);
                if (rc != 0) {
                    bye("Sorry, could not resolve source route hop \"%s\": %s.",
                    a, gai_strerror(rc));
                }
                o.srcrtes[o.numsrcrtes++] = addr.in.sin_addr;
            }
            if (strtok(from, ","))
                bye("Sorry, you gave too many source route hops.");
            break;
        }
        case 'G':
            o.srcrteptr = atoi(optarg);
            if (o.srcrteptr < 4 || (o.srcrteptr % 4) || o.srcrteptr > 28)
                bye("Invalid source-route hop pointer %d.", o.srcrteptr);
            break;
        case 'k':
            o.keepopen = 1;
            break;
        case 'm':
            o.conn_limit = atoi(optarg);
            break;
        case 'd':
            o.linedelay = tval2msecs(optarg);
            if (o.linedelay <= 0)
                bye("Invalid -d delay \"%s\" (must be greater than 0).", optarg);
            if (o.linedelay >= 100 * 1000 && tval_unit(optarg) == NULL)
                bye("Since April 2010, the default unit for -d is seconds, so your time of \"%s\" is %.1f minutes. Use \"%sms\" for %g milliseconds.", optarg, o.linedelay / 1000.0 / 60, optarg, o.linedelay / 1000.0);
            break;
        case 'o':
            o.normlog = optarg;
            break;
        case 'x':
            o.hexlog = optarg;
            break;
        case 'p':
            srcport = atoi(optarg);
            if (srcport < 0 || srcport > 0xffff)
                bye("Invalid source port %d.", srcport);
            break;
        case 'i':
            o.idletimeout = tval2msecs(optarg);
            if (o.idletimeout <= 0)
                bye("Invalid -i timeout (must be greater than 0).");
            if (o.idletimeout >= 100 * 1000 && tval_unit(optarg) == NULL)
                bye("Since April 2010, the default unit for -i is seconds, so your time of \"%s\" is %.1f minutes. Use \"%sms\" for %g milliseconds.", optarg, o.idletimeout / 1000.0 / 60, optarg, o.idletimeout / 1000.0);
            break;
        case 's':
            source = optarg;
            break;
        case 'l':
            o.listen = 1;
            break;
        case 'u':
            o.proto = IPPROTO_UDP;
            break;
        case 'v':
            /* One -v activates verbose, after that it's debugging. */
            if (o.verbose == 0)
                o.verbose++;
            else
                o.debug++;
            break;
        case 'n':
            o.nodns = 1;
            break;
        case 'w':
            o.conntimeout = tval2msecs(optarg);
            if (o.conntimeout <= 0)
                bye("Invalid -w timeout (must be greater than 0).");
            if (o.conntimeout >= 100 * 1000 && tval_unit(optarg) == NULL)
                bye("Since April 2010, the default unit for -w is seconds, so your time of \"%s\" is %.1f minutes. Use \"%sms\" for %g milliseconds.", optarg, o.conntimeout / 1000.0 / 60, optarg, o.conntimeout / 1000.0);
            break;
        case 't':
            o.telnet = 1;
            break;
        case 'z':
            o.zerobyte = 1;
            break;
        case 0:
            if (strcmp(long_options[option_index].name, "version") == 0) {
                print_banner();
                exit(EXIT_SUCCESS);
            } else if (strcmp(long_options[option_index].name, "proxy") == 0) {
                if (o.proxyaddr)
                    bye("You can't specify more than one --proxy.");
                o.proxyaddr = optarg;
            } else if (strcmp(long_options[option_index].name, "proxy-type") == 0) {
                if (o.proxytype)
                    bye("You can't specify more than one --proxy-type.");
                o.proxytype = optarg;
            } else if (strcmp(long_options[option_index].name, "proxy-auth") == 0) {
                if (o.proxy_auth)
                    bye("You can't specify more than one --proxy-auth.");
                o.proxy_auth = optarg;
            } else if (strcmp(long_options[option_index].name, "nsock-engine") == 0) {
                if (nsock_set_default_engine(optarg) < 0)
                    bye("Unknown or non-available engine: %s.", optarg);
                o.nsock_engine = 1;
            } else if (strcmp(long_options[option_index].name, "test") == 0) {
                o.test = 1;
            } else if (strcmp(long_options[option_index].name, "broker") == 0) {
                o.broker = 1;
                /* --broker implies --listen. */
                o.listen = 1;
            } else if (strcmp(long_options[option_index].name, "chat") == 0
                       || strcmp(long_options[option_index].name, "talk") == 0) {
                /* --talk is an older name for --chat. */
                o.chat = 1;
                /* --chat implies --broker. */
                o.broker = 1;
            } else if (strcmp(long_options[option_index].name, "allow") == 0) {
                o.allow = 1;
                host_list_add_spec(&allow_host_list, optarg);
            } else if (strcmp(long_options[option_index].name, "allowfile") == 0) {
                o.allow = 1;
                host_list_add_filename(&allow_host_list, optarg);
            } else if (strcmp(long_options[option_index].name, "deny") == 0) {
                host_list_add_spec(&deny_host_list, optarg);
            } else if (strcmp(long_options[option_index].name, "denyfile") == 0) {
                host_list_add_filename(&deny_host_list, optarg);
            } else if (strcmp(long_options[option_index].name, "append-output") == 0) {
                o.append = 1;
            } else if (strcmp(long_options[option_index].name, "sctp") == 0) {
                o.proto = IPPROTO_SCTP;
            }
#ifdef HAVE_OPENSSL
            else if (strcmp(long_options[option_index].name, "ssl-cert") == 0) {
                o.ssl = 1;
                o.sslcert = Strdup(optarg);
            } else if (strcmp(long_options[option_index].name, "ssl-key") == 0) {
                o.ssl = 1;
                o.sslkey = Strdup(optarg);
            } else if (strcmp(long_options[option_index].name, "ssl-verify") == 0) {
                o.sslverify = 1;
                o.ssl = 1;
            } else if (strcmp(long_options[option_index].name, "ssl-trustfile") == 0) {
                o.ssl = 1;
                if (o.ssltrustfile != NULL)
                    bye("The --ssl-trustfile option may be given only once.");
                o.ssltrustfile = Strdup(optarg);
                /* If they list a trustfile assume they want certificate
                   verification. */
                o.sslverify = 1;
            } else if (strcmp(long_options[option_index].name, "ssl-ciphers") == 0) {
                o.ssl = 1;
                o.sslciphers = Strdup(optarg);
            }
#else
            else if (strcmp(long_options[option_index].name, "ssl-cert") == 0) {
                bye("OpenSSL isn't compiled in. The --ssl-cert option cannot be chosen.");
            } else if (strcmp(long_options[option_index].name, "ssl-key") == 0) {
                bye("OpenSSL isn't compiled in. The --ssl-key option cannot be chosen.");
            } else if (strcmp(long_options[option_index].name, "ssl-verify") == 0) {
                bye("OpenSSL isn't compiled in. The --ssl-verify option cannot be chosen.");
            } else if (strcmp(long_options[option_index].name, "ssl-trustfile") == 0) {
                bye("OpenSSL isn't compiled in. The --ssl-trustfile option cannot be chosen.");
            } else if (strcmp(long_options[option_index].name, "ssl-ciphers") == 0) {
                bye("OpenSSL isn't compiled in. The --ssl-ciphers option cannot be chosen.");
            }
#endif
#ifdef HAVE_LUA
            else if (strcmp(long_options[option_index].name, "lua-exec") == 0) {
                if (o.cmdexec != NULL)
                    bye("Only one of --exec, --sh-exec, and --lua-exec is allowed.");
                o.cmdexec = optarg;
                o.execmode = EXEC_LUA;
            } else if (strcmp(long_options[option_index].name, "lua-exec-internal") == 0) {
                /* This command-line switch is undocumented on purpose. Do NOT use it
                   explicitly as its behavior might differ between Ncat releases.

                   Its goal is to switch the Ncat process to the Lua interpreter state
                   so that its standard output and input can be redirected to
                   particular connection's streams. Although it is implemented by
                   forking in POSIX builds, Windows does not have the fork() system
                   call and thus requires this workaround. More info here:
                   http://seclists.org/nmap-dev/2013/q2/492 */
#ifdef WIN32
                if (o.debug)
                    logdebug("Enabling binary stdout for the Lua output.\n");
                int result = _setmode(_fileno(stdout), _O_BINARY);
                if (result == -1)
                    perror("Cannot set mode");
#endif
                ncat_assert(argc == 3);
                o.cmdexec = argv[2];
                lua_setup();
                lua_run();
            }
#endif
            break;
        case 'h':
            printf("%s %s ( %s )\n", NCAT_NAME, NCAT_VERSION, NCAT_URL);
            printf(
"Usage: ncat [options] [hostname] [port]\n"
"\n"
"Options taking a time assume seconds. Append 'ms' for milliseconds,\n"
"'s' for seconds, 'm' for minutes, or 'h' for hours (e.g. 500ms).\n"
"  -4                         Use IPv4 only\n"
"  -6                         Use IPv6 only\n"
#if HAVE_SYS_UN_H
"  -U, --unixsock             Use Unix domain sockets only\n"
#endif
"  -C, --crlf                 Use CRLF for EOL sequence\n"
"  -c, --sh-exec <command>    Executes the given command via /bin/sh\n"
"  -e, --exec <command>       Executes the given command\n"
#ifdef HAVE_LUA
"      --lua-exec <filename>  Executes the given Lua script\n"
#endif
"  -g hop1[,hop2,...]         Loose source routing hop points (8 max)\n"
"  -G <n>                     Loose source routing hop pointer (4, 8, 12, ...)\n"
"  -m, --max-conns <n>        Maximum <n> simultaneous connections\n"
"  -h, --help                 Display this help screen\n"
"  -d, --delay <time>         Wait between read/writes\n"
"  -o, --output <filename>    Dump session data to a file\n"
"  -x, --hex-dump <filename>  Dump session data as hex to a file\n"
"  -i, --idle-timeout <time>  Idle read/write timeout\n"
"  -p, --source-port port     Specify source port to use\n"
"  -s, --source addr          Specify source address to use (doesn't affect -l)\n"
"  -l, --listen               Bind and listen for incoming connections\n"
"  -k, --keep-open            Accept multiple connections in listen mode\n"
"  -n, --nodns                Do not resolve hostnames via DNS\n"
"  -t, --telnet               Answer Telnet negotiations\n"
"  -u, --udp                  Use UDP instead of default TCP\n"
"      --sctp                 Use SCTP instead of default TCP\n"
"  -v, --verbose              Set verbosity level (can be used several times)\n"
"  -w, --wait <time>          Connect timeout\n"
"  -z                         Zero-I/O mode, report connection status only\n"
"      --append-output        Append rather than clobber specified output files\n"
"      --send-only            Only send data, ignoring received; quit on EOF\n"
"      --recv-only            Only receive data, never send anything\n"
"      --allow                Allow only given hosts to connect to Ncat\n"
"      --allowfile            A file of hosts allowed to connect to Ncat\n"
"      --deny                 Deny given hosts from connecting to Ncat\n"
"      --denyfile             A file of hosts denied from connecting to Ncat\n"
"      --broker               Enable Ncat's connection brokering mode\n"
"      --chat                 Start a simple Ncat chat server\n"
"      --proxy <addr[:port]>  Specify address of host to proxy through\n"
"      --proxy-type <type>    Specify proxy type (\"http\" or \"socks4\" or \"socks5\")\n"
"      --proxy-auth <auth>    Authenticate with HTTP or SOCKS proxy server\n"

#ifdef HAVE_OPENSSL
"      --ssl                  Connect or listen with SSL\n"
"      --ssl-cert             Specify SSL certificate file (PEM) for listening\n"
"      --ssl-key              Specify SSL private key (PEM) for listening\n"
"      --ssl-verify           Verify trust and domain name of certificates\n"
"      --ssl-trustfile        PEM file containing trusted SSL certificates\n"
"      --ssl-ciphers          Cipherlist containing SSL ciphers to use\n"
#endif
"      --version              Display Ncat's version information and exit\n"
"\n"
"See the ncat(1) manpage for full options, descriptions and usage examples\n"
            );
            exit(EXIT_SUCCESS);
        case '?':
            /* Consider unrecognised parameters/arguments as fatal. */
            bye("Try `--help' or man(1) ncat for more information, usage options and help.");
        default:
            /* We consider an unrecognised option fatal. */
            bye("Unrecognised option.");
        }
    }

#ifndef HAVE_OPENSSL
    if (o.ssl)
        bye("OpenSSL isn't compiled in. The --ssl option cannot be chosen.");
#endif

    if (o.normlog)
        o.normlogfd = ncat_openlog(o.normlog, o.append);
    if (o.hexlog)
        o.hexlogfd = ncat_openlog(o.hexlog, o.append);

    if (o.verbose)
        print_banner();

    if (o.debug)
        nbase_set_log(loguser, logdebug);
    else
        nbase_set_log(loguser, NULL);

#if HAVE_SYS_UN_H
    /* Using Unix domain sockets, so do the checks now */
    if (o.af == AF_UNIX) {
        if (o.proxyaddr || o.proxytype)
            bye("Proxy option not supported when using Unix domain sockets.");
#ifdef HAVE_OPENSSL
        if (o.ssl)
            bye("SSL option not supported when using Unix domain sockets.");
#endif
        if (o.broker)
            bye("Connection brokering not supported when using Unix domain sockets.");
        if (srcport != -1)
            bye("Specifying source port when using Unix domain sockets doesn't make sense.");
        if (o.numsrcrtes > 0)
            bye("Loose source routing not allowed when using Unix domain sockets.");
    }
#endif  /* HAVE_SYS_UN_H */

    /* Will be AF_INET or AF_INET6 or AF_UNIX when valid */
    memset(&targetss.storage, 0, sizeof(targetss.storage));
    targetss.storage.ss_family = AF_UNSPEC;
    srcaddr.storage = targetss.storage;

    /* Clear the listenaddrs array */
    int i;
    for (i = 0; i < NUM_LISTEN_ADDRS; i++) {
        listenaddrs[i].storage = targetss.storage;
    }

    if (o.proxyaddr) {
        if (!o.proxytype)
            o.proxytype = Strdup("http");

        if (!strcmp(o.proxytype, "http") ||
            !strcmp(o.proxytype, "socks4") || !strcmp(o.proxytype, "4") ||
            !strcmp(o.proxytype, "socks5") || !strcmp(o.proxytype, "5")) {
            /* Parse HTTP/SOCKS proxy address and store it in targetss.
             * If the proxy server is given as an IPv6 address (not hostname),
             * the port number MUST be specified as well or parsing will break
             * (due to the colons in the IPv6 address and host:port separator).
             */

            targetsslen = parseproxy(o.proxyaddr,
                &targetss.storage, &targetsslen, &proxyport);
            if (o.af == AF_INET) {
                targetss.in.sin_port = htons(proxyport);
            } else { // might modify to else if and test AF_{INET6|UNIX|UNSPEC}
                targetss.in6.sin6_port = htons(proxyport);
            }
        } else {
            bye("Invalid proxy type \"%s\".", o.proxytype);
        }

        if (o.listen)
            bye("Invalid option combination: --proxy and -l.");
    } else {
        if (o.proxytype) {
            if (!o.listen)
                bye("Proxy type (--proxy-type) specified without proxy address (--proxy).");
            if (strcmp(o.proxytype, "http"))
                bye("Invalid proxy type \"%s\".", o.proxytype);
        }
    }

    if (o.zerobyte) {
      if (o.listen)
        bye("Services designed for LISTENING can't be used with -z");
      if (o.telnet)
        bye("Invalid option combination: -z and -t.");
      if (o.execmode||o.cmdexec)
        bye("Command execution can't be done along with option -z.");
      if (!o.idletimeout && o.proto == IPPROTO_UDP)
        o.idletimeout = 2 * 1000;
    }
    /* Default port */
    if (o.listen && o.proxytype && !o.portno && srcport == -1)
        o.portno = DEFAULT_PROXY_PORT;
    else
        o.portno = DEFAULT_NCAT_PORT;

    /* Resolve the given source address */
    if (source) {
        int rc = 0;

        if (o.listen)
            bye("-l and -s are incompatible.  Specify the address and port to bind to like you would a host to connect to.");

#if HAVE_SYS_UN_H
        /* if using UNIX sockets just copy the path.
         * If it's not valid, it will fail later! */
        if (o.af == AF_UNIX) {
            if (o.proto == IPPROTO_UDP) {
                srcaddr.un.sun_family = AF_UNIX;
                strncpy(srcaddr.un.sun_path, source, sizeof(srcaddr.un.sun_path));
                srcaddrlen = SUN_LEN(&srcaddr.un);
            }
            else
                if (o.verbose)
                    loguser("Specifying source socket for other than DATAGRAM Unix domain sockets have no effect.\n");
        } else
#endif
            rc = resolve(source, 0, &srcaddr.storage, &srcaddrlen, o.af);
        if (rc != 0)
            bye("Could not resolve source address \"%s\": %s.", source, gai_strerror(rc));
    }

    host_list_to_set(&o.allowset, allow_host_list);
    host_list_free(allow_host_list);
    host_list_to_set(&o.denyset, deny_host_list);
    host_list_free(deny_host_list);

    if (optind == argc) {
#if HAVE_SYS_UN_H
        if (o.af == AF_UNIX) {
            if (!o.listen)
                bye("You have to specify path to a socket to connect to.");
            else
                bye("You have to specify path to a socket to listen on.");
        }
#endif
        /* Listen defaults to any address and DEFAULT_NCAT_PORT */
        if (!o.listen)
            bye("You must specify a host to connect to.");
    } else {
#if HAVE_SYS_UN_H
        if (o.af == AF_UNIX) {
            memset(&targetss.storage, 0, sizeof(struct sockaddr_un));
            targetss.un.sun_family = AF_UNIX;
            strncpy(targetss.un.sun_path, argv[optind], sizeof(targetss.un.sun_path));
            targetsslen = SUN_LEN(&targetss.un);
            o.target = argv[optind];
            optind++;
        } else
#endif
        /* Resolve hostname if we're given one */
        if (strspn(argv[optind], "0123456789") != strlen(argv[optind])) {
            int rc;

            o.target = argv[optind];
            /* resolve hostname only if o.proxytype == NULL
             * targetss contains data already and you don't want remove them
             */
            if( !o.proxytype
                && (rc = resolve(o.target, 0, &targetss.storage, &targetsslen, o.af)) != 0)

                bye("Could not resolve hostname \"%s\": %s.", o.target, gai_strerror(rc));
            optind++;
        } else {
            if (!o.listen)
                bye("You must specify a host to connect to.");
        }
    }

    /* Whatever's left is the port number; there should be at most one. */
#if HAVE_SYS_UN_H
    /* We do not use ports with Unix domain sockets. */
    if (o.af == AF_UNIX && optind > argc)
        bye("Using Unix domain sockets and specifying port doesn't make sense.");
#endif

    if (optind + 1 < argc || (o.listen && srcport != -1 && optind + 1 == argc)) {
        loguser("Got more than one port specification:");
        if (o.listen && srcport != -1)
            loguser_noprefix(" %d", srcport);
        for (; optind < argc; optind++)
            loguser_noprefix(" %s", argv[optind]);
        loguser_noprefix(". QUITTING.\n");
        exit(2);
    } else if (optind + 1 == argc) {
        long long_port;

        errno = 0;
        long_port = strtol(argv[optind], NULL, 10);
        if (errno != 0 || long_port <= 0 || long_port > 65535)
            bye("Invalid port number \"%s\".", argv[optind]);

        o.portno = (unsigned short) long_port;
    }

    if (o.proxytype && !o.listen)
        ; /* Do nothing - port is already set to proxyport  */
    else if (targetss.storage.ss_family == AF_INET)
        targetss.in.sin_port = htons(o.portno);
#ifdef HAVE_IPV6
    else if (targetss.storage.ss_family == AF_INET6)
        targetss.in6.sin6_port = htons(o.portno);
#endif
#if HAVE_SYS_UN_H
    /* If we use Unix domain sockets, we have to count with them. */
    else if (targetss.storage.ss_family == AF_UNIX)
        ; /* Do nothing. */
#endif
    else if (targetss.storage.ss_family == AF_UNSPEC)
        ; /* Leave unspecified. */
    else
        bye("Unknown address family %d.", targetss.storage.ss_family);

    if (srcport != -1) {
        if (o.listen) {
            /* Treat "ncat -l -p <port>" the same as "ncat -l <port>" for nc
               compatibility. */
            o.portno = srcport;
        } else {
            if (srcaddr.storage.ss_family == AF_UNSPEC) {
                /* We have a source port but not an explicit source address;
                   fill in an unspecified address of the same family as the
                   target. */
                srcaddr.storage.ss_family = targetss.storage.ss_family;
                if (srcaddr.storage.ss_family == AF_INET)
                    srcaddr.in.sin_addr.s_addr = INADDR_ANY;
                else if (srcaddr.storage.ss_family == AF_INET6)
                    srcaddr.in6.sin6_addr = in6addr_any;
            }
            if (srcaddr.storage.ss_family == AF_INET)
                srcaddr.in.sin_port = htons(srcport);
#ifdef HAVE_IPV6
            else
                srcaddr.in6.sin6_port = htons(srcport);
#endif
        }
    }

    if (o.proto == IPPROTO_UDP) {
        /* Don't allow a false sense of security if someone tries SSL over UDP. */
        if (o.ssl)
            bye("UDP mode does not support SSL.");
        if (o.keepopen && o.cmdexec == NULL)
            bye("UDP mode does not support the -k or --keep-open options, except with --exec or --sh-exec.");
        if (o.broker)
            bye("UDP mode does not support connection brokering.\n\
If this feature is important to you, write dev@nmap.org with a\n\
description of how you intend to use it, as an aid to deciding how UDP\n\
connection brokering should work.");
    }

    /* Do whatever is necessary to receive \n for line endings on input from
       the console. A no-op on Unix. */
    set_lf_mode();

#ifdef HAVE_LUA
    if (o.execmode == EXEC_LUA)
        lua_setup();
#endif

    if (o.listen)
        return ncat_listen_mode();
    else
        return ncat_connect_mode();
}

/* connect error handling and operations. */
static int ncat_connect_mode(void)
{
    /*
     * allow/deny commands with connect make no sense. If you don't want to
     * connect to a host, don't try to.
     */
    if (o.allow || o.deny)
        bye("Invalid option combination: allow/deny with connect.");

    /* o.conn_limit with 'connect' doesn't make any sense. */
    if (o.conn_limit != -1)
        bye("Invalid option combination: `--max-conns' with connect.");

    if (o.chat)
        bye("Invalid option combination: `--chat' with connect.");

    if (o.keepopen)
        bye("Invalid option combination: `--keep-open' with connect.");

    return ncat_connect();
}

static int ncat_listen_mode(void)
{
    /* Can't 'listen' AND 'connect' to a proxy server at the same time. */
    if (o.proxyaddr != NULL)
        bye("Invalid option combination: --proxy and -l.");

    if (o.broker && o.cmdexec != NULL)
        bye("Invalid option combination: --broker and -e.");

    if (o.proxytype != NULL && o.telnet)
        bye("Invalid option combination: --telnet has no effect with --proxy-type.");

    if (o.conn_limit != -1 && !(o.keepopen || o.broker))
        loguser("Warning: Maximum connections ignored, since it does not take "
                "effect without -k or --broker.\n");

    /* Set the default maximum simultaneous TCP connection limit. */
    if (o.conn_limit == -1)
        o.conn_limit = DEFAULT_MAX_CONNS;

#ifndef WIN32
    /* See if the shell is executable before we get deep into this */
    if (o.execmode == EXEC_SHELL && access("/bin/sh", X_OK) == -1)
        bye("/bin/sh is not executable, so `-c' won't work.");
#endif

    if (targetss.storage.ss_family != AF_UNSPEC) {
        listenaddrs[num_listenaddrs++] = targetss;
    } else {
        size_t ss_len;
        int rc;

        /* No command-line address. Listen on IPv4 or IPv6 or both. */
        /* Try to bind to IPv6 first; on AIX a bound IPv4 socket blocks an IPv6
           socket on the same port, despite IPV6_V6ONLY. */
#ifdef HAVE_IPV6
        if (o.af == AF_INET6 || o.af == AF_UNSPEC) {
            ss_len = sizeof(listenaddrs[num_listenaddrs]);
            rc = resolve("::", o.portno, &listenaddrs[num_listenaddrs].storage, &ss_len, AF_INET6);
            if (rc == 0)
                num_listenaddrs++;
            else if (o.debug > 0)
                logdebug("Failed to resolve default IPv6 address: %s\n", gai_strerror(rc));
        }
#endif
        if (o.af == AF_INET || o.af == AF_UNSPEC) {
            ss_len = sizeof(listenaddrs[num_listenaddrs]);
            rc = resolve("0.0.0.0", o.portno, &listenaddrs[num_listenaddrs].storage, &ss_len, AF_INET);
            if (rc != 0)
                bye("Failed to resolve default IPv4 address: %s.", gai_strerror(rc));
            num_listenaddrs++;
        }
    }

    if (o.proxytype) {
        if (strcmp(o.proxytype, "http") == 0)
            o.httpserver = 1;
    }

    /* Fire the listen/select dispatcher for bog-standard listen operations. */
    return ncat_listen();
}
