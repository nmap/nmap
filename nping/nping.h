/***************************************************************************
 * Nping.h -- This file contains general defines and constants used        *
 * throughout Nping's code.                                                *
 *                                                                         *
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

#ifndef NPING_H
#define NPING_H 1

/* Common library requirements and definitions *******************************/
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <nbase.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../libnetutil/netutil.h"
#include "../libnetutil/npacket.h"

#ifdef HAVE_CONFIG_H
    #include "nping_config.h"
#else
    #ifdef WIN32
        #include "nping_winconfig.h"
    #endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#ifndef WIN32
    #include <sysexits.h>
#endif

#if HAVE_UNISTD_H
    #include <unistd.h>
#endif

#ifdef STDC_HEADERS
    #include <stdlib.h>
#else
    void *malloc();
    void *realloc();
#endif

#if STDC_HEADERS || HAVE_STRING_H
    #include <string.h>
    #if !STDC_HEADERS && HAVE_MEMORY_H
        #include <memory.h>
    #endif
#endif

#if HAVE_STRINGS_H
    #include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
    #include <bstring.h>
#endif

#ifndef WIN32
    #include <sys/wait.h>
#endif /* !WIN32 */

#if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
#endif

#if HAVE_NETINET_IN_H
    #include <netinet/in.h>
#endif

#if HAVE_NETDB_H
    #include <netdb.h>
#endif

#if TIME_WITH_SYS_TIME
    #include <sys/time.h>
    #include <time.h>
#else
    #if HAVE_SYS_TIME_H
        #include <sys/time.h>
    #else
        #include <time.h>
    # endif
#endif

#ifdef HAVE_PWD_H
    #include <pwd.h>
#endif

#if HAVE_ARPA_INET_H
    #include <arpa/inet.h>
#endif

#if HAVE_SYS_RESOURCE_H
    #include <sys/resource.h>
#endif

/* Keep assert() defined for security reasons */
#undef NDEBUG

#define MAXLINE 255

/* CONSTANT DEFINES ***********************************************************
 * @warning It's better not to play with these, because the code may make     *
 * SOME assumptions like "defined value A is an integer greater than defined  *
 * value B" or "value C is an odd integer greater than 0", etc.               */

/* VERBOSITY LEVELS */
/* These are the defines for Nping's internal verbosity levels. Every time
 * you write code for Nping and you have to print something to the terminal,
 * you'll have to choose a verbosity level. You choose a level so your message
 * gets printed only when the user has requested messages from that level to be
 * printed. For example, we have some calls to output functions that print out
 * things like "%d target IPs resolved". We don't want that message to always
 * get printed during  Nping's execution. We only want it out when the user
 * has increase the verbosity.
 * 
 * So the thing here is that there are two things that should be taken
 * into account:
 *  1. The current verbosity level that user has supplied from the command line
 *  2. The verbosity level that we supply in our print calls ( nping_print(),
 *     nping_warning(), etc...)
 *
 *  Fortunately Nping output functions already take care of checking the
 *  current verbosity level, so programmers only have to decide which level
 *  should they specify in their output calls. If you are a programmer and
 *  you are using nping_print(), nping_warning() or nping_fatal() calls in Nping's code,
 *  you have to ask yourself: Do I want to print extra information that
 *  shouldn't be printed by default? Or am I printing important stuff like
 *  errors, etc, that should almost always be printed out?
 *
 *  In the first case, you will call the output function using a verbosity
 *  level of VB_0 or higher. Calls that specify VB_0 are printed by default
 *  as VB_0 is the base verbosity level. Calls that specify VB_1 get printed
 *  only when the user has incremented verbosity level by at least one using
 *  option "-v". Same with VB_2 for which the users needs to have specified
 *  either "-v2" or "-v -v".
 *
 *  In the other case, where you are printing errors etc, you have supply
 *  levels like QT_1, QT_2, QT_3 or QT_4. Those are called quiet levels.
 *  They are called quiet levels from a user point of view but they are
 *  verbose to us, programmers, because calls that supply QT_X levels almost
 *  always get printed. This is because base verbosity is VB_0 and that
 *  includes all QT_X levels. So you have to be careful with those. QT_ levels
 *  should only be used to print important stuff like fatal errors, warnings,
 *  and some basic running time information. Level QT_4 is the quiet-est one
 *  and nothing is ever printed out.
 *
 *  Check the comments after each level definition to see how they should be
 *  used. Here are some examples:
 * 
 *  nping_fatal(QT_3,"createIPv4(): NULL pointer supplied.");
 *  nping_print(DBG_2,"Resolving specified targets...");
 *  nping_print(VB_0, "Raw packets sent: %llu ", this->stats.getSentPackets() );
 *
 * */

/* Less verbosity */
#define QT_4 0   /**< No output at all                                       */
#define QT_3 1   /**< Fatal error messages, help info, version number        */
#define QT_2 2   /**< Warnings and very limited output(just some statistics) */
#define QT_1 3   /**< Start and timing information but no sent/recv packets  */

/* Base level (QT_0 is provided for consistency but should not be used)      */
#define QT_0 4   /**< Normal info (sent/recv packets, statistics...) (DEFAULT */
#define VB_0 4   /**< Normal info (sent/recv packets, statistics...) (DEFAULT)*/

/* More verbosity */
#define VB_1 5   /**< Detailed information about times, flags, etc.          */
#define VB_2 6   /**< Very detailed information about packets,               */
#define VB_3 7   /**< Reserved for future use                                */
#define VB_4 8   /**< Reserved for future use                                */



/* DEBUGGING LEVELS */
#define DBG_0 30 /**< No debug information at all (DEFAULT)                  */
#define DBG_1 31 /**< Very important or high level debug information         */
#define DBG_2 32 /**< Important or medium level debug information            */
#define DBG_3 33 /**< Regular and low level debug information                */
#define DBG_4 34 /**< Messages only a real Nping freak would want to see     */
#define DBG_5 35 /**< Enables Nsock (and other libs) basic tracing           */
#define DBG_6 36 /**< Enables full Nsock (and other libs) tracing            */
#define DBG_7 37 /**< Reserved for future use                                */
#define DBG_8 38 /**< Reserved for future use                                */
#define DBG_9 39 /**< Reserved for future use                                */


#define MAX_IP_PACKET_LEN 65535   /**< Max len of an IP datagram             */
#define MAX_UDP_PAYLOAD_LEN 65507 /**< Check comments in UDPHeader::setSum() */

#define MAX_DEV_LEN 128           /**< Max network interface name length     */

#define NO_NEWLINE 0x8000 /**< Used in nping_fatal(), nping_warning() and nping_print() */

/** Bit count for number parsing functions */
#define RANGE_8_BITS  8
#define RANGE_16_BITS 16
#define RANGE_32_BITS 32
#define RANGE_64_BITS 64

/* Crypto Lengths */
#define CIPHER_BLOCK_SIZE (128/8)
#define CIPHER_KEY_LEN (128/8)
#define MAC_KEY_LEN (128/8)

/* General tunable defines  **************************************************/
#define NPING_NAME "Nping"
#define NPING_URL "https://nmap.org/nping"
#define NPING_VERSION "0.7.94"


#define DEFAULT_VERBOSITY VB_0
#define DEFAULT_DEBUGGING DBG_0


/**< Default number of probes that are sent to each target */
#define DEFAULT_PACKET_COUNT 5          

/* When doing traceroute, the number of packets sent to each host must be
 * higher because 5 is probably not enough to reach the average target on the
 * Internet. The following paper suggests that internet hosts are no more than
 * 30 hops apart, so setting the packet count to 48 when --traceroute is set
 * seems like a safe choice.
 *    Cheng, J., Haining, W. and Kang, GS. (2006). Hop-Count Filtering: An
 *    Effective Defense Against Spoofed DDoS Traffic. Australian Telecommu-
 *    nication Networks & Applications Conference (ATNAC). Australia.
 *    <http://portal.acm.org/citation.cfm?id=948109.948116>
 */
#define TRACEROUTE_PACKET_COUNT 48

#define DEFAULT_DELAY 1000              /**< Milliseconds between each probe */

 /** Milliseconds Nping waits for replies after all probes have been sent */
#define DEFAULT_WAIT_AFTER_PROBES 1000 

#define DEFAULT_IP_TTL 64               /**< Default IP Time To Live         */
#define DEFAULT_IP_TOS 0                /**< Default IP Type of Service      */

#define DEFAULT_IPv6_TTL 64             /**< Default IPv6 Hop Limit          */
#define DEFAULT_IPv6_TRAFFIC_CLASS 0x00 /**< Default IPv6 Traffic Class      */


#define DEFAULT_TCP_TARGET_PORT 80      /**< Default TCP target port         */
#define DEFAULT_UDP_TARGET_PORT 40125   /**< Default UDP target port         */
#define DEFAULT_UDP_SOURCE_PORT 53      /**< Default UDP source port         */
#define DEFAULT_TCP_WINDOW_SIZE 1480    /**< Default TCP Window size         */

/**< MTU used when user just supplies option -f but no MTU value */
#define DEFAULT_MTU_FOR_FRAGMENTATION 72   

#define DEFAULT_ICMP_TYPE 8  /**< Default ICMP message: Echo Request         */
#define DEFAULT_ICMP_CODE 0  /**< Default ICMP code: 0 (standard)            */

#define DEFAULT_ICMPv6_TYPE 128 /**< Default ICMPv6 message: Echo Request    */
#define DEFAULT_ICMPv6_CODE 0   /**< Default ICMPv6 code: 0 (standard)       */

#define DEFAULT_ARP_OP 1   /**< Default ARP operation: OP_ARP_REQUEST      */

/* WARNING: This is the max length for UDP and TCP payloads. Whatever you set
 * here, it cannot exceed the worst case:
 * 65535 bytes - IPv6Header with options - TCP  Header with options. */
#define MAX_PAYLOAD_ALLOWED 65400

/* I've tested this on a GNU/Linux 2.6.24 and I've seen that if the length
 * of the whole IP packet is more than 16436 when using loopback interface or
 * more than 1500 when using a normal network interface, the kernel complains
 * and says "Message too long". This is obviously caused by the configured
 * MTU. So the thing is that although we allow users to specify payloads up to
 * MAX_PAYLOAD_ALLOWED bytes, when we generate random payloads, we set our
 * on limit on 1500-20-20=1460 bytes. Let's be conservative and consider that
 * IP packet has 40bytes of options and TCP has 20. So max length should be
 * 1500-60-40 = 1400. */
#define MAX_RANDOM_PAYLOAD  1400
#define MAX_RECOMMENDED_PAYLOAD 1400


/* Cached hosts in resolveChached() and gethostbynameCached() */
#define MAX_CACHED_HOSTS 512
#define MAX_CACHED_HOSTNAME_LEN 512

/* (9929 because is prime as has not been assigned by IANA yet) */
#define DEFAULT_ECHO_PORT 9929

/* The echo server tries to zero any application layer data before echoing
 * network packets. However, sometimes we may not be able to successfully
 * parse a given packet (decide whether the packet contains application data
 * or not), so this define specifies the amount of bytes of a packet that the
 * server does not zero in such case. 40 bytes allows IPv4+TCP, an IPv6 header,
 * an IPv4+UDP+12payload bytes, etc. In the case of UDP, the first 12 data bytes
 * would be leaked. However, we should be able to parse simple IPv4-UDP packets
 * without problem, so it should never happen. We expect to use this constant
 * when received packets are really weird (eg. tunneled traffic, protocols we
 * don't understand, etc. The 40 bytes are a compromise between dropping the
 * packet but provide total protection against data leakage due to attacks to
 * the echo server, and providing some flexibility at the risk of leaking
 * a few bytes if an attacker is able to trick the echo server into echoing
 * packets that were not originated by him. */
#define PAYLOAD_ECHO_BYTES_IN_DOUBT 40

#define NSOCK_INFINITE -1

/* Prototypes for nping.cc shared functions */
char *getBPFFilterString();

#endif
