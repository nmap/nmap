/***************************************************************************
 * nbase_winconfig.h -- Since the Windows port is currently eschewing      *
 * autoconf-style configure scripts, nbase_winconfig.h contains the        *
 * platform-specific definitions for Windows and is used as a replacement  *
 * for nbase_config.h                                                      *
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

/* $Id$ */

#ifndef NBASE_WINCONFIG_H
#define NBASE_WINCONFIG_H

/* Define the earliest version of Windows we support.  These control
what parts of the Windows API are available. The available constants
are in <sdkddkver.h>.
http://msdn.microsoft.com/en-us/library/aa383745.aspx
http://blogs.msdn.com/oldnewthing/archive/2007/04/11/2079137.aspx */
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7

//This disables the warning 4800 http://msdn.microsoft.com/en-us/library/b6801kcy(v=vs.71).aspx
#pragma warning(disable : 4800)
/* It doesn't really have struct IP, but we use a different one instead
   of the one that comes with Nmap */
#define HAVE_STRUCT_IP 1
/* #define HAVE_STRUCT_ICMP 1 */
#define HAVE_STRNCASECMP 1
#define HAVE_IP_IP_SUM 1
#define STDC_HEADERS 1
#define HAVE_STRING_H 1
#define HAVE_MEMORY_H 1
#define HAVE_FCNTL_H 1
#define HAVE_ERRNO_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_MEMCPY 1
#define HAVE_STRERROR 1
/* #define HAVE_SYS_SOCKIO_H 1 */
/* #undef HAVE_TERMIOS_H */
#define HAVE_ERRNO_H 1
#define HAVE_GAI_STRERROR 1
/* #define HAVE_STRCASESTR 1 */
#define HAVE_STRCASECMP 1
#define HAVE_NETINET_IF_ETHER_H 1
#define HAVE_SYS_STAT_H 1
/* #define HAVE_INTTYPES_H */

/* These functions are available on Vista and later */
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= _WIN32_WINNT_WIN6
#define HAVE_INET_PTON 1
#define HAVE_INET_NTOP 1
#endif

#ifdef _MSC_VER
/* <wspiapi.h> only comes with Visual Studio. */
#define HAVE_WSPIAPI_H 1
#else
#undef HAVE_WSPIAPI_H
#endif

#define HAVE_GETADDRINFO 1
#define HAVE_GETNAMEINFO 1

#define HAVE_SNPRINTF 1
// #undef HAVE_VASPRINTF
#define HAVE_VSNPRINTF 1

typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef signed __int8 int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;

#define HAVE_IPV6 1
#define HAVE_AF_INET6 1
#define HAVE_SOCKADDR_STORAGE 1

/* Without these, Windows will give us all sorts of crap about using functions
   like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif
#pragma warning(disable: 4996)

#ifdef __GNUC__
#define bzero(addr, num) __builtin_memset (addr, '\0', num)
#else
#define __attribute__(x)
#endif

#define HAVE_OPENSSL 1
#define HAVE_DTLS_CLIENT_METHOD 1
#define HAVE_SSL_SET_TLSEXT_HOST_NAME 1
/* Apparently __func__ isn't yet supported */
#define __func__ __FUNCTION__

#endif /* NBASE_WINCONFIG_H */
