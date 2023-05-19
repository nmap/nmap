/***************************************************************************
 * nbase_winunix.h -- Misc. compatibility routines that generally try to   *
 * reproduce UNIX-centric concepts on Windows.                             *
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

#ifndef NBASE_WINUNIX_H
#define NBASE_WINUNIX_H


#include "nbase_winconfig.h"

/* Winsock defines its own error codes that are analogous to but
   different from those in <errno.h>. The error macros have similar
   names, for example
     EINTR -> WSAEINTR
     ECONNREFUSED -> WSAECONNREFUSED
   But the values are different. The errno codes are small integers,
   while the Winsock codes start at 10000 or so.
   http://msdn.microsoft.com/en-us/library/ms737828

   Later in this file there is a block of code that defines the errno
   names to their Winsock equivalents, so that you can write code using
   the errno names only, and have it still work on Windows. However this
   causes some problems that are worked around in the following few
   lines. First, we prohibit the inclusion of <errno.h>, so that the
   only error codes visible are those we explicitly define in this file.
   This will cause a compilation error if someone uses a code we're not
   yet aware of instead of using an incompatible value at runtime.
   Second, because <errno.h> is not defined, the C++0x header
   <system_error> doesn't compile, so we pretend not to have C++0x to
   avoid it. */
#if _MSC_VER < 1600 /* Breaks on VS2010 and later */
#define _INC_ERRNO  /* suppress errno.h */
#define _ERRNO_H_ /* Also for errno.h suppression */
#define _SYSTEM_ERROR_
#undef _HAS_CPP0X
#define _HAS_CPP0X 0
#else
/* VS2013: we include errno.h, then redefine the constants we want.
 * This may work in other versions, but haven't tested (since the other method
 * has been working just fine). */
#include <errno.h>
#endif

/* Suppress winsock.h */
#define _WINSOCKAPI_
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* IPv6 stuff */
#if HAVE_WSPIAPI_H
/* <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
   available on some platforms like MinGW. */
#include <wspiapi.h>
#endif
#include <time.h>
#include <iptypes.h>
#include <stdlib.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>
#include <limits.h>
#include <WINCRYPT.H>
#include <math.h>


#define SIOCGIFCONF     0x8912          /* get iface list */

#ifndef GLOBALS
#define GLOBALS 1

#endif

#define munmap(ptr, len) win32_munmap(ptr, len)

/* Windows error message names */
#undef  ECONNABORTED
#define ECONNABORTED    WSAECONNABORTED
#undef ECONNRESET
#define ECONNRESET      WSAECONNRESET
#undef ECONNREFUSED
#define ECONNREFUSED    WSAECONNREFUSED
#undef  EAGAIN
#define EAGAIN		WSAEWOULDBLOCK
#undef EWOULDBLOCK
#define EWOULDBLOCK	WSAEWOULDBLOCK
#undef EHOSTUNREACH
#define EHOSTUNREACH	WSAEHOSTUNREACH
#undef ENETDOWN
#define ENETDOWN	WSAENETDOWN
#undef ENETUNREACH
#define ENETUNREACH	WSAENETUNREACH
#undef ENETRESET
#define ENETRESET	WSAENETRESET
#undef ETIMEDOUT
#define ETIMEDOUT	WSAETIMEDOUT
#undef EHOSTDOWN
#define EHOSTDOWN	WSAEHOSTDOWN
#undef EINPROGRESS
#define EINPROGRESS	WSAEINPROGRESS
#undef  EINVAL
#define EINVAL          WSAEINVAL      /* Invalid argument */
#undef  EPERM
#define EPERM           WSAEACCES      /* Operation not permitted */
#undef  EACCES
#define EACCES          WSAEACCES     /* Operation not permitted */
#undef  EINTR
#define EINTR           WSAEINTR      /* Interrupted system call */
#undef ENOBUFS
#define ENOBUFS         WSAENOBUFS     /* No buffer space available */
#undef EMSGSIZE
#define EMSGSIZE        WSAEMSGSIZE    /* Message too long */
#undef  ENOMEM
#define ENOMEM          WSAENOBUFS
#undef  ENOTSOCK
#define ENOTSOCK        WSAENOTSOCK
#undef  EOPNOTSUPP
#define EOPNOTSUPP      WSAEOPNOTSUPP
#undef  EIO
#define EIO             WSASYSCALLFAILURE

/*
This is not used by our network code, and causes problems in programs using
Nbase that legitimately use ENOENT for file operations.
#undef  ENOENT
#define ENOENT          WSAENOENT
*/

#define close(x) closesocket(x)

typedef unsigned short u_short_t;

int win_stdin_start_thread(void);
int win_stdin_ready(void);

#endif /* NBASE_WINUNIX_H */
