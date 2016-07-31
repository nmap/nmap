/***************************************************************************
 * nbase_winunix.h -- Misc. compatibility routines that generally try to   *
 * reproduce UNIX-centric concepts on Windows.                             *
 *                                                                         *
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
