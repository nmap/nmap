/***************************************************************************
 * nsock_log.c -- nsock logging infrastructure.                            *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2016 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
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
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                           *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


#ifndef NSOCK_LOG_H
#define NSOCK_LOG_H

#include "nsock.h"

extern nsock_loglevel_t NsockLogLevel;
extern nsock_logger_t   NsockLogger;


#define NSOCK_LOG_WRAP(lvl, ...)  \
    do { \
        if (NsockLogger && (lvl) >= NsockLogLevel) { \
            __nsock_log_internal((lvl), __FILE__, __LINE__, __func__, __VA_ARGS__); \
        } \
    } while (0)


static inline const char *nsock_loglevel2str(nsock_loglevel_t level)
{
  switch (level) {
    case NSOCK_LOG_DBG_ALL:
      return "FULL DEBUG";
    case NSOCK_LOG_DBG:
      return "DEBUG";
    case NSOCK_LOG_INFO:
      return "INFO";
    case NSOCK_LOG_ERROR:
      return "ERROR";
    default:
      return "???";
  }
}

/* -- Internal logging macros -- */
/**
 * Most detailed debug messages, like allocating or moving objects.
 */
#define nsock_log_debug_all(...) NSOCK_LOG_WRAP(NSOCK_LOG_DBG_ALL, __VA_ARGS__)

/**
 * Detailed debug messages, describing internal operations.
 */
#define nsock_log_debug(...)     NSOCK_LOG_WRAP(NSOCK_LOG_DBG, __VA_ARGS__)

/**
 * High level debug messages, describing top level operations and external
 * requests.
 */
#define nsock_log_info(...)      NSOCK_LOG_WRAP(NSOCK_LOG_INFO, __VA_ARGS__)

/**
 * Error messages.
 */
#define nsock_log_error(...)     NSOCK_LOG_WRAP(NSOCK_LOG_ERROR, __VA_ARGS__)


void __nsock_log_internal(nsock_loglevel_t loglevel, const char *file, int line,
                          const char *func, const char *format, ...)
                          __attribute__((format (printf, 5, 6)));

#endif /* NSOCK_LOG_H */

