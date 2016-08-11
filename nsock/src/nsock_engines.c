/***************************************************************************
 * nsock_engines.c -- This contains the functions and definitions to       *
 * manage the list of available IO engines.  Each IO engine leverages a    *
 * specific IO notification function to wait for events.  Nsock will try   *
 * to use the most efficient engine for your system.                       *
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

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#endif

#include "nsock_internal.h"

#if HAVE_EPOLL
  extern struct io_engine engine_epoll;
  #define ENGINE_EPOLL &engine_epoll,
#else
  #define ENGINE_EPOLL
#endif /* HAVE_EPOLL */

#if HAVE_KQUEUE
  extern struct io_engine engine_kqueue;
  #define ENGINE_KQUEUE &engine_kqueue,
#else
  #define ENGINE_KQUEUE
#endif /* HAVE_KQUEUE */

#if HAVE_POLL
  extern struct io_engine engine_poll;
  #define ENGINE_POLL &engine_poll,
#else
  #define ENGINE_POLL
#endif /* HAVE_POLL */

/* select() based engine is the fallback engine, we assume it's always available */
extern struct io_engine engine_select;
#define ENGINE_SELECT &engine_select,

/* Available IO engines. This depends on which IO management interfaces are
 * available on your system. Engines must be sorted by order of preference */
static struct io_engine *available_engines[] = {
  ENGINE_EPOLL
  ENGINE_KQUEUE
  ENGINE_POLL
  ENGINE_SELECT
  NULL
};

static char *engine_hint;


struct io_engine *get_io_engine(void) {
  struct io_engine *engine = NULL;
  int i;

  if (!engine_hint) {
    engine = available_engines[0];
  } else {
    for (i = 0; available_engines[i] != NULL; i++)
      if (strcmp(engine_hint, available_engines[i]->name) == 0) {
        engine = available_engines[i];
        break;
      }
  }

  if (!engine)
    fatal("No suitable IO engine found! (%s)\n",
          engine_hint ? engine_hint : "no hint");

  return engine;
}

int nsock_set_default_engine(char *engine) {
  if (engine_hint)
    free(engine_hint);

  if (engine) {
    int i;

    for (i = 0; available_engines[i] != NULL; i++) {
      if (strcmp(engine, available_engines[i]->name) == 0) {
        engine_hint = strdup(engine);
        return 0;
      }
    }
    return -1;
  }
  /* having engine = NULL is fine. This is actually the
   * way to tell nsock to use the default engine again. */
  engine_hint = NULL;
  return 0;
}

const char *nsock_list_engines(void) {
  return
#if HAVE_EPOLL
  "epoll "
#endif
#if HAVE_KQUEUE
  "kqueue "
#endif
#if HAVE_POLL
  "poll "
#endif
  "select";
}

