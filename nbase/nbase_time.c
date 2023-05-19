
/***************************************************************************
 * nbase_time.c -- Some small time-related utility/compatibility           *
 * functions.                                                              *
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

#include "nbase.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#ifdef WIN32
#include <sys/timeb.h>
#include <winsock2.h>
#endif

#ifndef HAVE_USLEEP
void usleep(unsigned long usec) {
#ifdef HAVE_NANOSLEEP
struct timespec ts;
ts.tv_sec = usec / 1000000;
ts.tv_nsec = (usec % 1000000) * 1000;
nanosleep(&ts, NULL);
#else /* Windows style */
 Sleep( usec / 1000 );
#endif /* HAVE_NANOSLEEP */
}
#endif

/* Thread safe time stuff */
#ifdef WIN32
/* On Windows, use CRT function localtime_s:
 * errno_t localtime_s(
 *    struct tm* const tmDest,
 *       time_t const* const sourceTime
 *       );
 */
int n_localtime(const time_t *timer, struct tm *result) {
  return localtime_s(result, timer);
}

int n_gmtime(const time_t *timer, struct tm *result) {
  return gmtime_s(result, timer);
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer) {
  return ctime_s(buffer, bufsz, timer);
}

#else /* WIN32 */

#include <errno.h>
#ifdef HAVE_LOCALTIME_S
/* C11 localtime_s similar to Posix localtime_r, but with validity checking:
 * struct tm *localtime_s(const time_t *restrict time, struct tm *restrict result);
 */
int n_localtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = localtime_s(timer, result);
  if (!tmp) {
    return errno;
  }
  return 0;
}

int n_gmtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = gmtime_s(timer, result);
  if (!tmp) {
    return errno;
  }
  return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer) {
  return ctime_s(buffer, bufsz, timer);
}
#else
#ifdef HAVE_LOCALTIME_R
/* POSIX localtime_r thread-safe localtime function:
 * struct tm *localtime_r(const time_t *timep, struct tm *result);
 */
int n_localtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = localtime_r(timer, result);
  if (!tmp) {
    return errno;
  }
  return 0;
}

int n_gmtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = gmtime_r(timer, result);
  if (!tmp) {
    return errno;
  }
  return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer) {
  char *tmp = ctime_r(timer, buffer);
  if (!tmp) {
    return errno;
  }
  return 0;
}

#else
/* No thread-safe alternatives. */
// Using C99's one-line commments since LGTM.com does not recognize C-style
// block comments. This may cause problems, but only for very old systems
// without a C99-compatible compiler that do not have localtime_r or
// localtime_s
int n_localtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = localtime(timer); // lgtm[cpp/potentially-dangerous-function]
  if (tmp)
    *result = *tmp;
  else
    return errno;
  return 0;
}

int n_gmtime(const time_t *timer, struct tm *result) {
  struct tm *tmp = gmtime(timer); // lgtm[cpp/potentially-dangerous-function]
  if (tmp)
    *result = *tmp;
  else
    return errno;
  return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer) {
  char *tmp = ctime(timer); // lgtm[cpp/potentially-dangerous-function]
  if (tmp)
    Strncpy(buffer, tmp, bufsz);
  else
    return errno;
  return 0;
}
#endif /* HAVE_LOCALTIME_R */
#endif /* HAVE_LOCALTIME_S */
#endif /* WIN32 */

#ifdef WIN32
int gettimeofday(struct timeval *tv, struct timeval *tz)
{
  struct _timeb timebuffer;

  _ftime( &timebuffer );

  tv->tv_sec = (long) timebuffer.time;
  tv->tv_usec = timebuffer.millitm * 1000;
  return 0;
};

unsigned int sleep(unsigned int seconds)
{
  Sleep(1000*seconds);
  return(0);
};
#endif /* WIN32 */

