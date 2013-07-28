/***************************************************************************
 * nmap_tty.cc -- Handles runtime interaction with Nmap, so you can        *
 * increase verbosity/debugging or obtain a status line upon request.      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

#ifndef WIN32
#include "nmap_config.h"
#endif

#include "nmap.h"

#include <sys/types.h>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_TERMIOS_H
#include <termios.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>

#include "nmap_tty.h"
#include "utils.h"
#include "NmapOps.h"

extern NmapOps o;

#ifdef WIN32
#include <conio.h>

// Microsoft's runtime makes this fairly simple. :)
void tty_init() { return; }
static int tty_getchar() { return _kbhit() ? _getch() : -1; }
static void tty_done() { return; }

static void tty_flush(void)
{
	static HANDLE stdinput = GetStdHandle(STD_INPUT_HANDLE);

	FlushConsoleInputBuffer(stdinput);
}

#else
#if !defined(O_NONBLOCK) && defined(O_NDELAY)
#define O_NONBLOCK			O_NDELAY
#endif

#ifdef __CYGWIN32__
#include <string.h>
#include <sys/socket.h>
#ifndef __CYGWIN__
extern int tcgetattr(int fd, struct termios *termios_p);
extern int tcsetattr(int fd, int actions, struct termios *termios_p);
#endif
#endif

static int tty_fd = 0;
static struct termios saved_ti;

static int tty_getchar()
{
	int c, numChars;
#ifdef __CYGWIN32__
	fd_set set;
	struct timeval tv;
#endif
        
	if (tty_fd && tcgetpgrp(tty_fd) == getpid()) {
           
           // This is so that when the terminal has been disconnected, it will be reconnected when possible. If it slows things down, just remove it
           // tty_init();
           
#ifdef __CYGWIN32__
		FD_ZERO(&set); FD_SET(tty_fd, &set);
		tv.tv_sec = 0; tv.tv_usec = 0;
		if (select(tty_fd + 1, &set, NULL, NULL, &tv) <= 0)
			return -1;
#endif
		c = 0;
                numChars = read(tty_fd, &c, 1);
		if (numChars > 0) return c;
	}

	return -1;
}

static void tty_done()
{
	if (!tty_fd) return;

	tcsetattr(tty_fd, TCSANOW, &saved_ti);

	close(tty_fd);
	tty_fd = 0;
}

static void tty_flush(void)
{
	/* we don't need to test for tty_fd==0 here because
	 * this isn't called unless we succeeded
	 */

	tcflush(tty_fd, TCIFLUSH);
}

/*
 * Initializes the terminal for unbuffered non-blocking input. Also
 * registers tty_done() via atexit().  You need to call this before
 * you ever call keyWasPressed().
 */
void tty_init()
{
	struct termios ti;

	if(o.noninteractive)
		return;

	if (tty_fd)
		return;

	if ((tty_fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0) return;

#ifndef __CYGWIN32__
	if (tcgetpgrp(tty_fd) != getpid()) {
		close(tty_fd); return;
	}
#endif

	tcgetattr(tty_fd, &ti);
	saved_ti = ti;
	ti.c_lflag &= ~(ICANON | ECHO);
	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;
	tcsetattr(tty_fd, TCSANOW, &ti);

	atexit(tty_done);
}

#endif  //!win32

/* Catches all of the predefined
   keypresses and interpret them, and it will also tell you if you
   should print anything. A value of true being returned means a
   nonstandard key has been pressed and the calling method should
   print a status message */
bool keyWasPressed()
{
  /* Where we keep the automatic stats printing schedule. */
  static struct timeval stats_time = { 0 };
  int c;

  if (o.noninteractive)
    return false;

  if ((c = tty_getchar()) >= 0) {
    tty_flush(); /* flush input queue */

    // printf("You pressed key '%c'!\n", c);
    if (c == 'v') {
       o.verbose++;
       log_write(LOG_STDOUT, "Verbosity Increased to %d.\n", o.verbose);
    } else if (c == 'V') {
       if (o.verbose > 0)
	 o.verbose--;
       log_write(LOG_STDOUT, "Verbosity Decreased to %d.\n", o.verbose);
    } else if (c == 'd') {
       o.debugging++;
       log_write(LOG_STDOUT, "Debugging Increased to %d.\n", o.debugging);
    } else if (c == 'D') {
       if (o.debugging > 0) o.debugging--;
       log_write(LOG_STDOUT, "Debugging Decreased to %d.\n", o.debugging);
    } else if (c == 'p') {
       o.setPacketTrace(true);
       log_write(LOG_STDOUT, "Packet Tracing enabled.\n");
    } else if (c == 'P') {
       o.setPacketTrace(false);
       log_write(LOG_STDOUT, "Packet Tracing disabled.\n");
    } else if (c == '?') {
      log_write(LOG_STDOUT,
		"Interactive keyboard commands:\n"
		"?               Display this information\n"
		"v/V             Increase/decrease verbosity\n"
		"d/D             Increase/decrease debugging\n"
		"p/P             Enable/disable packet tracing\n"
		"anything else   Print status\n"
                "More help: http://nmap.org/book/man-runtime-interaction.html\n");
    } else {
       printStatusMessage();
       return true;
    }
  }

  /* Check if we need to print a status update according to the --stats-every
     option. */
  if (o.stats_interval != 0.0) {
    struct timeval now;

    gettimeofday(&now, NULL);
    if (stats_time.tv_sec == 0) {
      /* Initialize the scheduled stats time. */
      stats_time = *o.getStartTime();
      TIMEVAL_ADD(stats_time, stats_time, (time_t) (o.stats_interval * 1000000));
    }

    if (TIMEVAL_AFTER(now, stats_time)) {
      /* Advance to the next print time. */
      TIMEVAL_ADD(stats_time, stats_time, (time_t) (o.stats_interval * 1000000));
      /* If it's still in the past, catch it up to the present. */
      if (TIMEVAL_AFTER(now, stats_time))
        stats_time = now;
      printStatusMessage();
      /* Instruct the caller to print status too. */
      return true;
    }
  }

  return false;
}
