/***************************************************************************
 * nmap_tty.cc -- Handles runtime interaction with Nmap, so you can        *
 * increase verbosity/debugging or obtain a status line upon request.      *
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

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "nmap_tty.h"
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

#else  //!win32
#include <signal.h>
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

        if (tty_fd && tcgetpgrp(tty_fd) == getpgrp()) {

        // This is so that when the terminal has been disconnected, it will be
        // reconnected when possible. If it slows things down, just remove it
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

static void install_handler(int signo, void (*handler) (int signo))
{
        struct sigaction sa;
        sa.sa_handler = handler;
        sigfillset(&sa.sa_mask); /* block all signals during handler execution */
        sa.sa_flags = 0;
        sigaction(signo, &sa, NULL);
}

static void shutdown_clean(int signo)
{
        sigset_t set;

/* We reinstall the default handler and call tty_done */
        install_handler(signo, SIG_DFL);
        tty_done();

/* Unblock signo and raise it (thus allowing the default handler to occur) */
        sigemptyset(&set);
        sigaddset(&set, signo);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        raise(signo); /* This _should_ kill us */
        _exit(EXIT_FAILURE); /* If it does not */
}

static void install_all_handlers() {
        install_handler(SIGINT, shutdown_clean);
        install_handler(SIGTERM, shutdown_clean);
        install_handler(SIGQUIT, shutdown_clean);
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

        install_all_handlers();

        if (tty_fd)
                return;

        if ((tty_fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0) {
          o.noninteractive = true;
          return;
        }

#ifndef __CYGWIN32__
        if (tcgetpgrp(tty_fd) != getpgrp()) {
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
       if (o.verbose < 10) o.verbose++;
       log_write(LOG_STDOUT, "Verbosity Increased to %d.\n", o.verbose);
    } else if (c == 'V') {
       if (o.verbose > 0) o.verbose--;
       log_write(LOG_STDOUT, "Verbosity Decreased to %d.\n", o.verbose);
    } else if (c == 'd') {
       if (o.debugging < 10) o.debugging++;
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
                "More help: https://nmap.org/book/man-runtime-interaction.html\n");
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
      /* If it's still in the past, catch it up to the present,
       * plus half a second to avoid double-printing without any progress. */
      if (TIMEVAL_AFTER(now, stats_time))
        TIMEVAL_MSEC_ADD(stats_time, now, 500);
      printStatusMessage();
      /* Instruct the caller to print status too. */
      return true;
    }
  }

  return false;
}
