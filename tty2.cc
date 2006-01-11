#ifndef WIN32
#include "config.h"
#endif

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

#ifdef WIN32
// We currently just have stub functions for Win32 that don't actually
// do anything.  Any volunteers to add real support?
void tty_init() { return; }
bool keyWasPressed() { return false; }
void tty_done() { return; }

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

#include "output.h"
#include "tty.h"
#include "NmapOps.h"

extern NmapOps o;


static int tty_fd = 0;
static struct termios saved_ti;

void tty_init()
{
	int fd;
	struct termios ti;

	if ((fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0) return;

#ifndef __CYGWIN32__
	if (tcgetpgrp(fd) != getpid()) {
		close(fd); return;
	}
#endif

	tcgetattr(fd, &ti);
	if (tty_fd == 0)
	  saved_ti = ti;
	ti.c_lflag &= ~(ICANON | ECHO);
	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;
	tcsetattr(fd, TCSANOW, &ti);

	if (tty_fd == 0) 
	  tty_fd = fd;
	
	atexit(tty_done);
}

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

/* This is the best method here. It will catch all of the predefined keypresses and interpret them, and it will also tell you if you should print anything. A value of true being returned means a nonstandard key has been pressed and the calling method should print a status message */
bool keyWasPressed()
{
  int c;
  
  if ((c = tty_getchar()) >= 0) {
    // Eat any extra keys (so they can't queue up and print forever)
    while (tty_getchar() >= 0); 

    // printf("You pressed key '%c'!\n", c);
    if (c == 'v') {
       o.verbose++;
       log_write(LOG_STDOUT, "Verbosity Increased to %d.\n", o.verbose);
    } else if (c == 'V') {
       o.verbose--;
       log_write(LOG_STDOUT, "Verbosity Decreased to %d.\n", o.verbose);
    } else if (c == 'd') {
       o.debugging++;
       log_write(LOG_STDOUT, "Debugging Increased to %d.\n", o.debugging);
    } else if (c == 'D') {
       o.debugging--;
       log_write(LOG_STDOUT, "Debugging Decreased to %d.\n", o.debugging);
    } else if (c == 'p') {
       o.setPacketTrace(true);
       log_write(LOG_STDOUT, "Packet Tracing enabled\n.");
    } else if (c == 'P') {
       o.setPacketTrace(false);
       log_write(LOG_STDOUT, "Packet Tracing disabled\n.");
    } else {
       printStatusMessage();
       return true;
    }
  }
  return false;
}

void tty_done()
{
	int fd;

	if (!tty_fd) return;

	fd = tty_fd; tty_fd = 0;
	tcsetattr(fd, TCSANOW, &saved_ti);

	close(fd);
}

#endif  //!win32
