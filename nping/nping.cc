
/***************************************************************************
 * Nping.cc -- This file contains function main() and some other general   *
 * high level functions.                                                   *
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

#ifdef WIN32
#include "winfix.h"
#endif

#include "nping.h"
#include "output.h"
#include "NpingOps.h"
#include "utils.h"
#include "utils_net.h"
#include "nsock.h"
#include "global_structures.h"
#include "ArgParser.h"
#include "EchoHeader.h"
#include "EchoClient.h"
#include "EchoServer.h"
#include "ProbeMode.h"
#include "common.h"
#include "dnet.h"
#include "pcap.h"
#include <signal.h>
#include <time.h>

NpingOps o;
EchoClient ec;
EchoServer es;

int do_safe_checks();
void test_stuff();
void signal_handler(int signo);


/** Main function. It basically inits Nping working environment, calls the
  * command-line argument parser, and enters the appropriate mode (normal
  * probe mode, echo client or echo server). */
int main(int argc, char *argv[] ){

  struct tm tm;    /* For time display                */
  int err;
  time_t now;       /* Stores current time             */
  char tbuf[128];   /* Stores current time as a string */
  ArgParser a;      /* Command line argument parser    */
  unsigned long int i=0;
  ProbeMode prob;
  NpingTarget *t=NULL;

  /* Get current time */
  tzset();
  now = time(NULL);
  err = n_localtime(&now, &tm);
  if (err)
    nping_fatal(QT_3,"Error in localtime: %s", strerror(err));
  o.stats.startRuntime();

  /* Some run-time tests to ensure everything works as expected */
  do_safe_checks();

  /* Init a few things on Windows */
  #ifdef WIN32
    win_pre_init();
  #endif

  /* Register the SIGINT signal so when the users presses CTRL-C we print stats
   * before quitting. */
  #if HAVE_SIGNAL
    signal(SIGINT, signal_handler); 
  #endif

  /* Let's parse and validate user supplied args */
  a.parseArguments(argc, argv);
  #ifdef WIN32
    // Must come after parseArguments because of --unprivileged
    // Must come before validateOptions because it sets o.isRoot
    win_init();
  #endif
  o.validateOptions();

  /* ISO 8601 date/time -- http://www.cl.cam.ac.uk/~mgk25/iso-time.html */
  if ( strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", &tm) <= 0)
    nping_fatal(QT_3,"Unable to properly format time");
  nping_print(QT_1, "\nStarting %s %s ( %s ) at %s", NPING_NAME, NPING_VERSION, NPING_URL, tbuf);

  /*If nping is called on something that doesn't take port scanning
   * we should alert the user that their port command is going to be ignored
   * I choose to print out a Fatal error since the scan doesn't make sense.
   */
  if(o.issetTargetPorts() && !o.scan_mode_uses_target_ports(o.getMode()))
      nping_fatal(QT_3, "You cannot use -p (explicit port selection) in your current scan mode.\n(Perhaps you meant to use --tcp or --udp)");



  /* Resolve and cache target specs */
  nping_print(DBG_2,"Resolving specified targets...");
  o.targets.processSpecs();
  if( ((i=o.targets.getTargetsFetched())<=0) && o.getRole()!=ROLE_SERVER )
    nping_fatal(QT_3, "Execution aborted. Nping needs at least one valid target to operate.");
  else
    nping_print(DBG_2,"%lu target IP address%s determined.", i, (i==1)? "":"es" );

  switch( o.getRole() ){

        case ROLE_NORMAL:
            prob.start();
            prob.cleanup();
        break;

        case ROLE_CLIENT:
            t=o.targets.getNextTarget();
            o.targets.rewind();
            ec.start(t, o.getEchoPort() );
            ec.cleanup();
        break;

        case ROLE_SERVER:
            o.stats.startClocks();
            es.start();
            // Cleanup currently does nothing, but needs to be called in case
            // it does something in the future.
            es.cleanup(); // lgtm [cpp/useless-expression]
            o.stats.stopClocks();
        break;

        default:
            nping_fatal(QT_3, "Invalid role %d\n", o.getRole() );
        break;
  }

  /* Display stats, clean up and quit */ 
  o.stats.stopRuntime();
  o.displayStatistics();
  o.displayNpingDoneMsg();
  o.cleanup();
  exit(EXIT_SUCCESS);

  exit(EXIT_SUCCESS);
} /* End of main() */


/* Things that should be guaranteed by the compiler, standard library, OS etc,
 *  but that we check just in case... */
int do_safe_checks(){
 if( (sizeof(u32) != 4) || (sizeof(u16) != 2) || (sizeof(u8) != 1) )
    nping_fatal(QT_3,"Types u32, u16 and u8 do not have the correct sizes on your system.");
  test_stuff(); /* Little function that is called quite early to test some misc stuff. */
  return OP_SUCCESS;
} /* End of do_safe_checks() */



/** Use this function whenever you have some code that you want to test, but
  * you don't want to bother creating a new dummy main.c file, etc. This
  * function is called by do_safe_checks() at the beginning of nping execution.
  * Command line arguments have not been parsed yet so even if you run nping
  * with no arguments you will not get an error, and this function will be
  * called. You probably want to place an exit() call at the end of your
  * testing code so Nping does not actually continue its normal execution path
  * but exit after your tests.  */
void test_stuff(){
  return;
} /* End of test_stuff() */


/** This function is called whenever user presses CTRL-C. Basically what we
  * do here is stop Tx and Rx clocks, stop global clock, display statistics,
  * do a bit of cleanup and exit the program. The exit() call makes the
  * program return EXIT_FAILURE instead of the usual EXIT_SUCCESS.
  *
  * TODO: Many of the things done in this function may not be safe due to
  * reentrancy issues. Check http://seclists.org/nmap-dev/2009/q3/0596.html
  * and http://seclists.org/nmap-dev/2009/q3/0596.html */
void signal_handler(int signo){
  fflush(stdout);
  nping_print(DBG_1,"signal_handler(): Received signal %d", signo);
  switch(signo) {
      case SIGINT:
        o.stats.stopTxClock();
        o.stats.stopRxClock();
        o.stats.stopRuntime();
        o.displayStatistics();
        o.displayNpingDoneMsg();
        o.cleanup();
        fflush(stderr);
        exit(EXIT_FAILURE);
      break;

      default:
        nping_warning(QT_2, "signal_handler(): Unexpected signal received (%d). Please report a bug.", signo);
      break;
  }
  fflush(stderr);
  exit(EXIT_FAILURE);
} /* End of signal_handler() */
