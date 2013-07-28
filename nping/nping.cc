
/***************************************************************************
 * Nping.cc -- This file contains function main() and some other general   *
 * high level functions.                                                   *
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
#ifdef WIN32
#include "winfix.h"
#endif
using namespace std;
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

  struct tm *tm;    /* For time display                */
  time_t now;       /* Stores current time             */
  char tbuf[128];   /* Stores current time as a string */
  ArgParser a;      /* Command line argument parser    */
  unsigned long int i=0;
  ProbeMode prob;
  NpingTarget *t=NULL;

  /* Get current time */
  now = time(NULL);
  tm = localtime(&now);
  o.stats.startRuntime();

  /* Some run-time tests to ensure everything works as expected */
  do_safe_checks();

  /* Init a few things on Windows */
  #ifdef WIN32
    win_pre_init();
    win_init();
  #endif

  /* Register the SIGINT signal so when the users presses CTRL-C we print stats
   * before quitting. */
  #if HAVE_SIGNAL
    signal(SIGINT, signal_handler); 
  #endif

  /* Let's parse and validate user supplied args */
  a.parseArguments(argc, argv);
  o.validateOptions();

  /* ISO 8601 date/time -- http://www.cl.cam.ac.uk/~mgk25/iso-time.html */
  if ( strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
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
            es.cleanup();
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
