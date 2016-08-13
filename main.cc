
/***************************************************************************
 * main.cc -- Contains the main() function of Nmap.  Note that main()      *
 * does very little except for calling nmap_main() (which is in nmap.cc)   *
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

#include <signal.h>

#include "nmap.h"
#include "NmapOps.h"
#include "utils.h"

#ifdef MTRACE
#include "mcheck.h"
#endif

#ifdef __amigaos__
#include <proto/exec.h>
#include <proto/dos.h>
#include "nmap_amigaos.h"
struct Library *SocketBase = NULL, *MiamiBase = NULL, *MiamiBPFBase = NULL, *MiamiPCapBase = NULL;
static const char ver[] = "$VER:" NMAP_NAME " v"NMAP_VERSION " [Amiga.sf]";

static void CloseLibs(void) {
  if (MiamiPCapBase ) CloseLibrary( MiamiPCapBase );
  if (MiamiBPFBase  ) CloseLibrary(  MiamiBPFBase );
  if ( SocketBase   ) CloseLibrary(   SocketBase  );
  if (  MiamiBase   ) CloseLibrary(   MiamiBase   );
}

static BOOL OpenLibs(void) {
 if(!(    MiamiBase = OpenLibrary(MIAMINAME,21))) return FALSE;
 if(!(   SocketBase = OpenLibrary("bsdsocket.library", 4))) return FALSE;
 if(!( MiamiBPFBase = OpenLibrary(MIAMIBPFNAME,3))) return FALSE;
 if(!(MiamiPCapBase = OpenLibrary(MIAMIPCAPNAME,5))) return FALSE;
 atexit(CloseLibs);
 return TRUE;
}
#endif

/* global options */
extern NmapOps o;  /* option structure */

extern void set_program_name(const char *name);

int main(int argc, char *argv[]) {
  /* The "real" main is nmap_main().  This function hijacks control at the
     beginning to do the following:
     1) Check the environment variable NMAP_ARGS.
     2) Check if Nmap was called with --resume.
     3) Resume a previous scan or just call nmap_main.
  */
  char command[2048];
  int myargc;
  char **myargv = NULL;
  char *cptr;
  int ret;
  int i;

  set_program_name(argv[0]);

#ifdef __amigaos__
        if(!OpenLibs()) {
                error("Couldn't open TCP/IP Stack Library(s)!");
                exit(20);
        }
        MiamiBPFInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
        MiamiPCapInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
#endif

#ifdef MTRACE
  // This glibc extension enables memory tracing to detect memory
  // leaks, frees of unallocated memory, etc.
  // See http://www.gnu.org/manual/glibc-2.2.5/html_node/Allocation-Debugging.html#Allocation%20Debugging .
  // It only works if the environment variable MALLOC_TRACE is set to a file
  // which a memory usage log will be written to.  After the program quits
  // I can analyze the log via the command 'mtrace [binaryiran] [logfile]'
  // MTRACE should only be defined during debug sessions.
  mtrace();
#endif

  if ((cptr = getenv("NMAP_ARGS"))) {
    if (Snprintf(command, sizeof(command), "nmap %s", cptr) >= (int) sizeof(command)) {
        error("Warning: NMAP_ARGS variable is too long, truncated");
    }
    /* copy rest of command-line arguments */
    for (i = 1; i < argc && strlen(command) + strlen(argv[i]) + 1 < sizeof(command); i++) {
      strcat(command, " ");
      strcat(command, argv[i]);
    }
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      fatal("NMAP_ARGS variable could not be parsed");
    }
    ret = nmap_main(myargc, myargv);
    arg_parse_free(myargv);
    return ret;
  }

  if (argc == 3 && strcmp("--resume", argv[1]) == 0) {
    /* OK, they want to resume an aborted scan given the log file specified.
       Lets gather our state from the log file */
    if (gather_logfile_resumption_state(argv[2], &myargc, &myargv) == -1) {
      fatal("Cannot resume from (supposed) log file %s", argv[2]);
    }
    return nmap_main(myargc, myargv);
  }

  return nmap_main(argc, argv);
}
