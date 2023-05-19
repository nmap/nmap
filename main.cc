
/***************************************************************************
 * main.cc -- Contains the main() function of Nmap.  Note that main()      *
 * does very little except for calling nmap_main() (which is in nmap.cc)   *
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

#include <signal.h>
#include <locale.h>

#include "nmap.h"
#include "NmapOps.h"
#include "utils.h"
#include "nmap_error.h"

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

  o.locale = strdup(setlocale(LC_CTYPE, NULL));
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
    o.resuming = true;
    return nmap_main(myargc, myargv);
  }

  return nmap_main(argc, argv);
}
