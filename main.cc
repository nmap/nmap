
/***************************************************************************
 * main.cc -- Contains the main() function of Nmap.  Note that main()      *
 * does very little except for calling nmap_main() (which is in nmap.cc)   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
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
  if ( MiamiPCapBase ) CloseLibrary( MiamiPCapBase );
  if ( MiamiBPFBase  ) CloseLibrary(  MiamiBPFBase );
  if (  SocketBase   ) CloseLibrary(   SocketBase  );
  if (   MiamiBase   ) CloseLibrary(   MiamiBase   );
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

int main(int argc, char *argv[]) {
  /* The "real" main is nmap_main().  This function hijacks control at the
     beginning to do the following:
     1) Check if Nmap was called with --interactive.
     2) Start interactive mode or just call nmap_main
  */
  char command[2048];
  int myargc, fakeargc;
  char **myargv = NULL, **fakeargv = NULL;
  char *cptr;
  int ret;
  int i;
  char nmapargs[1024];
  char fakeargs[1024];
  char nmappath[MAXPATHLEN];
  char *pptr;
  char path[4096];
  struct stat st;
  char *endptr;
  int interactivemode = 0;
  int fd;
  int arglen = 0;

#ifdef __amigaos__
	if(!OpenLibs()) {
		printf("Couldn't open TCP/IP Stack Library(s)!\n");
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

  /* Trap these sigs for cleanup */
#if HAVE_SIGNAL
  signal(SIGINT, sigdie);
  signal(SIGTERM, sigdie);
#ifndef WIN32
  signal(SIGHUP, sigdie); 
  signal(SIGCHLD, reaper);
#endif
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
      fatal("NMAP_ARG variable could not be parsed");
    }
    ret = nmap_main(myargc, myargv);
    arg_parse_free(myargv);
    return ret;
  }

  if (interactivemode == 0 &&
      argc == 2 && strcmp("--interactive", argv[1]) == 0) {
    interactivemode = 1;
  }

  if (!interactivemode) {
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

  printf("\nStarting %s V. %s ( %s )\n", NMAP_NAME, NMAP_VERSION, NMAP_URL);

  printf("Welcome to Interactive Mode -- press h <enter> for help\n");

  while(1) {
    printf("nmap> ");
    fflush(stdout);
    if (fgets(command, sizeof(command), stdin) == NULL && feof(stdin)) {
      fatal("EOF reached -- quitting");
    }
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      printf("Bogus command -- press h <enter> for help\n");
      continue;
    }
    if (strcasecmp(myargv[0], "h") == 0 ||
	strcasecmp(myargv[0], "help") == 0) {
      printinteractiveusage();
      continue;
    } else if (strcasecmp(myargv[0], "x") == 0 ||
	       strcasecmp(myargv[0], "q") == 0 ||
	       strcasecmp(myargv[0], "e") == 0 ||
	       strcasecmp(myargv[0], ".") == 0 ||
	       strcasecmp(myargv[0], "exit") == 0 ||
	       strcasecmp(myargv[0], "quit") == 0) {
      printf("Quitting by request.\n");
      exit(0);
    } else if (strcasecmp(myargv[0], "n") == 0 ||
	       strcasecmp(myargv[0], "nmap") == 0) {
      o.ReInit();
      o.interactivemode = 1;
      nmap_main(myargc, myargv);
    } else if (*myargv[0] == '!') {
      cptr = strchr(command, '!');
      int rc = system(cptr + 1);
      if (rc < 1) printf("system() execution of command failed\n");
    } else if (*myargv[0] == 'd') {
      o.debugging++;
    } else if (strcasecmp(myargv[0], "f") == 0) {
      switch((ret = fork())) {
      case 0: /* Child */
	/* My job is as follows:
	   1) Go through arguments for the following 3 purposes:
	   A.  Build env variable nmap execution will read args from
	   B.  Find spoof and realpath variables
	   C.  If realpath var was not set, find an Nmap to use
	   2) Exec the sucka!@#$! 
	*/
	fakeargs[0] = nmappath[0] = '\0';
	strcpy(nmapargs, "NMAP_ARGS=");
	for(i=1; i < myargc; i++) {
	  if (strcasecmp(myargv[i], "--spoof") == 0) {
	    if (++i > myargc -1) {
	      fatal("Bad arguments to f!");
	    }	    
	    strncpy(fakeargs, myargv[i], sizeof(fakeargs));
	  } else if (optcmp(myargv[i], "--nmap-path") == 0) {
	    if (++i > myargc -1) {
	      fatal("Bad arguments to f!");
	    }	    
	    strncpy(nmappath, myargv[i], sizeof(nmappath));
	  } else {
	    arglen = strlen(nmapargs);
	    if (arglen + strlen(myargv[i]) + 1 < sizeof(nmapargs)) {
	      strcat(nmapargs, " ");
	      strncat(nmapargs, myargv[i], arglen - 1);
	    } else fatal("Arguments too long.");
	  }	 
	}

	if (o.debugging) {
	  error("Adding to environment: %s", nmapargs);
	}
	if (putenv(nmapargs) == -1) {
	  pfatal("Failed to add NMAP_ARGS to environment");
	}
	/* Now we figure out where the #@$#@ Nmap is located */
	if (!*nmappath) {
	  if (stat(argv[0], &st) != -1 && !S_ISDIR(st.st_mode)) {
	    strncpy(nmappath, argv[0], sizeof(nmappath));
	  } else {
	    nmappath[0] = '\0';
	    /* Doh!  We must find it in path */
	    if ((pptr = getenv("PATH"))) {
	      Strncpy(path, pptr, sizeof(path));
	      pptr = path;
	      /* Get the name Nmap was called as. */
	      char *nmapcalledas = path_get_basename(argv[0]);
	      if (nmapcalledas == NULL)
		pfatal("Could not get nmap executable basename");
	      while(pptr && *pptr) {
		endptr = strchr(pptr, ':');
		if (endptr) { 
		  *endptr = '\0';
		}
		Snprintf(nmappath, sizeof(nmappath), "%s/%s", pptr, nmapcalledas);
		if (stat(nmappath, &st) != -1)
		  break;
		nmappath[0] = '\0';
		if (endptr) pptr = endptr + 1;
		else pptr = NULL;
	      }
	      free(nmapcalledas);
	    }
	  }
	}
	if (!*nmappath) {
	  fatal("Could not find Nmap -- you must add --nmap-path argument");
	}       

	/* We should be courteous and give Nmap reasonable signal defaults */
#if HAVE_SIGNAL
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
#ifndef WIN32
	signal(SIGHUP, SIG_DFL);
#endif
	signal(SIGSEGV, SIG_DFL);
#endif

	/* Now I must handle spoofery */
	if (*fakeargs) {
	  fakeargc = arg_parse(fakeargs, &fakeargv);
	  if (fakeargc < 1) {
	    fatal("Bogus --spoof parameter");
	  }
	} else {
	  fakeargc = 1;
	  fakeargv = (char **) safe_malloc(sizeof(char *) * 2);
	  fakeargv[0] = nmappath;
	  fakeargv[1] = NULL;
	}

	if (o.debugging) error("About to exec %s", nmappath);
	/* Kill stdout & stderr */
	if (!o.debugging) {
	  fd = open(DEVNULL, O_WRONLY);
	  if (fd != -1) {
	    dup2(fd, STDOUT_FILENO);
	    dup2(fd, STDERR_FILENO);
	  }
	}

	/* OK, I think we are finally ready for the big exec() */
	ret = execv(nmappath, fakeargv);
	if (ret == -1) {
	  pfatal("Could not exec %s", nmappath);
	}
	break;
      case -1:
	gh_perror("fork() failed");
	break;
      default: /* Parent */
	printf("[PID: %d]\n", ret);
	break;
      }
    } else {
      printf("Unknown command (%s) -- press h <enter> for help\n", myargv[0]);
      continue;
    }
    arg_parse_free(myargv);
  }
  return 0;

}
