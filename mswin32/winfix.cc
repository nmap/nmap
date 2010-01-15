
/***************************************************************************
 * winfix.cc -- A few trivial windows-compatabilty-related functions that  *
 * are specific to Nmap.  Most of this has been moved into nbase so it can *
 * be shared.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id: */

#include <winclude.h>
#include <sys/timeb.h>
#include <shellapi.h>


#include "..\nmap.h"
#include "..\tcpip.h"
#include "winfix.h"
#include "..\NmapOps.h"
#include "..\nmap_error.h"

#ifdef _MSC_VER
# include <delayimp.h>
#endif

#ifdef _MSC_VER
#define DLI_ERROR VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)
#endif

extern NmapOps o;

/*   internal functions   */
static void win_cleanup(void);
static char pcaplist[4096];

/* The code that has no preconditions to being called, so it can be
   executed before even Nmap options parsing (so o.debugging and the
   like don't need to be used.  Its main function is to do
   WSAStartup() as some of the option parsing code does DNS
   resolution */
void win_pre_init() {
	WORD werd;
	WSADATA data;

	werd = MAKEWORD( 2, 2 );
	if( (WSAStartup(werd, &data)) !=0 )
		fatal("failed to start winsock.\n");
}

/* Check if the NPF service is running on Windows, and try to start it if it's
   not. Return true if it was running or we were able to start it, false
   otherwise. */
static bool start_npf() {
  SC_HANDLE scm, npf;
  SERVICE_STATUS service;
  bool npf_running;
  int ret;

  scm = NULL;
  npf = NULL;

  scm = OpenSCManager(NULL, NULL, 0);
  if (scm == NULL) {
    error("Error in OpenSCManager");
    goto quit_error;
  }
  npf = OpenService(scm, "npf", SC_MANAGER_CONNECT | SERVICE_QUERY_STATUS);
  if (npf == NULL) {
    error("Error in OpenService");
    goto quit_error;
  }
  if (!QueryServiceStatus(npf, &service)) {
    error("Error in QueryServiceStatus");
    goto quit_error;
  }
  npf_running = (service.dwCurrentState & SERVICE_RUNNING) != 0;
  CloseServiceHandle(scm);
  CloseServiceHandle(npf);

  if (npf_running) {
    if (o.debugging > 1)
      log_write(LOG_PLAIN, "NPF service is already running.\n");
    return true;
  }

  /* NPF is not running. Try to start it. */

  if (o.debugging > 1)
    log_write(LOG_PLAIN, "NPF service is not running.\n");

  ret = (int) ShellExecute(0, "runas", "net.exe", "start npf", 0, SW_HIDE);
  if (ret <= 32) {
    error("Unable to start NPF service: ShellExecute returned %d.\n\
Resorting to unprivileged (non-administrator) mode.", ret);
    return false;
  }

  return true;

quit_error:
  if (scm != NULL)
    CloseHandle(scm);
  if (npf != NULL)
    CloseHandle(npf);

  return false;
}

/* Requires that win_pre_init() has already been called, also that
   options processing has been done so that o.debugging is
   available */
void win_init()
{
	//   variables
	DWORD cb = 0;
	DWORD nRes;
	OSVERSIONINFOEX ver;
	PMIB_IPADDRTABLE pIp = 0;
	int i;
	int numipsleft;


	ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(!GetVersionEx((LPOSVERSIONINFO)&ver))
	{
		ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if(!GetVersionEx((LPOSVERSIONINFO)&ver))
			fatal("GetVersionEx failed\n");

		ver.wServicePackMajor = 0;
		ver.wServicePackMinor = 0;
	}


	//   Try to initialize winpcap
#ifdef _MSC_VER
	__try
#endif
	{
		ULONG len = sizeof(pcaplist);

		o.have_pcap = true;
		if(o.debugging > 2) printf("***WinIP***  trying to initialize WinPcap\n");
		PacketGetAdapterNames(pcaplist, &len);

#ifdef _MSC_VER
		if(FAILED(__HrLoadAllImportsForDll("wpcap.dll")))
		{
			error("WARNING: your winpcap is too old to use.  Nmap may not function.\n");
			o.have_pcap = false;
		}
#endif
		if(o.debugging)
			printf("Winpcap present, dynamic linked to: %s\n", pcap_lib_version());

		/* o.is00t will be false at this point if the used asked for
		   --unprivileged. In that case don't bother them with a
		   potential UAC dialog when starting NPF. */
		if (o.isr00t)
			o.have_pcap = o.have_pcap && start_npf();
	}
#ifdef _MSC_VER
	__except (1) {
			error("WARNING: Could not import all necessary WinPcap functions.  You may need to upgrade to version 3.1 or higher from http://www.winpcap.org.  Resorting to connect() mode -- Nmap may not function completely");
		o.have_pcap=false;
		}
#endif

	if (!o.have_pcap)
		o.isr00t = 0;
	atexit(win_cleanup);
}


static void win_cleanup(void)
{
  WSACleanup();
}

int fork()
{
	fatal("no fork for you!\n");
	return 0;
}
