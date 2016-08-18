
/***************************************************************************
 * winfix.cc -- A few trivial windows-compatibility-related functions that *
 * are specific to Nping.  Most of this has been moved into nbase so it can *
 * be shared.                                                              *
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

/* $Id: */

#include <winclude.h>
#include <sys/timeb.h>
#include <shellapi.h>


#include "nping.h"
//#include "tcpip.h"
#include "winfix.h"
#include "NpingOps.h"
#include "output.h"

#ifdef _MSC_VER
# include <delayimp.h>
#endif

#ifdef _MSC_VER
#define DLI_ERROR VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)
#endif

#define PCAP_DRIVER_NONE 0
#define PCAP_DRIVER_WINPCAP 1
#define PCAP_DRIVER_NPCAP 2

extern NpingOps o;

/*   internal functions   */
static void win_cleanup(void);
static char pcaplist[4096];

/* The code that has no preconditions to being called, so it can be
   executed before even Nping options parsing (so o.getDebugging() and the
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

/* Check if the NPCAP service is running on Windows, and try to start it if it's
   not. Return true if it was running or we were able to start it, false
   otherwise. */
static bool start_service(const char *svcname) {
  SC_HANDLE scm, npf;
  SERVICE_STATUS service;
  bool npf_running;
  int ret;
  char startsvc[32];

  scm = NULL;
  npf = NULL;

  scm = OpenSCManager(NULL, NULL, 0);
  if (scm == NULL) {
    error("Error in OpenSCManager");
    goto quit_error;
  }
  npf = OpenService(scm, svcname, SC_MANAGER_CONNECT | SERVICE_QUERY_STATUS);
  if (npf == NULL) {
    error("Error in OpenService");
    goto quit_error;
  }
  if (!QueryServiceStatus(npf, &service)) {
    /* No need to warn at this point: we'll check later
    error("Error in QueryServiceStatus");
    */
    goto quit_error;
  }
  npf_running = (service.dwCurrentState & SERVICE_RUNNING) != 0;
  CloseServiceHandle(scm);
  CloseServiceHandle(npf);

  if (npf_running) {
    if (o.getDebugging() > DBG_1)
      printf("%s service is already running.\n", svcname);
    return true;
  }

  /* Service is not running. Try to start it. */

  if (o.getDebugging() > DBG_1)
    printf("%s service is already running.\n", svcname);

  Snprintf(startsvc, 32, "start %s", svcname);
  ret = (int) ShellExecute(0, "runas", "net.exe", startsvc, 0, SW_HIDE);
  if (ret <= 32) {
    error("Unable to start %s service: ShellExecute returned %d.\n\
Resorting to unprivileged (non-administrator) mode.", svcname, ret);
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

/* Restrict where we're willing to load DLLs from to prevent DLL hijacking. */
static void init_dll_path()
{
	BOOL (WINAPI *SetDllDirectory)(LPCTSTR);

	SetDllDirectory = (BOOL (WINAPI *)(LPCTSTR)) GetProcAddress(GetModuleHandle("kernel32.dll"), "SetDllDirectoryA");
	if (SetDllDirectory == NULL) {
		char nmapdir[MAX_PATH];

		/* SetDllDirectory is not available before XP SP1. Instead, set
		   the current directory to the home of the executable (instead
		   of where a malicious DLL may be). */
		if (GetModuleFileName(NULL, nmapdir, sizeof(nmapdir)) == 0 ||
		    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			pfatal("Error in GetModuleFileName");
		}
		if (SetCurrentDirectory(nmapdir))
			pfatal("Error in SetCurrentDirectory");
	} else {
		if (SetDllDirectory("") == 0)
			pfatal("Error in SetDllDirectory(\"\")");
	}
}

/* If we find the Npcap driver, allow Nping to load Npcap DLLs from the "\System32\Npcap" directory. */
static void init_npcap_dll_path()
{
	BOOL(WINAPI *SetDllDirectory)(LPCTSTR);
	char sysdir_name[512];
	int len;

	SetDllDirectory = (BOOL(WINAPI *)(LPCTSTR)) GetProcAddress(GetModuleHandle("kernel32.dll"), "SetDllDirectoryA");
	if (SetDllDirectory == NULL) {
		pfatal("Error in SetDllDirectory");
	}
	else {
		len = GetSystemDirectory(sysdir_name, 480);	//	be safe
		if (!len)
			pfatal("Error in GetSystemDirectory (%d)", GetLastError());
		strcat(sysdir_name, "\\Npcap");
		if (SetDllDirectory(sysdir_name) == 0)
			pfatal("Error in SetDllDirectory(\"System32\\Npcap\")");
	}
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
	int pcap_driver;

	init_dll_path();

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
    HANDLE pcapMutex;
    DWORD wait;
		ULONG len = sizeof(pcaplist);

    if(o.getDebugging() >= DBG_2) printf("Trying to initialize Windows pcap engine\n");

    /* o.getIsRoot() will be false at this point if the user asked for
       --unprivileged. In that case don't bother them with a
       potential UAC dialog when starting NPF. */
    if (o.isRoot()) {
      if (start_service("npcap"))
        pcap_driver = PCAP_DRIVER_NPCAP;
      else if (start_service("npf"))
        pcap_driver = PCAP_DRIVER_WINPCAP;
      else {
        if(o.getDebugging() >= DBG_0) {
          error("Unable to start either npcap or npf service");
        }
        pcap_driver = PCAP_DRIVER_NONE;
        o.setHavePcap(false);
      }
    }

    if (pcap_driver == PCAP_DRIVER_NPCAP)
      init_npcap_dll_path();

    pcapMutex = CreateMutex(NULL, 0, "Global\\DnetPcapHangAvoidanceMutex");
    wait = WaitForSingleObject(pcapMutex, INFINITE);
		PacketGetAdapterNames(pcaplist, &len);
    if (wait == WAIT_ABANDONED || wait == WAIT_OBJECT_0) {
      ReleaseMutex(pcapMutex);
    }
    CloseHandle(pcapMutex);

#ifdef _MSC_VER
		if(FAILED(__HrLoadAllImportsForDll("wpcap.dll")))
		{
			error("WARNING: your winpcap is too old to use.  Nping may not function.\n");
			o.setHavePcap(false);
		}
#endif
		if(o.getDebugging() >= DBG_1)
			printf("Winpcap present, dynamic linked to: %s\n", pcap_lib_version());

	}
#ifdef _MSC_VER
	__except (1) {
			error("WARNING: Could not import all necessary Npcap functions.  You may need to upgrade to version 0.07 or higher from http://www.npcap.org.  Resorting to connect() mode -- Nping may not function completely");
		o.setHavePcap(false);
		}
#endif

	if (!o.havePcap())
		o.setIsRoot(0);
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
