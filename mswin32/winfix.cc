
/***************************************************************************
 * winfix.cc -- A few trivial windows-compatibility-related functions that *
 * are specific to Nmap.  Most of this has been moved into nbase so it can *
 * be shared.                                                              *
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

/* $Id: */

#include <nmap_winconfig.h>
#include "..\nmap.h"
#include "..\tcpip.h"
#include "winfix.h"
#include "..\NmapOps.h"
#include "..\nmap_error.h"
#include <Packet32.h>

#include <shellapi.h>

#ifdef _MSC_VER
# include <delayimp.h>
#endif

extern NmapOps o;

/*   internal functions   */
static void win_cleanup(void);

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
    /* No need to warn at this point: we'll check later
    error("Error in OpenService");
    */
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
      log_write(LOG_PLAIN, "%s service is already running.\n", svcname);
    return true;
  }

  /* Service is not running. Try to start it. */

  if (o.debugging > 1)
    log_write(LOG_PLAIN, "%s service is not running.\n", svcname);

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
    CloseServiceHandle(scm);
  if (npf != NULL)
    CloseServiceHandle(npf);

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

/* If we find the Npcap driver, allow Nmap to load Npcap DLLs from the "\System32\Npcap" directory. */
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
			pfatal("Error in GetSystemDirectory");
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
	init_dll_path();

	//   Try to initialize Npcap
#ifdef _MSC_VER
	__try
#endif
	{
	  const char *pcap_ver = NULL;

		o.have_pcap = true;
		if(o.debugging > 2) printf("Trying to initialize Windows pcap engine\n");
		
    /* o.isr00t will be false at this point if the user asked for
       --unprivileged. In that case don't bother them with a
       potential UAC dialog when starting Npcap. */
    if (o.isr00t) {
      if (!start_service("npcap")) {
        if (o.debugging) {
          error("Unable to start the npcap service");
        }
        o.have_pcap = false;
      }
    }

		init_npcap_dll_path();
		
		pcap_ver = PacketGetVersion();
		if (o.debugging)
		  printf("Packet.dll present, library version %s\n", pcap_ver);

#ifdef _MSC_VER
		if(FAILED(__HrLoadAllImportsForDll("wpcap.dll")))
		{
			error("WARNING: Failed to load wpcap.dll.  Nmap may not function.\n");
			o.have_pcap = false;
		}
#endif
		if(o.debugging)
			printf("wpcap.dll present, library version: %s\n", pcap_lib_version());

	}
#ifdef _MSC_VER
	__except (1) {
			error("WARNING: Could not import all necessary Npcap functions. You may need to upgrade to the latest version from https://npcap.com. Resorting to connect() mode -- Nmap may not function completely");
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
