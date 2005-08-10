
/***************************************************************************
 * winfix.cc -- A few trivial windows-compatabilty-related functions that  *
 * are specific to Nmap.  Most of this has been moved into nbase so it can *
 * be shared.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
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
 * http://www.insecure.org/nmap/ to download Nmap.                         *
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
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
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
 * distribution.  By sending these changes to Fyodor or one the            *
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
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id: */

#include <winclude.h>
#include <sys/timeb.h>


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

/*   delay-load hooks only for troubleshooting   */
#ifdef _MSC_VER
static int dli_done = 0;
static FARPROC WINAPI winip_dli_fail_hook(unsigned code, PDelayLoadInfo info);
#endif

extern NmapOps o;

int pcap_avail = 0;

/*   internal functions   */
static void win_cleanup(void);
static char pcaplist[4096];

void win_barf(const char *msg)
{
  if(msg) printf("%s\n\n", msg);
  printf("\nYour system doesn't have iphlpapi.dll\n\nIf you have Win95, "
  "maybe you could grab it from a Win98 system\n"
  "If you have NT4, you need service pack 4 or higher\n"
  "If you have NT3.51, try grabbing it from an NT4 system\n"
  "Otherwise, your system has problems ;-)\n");
  exit(0);
}

void win_init()
{
	//   variables
	DWORD cb = 0;
	DWORD nRes;
	OSVERSIONINFOEX ver;
	PMIB_IPADDRTABLE pIp = 0;
	int i;
	int numipsleft;
	WORD werd;
	WSADATA data;

	werd = MAKEWORD( 2, 2 );
	if( (WSAStartup(werd, &data)) !=0 )
		fatal("failed to start winsock.\n");

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

		pcap_avail = 1;
		if(o.debugging > 2) printf("***WinIP***  trying to initialize winpcap 2.1\n");
		PacketGetAdapterNames(pcaplist, &len);
		if(o.debugging)
			printf("***WinIP***  winpcap present, dynamic linked to: %s\n", pcap_lib_version());
	}
#ifdef _MSC_VER
	__except(GetExceptionCode() == DLI_ERROR)
	{
		pcap_avail = 0;
		printf("WARNING: Failed to locate Winpcap. Nmap may not function properly until this is installed!  WinPcap is freely available from http://winpcap.polito.it.\n");
	}
#endif

	//   Check for a wpcap.dll (so we don't crash on old winpcap
	//   But only with VC++.NET, since old versions do not
	//   provide this functionality :(
#if defined(_MSC_VER) && _MSC_VER >= 1300
	if(pcap_avail)
	{
		if(FAILED(__HrLoadAllImportsForDll("wpcap.dll")))
		{
			error("WARNING: your winpcap is too old to use.  Nmap may not function.\n");
			pcap_avail = 0;
		}
	}
#endif

	o.isr00t = pcap_avail;
	atexit(win_cleanup);

	//   Mark load as complete so that dli errors are handled
#ifdef _MSC_VER
	dli_done = 1;
#endif
}


static void win_cleanup(void)
{
  WSACleanup();
}

typedef DWORD (__stdcall *PGBI)(IPAddr, PDWORD);

#ifdef _MSC_VER
static FARPROC WINAPI winip_dli_fail_hook(unsigned code, PDelayLoadInfo info)
{
  if(o.debugging)
    {
      printf("***WinIP***  delay load error:\n");
      switch(code)
 {
 case dliFailLoadLib:
   printf(" failed to load dll: %s\n", info->szDll);
   break;

 case dliFailGetProc:
   printf(" failed to load ");
   if(info->dlp.fImportByName)
     printf("function %s", info->dlp.szProcName + 2);
   else printf("ordinal %d", info->dlp.dwOrdinal);
   printf(" in dll %s\n", info->szDll);
   break;

 default:
   printf(" unknown error\n");
   break;
 }
    }

  if(dli_done)
    {
      printf("******* Unexpected delay-load failure *******\n");

      switch(code)
 {
 case dliFailLoadLib:
   printf(" failed to load dll: %s\n", info->szDll);
   if(!stricmp(info->szDll, "wpcap.dll"))
     printf(" this is most likely because you have"
     " winpcap 2.0 (2.1 or later is required)\n"
     "Get it from http://netgroup-serv.polito.it/winpcap\n");
   break;

 case dliFailGetProc:
   printf(" failed to load ");
   if(info->dlp.fImportByName)
     printf("function %s", info->dlp.szProcName + 2);
   else printf("ordinal %d", info->dlp.dwOrdinal);
   printf(" in dll %s\n", info->szDll);
   break;

 default:
   printf(" unknown error\n");
   break;
  }
    }

  return 0;
}
#endif // _MSC_VER



int my_close(int sd)
{
	return closesocket(sd);
}

int fork()
{
	fatal("no fork for you!\n");
	return 0;
}
