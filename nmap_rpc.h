
/***************************************************************************
 * nmap_rpc.h -- Functions related to the RPCGrind facility of Nmap.       *
 * This includes reading the nmap-rpc services file and sending rpc        *
 * queries and interpreting responses.  The actual scan engine used for    *
 * rpc grinding is pos_scan (which is not in this file)                    *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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

/* $Id$ */

#ifndef NMAP_RPC_H
#define NMAP_RPC_H

#include "nmap.h"
#include "global_structures.h"
#include "portlist.h"

/* rpc related #define's */
#define RECORD_MARKING 4        /* length of recoder marking (bytes)     */

/* defines used to check RPC answers */

#define RPC_MSG_CALL           0        /* RPC request                           */
#define RPC_MSG_REPLY          1        /* RPC answer                            */

#define MSG_ACCEPTED   0        /* RPC request was accepted              */
#define MSG_DENIED     1        /* RPC request was denied                */

#define SUCCESS        0        /* RPC proc_null request was a success   */
#define PROG_UNAVAIL   1        /* RPC prog not on this port             */
#define PROG_MISMATCH  2        /* RPC prog here but wrong version       */

/* structure used for RPC calls */
struct rpc_hdr                          
{       u_long  xid;                    /* xid number                    */
        u_long  type_msg;               /* request or answer             */
        u_long  version_rpc;            /* portmapper/rpcbind version    */
        u_long  prog_id;                /* rpc program id                */
        u_long  prog_ver;               /* rpc program version           */
        u_long  prog_proc;              /* remote procedure call number  */
        u_long  authcred_flavor;        /* credentials field             */
        u_long  authcred_length;
        u_long  authveri_flavor;        /* verification field            */
        u_long  authveri_length;
};

struct rpc_hdr_rcv {
  unsigned long xid;
  unsigned long type_msg;
  unsigned long rp_stat;
  unsigned long auth_flavor;
  unsigned long opaque_length;
  unsigned long accept_stat;
  unsigned long low_version;
  unsigned long high_version;
};

struct rpc_info {
  char **names;
  unsigned long *numbers;
  int num_used;
  int num_alloc;
};

struct rpcscaninfo {
  const Port *rpc_current_port;
  unsigned long *rpc_progs;
  unsigned long rpc_number;
  int valid_responses_this_port; /* Number of valid (RPC wise) responses we
				    have received on this particular port */
#define RPC_STATUS_UNTESTED 0
#define RPC_STATUS_UNKNOWN 1   /* Don't know yet */
#define RPC_STATUS_GOOD_PROG 2 /* the prog # specified in rpc_status_info and
                                  the version info is
				  valid for the rpc_current_port */
#define RPC_STATUS_NOT_RPC 4   /* This doesn't even seem to be an RPC port */
  int rpc_status;
  unsigned long rpc_program;
  unsigned long rpc_lowver; /* Lowest version number of program supported */
  unsigned long rpc_highver; /* Highest version supported */
};


int get_rpc_procs(unsigned long **programs, unsigned long *num_programs);
char *nmap_getrpcnamebynum(unsigned long num);
int send_rpc_query(Target *target_host, unsigned short portno,
		   int ipproto, unsigned long program, int scan_offset, 
		   int trynum);
void get_rpc_results(Target *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
		     struct rpcscaninfo *rsi);
void close_rpc_query_sockets();

#endif /* NMAP_RPC_H */

