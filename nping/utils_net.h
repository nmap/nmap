
/***************************************************************************
 * utils_net.cc -- Miscellanious network-related functions that perform    *
 * various tasks.                                                          *
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

#include "NpingTarget.h"

#ifndef UTILS_NET_H
#define UTILS_NET_H 1

#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h> /* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTM_H
#endif
#ifndef NETINET_IP_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif

int atoIP(const char *hostname, struct in_addr *dst);
int atoIP(const char *hostname, struct sockaddr_storage *ss, int family);
char *IPtoa(u32 i);
char *IPtoa(struct sockaddr_storage *ss);
char *IPtoa(struct in_addr addr);
char *IPtoa(struct in6_addr addr);
char *IPtoa(struct sockaddr_storage ss);
char *IPtoa(struct sockaddr_storage *ss, int family);
char *IPtoa(u8 *ipv6addr);
u16 sockaddr2port(struct sockaddr_storage *ss);
u16 sockaddr2port(struct sockaddr_storage ss);
u16 sockaddr2port(struct sockaddr_in *s4);
u16 sockaddr2port(struct sockaddr_in6 *s6);
int setsockaddrfamily(struct sockaddr_storage *ss, int family);
int setsockaddrany(struct sockaddr_storage *ss);
bool isICMPType(u8 type);
bool isICMPCode(u8 code);
bool isICMPCode(u8 code, u8 type);
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen, struct sockaddr_storage *ss_src, struct sockaddr_storage *ss_dst);
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen);
int getNetworkInterfaceName(u32 destination, char *dev);
int getNetworkInterfaceName(struct sockaddr_storage *dst, char *dev);
int nping_getpts_simple(const char *origexpr, u16 **list, int *count);
int resolveCached(char *host, struct sockaddr_storage *ss, size_t *sslen,int pf) ;
struct hostent *gethostbynameCached(char *host);
struct hostent *hostentcpy(struct hostent *src);
int hostentfree(struct hostent *src);
int parseMAC(const char *txt, u8 *targetbuff);
char *MACtoa(u8 *mac);
const char *arppackethdrinfo(const u8 *packet, u32 len, int detail );
int arppackethdrinfo(const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen);
int tcppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen, int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst);
int udppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen, int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst);
const char *getRandomTextPayload();
int send_packet(NpingTarget *target, int rawfd, u8 *pkt, size_t pktLen);
int print_dnet_interface(const struct intf_entry *entry, void *arg) ;
int print_interfaces_dnet();
struct sockaddr_storage *getSrcSockAddrFromIPPacket(u8 *pkt, size_t pktLen);
u8 *getUDPheaderLocation(u8 *pkt, size_t pktLen);
u8 *getTCPheaderLocation(u8 *pkt, size_t pktLen);
u8 getProtoFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getSrcPortFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getDstPortFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getDstPortFromTCPHeader(u8 *pkt, size_t pktLen);
u16 *getDstPortFromUDPHeader(u8 *pkt, size_t pktLen);
int obtainRawSocket();

#define DEVNAMELEN 16
#define PATH_PROC_IFINET6 "/proc/net/if_inet6"
typedef struct ipv6_interface{
  char devname[DEVNAMELEN];            /* Interface name                    */
  struct sockaddr_storage ss;          /* Address as a sockaddr_storage var */
  u8 addr[16];                         /* Address as a 128bit array         */        
  u16 netmask_bits;                    /* Prefix length                     */
  u8 dev_no;                           /* Netlink device number             */
  u8 scope;                            /* Scope                             */
  u8 flags;                            /* Interface flags                   */
  u8 mac[6];                           /* MAC addr. (I wish we could get it)*/
}if6_t;

int getinterfaces_inet6_linux(if6_t *ifbuf, int max_ifaces);

#define PATH_PROC_IPV6ROUTE "/proc/net/ipv6_route"

typedef struct sys_route6 {
  struct in6_addr dst_net;             /* Destination Network               */
  u8 dst_prefix;                       /* Destination Prefix Length         */
  struct in6_addr src_net;             /* Source Network                    */
  u8 src_prefix;                       /* Source Prefix Length              */
  struct in6_addr next_hop;            /* Gateway - 0 if none               */
  u32 metric;                          /* Metric                            */
  u32 ref_count;                       /* Reference Counter                 */
  u32 use_count;                       /* Use Counter                       */
  u32 flags;                           /* Flags                             */
  char devname[DEVNAMELEN];            /* Device name                       */
}route6_t;

int getroutes_inet6_linux(route6_t *rtbuf, int max_routes);
route6_t *route_dst_ipv6_linux(const struct sockaddr_storage *const dst);

#endif /* UTILS_NET_H */
