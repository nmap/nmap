
/***************************************************************************
 * NpingTarget.h -- The NpingTarget class encapsulates much of the         *
 * information Nping has about a host. Things like next hop address or the *
 * network interface that should be used to send probes to the target, are *
 * stored in this class as they are determined.                            *
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

#ifndef NPINGTARGET_H
#define NPINGTARGET_H

#include "nping.h"
#include "common.h"
#include "../libnetutil/netutil.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

class NpingTarget {

  private:

    char devname[32];       /**< Net interface normal name                   */
    char devfullname[32];   /**< Net interface full name                     */
    devtype dev_type;       /**< Type of network interface                   */
    int directly_connected; /**< -1 = unset; 0 = no; 1 = yes                 */  
    int distance;           /**< Distance to target in hops                  */
    int addressfamily;      /**< Address family:  AF_INET or AF_INET6        */
    char *nameIPBuf;        /**< for the NameIP(void) function to return     */
    char *hostname;         /**< Resolved host name                          */
    int namedhost;          /**< =1 is named host; =0 is an IP; =-1 unset    */
    char *targetname;       /**< Name of the target host given on the        *
                             *   commmand line if it is a named host         */

    struct sockaddr_storage targetsock;   /**< Target address                */
    size_t targetsocklen;

    struct sockaddr_storage sourcesock;   /**< Source address                */
    size_t sourcesocklen;

    struct sockaddr_storage spoofedsrcsock; /**< Spoofed Source address      */
    size_t spoofedsrcsocklen;
    bool spoofedsrc_set;

    struct sockaddr_storage nexthopsock;  /**< Next Hop address              */
    size_t nexthopsocklen;
    
    char targetipstring[INET6_ADDRSTRLEN];
    bool targetipstring_set;

    u8 MACaddress[6];         /**< Target MAC Address                        */
    bool MACaddress_set;
    
    u8 SrcMACaddress[6];      /**< Source MAC Address                        */
    bool SrcMACaddress_set;
    
    u8 NextHopMACaddress[6];  /**< Next Hop MAC Address                      */
    bool NextHopMACaddress_set;

    /* This is for the ICMP identification field. It is supposed to be
     * initialized only once so we send all ICMP probes to this target with
     * the same ID (as ping utilities do) */
    u16 icmp_id;

    /* This is for the ICMP sequence field. It is supposed to be initialized
     * to 1 and then be incremented each time its value is requested through
     * obtainICMPSequence(). */
    u16 icmp_seq;

    /* Private methods */
    void Initialize();
    void FreeInternal();
    void generateIPString();
  
  public:
  
    NpingTarget();
    ~NpingTarget();
    void Recycle();
  
    /* Target IP address */
    int getTargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
    int setTargetSockAddr(struct sockaddr_storage *ss, size_t ss_len);
    struct in_addr getIPv4Address();
    const struct in_addr *getIPv4Address_aux();
    struct in6_addr getIPv6Address();
    const struct in6_addr *getIPv6Address_aux();
    u8 *getIPv6Address_u8();
    
    /* Source address used to reach the target */
    int getSourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
    int setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);
    int getSpoofedSourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
    int setSpoofedSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);
    bool spoofingSourceAddress();
    struct in_addr getIPv4SourceAddress();  
    const struct in_addr *getIPv4SourceAddress_aux();
    struct in_addr getIPv4SpoofedSourceAddress();  
    const struct in_addr *getIPv4SpoofedSourceAddress_aux();
    struct in6_addr getIPv6SourceAddress();  
    const struct in6_addr *getIPv6SourceAddress_aux();
    u8 *getIPv6SourceAddress_u8();
    
    /* Info about host proximity */
    void setDirectlyConnected(bool connected);
    bool isDirectlyConnected();
    int isDirectlyConnectedOrUnset();

    /* Next hop */
    void setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len);  
    bool getNextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len);
    int setNextHopMACAddress(const u8 *addy);
    const u8 *getNextHopMACAddress();

    /* Target MAC address (used when target is directly connected) */
    int setMACAddress(const u8 *addy);
    const u8 *getMACAddress();
    bool determineNextHopMACAddress();
    bool determineTargetMACAddress();
    
    /* Source MAC address */
    int setSrcMACAddress(const u8 *addy);
    const u8 *getSrcMACAddress();

    /* Network device used for this target */
    void setDeviceNames(const char *name, const char *fullname);
    const char *getDeviceName();
    const char *getDeviceFullName();
    int setDeviceType(devtype type);
    devtype getDeviceType();
 
    /* Resolved Host name */
    const char *getResolvedHostName();
    void setResolvedHostName(char *name);

    /* Target name as supplied from the command line */
    const char *getSuppliedHostName();
    int setSuppliedHostName(char *name);
    int setNamedHost(bool val);
    bool isNamedHost();

    /* Printable strings */
    const char *getTargetIPstr();
    const char *getNameAndIP(char *buf, size_t buflen);
    const char *getNameAndIP();
    const char *getSourceIPStr();
    const char *getSpoofedSourceIPStr();
    const char *getNextHopIPStr();
    const char *getMACStr(u8 *mac);
    const char *getTargetMACStr();
    const char *getSourceMACStr();
    const char *getNextHopMACStr(); 

    /* ICMP related methods */
    u16 obtainICMPSequence();
    u16 getICMPIdentifier();

    /* Misc */
    void printTargetDetails();



/* STATS***********************************************************************/
#define MAX_SENTPROBEINFO_ENTRIES 10

typedef struct pkt_stat{
    int proto;
    u16 tcp_port;
    u16 icmp_id;
    u16 icmp_seq;
    struct timeval sent;
    struct timeval recv;    
}pktstat_t;


pktstat_t sentprobes[MAX_SENTPROBEINFO_ENTRIES];
int current_stat;
int total_stats;

unsigned long int sent_total;
unsigned long int recv_total;
unsigned long int max_rtt;
bool max_rtt_set;
unsigned long int min_rtt;
bool min_rtt_set;
unsigned long int avg_rtt;
bool avg_rtt_set;


int setProbeRecvTCP(u16 sport, u16 dport);
int setProbeSentTCP(u16 sport, u16 dport);
int setProbeRecvUDP(u16 sport, u16 dport);
int setProbeSentUDP(u16 sport, u16 dport);
int setProbeSentICMP(u16 id, u16 seq);
int setProbeRecvICMP(u16 id, u16 seq);
int setProbeSentARP();
int setProbeRecvARP();
int updateRTTs(unsigned long int diff);
int printStats();
void printCounts();
void printRTTs();
/* STATS***********************************************************************/

};

#endif /* NPINGTARGET_H */
