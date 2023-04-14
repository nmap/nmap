
/***************************************************************************
 * NpingTarget.h -- The NpingTarget class encapsulates much of the         *
 * information Nping has about a host. Things like next hop address or the *
 * network interface that should be used to send probes to the target, are *
 * stored in this class as they are determined.                            *
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
                             *   command line if it is a named host          */

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
