
/***************************************************************************
 * NpingOps.h -- The NpingOps class contains global options, mostly based  *
 * on user-provided command-line settings.                                 *
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

#ifndef NPING_NPINGOPS_H
#define NPING_NPINGOPS_H

/* Probe Modes */
#define TCP_CONNECT   0xF1
#define TCP           0xF2
#define UDP           0xF3
#define UDP_UNPRIV    0xF4
#define ICMP          0xF5
#define ARP           0xF6

/* Roles */
#define ROLE_NORMAL 0x22
#define ROLE_CLIENT 0x44
#define ROLE_SERVER 0x66

/* Payload types */
#define PL_NONE 0x00
#define PL_HEX  0xAA
#define PL_RAND 0xBB
#define PL_FILE 0xCC
#define PL_STRING 0xDD

/* Misc */
#define ARP_TYPE_REQUEST  0x01
#define ARP_TYPE_REPLY    0x02
#define RARP_TYPE_REQUEST 0x03
#define RARP_TYPE_REPLY   0x04

#define FLAG_CWR  0  /* Do not change these values because they */
#define FLAG_ECN  1  /* are used as indexes of an array         */
#define FLAG_URG  2
#define FLAG_ACK  3
#define FLAG_PSH  4
#define FLAG_RST  5
#define FLAG_SYN  6
#define FLAG_FIN  7

#define PACKET_SEND_NOPREF 1 /* These have been taken from NmapOps.h */
#define PACKET_SEND_ETH_WEAK 2
#define PACKET_SEND_ETH_STRONG 4
#define PACKET_SEND_ETH 6
#define PACKET_SEND_IP_WEAK 8
#define PACKET_SEND_IP_STRONG 16
#define PACKET_SEND_IP 24

#define IP_VERSION_4 0x04
#define IP_VERSION_6 0x06

#define NOT_SET -1
#define SET_RANDOM -2

#define MAX_ICMP_ADVERT_ENTRIES 128

#include "nping.h"
#include "global_structures.h"
#include "stats.h"
#include "NpingTargets.h"
#include <string>

class NpingOps {

  private:

    /* Probe modes */
    int mode;                 /* Probe mode (TCP,UDP,ICMP,ARP,RARP...) */
    bool mode_set;
    bool traceroute;          /* Is traceroute mode enabled?           */
    bool traceroute_set;

    /* Output */
    int vb;                   /* Current Verbosity level               */
    bool vb_set;
    int dbg;                  /* Current Debugging level               */
    bool dbg_set;
    bool show_sent_pkts;      /* Print packets sent by Nping?          */
    bool show_sent_pkts_set;

    /* Operation and Performance */
    u32 pcount;               /* No of packets 2be sent to each target */
    bool pcount_set;
    int sendpref;             /* Sending preference: eth or raw ip     */
    bool sendpref_set;
    bool send_eth;            /* True: send at raw ethernet level      */
    bool send_eth_set;
    long delay;               /* Delay between each probe              */
    bool delay_set;
    char device[MAX_DEV_LEN]; /* Network interface                     */
    bool device_set;
    bool spoofsource;         /* Did user request IP spoofing?         */
    bool spoofsource_set;
    char *bpf_filter_spec;    /* Custom, user-supplied BPF filter spec */
    bool bpf_filter_spec_set;
    int current_round;        /** Current round. Used in traceroute mode */
    bool have_pcap;           /* True if we have access to libpcap     */
    bool disable_packet_capture; /* If false, no packets are captured  */
    bool disable_packet_capture_set;

    /* Privileges */
    bool isr00t;              /* True if current user has root privs   */

    /* Payloads */
    int payload_type;         /* Type of payload (RAND,HEX,FILE)       */
    bool payload_type_set;
    u8 *payload_buff;         /* Pointer 2buff with the actual payload */
    bool payload_buff_set;
    int payload_len;          /* Length of payload                     */
    bool payload_len_set;

    /* Roles */
    int role;                 /* Nping's role: normal|client|server.  */
    bool role_set;

    /* IPv4 */
    u8 ttl;                   /* IPv4 TTL / IPv6 Hop limit             */
    bool ttl_set;
    u8 tos;                   /* Type of service                       */
    bool tos_set;
    u16 identification;       /* Identification field                  */
    bool identification_set;
    bool mf;                  /* More fragments flag                   */
    bool mf_set;
    bool df;                  /* Don't fragment flag                   */
    bool df_set;
    bool rf;                  /* Reserved / Evil flag                  */
    bool rf_set;
    u32 mtu;                  /* Custom MTU len (for IP fragmentation) */
    bool mtu_set;
    bool badsum_ip;           /* Generate invalid checksums in TCP/UDP */
    bool badsum_ip_set;
    u8 ipversion;             /* IP version to be used in all packets  */
    bool ipversion_set;
    struct in_addr ipv4_src_address;     /* Source IPv4 address        */
    bool ipv4_src_address_set;
    char *ip_options;         /* IP Options                            */
    bool ip_options_set;

    /* IPv6 */
    u8 ipv6_tclass;           /* Traffic Class                         */
    bool ipv6_tclass_set;
    u32 ipv6_flowlabel;       /* Flow Label                            */
    bool ipv6_flowlabel_set;
    struct in6_addr ipv6_src_address;  /**< Source IPv6 address          */
    bool ipv6_src_address_set;

    /* TCP / UDP */
    u16 *target_ports;        /* Will point to an array of ports       */
    int tportcount;           /* Total number of target ports          */
    bool target_ports_set;
    u16 source_port;          /* Source port for TCP/UPD packets       */
    bool source_port_set;
    u32 tcpseq;               /* TCP Sequence number                   */
    bool tcpseq_set;
    u32 tcpack;               /* TCP Acknowledgement                   */
    bool tcpack_set;
    u8 tcpflags[8];           /* TCP Flags                             */
    bool tcpflags_set;
    u16 tcpwin;               /* TCP Window                            */
    bool tcpwin_set;
    bool badsum;              /* Generate invalid TCP/UDP checksums?   */
    bool badsum_set;

    /* ICMP */
    u8 icmp_type;             /* ICMP Type                             */
    bool icmp_type_set;
    u8 icmp_code;             /* ICMP Code                             */
    bool icmp_code_set;
    bool badsum_icmp;         /* Generate invalid ICMP checksums?      */
    bool badsum_icmp_set;
    struct in_addr icmp_redir_addr; /* ICMP Redirect Address */ /* ##TODO## Turn this into an IPAddress object */
    bool icmp_redir_addr_set;
    u8 icmp_paramprob_pnt;    /* ICMP Parameter Problem pointer        */
    bool icmp_paramprob_pnt_set;
    u16 icmp_routeadv_ltime;  /* ICMP Router Advertisement lifetime    */
    bool icmp_routeadv_ltime_set;
    u16 icmp_id;              /* ICMP message identifier               */
    bool icmp_id_set;
    u16 icmp_seq;             /* ICMP sequence number                  */
    bool icmp_seq_set;
    u32 icmp_orig_time;       /* ICMP originate timestamp              */
    bool icmp_orig_time_set;
    u32 icmp_recv_time;       /* ICMP receive timestamp                */
    bool icmp_recv_time_set;
    u32 icmp_trans_time;      /* ICMP transmit timestamp               */
    bool icmp_trans_time_set;
    /* ICMP Router advertisement entries */
    struct in_addr icmp_advert_entry_addr[MAX_ICMP_ADVERT_ENTRIES];
    u32 icmp_advert_entry_pref[MAX_ICMP_ADVERT_ENTRIES];
    int icmp_advert_entry_count;
    bool icmp_advert_entry_set;

    /* Ethernet */
    u8 src_mac[6];            /* Source MAC address                    */
    bool src_mac_set;
    u8 dst_mac[6];            /* Destination MAC address               */
    bool dst_mac_set;
    u16 eth_type;             /* EtherType field of the Ethernet frame */
    bool eth_type_set;

    /* ARP/RARP */
    u16 arp_htype;            /* ARP Hardware type                     */
    bool arp_htype_set;
    u16 arp_ptype;            /* ARP Protocol type                     */
    bool arp_ptype_set;
    u8 arp_hlen;              /* ARP Hardware address length           */
    bool arp_hlen_set;
    u8 arp_plen;              /* ARP protocol address length           */
    bool arp_plen_set;
    u16 arp_opcode;           /* ARP Operation code                    */
    bool arp_opcode_set;
    u8 arp_sha[6];            /* ARP Sender hardware address           */
    bool arp_sha_set;
    u8 arp_tha[6];            /* ARP Target hardware address           */
    bool arp_tha_set;
    struct in_addr arp_spa;   /* ARP Sender protocol address           */
    bool arp_spa_set;
    struct in_addr arp_tpa;   /* ARP Target protocol address           */
    bool arp_tpa_set;

    /* Echo mode */
    u16 echo_port;           /* Echo port to listen or connect to      */
    bool echo_port_set;
    char echo_passphrase[1024]; /* User passphrase                     */
    bool echo_passphrase_set;
    bool do_crypto;          /* Do encrypted & authenticated sessions? */
    bool echo_payload;       /* Echo application-layer payloads?       */
    bool echo_payload_set;   
    bool echo_server_once;   /* Run server for only 1 client and quit? */
    bool echo_server_once_set;
    struct timeval last_sent_pkt_time; /* Time last packet was sent    */
    char *delayed_rcvd_str;    /* Delayed RCVD output string           */
    bool delayed_rcvd_str_set; /* Do we have a delayed RCVD string?    */
    nsock_event_id delayed_rcvd_event; /* Nsock event for delayed RCVD */

  public:
    NpingTargets targets;
    NpingStats stats;                      /* Global statistics           */

  public:

    /* Constructors / Destructors */
    NpingOps();
    ~NpingOps();

    /* Probe modes */
    int setMode(int md);
    int getMode();
    char *mode2Ascii(int md);
    bool issetMode();

    bool getTraceroute();
    bool enableTraceroute();
    bool disableTraceroute();
    bool issetTraceroute();

    /* Output */
    int setVerbosity(int level);
    int getVerbosity();
    int increaseVerbosity();
    int decreaseVerbosity();
    bool issetVerbosity();

    int setDebugging(int level);
    int getDebugging();
    int increaseDebugging();
    bool issetDebugging();

    int setShowSentPackets(bool val);
    bool showSentPackets();
    bool issetShowSentPackets();

    /* Operation and Performance */
    int setHostTimeout(long t);
    long getHostTimeout();
    bool issetHostTimeout();

    int setDelay(long t);
    long getDelay();
    bool issetDelay();

    int setPacketCount(u32 val);
    u32 getPacketCount();
    bool issetPacketCount();

    int setSendPreference(int v);
    int getSendPreference();
    bool issetSendPreference();
    bool sendPreferenceEthernet();
    bool sendPreferenceIP();

    int setSendEth(bool val);
    bool sendEth();
    bool issetSendEth();

    int setDevice(char *n);
    char *getDevice();
    bool issetDevice();

    int setSpoofSource();
    bool spoofSource();
    bool getSpoofSource();
    bool issetSpoofSource();

    int setBPFFilterSpec(char *val);
    char *getBPFFilterSpec();
    bool issetBPFFilterSpec();

    int setCurrentRound(int val);
    int getCurrentRound();
    bool issetCurrentRound();

    bool havePcap();
    int setHavePcap(bool val);

    int setDisablePacketCapture(bool val);
    bool disablePacketCapture();
    bool issetDisablePacketCapture();

    int setIPVersion(u8 val);
    int getIPVersion();
    bool issetIPVersion();
    bool ipv4();
    bool ipv6();
    bool ipv6UsingSocket();
    int af();

    /* Privileges */
    int setIsRoot(int v);
    int setIsRoot();
    bool isRoot();

    /* Payloads */
    int setPayloadType(int t);
    int getPayloadType();
    bool issetPayloadType();
    int setPayloadBuffer(u8 *p, int len);
    u8 *getPayloadBuffer();
    bool issetPayloadBuffer();
    int getPayloadLen();
    bool issetPayloadLen();

    /* Roles */
    int setRole(int r);
    int setRoleClient();
    int setRoleServer();
    int setRoleNormal();
    int getRole();
    bool issetRole();

    /* IPv4 */
    bool enableBadsumIP();
    bool disableBadsumIP();
    bool getBadsumIP();
    bool issetBadsumIP();

    int setTTL(u8 t);
    u8 getTTL();
    bool issetTTL();

    int setTOS(u8 tos);
    u8 getTOS();
    bool issetTOS();

    int setIdentification(u16 i);
    u16 getIdentification();
    bool issetIdentification();

    int setMF();
    bool getMF();
    bool issetMF();

    int setDF();
    bool getDF();
    bool issetDF();

    int setRF();
    bool getRF();
    bool issetRF();

    struct in_addr getIPv4SourceAddress();
    int setIPv4SourceAddress(struct in_addr i);
    bool issetIPv4SourceAddress();

    int setIPOptions(char *txt);
    char *getIPOptions();
    bool issetIPOptions();

    int setMTU(u32 t);
    u32 getMTU();
    bool issetMTU();

    /* IPv6 */
    int setTrafficClass(u8 val);
    u8 getTrafficClass();
    bool issetTrafficClass();

    int setFlowLabel(u32 val);
    u32 getFlowLabel();
    bool issetFlowLabel();

    int setHopLimit(u8 t);
    u8 getHopLimit();
    bool issetHopLimit();

    int setIPv6SourceAddress(u8 *val);
    int setIPv6SourceAddress(struct in6_addr val);    
    struct in6_addr getIPv6SourceAddress();
    bool issetIPv6SourceAddress();

    struct sockaddr_storage *getSourceSockAddr();
    struct sockaddr_storage *getSourceSockAddr(struct sockaddr_storage *ss);

    /* TCP / UDP */
    u16 *getTargetPorts( int *len );
    int setTargetPorts( u16 *pnt, int n );
    bool issetTargetPorts();
    bool scan_mode_uses_target_ports(int mode);



    int setSourcePort(u16 val);
    u16 getSourcePort();
    bool issetSourcePort();

    bool enableBadsum();
    bool disableBadsum();
    bool getBadsum();
    bool issetBadsum();

    int setFlagTCP(int flag);
    int setAllFlagsTCP();
    int unsetAllFlagsTCP();
    int getFlagTCP(int flag);
    u8 getTCPFlags();
    bool issetTCPFlags();

    int setTCPSequence(u32 val);
    u32 getTCPSequence();
    bool issetTCPSequence();

    int setTCPAck(u32 val);
    u32 getTCPAck();
    bool issetTCPAck();

    int setTCPWindow(u16 val);
    u16 getTCPWindow();
    bool issetTCPWindow();

    /* ICMP */
    int setICMPType(u8 type);
    u8 getICMPType();
    bool issetICMPType();

    int setICMPCode(u8 val);
    u8 getICMPCode();
    bool issetICMPCode();

    bool enableBadsumICMP();
    bool disableBadsumICMP();
    bool getBadsumICMP();
    bool issetBadsumICMP();

    int setICMPRedirectAddress(struct in_addr val);
    struct in_addr getICMPRedirectAddress();
    bool issetICMPRedirectAddress();

    int setICMPParamProblemPointer(u8 val);
    u8 getICMPParamProblemPointer();
    bool issetICMPParamProblemPointer();

    int setICMPRouterAdvLifetime(u16 val);
    u16 getICMPRouterAdvLifetime();
    bool issetICMPRouterAdvLifetime();

    int setICMPIdentifier(u16 val);
    u16 getICMPIdentifier();
    bool issetICMPIdentifier();

    int setICMPSequence(u16 val);
    u16 getICMPSequence();
    bool issetICMPSequence();

    int setICMPOriginateTimestamp(u32 val);
    u32 getICMPOriginateTimestamp();
    bool issetICMPOriginateTimestamp();

    int setICMPReceiveTimestamp(u32 val);
    u32 getICMPReceiveTimestamp();
    bool issetICMPReceiveTimestamp();

    int setICMPTransmitTimestamp(u32 val);
    u32 getICMPTransmitTimestamp();
    bool issetICMPTransmitTimestamp();

    int addICMPAdvertEntry(struct in_addr addr, u32 pref );
    int getICMPAdvertEntry(int num, struct in_addr *addr, u32 *pref);
    int getICMPAdvertEntryCount();
    bool issetICMPAdvertEntry();

    /* Ethernet */
    int setSourceMAC(u8 * val);
    u8 * getSourceMAC();
    bool issetSourceMAC();

    int setDestMAC(u8 * val);
    u8 * getDestMAC();
    bool issetDestMAC();

    int setEtherType(u16 val);
    u16 getEtherType();
    bool issetEtherType();

    /* ARP/RARP */
    int setARPHardwareType(u16 val);
    u16 getARPHardwareType();
    bool issetARPHardwareType();

    int setARPProtocolType(u16 val);
    u16 getARPProtocolType();
    bool issetARPProtocolType();

    int setARPHwAddrLen(u8 val);
    u8 getARPHwAddrLen();
    bool issetARPHwAddrLen();

    int setARPProtoAddrLen(u8 val);
    u8 getARPProtoAddrLen();
    bool issetARPProtoAddrLen();

    int setARPOpCode(u16 val);
    u16 getARPOpCode();
    bool issetARPOpCode();

    int setARPSenderHwAddr(u8 * val);
    u8 * getARPSenderHwAddr();
    bool issetARPSenderHwAddr();

    int setARPTargetHwAddr(u8 * val);
    u8 * getARPTargetHwAddr();
    bool issetARPTargetHwAddr();

    int setARPSenderProtoAddr(struct in_addr val);
    struct in_addr getARPSenderProtoAddr();
    bool issetARPSenderProtoAddr();

    int setARPTargetProtoAddr(struct in_addr val);
    struct in_addr getARPTargetProtoAddr();
    bool issetARPTargetProtoAddr();

    /* Echo Mode */
    int setEchoPort(u16 val);
    u16 getEchoPort();
    bool issetEchoPort();

    int setEchoPassphrase(const char *str);
    char *getEchoPassphrase();
    bool issetEchoPassphrase();

    bool doCrypto();
    int doCrypto(bool value);

    bool echoPayload();
    int echoPayload(bool value);

    int setOnce(bool val);
    bool once();

    /* Validation */
    void validateOptions();
    bool canRunUDPWithoutPrivileges();
    bool canDoIPv6ThroughSocket();
    bool canDoIPv6Ethernet();
    char *select_network_iface();

    /* Misc */
    void displayNpingDoneMsg();
    void displayStatistics();
    int cleanup();
    int setDefaultHeaderValues();
    int getTotalProbes();

    int setLastPacketSentTime(struct timeval t);
    struct timeval getLastPacketSentTime();

    int setDelayedRcvd(const char *str, nsock_event_id id);
    char *getDelayedRcvd(nsock_event_id *id);

}; /* End of class NpingOps */

#endif // NPING_NPINGOPS_H
