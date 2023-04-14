/***************************************************************************
 * ICMPv4Header.h -- The ICMPv4Header Class represents an ICMP version 4   *
 * packet. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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
/* This code was originally part of the Nping tool.                        */

#ifndef ICMPv4HEADER_H
#define ICMPv4HEADER_H 1

#include "ICMPHeader.h"

/* ICMP types and codes. These defines were originally taken from  Slirp 1.0
 * source file ip_icmp.h  http://slirp.sourceforge.net/ (BSD licensed) and
 * then, partially modified for Nping                                        */
#define ICMP_ECHOREPLY               0     /* Echo reply                     */
#define ICMP_UNREACH                 3     /* Destination unreachable:       */
#define    ICMP_UNREACH_NET            0   /*  --> Bad network               */
#define    ICMP_UNREACH_HOST           1   /*  --> Bad host                  */
#define    ICMP_UNREACH_PROTOCOL       2   /*  --> Bad protocol              */
#define    ICMP_UNREACH_PORT           3   /*  --> Bad port                  */
#define    ICMP_UNREACH_NEEDFRAG       4   /*  --> DF flag caused pkt drop   */
#define    ICMP_UNREACH_SRCFAIL        5   /*  --> Source route failed       */
#define    ICMP_UNREACH_NET_UNKNOWN    6   /*  --> Unknown network           */
#define    ICMP_UNREACH_HOST_UNKNOWN   7   /*  --> Unknown host              */
#define    ICMP_UNREACH_ISOLATED       8   /*  --> Source host isolated      */
#define    ICMP_UNREACH_NET_PROHIB     9   /*  --> Prohibited access         */
#define    ICMP_UNREACH_HOST_PROHIB    10  /*  --> Prohibited access         */
#define    ICMP_UNREACH_TOSNET         11  /*  --> Bad TOS for network       */
#define    ICMP_UNREACH_TOSHOST        12  /*  --> Bad TOS for host          */
#define    ICMP_UNREACH_COMM_PROHIB    13  /*  --> Prohibited communication  */
#define    ICMP_UNREACH_HOSTPRECEDENCE 14  /*  --> Host precedence violation */
#define    ICMP_UNREACH_PRECCUTOFF     15  /*  --> Precedence cutoff         */
#define ICMP_SOURCEQUENCH            4     /* Source Quench.                 */
#define ICMP_REDIRECT                5     /* Redirect:                      */
#define    ICMP_REDIRECT_NET           0   /*  --> For the network           */
#define    ICMP_REDIRECT_HOST          1   /*  --> For the host              */
#define    ICMP_REDIRECT_TOSNET        2   /*  --> For the TOS and network   */
#define    ICMP_REDIRECT_TOSHOST       3   /*  --> For the TOS and host      */
#define ICMP_ECHO                    8     /* Echo request                   */
#define ICMP_ROUTERADVERT            9     /* Router advertisement           */
#define    ICMP_ROUTERADVERT_MOBILE    16  /* Used by mobile IP agents       */
#define ICMP_ROUTERSOLICIT           10    /* Router solicitation            */
#define ICMP_TIMXCEED                11    /* Time exceeded:                 */
#define    ICMP_TIMXCEED_INTRANS       0   /*  --> TTL==0 in transit         */
#define    ICMP_TIMXCEED_REASS         1   /*  --> TTL==0 in reassembly      */
#define ICMP_PARAMPROB               12    /* Parameter problem              */
#define    ICMM_PARAMPROB_POINTER      0   /*  --> Pointer shows the problem */
#define    ICMP_PARAMPROB_OPTABSENT    1   /*  --> Option missing            */
#define    ICMP_PARAMPROB_BADLEN       2   /*  --> Bad datagram length       */
#define ICMP_TSTAMP                  13    /* Timestamp request              */
#define ICMP_TSTAMPREPLY             14    /* Timestamp reply                */
#define ICMP_INFO                    15    /* Information request            */
#define ICMP_INFOREPLY               16    /* Information reply              */
#define ICMP_MASK                    17    /* Address mask request           */
#define ICMP_MASKREPLY               18    /* Address mask reply             */
#define ICMP_TRACEROUTE              30    /* Traceroute                     */
#define    ICMP_TRACEROUTE_SUCCESS     0   /*  --> Dgram sent to next router */
#define    ICMP_TRACEROUTE_DROPPED     1   /*  --> Dgram was dropped         */
#define ICMP_DOMAINNAME              37    /* Domain name request            */
#define ICMP_DOMAINNAMEREPLY         38    /* Domain name reply              */
#define ICMP_SECURITYFAILURES        40    /* Security failures              */


#define ICMP_STD_HEADER_LEN 8
#define ICMP_MAX_PAYLOAD_LEN 1500
#define MAX_ROUTER_ADVERT_ENTRIES (((ICMP_MAX_PAYLOAD_LEN-4)/8)-1)


class ICMPv4Header : public ICMPHeader {

    private:

        /**********************************************************************/
        /* COMMON ICMPv4 packet HEADER                                        */
        /**********************************************************************/
        /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                         Message Body                          +
           |                                                               | */
        struct nping_icmpv4_hdr {
            u8 type;                     /* ICMP Message Type                 */
            u8 code;                     /* ICMP Message Code                 */
            u16 checksum;                /* Checksum                          */
            u8 data[ICMP_MAX_PAYLOAD_LEN];
        }__attribute__((__packed__));
        typedef struct nping_icmpv4_hdr nping_icmpv4_hdr_t;


        /**********************************************************************/
        /* ICMPv4 MESSAGE SPECIFIC HEADERS                                    */
        /**********************************************************************/

        /* Destination Unreachable Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             unused                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Internet Header + 64 bits of Original Data Datagram      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_dest_unreach_msg{
            u32 unused;
            //u8 original_dgram[?];
        }__attribute__((__packed__));
        typedef struct icmp4_dest_unreach_msg icmp4_dest_unreach_msg_t;


        /* Time Exceeded Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             unused                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Internet Header + 64 bits of Original Data Datagram      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_time_exceeded_msg{
            u32 unused;
            //u8 original_dgram[?];
        }__attribute__((__packed__));
        typedef struct icmp4_time_exceeded_msg icmp4_time_exceeded_msg_t;


        /* Parameter Problem Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    Pointer    |                   unused                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Internet Header + 64 bits of Original Data Datagram      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  */

        struct icmp4_parameter_problem_msg{
            u8 pointer;
            u8 unused[3];
            //u8 original_dgram[?];
        }__attribute__((__packed__));
        typedef struct icmp4_parameter_problem_msg icmp4_parameter_problem_msg_t;


        /* Source Quench Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             unused                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Internet Header + 64 bits of Original Data Datagram      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_source_quench_msg{
            u32 unused;
            //u8 original_dgram[?];
        }__attribute__((__packed__));
        typedef struct icmp4_source_quench_msg icmp4_source_quench_msg_t;


        /* Redirect Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                 Gateway Internet Address                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Internet Header + 64 bits of Original Data Datagram      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_redirect_msg{
            struct in_addr gateway_address;
            //u8 original_dgram[?];
        }__attribute__((__packed__));
        typedef struct icmp4_redirect_msg icmp4_redirect_msg_t;


        /* Echo Request/Reply Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Data ...
          +-+-+-+-+-                                                        */
        struct icmp4_echo_msg{
            u16 identifier;
            u16 sequence;
            //u8 data[?];
        }__attribute__((__packed__));
        typedef struct icmp4_echo_msg icmp4_echo_msg_t;


        /* Timestamp Request/Reply Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |      Code     |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Originate Timestamp                                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Receive Timestamp                                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Transmit Timestamp                                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_timestamp_msg{
            u16 identifier;
            u16 sequence;
            u32 originate_ts;
            u32 receive_ts;
            u32 transmit_ts;
        }__attribute__((__packed__));
        typedef struct icmp4_timestamp_msg icmp4_timestamp_msg_t;


        /* Information Request/Reply Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |      Code     |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_information_msg{
            u16 identifier;
            u16 sequence;
        }__attribute__((__packed__));
        typedef struct icmp4_information_msg icmp4_information_msg_t;


        /* ICMP Router Advertisement Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |           Checksum            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Num Addrs   |Addr Entry Size|           Lifetime            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                       Router Address[1]                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                      Preference Level[1]                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                       Router Address[2]                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                      Preference Level[2]                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                               .                               |
          |                               .                               |
          |                               .                               | */
        struct icmp4_router_advert_entry{
            struct in_addr router_addr;
            u32 preference_level;
        }__attribute__((__packed__));
        typedef struct icmp4_router_advert_entry icmp4_router_advert_entry_t;

        struct icmp4_router_advert_msg{
            u8 num_addrs;
            u8 addr_entry_size;
            u16 lifetime;
            icmp4_router_advert_entry_t adverts[MAX_ROUTER_ADVERT_ENTRIES];
        }__attribute__((__packed__));
        typedef struct icmp4_router_advert_msg icmp4_router_advert_msg_t;


        /* ICMP Router Solicitation Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |           Checksum            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_router_solicit_msg{
            u32 reserved;
        }__attribute__((__packed__));
        typedef struct icmp4_router_solicit_msg icmp4_router_solicit_msg_t;


        /* ICMP Security Failures Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Reserved            |          Pointer              |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          ~     Original Internet Headers + 64 bits of Payload            ~
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_security_failures_msg{
            u16 reserved;
            u16 pointer;
            //u8 original_headers[?];
        }__attribute__((__packed__));
        typedef struct icmp4_security_failures_msg icmp4_security_failures_msg_t;


        /* ICMP Address Mask Request/Reply Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |      Code     |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |       Sequence Number         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                        Address Mask                           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_address_mask_msg{
            u16 identifier;
            u16 sequence;
            struct in_addr address_mask;
        }__attribute__((__packed__));
        typedef struct icmp4_address_mask_msg icmp4_address_mask_msg_t;


        /* ICMP Traceroute Message
          +---------------+---------------+---------------+---------------+
          |     Type      |     Code      |           Checksum            |
          +---------------+---------------+---------------+---------------+
          |           ID Number           |            unused             |
          +---------------+---------------+---------------+---------------+
          |      Outbound Hop Count       |       Return Hop Count        |
          +---------------+---------------+---------------+---------------+
          |                       Output Link Speed                       |
          +---------------+---------------+---------------+---------------+
          |                        Output Link MTU                        |
          +---------------+---------------+---------------+---------------+ */
        struct icmp4_traceroute_msg{
            u16 id_number;
            u16 unused;
            u16 outbound_hop_count;
            u16 return_hop_count;
            u32 output_link_speed;
            u32 output_link_mtu;
        }__attribute__((__packed__));
        typedef struct icmp4_traceroute_msg icmp4_traceroute_msg_t;


        /* ICMP Domain Name Request Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct icmp4_domain_name_request_msg{
            u16 identifier;
            u16 sequence;
        }__attribute__((__packed__));
        typedef struct icmp4_domain_name_request_msg icmp4_domain_name_request_msg_t;


        /* ICMP Domain Name Reply Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                          Time-To-Live                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Names ...
          +-+-+-+-+-+-+-+-                                                  */
        struct icmp4_domain_name_reply_msg{
            u16 identifier;
            u16 sequence;
            s16 ttl; /* Signed! */
            u8 names[ICMP_MAX_PAYLOAD_LEN-8];
        }__attribute__((__packed__));
        typedef struct icmp4_domain_name_reply_msg icmp4_domain_name_reply_msg_t;


        /* Main data structure */
        nping_icmpv4_hdr_t h;

        /* Helper pointers */
        icmp4_dest_unreach_msg_t         *h_du;
        icmp4_time_exceeded_msg_t        *h_te;
        icmp4_parameter_problem_msg_t    *h_pp;
        icmp4_source_quench_msg_t        *h_sq;
        icmp4_redirect_msg_t             *h_r;
        icmp4_echo_msg_t                 *h_e;
        icmp4_timestamp_msg_t            *h_t;
        icmp4_information_msg_t          *h_i;
        icmp4_router_advert_msg_t        *h_ra;
        icmp4_router_solicit_msg_t       *h_rs;
        icmp4_security_failures_msg_t    *h_sf;
        icmp4_address_mask_msg_t         *h_am;
        icmp4_traceroute_msg_t           *h_trc;
        icmp4_domain_name_request_msg_t  *h_dn;
        icmp4_domain_name_reply_msg_t    *h_dnr;

        /* Internal counts */
        int routeradventries;
        int domainnameentries;

    public:
        /* PacketElement:: Mandatory methods */
        ICMPv4Header();
        ~ICMPv4Header();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        /* ICMP Type */
        int setType(u8 val);
        u8 getType() const;
        bool validateType();
        bool validateType(u8 val);

        /* ICMP Code */
        int setCode(u8 c);
        u8 getCode() const;
        bool validateCode();
        bool validateCode(u8 type, u8 code);

        /* Checksum */
        int setSum();
        int setSum(u16 s);
        u16 getSum() const;

        /* Unused and reserved fields */
        int setUnused(u32 val);
        u32 getUnused() const;
        int setReserved( u32 val );
        u32 getReserved() const;

        /* Redirect */
        int setGatewayAddress(struct in_addr ipaddr);
        struct in_addr getGatewayAddress() const;

        /* Parameter problem */
        int setParameterPointer(u8 val);
        u8 getParameterPointer() const;

        /* Router advertisement */
        int setNumAddresses(u8 val);
        u8 getNumAddresses() const;
        int setAddrEntrySize(u8 val);
        u8 getAddrEntrySize() const;
        int setLifetime(u16 val);
        u16 getLifetime() const;
        int addRouterAdvEntry(struct in_addr raddr, u32 pref);
        u8 *getRouterAdvEntries(int *num) const;
        int clearRouterAdvEntries();

        /* Echo/Timestamp/Mask */
        int setIdentifier(u16 val);
        u16 getIdentifier() const;
        int setSequence(u16 val);
        u16 getSequence() const;

        /* Timestamp only */
        int setOriginateTimestamp(u32 t);
        u32 getOriginateTimestamp() const;
        int setReceiveTimestamp(u32 t);
        u32 getReceiveTimestamp() const;
        int setTransmitTimestamp(u32 t);
        u32 getTransmitTimestamp() const;

        /* Mask only */
        int setAddressMask(struct in_addr mask);
        struct in_addr getAddressMask() const;

        /* Security Failures */
        int setSecurityPointer(u16 val);
        u16 getSecurityPointer() const;

        /* Traceroute */
        int setIDNumber(u16 val);
        u16 getIDNumber() const;
        int setOutboundHopCount(u16 val);
        u16 getOutboundHopCount() const;
        int setReturnHopCount(u16 val);
        u16 getReturnHopCount() const;
        int setOutputLinkSpeed(u32 val);
        u32 getOutputLinkSpeed() const;
        int setOutputLinkMTU(u32 val);
        u32 getOutputLinkMTU() const;

        /* Misc */
        int getICMPHeaderLengthFromType( u8 type ) const;
        const char *type2string(int type, int code) const;
        bool isError() const;


}; /* End of class ICMPv4Header */

#endif
