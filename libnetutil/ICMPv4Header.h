
/***************************************************************************
 * ICMPv4Header.h -- The ICMPv4Header Class represents an ICMP version 4   *
 * packet. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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
