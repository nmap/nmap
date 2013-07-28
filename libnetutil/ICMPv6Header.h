
/***************************************************************************
 * ICMPv6Header.h -- The ICMPv6Header Class represents an ICMP version 6   *
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

#ifndef ICMPv6HEADER_H
#define ICMPv6HEADER_H 1

#include "ICMPHeader.h"

/******************************************************************************/
/*               IMPORTANT INFORMATION ON HOW TO USE THIS CLASS.              */
/******************************************************************************/
/* This class represents an ICMPv6 messages. ICMPv6 messages may be of
 * different types. Each type has its own header and possibly a variable
 * length data field. Information messages have an "invoking packet" field
 * which is the IP packet that triggered the emission of the ICMPv6 message.
 * Other messages may contain a "data" field, like echo requests an replies.
 * Some others may contain ICMPv6 Options.
 *
 * So the thing is, that this class only represents fixed-length ICMPv6
 * headers and does NOT offer storage for ANY variable-length field. This
 * fields may be added to the ICMPv6 header using instances of the RawData
 * class the ICMPv6Option class or even the IPv6Header class (in those cases
 * where a whole packet is appendend to the ICMPv6 message).
 *
 * So, how does this work? Let's look at some examples.
 *
 * 1. Imagine we need to build an ICMP echo request message that includes some
 *    arbitrary data to be echoed. We could do the following:
 * 
 *    u8 final_packet[1024];         <-- Buffer to store the resulting packet
 *    u32 final_packet_len=0;        <-- Length of the resulting packet
 *    ICMPv6Header header;           <-- The ICMPv6 fixed-length part
 *    RawData data;                  <-- The data to append to the echo message
 * 
 *    header.setType(ICMPv6_ECHO);   <-- Set ICMPv6 type to "Echo request"
 *    data.store("1234567890");      <-- Store data we need to send.
 *    header.setNextElement(&data);  <-- Tell ICMPv6Header what's after it
 *    header.setSum();               <-- Compute the checksum
 * 
 *    final_packet_len=header.dumpToBinaryBuffer(fina_packet, 1024);
 *    send_packet(final_packet, final_packet_len)
 *
 * 2. If we are sending a parameter problem message and we need to include the
 *    invoking datagram, we can call setNextElement() passing an IPv6Header
 *    pointer.
 * 
 *    u8 final_packet[1024];         <-- Buffer to store the resulting packet
 *    u32 final_packet_len=0;        <-- Length of the resulting packet
 *    ICMPv6Header header;           <-- The ICMPv6 fixed-length part
 *    IPv6Header ipv6;               <-- The IPv6 packet that triggered ICMPv6
 *
 *    header.setType(ICMPv6_PARAMPROB); <-- Set ICMPv6 type to "Param Problem"
 *    header.setNextElement(&ipv6);  <-- Tell ICMPv6Header what's after it
 *    header.setSum();               <-- Compute the checksum
 *
 *    Note that here we don't show how the ipv6 object is set.
 *
 * 3. If we are sending a router solicitation message, we'll call
 *    setNextElement() passing an IPv6Options Pointer.
 * 
 *    u8 final_packet[1024];         <-- Buffer to store the resulting packet
 *    u32 final_packet_len=0;        <-- Length of the resulting packet
 *    ICMPv6Header header;           <-- The ICMPv6 fixed-length part
 *    IPv6Options opts1;              <-- IPv6 options
 *    IPv6Options opts2;              <-- IPv6 options
 *    IPv6Options opts3;              <-- IPv6 options
 *
 *    header.setType(ICMPv6_ROUTERSOLICIT); <-- Set ICMPv6 type
 *
 *    opts1.setXXXX();   <-- Set up the options
 *    .
 *    .
 *    .
 *    opts3.setYYYY();
 *
 *    opts2.setNextElement(&opts3);  <-- Link the options
 *    opts1.setNextElement(&opts2);
 *    header.setNextElement(&opts1);
 *    header.setNextElement(&ipv6);  <-- Link the first option to the ICMPv6
 *    header.setSum();               <-- Compute the checksum
 *
 *    And so on...
 *
 */


/* Packet header diagrams included in this file have been taken from the
 * following IETF RFC documents: RFC 4443, RFC 2461, RFC 2894 */

/* ICMP types and codes.
 * The following types and codes have been defined by IANA. A complete list 
 * may be found at http://www.iana.org/assignments/icmpv6-parameters
 *
 * Definitions on the first level of indentation are ICMPv6 Types.
 * Definitions on the second level of indentation (values enclosed in 
 * parenthesis) are ICMPv6 Codes */
#define ICMPv6_UNREACH                      1    /* Destination unreachable  [RFC 2463, 4443] */
#define     ICMPv6_UNREACH_NO_ROUTE        (0)   /*  --> No route to destination */
#define     ICMPv6_UNREACH_PROHIBITED      (1)   /*  --> Communication administratively prohibited */
#define     ICMPv6_UNREACH_BEYOND_SCOPE    (2)   /*  --> Beyond scope of source address  [RFC4443] */
#define     ICMPv6_UNREACH_ADDR_UNREACH    (3)   /*  --> Address unreachable */
#define     ICMPv6_UNREACH_PORT_UNREACH    (4)   /*  --> Port unreachable */
#define     ICMPv6_UNREACH_SRC_ADDR_FAILED (5)   /*  --> Source address failed ingress/egress policy [RFC4443] */
#define     ICMPv6_UNREACH_REJECT_ROUTE    (6)   /*  --> Reject route to destination  [RFC4443] */
#define ICMPv6_PKTTOOBIG                    2    /* Packet too big  [RFC 2463, 4443] */
#define ICMPv6_TIMXCEED                     3    /* Time exceeded  [RFC 2463, 4443] */
#define     ICMPv6_TIMXCEED_HOP_EXCEEDED   (0)   /*  --> Hop limit exceeded in transit */
#define     ICMPv6_TIMXCEED_REASS_EXCEEDED (1)   /*  --> Fragment reassembly time exceeded */
#define ICMPv6_PARAMPROB                    4    /* Parameter problem  [RFC 2463, 4443] */
#define     ICMPv6_PARAMPROB_FIELD         (0)   /*  --> Erroneous header field encountered */
#define     ICMPv6_PARAMPROB_NEXT_HDR      (1)   /*  --> Unrecognized Next Header type encountered */
#define     ICMPv6_PARAMPROB_OPTION        (2)   /*  --> Unrecognized IPv6 option encountered */
#define ICMPv6_ECHO                        128   /* Echo request  [RFC 2463, 4443] */
#define ICMPv6_ECHOREPLY                   129   /* Echo reply  [RFC 2463, 4443] */
#define ICMPv6_GRPMEMBQUERY                130   /* Group Membership Query  [RFC 2710] */
#define ICMPv6_GRPMEMBREP                  131   /* Group Membership Report  [RFC 2710] */
#define ICMPv6_GRPMEMBRED                  132   /* Group Membership Reduction  [RFC 2710] */
#define ICMPv6_ROUTERSOLICIT               133   /* Router Solicitation  [RFC 2461] */
#define ICMPv6_ROUTERADVERT                134   /* Router Advertisement  [RFC 2461] */
#define ICMPv6_NGHBRSOLICIT                135   /* Neighbor Solicitation  [RFC 2461] */
#define ICMPv6_NGHBRADVERT                 136   /* Neighbor Advertisement  [RFC 2461] */
#define ICMPv6_REDIRECT                    137   /* Redirect  [RFC 2461] */
#define ICMPv6_RTRRENUM                    138   /* Router Renumbering  [RFC 2894] */
#define     ICMPv6_RTRRENUM_COMMAND        (0)   /*  --> Router Renumbering Command */
#define     ICMPv6_RTRRENUM_RESULT         (1)   /*  --> Router Renumbering Result */
#define     ICMPv6_RTRRENUM_SEQ_RESET      (255) /* Sequence Number Reset */
#define ICMPv6_NODEINFOQUERY               139   /* ICMP Node Information Query  [RFC 4620] */
#define     ICMPv6_NODEINFOQUERY_IPv6ADDR  (0)   /*  --> The Data field contains an IPv6 address */
#define     ICMPv6_NODEINFOQUERY_NAME      (1)   /*  --> The Data field contains a name */
#define     ICMPv6_NODEINFOQUERY_IPv4ADDR  (2)   /*  --> The Data field contains an IPv4 address */
#define ICMPv6_NODEINFORESP                140   /* ICMP Node Information Response  [RFC 4620] */
#define     ICMPv6_NODEINFORESP_SUCCESS    (0)   /*  --> A successful reply.   */
#define     ICMPv6_NODEINFORESP_REFUSED    (1)   /*  --> The Responder refuses to supply the answer */
#define     ICMPv6_NODEINFORESP_UNKNOWN    (2)   /*  --> The Qtype of the Query is unknown */
#define ICMPv6_INVNGHBRSOLICIT             141   /* Inverse Neighbor Discovery Solicitation Message  [RFC 3122] */
#define ICMPv6_INVNGHBRADVERT              142   /* Inverse Neighbor Discovery Advertisement Message  [RFC 3122] */
#define ICMPv6_MLDV2                       143   /* MLDv2 Multicast Listener Report  [RFC 3810] */
#define ICMPv6_AGENTDISCOVREQ              144   /* Home Agent Address Discovery Request Message  [RFC 3775] */
#define ICMPv6_AGENTDISCOVREPLY            145   /* Home Agent Address Discovery Reply Message  [RFC 3775] */
#define ICMPv6_MOBPREFIXSOLICIT            146   /* Mobile Prefix Solicitation  [RFC 3775] */
#define ICMPv6_MOBPREFIXADVERT             147   /* Mobile Prefix Advertisement  [RFC 3775] */
#define ICMPv6_CERTPATHSOLICIT             148   /* Certification Path Solicitation  [RFC 3971] */
#define ICMPv6_CERTPATHADVERT              149   /* Certification Path Advertisement  [RFC 3971] */
#define ICMPv6_EXPMOBILITY                 150   /* Experimental mobility protocols  [RFC 4065] */
#define ICMPv6_MRDADVERT                   151   /* MRD, Multicast Router Advertisement  [RFC 4286] */
#define ICMPv6_MRDSOLICIT                  152   /* MRD, Multicast Router Solicitation  [RFC 4286] */
#define ICMPv6_MRDTERMINATE                153   /* MRD, Multicast Router Termination  [RFC 4286] */
#define ICMPv6_FMIPV6                      154   /* FMIPv6 messages  [RFC 5568] */

/* Node Information parameters */
/* -> Query types */
#define NI_QTYPE_NOOP      0
#define NI_QTYPE_UNUSED    1
#define NI_QTYPE_NODENAME  2
#define NI_QTYPE_NODEADDRS 3
#define NI_QTYPE_IPv4ADDRS 4
/* -> Misc */
#define NI_NONCE_LEN 8

/* Nping ICMPv6Header Class internal definitions */
#define ICMPv6_COMMON_HEADER_LEN    4
#define ICMPv6_MIN_HEADER_LEN       8
#define ICMPv6_UNREACH_LEN          (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_PKTTOOBIG_LEN        (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_TIMXCEED_LEN         (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_PARAMPROB_LEN        (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_ECHO_LEN             (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_ECHOREPLY_LEN        (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_ROUTERSOLICIT_LEN    (ICMPv6_COMMON_HEADER_LEN+4)
#define ICMPv6_ROUTERADVERT_LEN     (ICMPv6_COMMON_HEADER_LEN+12)
#define ICMPv6_NGHBRSOLICIT_LEN     (ICMPv6_COMMON_HEADER_LEN+20)
#define ICMPv6_NGHBRADVERT_LEN      (ICMPv6_COMMON_HEADER_LEN+20)
#define ICMPv6_REDIRECT_LEN         (ICMPv6_COMMON_HEADER_LEN+36)
#define ICMPv6_RTRRENUM_LEN         (ICMPv6_COMMON_HEADER_LEN+12)
#define ICMPv6_NODEINFO_LEN         (ICMPv6_COMMON_HEADER_LEN+12)
#define ICMPv6_MLD_LEN              (ICMPv6_COMMON_HEADER_LEN+20)
/* This must the MAX() of all values defined above*/
#define ICMPv6_MAX_MESSAGE_BODY     (ICMPv6_REDIRECT_LEN-ICMPv6_COMMON_HEADER_LEN)



/* Node Information flag bitmaks */
#define ICMPv6_NI_FLAG_T    0x01
#define ICMPv6_NI_FLAG_A    0x02
#define ICMPv6_NI_FLAG_C    0x04
#define ICMPv6_NI_FLAG_L    0x08
#define ICMPv6_NI_FLAG_G    0x10
#define ICMPv6_NI_FLAG_S    0x20

class ICMPv6Header : public ICMPHeader {

        /**********************************************************************/
        /* COMMON ICMPv6 packet HEADER                                        */
        /**********************************************************************/
        /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                         Message Body                          +
           |                                                               | */
        struct nping_icmpv6_hdr{
            u8 type;
            u8 code;
            u16 checksum;
            u8 data[ICMPv6_MAX_MESSAGE_BODY];
        }__attribute__((__packed__));
        typedef struct nping_icmpv6_hdr nping_icmpv6_hdr_t;

        
        /**********************************************************************/
        /* ICMPv6 MESSAGE SPECIFIC HEADERS                                    */
        /**********************************************************************/

        /* Destination Unreachable Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             Unused                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                    As much of invoking packet                 |
          +                as possible without the ICMPv6 packet          +
          |                exceeding the minimum IPv6 MTU [IPv6]          | */
        struct dest_unreach_msg{
            u32 unused;
            //u8 invoking_pkt[?];
        }__attribute__((__packed__));
        typedef struct dest_unreach_msg dest_unreach_msg_t;


        /* Packet Too Big Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             MTU                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                    As much of invoking packet                 |
          +               as possible without the ICMPv6 packet           +
          |               exceeding the minimum IPv6 MTU [IPv6]           | */
        struct pkt_too_big_msg{
            u32 mtu;
            //u8 invoking_pkt[?];
        }__attribute__((__packed__));
        typedef struct pkt_too_big_msg pkt_too_big_msg_t;

        
        /* Time Exceeded Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                             Unused                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                    As much of invoking packet                 |
          +               as possible without the ICMPv6 packet           +
          |               exceeding the minimum IPv6 MTU [IPv6]           | */
        struct time_exceeded_msg{
            u32 unused;
            //u8 invoking_pkt[?];
        }__attribute__((__packed__));
        typedef struct time_exceeded_msg time_exceeded_msg_t;

        
        /* Parameter Problem Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                            Pointer                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                    As much of invoking packet                 |
          +               as possible without the ICMPv6 packet           +
          |               exceeding the minimum IPv6 MTU [IPv6]           | */
        struct parameter_problem_msg{
            u32 pointer;
            //u8 invoking_pkt[?];
        }__attribute__((__packed__));
        typedef struct parameter_problem_msg parameter_problem_msg_t;

        
        /* Echo Request/Response Messages
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Identifier          |        Sequence Number        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Data ...
          +-+-+-+-+-                                                        */
        struct echo_msg{
            u16 id;
            u16 seq;
            //u8 data[?];
        }__attribute__((__packed__));
        typedef struct echo_msg echo_msg_t;
        
        /* Router Advertisement Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Cur Hop Limit |M|O|H|Prf|P|R|R|       Router Lifetime         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                         Reachable Time                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                          Retrans Timer                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Options ...
          +-+-+-+-+-+-+-+-+-+-+-+-                                          */
        struct router_advert_msg{
            u8 current_hop_limit;
            u8 autoconfig_flags; /* See RFC 5175 */
            u16 router_lifetime;
            u32 reachable_time;
            u32 retransmission_timer;
            //u8 icmpv6_options[?];
        }__attribute__((__packed__));
        typedef struct router_advert_msg router_advert_msg_t;

        
        /* Router Solicitation Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                            Reserved                           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Options ...
          +-+-+-+-+-+-+-+-+-+-+-+-                                          */
        struct router_solicit_msg{
            u32 reserved;
            //u8 icmpv6_options[?];
        }__attribute__((__packed__));
        typedef struct router_solicit_msg router_solicit_msg_t;


        /* Neighbor Advertisement Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |R|S|O|                     Reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                                                               +
          |                                                               |
          +                       Target Address                          +
          |                                                               |
          +                                                               +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Options ...
          +-+-+-+-+-+-+-+-+-+-+-+-                                          */
        struct neighbor_advert_msg{
            u8 flags;
            u8 reserved[3];
            u8 target_address[16];
            //u8 icmpv6_options[?];
        }__attribute__((__packed__));
        typedef struct neighbor_advert_msg neighbor_advert_msg_t;


        /* Neighbor Solicitation Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                                                               +
          |                                                               |
          +                       Target Address                          +
          |                                                               |
          +                                                               +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Options ...
          +-+-+-+-+-+-+-+-+-+-+-+- */
        struct neighbor_solicit_msg{
            u32 reserved;
            u8 target_address[16];
            //u8 icmpv6_options[?];
        }__attribute__((__packed__));
        typedef struct neighbor_solicit_msg neighbor_solicit_msg_t;


        /* Redirect Message
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |          Checksum             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                                                               +
          |                                                               |
          +                       Target Address                          +
          |                                                               |
          +                                                               +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                                                               +
          |                                                               |
          +                     Destination Address                       +
          |                                                               |
          +                                                               +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |   Options ...
          +-+-+-+-+-+-+-+-+-+-+-+-                                          */
        struct redirect_msg{
            u32 reserved;
            u8 target_address[16];
            u8 destination_address[16];
            //u8 icmpv6_options[?];
        }__attribute__((__packed__));
        typedef struct redirect_msg redirect_msg_t;

        
        /* Router Renumbering Header
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |            Checksum           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                        SequenceNumber                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | SegmentNumber |     Flags     |            MaxDelay           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          /                       RR Message Body                         /
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct router_renumbering_msg{
            u32 seq;
            u8 segment_number;
            u8 flags;
            u16 max_delay;
            u32 reserved;
            //u8 rr_msg_body[?];
        }__attribute__((__packed__));
        typedef struct router_renumbering_msg router_renumbering_msg_t;


         /* Node Information Queries
           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |     Code      |           Checksum            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Qtype             |       unused      |G|S|L|C|A|T|
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                             Nonce                             +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          /                             Data                              /
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct nodeinfo_msg{
            u16 qtype;
            u16 flags;
            u64 nonce;
            //u8 data[?];
        }__attribute__((__packed__));
        typedef struct nodeinfo_msg nodeinfo_msg_t;


        /* Multicast Listener Discovery
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     Type      |     Code      |          Checksum             |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     Maximum Response Delay    |          Reserved             |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               |
         +                                                               +
         |                                                               |
         +                       Multicast Address                       +
         |                                                               |
         +                                                               +
         |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct mld_msg{
            u16 max_response_delay;
            u16 reserved;
            u8 mcast_address[16];
        }__attribute__((__packed__));
        typedef struct mld_msg mld_msg_t;

        
        nping_icmpv6_hdr_t h;

        /* Helper pointers */
        dest_unreach_msg_t       *h_du;
        pkt_too_big_msg_t        *h_ptb;
        time_exceeded_msg_t      *h_te;
        parameter_problem_msg_t  *h_pp;
        echo_msg_t               *h_e;
        router_advert_msg_t      *h_ra;
        router_solicit_msg_t     *h_rs;
        neighbor_advert_msg_t    *h_na;
        neighbor_solicit_msg_t   *h_ns;
        redirect_msg_t           *h_r;
        router_renumbering_msg_t *h_rr;
        nodeinfo_msg_t           *h_ni;
        mld_msg_t                *h_mld;

    public:
        ICMPv6Header();
        ~ICMPv6Header();
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

        /* Code */
        int setCode(u8 c);
        u8 getCode() const;
        bool validateCode();
        bool validateCode(u8 type, u8 code);

        /* Checksum */
        int setSum();
        int setSum(u16 s);
        int setSumRandom();
        u16 getSum() const;

        int setReserved(u32 val);
        u32 getReserved() const;
        int setUnused(u32 val);
        u32 getUnused() const;

        int setFlags(u8 val);
        u8 getFlags() const;

        int setMTU(u32 mtu);
        u32 getMTU() const;

        /* Parameter problem */
        int setPointer(u32 val);
        u32 getPointer() const;

        /* Echo */
        int setIdentifier(u16 val);
        u16 getIdentifier() const;
        int setSequence(u16 val);
        int setSequence(u32 val);
        u32 getSequence() const;

        /* Router Advertisement */
        int setCurrentHopLimit(u8 val);
        u8 getCurrentHopLimit() const;

        int setRouterLifetime(u16 val);
        u16 getRouterLifetime() const;

        int setReachableTime(u32 val);
        u32 getReachableTime() const;

        int setRetransmissionTimer(u32 val);
        u32 getRetransmissionTimer() const;

        int setTargetAddress(struct in6_addr addr);
        struct in6_addr getTargetAddress() const;

        int setDestinationAddress(struct in6_addr addr);
        struct in6_addr getDestinationAddress() const;

        int setSegmentNumber(u8 val);
        u8 getSegmentNumber() const;

        int setMaxDelay(u16 val);
        u16 getMaxDelay() const;

        /* Node Information Queries */
        int setQtype(u16 val);
        u16 getQtype() const;
        int setNodeInfoFlags(u16 val);
        u16 getNodeInfoFlags() const;
        int  setG(bool flag_value=true);
        bool getG() const;
        int  setS(bool flag_value=true);
        bool getS() const;
        int  setL(bool flag_value=true);
        bool getL() const;
        int  setC(bool flag_value=true);
        bool getC() const;
        int  setA(bool flag_value=true);
        bool getA() const;
        int  setT(bool flag_value=true);
        bool getT() const;
        int setNonce(u64 nonce_value);
        int setNonce(const u8 *nonce);
        u64 getNonce() const;

        /* Multicast Listener Discovery */
        int setMulticastAddress(struct in6_addr addr);
        struct in6_addr getMulticastAddress() const;

        /* Misc */
        int getHeaderLengthFromType(u8 type) const;
        bool isError() const;
        const char *type2string(int type, int code) const;

}; /* End of class ICMPv6Header */

#endif
