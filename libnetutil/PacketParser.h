
/***************************************************************************
 * PacketParser.h -- The PacketParser Class offers methods to parse        *
 * received network packets. Its main purpose is to facilitate the         *
 * conversion of raw sequences of bytes into chains of objects of the      *
 * PacketElement family.                                                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
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
/* This code was originally part of the Nping tool.                        */

#ifndef __PACKETPARSER_H__
#define __PACKETPARSER_H__ 1

#include "ApplicationLayerElement.h"
#include "ARPHeader.h"
#include "DataLinkLayerElement.h"
#include "EthernetHeader.h"
#include "ICMPHeader.h"
#include "ICMPv4Header.h"
#include "ICMPv6Header.h"
#include "ICMPv6Option.h"
#include "ICMPv6RRBody.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "NetworkLayerElement.h"
#include "PacketElement.h"
#include "RawData.h"
#include "TCPHeader.h"
#include "TransportLayerElement.h"
#include "UDPHeader.h"
#include "HopByHopHeader.h"
#include "DestOptsHeader.h"
#include "FragmentHeader.h"
#include "RoutingHeader.h"


#define LINK_LAYER         2
#define NETWORK_LAYER      3
#define TRANSPORT_LAYER    4
#define APPLICATION_LAYER  5
#define EXTHEADERS_LAYER   6

typedef struct header_type_string{
    u32 type;
    const char *str;
}header_type_string_t;


typedef struct packet_type{
    u32 type;
    u32 length;
}pkt_type_t;


class PacketParser {

    private:
    
    public:

    /* Misc */
    PacketParser();
    ~PacketParser();
    void reset();

    static const char *header_type2string(int val);
    static pkt_type_t *parse_packet(const u8 *pkt, size_t pktlen, bool eth_included);
    static int dummy_print_packet_type(const u8 *pkt, size_t pktlen, bool eth_included); /* TODO: remove */
    static int dummy_print_packet(const u8 *pkt, size_t pktlen, bool eth_included); /* TODO: remove */
    static int payload_offset(const u8 *pkt, size_t pktlen, bool link_included);
    static PacketElement *split(const u8 *pkt, size_t pktlen, bool eth_included);
    static PacketElement *split(const u8 *pkt, size_t pktlen);
    static int freePacketChain(PacketElement *first);
    static const char *test_packet_parser(PacketElement *test_pkt);
    static bool is_response(PacketElement *sent, PacketElement *rcvd);

}; /* End of class PacketParser */

#endif /* __PACKETPARSER_H__ */
