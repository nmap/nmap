
/***************************************************************************
 * PacketParser.cc -- The PacketParser Class offers methods to parse       *
 * received network packets. Its main purpose is to facilitate the         *
 * conversion of raw sequences of bytes into chains of objects of the      *
 * PacketElement family.                                                   *
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

#include "PacketParser.h"
#include <assert.h>

#define PKTPARSERDEBUG false

PacketParser::PacketParser() {
    this->reset();
} /* End of PacketParser constructor */


PacketParser::~PacketParser() {

} /* End of PacketParser destructor */


/** Sets every attribute to its default value- */
void PacketParser::reset() {

} /* End of PacketParser destructor */


const char *PacketParser::header_type2string(int val){
  header_type_string_t header_types[]={
    {HEADER_TYPE_IPv6_HOPOPT, "IPv6 Hop-by-Hop"},
    {HEADER_TYPE_ICMPv4,"ICMPv4"},
    {HEADER_TYPE_IGMP,"IGMP"},
    {HEADER_TYPE_IPv4,"IPv4"},
    {HEADER_TYPE_TCP,"TCP"},
    {HEADER_TYPE_EGP,"EGP"},
    {HEADER_TYPE_UDP,"UDP"},
    {HEADER_TYPE_IPv6,"IPv6"},
    {HEADER_TYPE_IPv6_ROUTE,"IPv6-Route"},
    {HEADER_TYPE_IPv6_FRAG,"IPv6-Frag"},
    {HEADER_TYPE_GRE,"GRE"},
    {HEADER_TYPE_ESP,"ESP"},
    {HEADER_TYPE_AH,"AH"},
    {HEADER_TYPE_ICMPv6,"ICMPv6"},
    {HEADER_TYPE_IPv6_NONXT,"IPv6-NoNxt"},
    {HEADER_TYPE_IPv6_OPTS,"IPv6-Opts"},
    {HEADER_TYPE_EIGRP,"EIGRP"},
    {HEADER_TYPE_ETHERNET,"Ethernet"},
    {HEADER_TYPE_L2TP,"L2TP"},
    {HEADER_TYPE_SCTP,"SCTP"},
    {HEADER_TYPE_IPv6_MOBILE,"Mobility Header"},
    {HEADER_TYPE_MPLS_IN_IP,"MPLS-in-IP"},
    {HEADER_TYPE_ARP,"ARP"},
    {HEADER_TYPE_RAW_DATA,"Raw Data"},
    {0,NULL}
  };
  int i=0;
  for(i=0; header_types[i].str!=NULL; i++ ){
      if((int)header_types[i].type==val)
          return header_types[i].str;
  }
  return NULL;
} /* End of header_type2string() */



#define MAX_HEADERS_IN_PACKET 32
pkt_type_t *PacketParser::parse_packet(const u8 *pkt, size_t pktlen, bool eth_included){
  if(PKTPARSERDEBUG)printf("%s(%p, %lu)\n", __func__, pkt, (long unsigned)pktlen);
  static pkt_type_t this_packet[MAX_HEADERS_IN_PACKET+1]; /* Packet structure array   */
  u8 current_header=0;             /* Current array position of "this_packet" */
  const u8 *curr_pkt=pkt;          /* Pointer to current part of the packet   */
  size_t curr_pktlen=pktlen;       /* Remaining packet length                 */
  int ethlen=0, arplen=0;          /* Aux length variables: link layer        */
  int iplen=0,ip6len=0;            /* Aux length variables: network layer     */
  int tcplen=0,udplen=0,icmplen=0; /* Aux length variables: transport layer   */
  int exthdrlen=0;                 /* Aux length variables: extension headers */
  int next_layer=0;                /* Next header type to process             */
  int expected=0;                  /* Next protocol expected                  */
  bool finished=false;             /* Loop breaking flag                      */
  bool unknown_hdr=false;          /* Indicates unknown header found          */
  IPv4Header ip4;
  IPv6Header ip6;
  TCPHeader tcp;
  UDPHeader udp;
  ICMPv4Header icmp4;
  ICMPv6Header icmp6;
  EthernetHeader eth;
  DestOptsHeader ext_dopts;
  FragmentHeader ext_frag;
  HopByHopHeader ext_hopt;
  RoutingHeader ext_routing;
  ARPHeader arp;
  memset(this_packet, 0, sizeof(this_packet));

  /* Decide which layer we have to start from */
  if( eth_included ){
    next_layer=LINK_LAYER;
    expected=HEADER_TYPE_ETHERNET;
  }else{
    next_layer=NETWORK_LAYER;
  }

  /* Header processing loop */
  while(!finished && curr_pktlen>0 && current_header<MAX_HEADERS_IN_PACKET){
    /* Ethernet and ARP headers ***********************************************/
    if(next_layer==LINK_LAYER ){
        if(PKTPARSERDEBUG)puts("Next Layer=Link");
        if(expected==HEADER_TYPE_ETHERNET){
            if(PKTPARSERDEBUG)puts("Expected Layer=Ethernet");
            if(eth.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            if( (ethlen=eth.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            /* Determine next header type */
            switch( eth.getEtherType() ){
                case ETHTYPE_IPV4:
                    expected=HEADER_TYPE_IPv4;
                    next_layer=NETWORK_LAYER;
                break;
                case ETHTYPE_IPV6:
                    expected=HEADER_TYPE_IPv6;
                    next_layer=NETWORK_LAYER;
                break;
                case ETHTYPE_ARP:
                    next_layer=LINK_LAYER;
                    expected=HEADER_TYPE_ARP;
                break;
                default:
                    next_layer=APPLICATION_LAYER;
                    expected=HEADER_TYPE_RAW_DATA;
                break;
            }
            this_packet[current_header].length=ethlen;
            this_packet[current_header++].type=HEADER_TYPE_ETHERNET;
            eth.reset();
            curr_pkt+=ethlen;
            curr_pktlen-=ethlen;
        }else if(expected==HEADER_TYPE_ARP){
            if(PKTPARSERDEBUG)puts("Expected Layer=ARP");
            if(arp.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            if( (arplen=arp.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            this_packet[current_header].length=arplen;
            this_packet[current_header++].type=HEADER_TYPE_ARP;
            arp.reset();
            curr_pkt+=arplen;
            curr_pktlen-=arplen;
            if(curr_pktlen>0){
                next_layer=APPLICATION_LAYER;
                expected=HEADER_TYPE_RAW_DATA;
            }else{
                finished=true;
            }
        }else{
            assert(finished==true);
        }
    /* IPv4 and IPv6 headers **************************************************/
    }else if(next_layer==NETWORK_LAYER){
        if(PKTPARSERDEBUG)puts("Next Layer=Network");
        /* Determine IP version */
        if (ip4.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE){
            unknown_hdr=true;
            break;
        }

        /* IP version 4 ---------------------------------*/
        if(ip4.getVersion()==4){
            if( (iplen=ip4.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            /* Determine next header type */
            switch(ip4.getNextProto()){
                case HEADER_TYPE_ICMPv4:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_ICMPv4;
                break;
                case HEADER_TYPE_IPv4: /* IP in IP */
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv4;
                break;
                case HEADER_TYPE_TCP:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_TCP;
                break;
                case HEADER_TYPE_UDP:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_UDP;
                break;
                case HEADER_TYPE_IPv6: /* IPv6 in IPv4 */
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv6;
                break;
                default:
                    next_layer=APPLICATION_LAYER;
                    expected=HEADER_TYPE_RAW_DATA;
                break;
            }
            this_packet[current_header].length=iplen;
            this_packet[current_header++].type=HEADER_TYPE_IPv4;
            ip4.reset();
            curr_pkt+=iplen;
            curr_pktlen-=iplen;
        /* IP version 6 ---------------------------------*/
        }else if(ip4.getVersion()==6){
            ip4.reset();
            if (ip6.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            if( (ip6len=ip6.validate())==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            switch( ip6.getNextHeader() ){
                case HEADER_TYPE_ICMPv6:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_ICMPv6;
                break;
                case HEADER_TYPE_IPv4: /* IPv4 in IPv6 */
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv4;
                break;
                case HEADER_TYPE_TCP:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_TCP;
                break;
                case HEADER_TYPE_UDP:
                    next_layer=TRANSPORT_LAYER;
                    expected=HEADER_TYPE_UDP;
                break;
                case HEADER_TYPE_IPv6: /* IPv6 in IPv6 */
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv6;
                break;
                case HEADER_TYPE_IPv6_HOPOPT:
                    next_layer=EXTHEADERS_LAYER;
                    expected=HEADER_TYPE_IPv6_HOPOPT;
                break;
                case HEADER_TYPE_IPv6_OPTS:
                    next_layer=EXTHEADERS_LAYER;
                    expected=HEADER_TYPE_IPv6_OPTS;
                break;
                case HEADER_TYPE_IPv6_ROUTE:
                    next_layer=EXTHEADERS_LAYER;
                    expected=HEADER_TYPE_IPv6_ROUTE;
                break;
                case HEADER_TYPE_IPv6_FRAG:
                    next_layer=EXTHEADERS_LAYER;
                    expected=HEADER_TYPE_IPv6_FRAG;
                break;
                default:
                    next_layer=APPLICATION_LAYER;
                    expected=HEADER_TYPE_RAW_DATA;
                break;
            }
            this_packet[current_header].length=ip6len;
            this_packet[current_header++].type=HEADER_TYPE_IPv6;
            ip6.reset();
            curr_pkt+=ip6len;
            curr_pktlen-=ip6len;
        /* Bogus IP version -----------------------------*/
        }else{
            /* Wrong IP version, treat as raw data. */
            next_layer=APPLICATION_LAYER;
            expected=HEADER_TYPE_RAW_DATA;
        }
    /* TCP, UDP, ICMPv4 and ICMPv6 headers ************************************/
    }else if(next_layer==TRANSPORT_LAYER){
        if(PKTPARSERDEBUG)puts("Next Layer=Transport");
        if(expected==HEADER_TYPE_TCP){
            if(PKTPARSERDEBUG)puts("Expected Layer=TCP");
            if(tcp.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (tcplen=tcp.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            expected=HEADER_TYPE_RAW_DATA;
            this_packet[current_header].length=tcplen;
            this_packet[current_header++].type=HEADER_TYPE_TCP;
            tcp.reset();
            curr_pkt+=tcplen;
            curr_pktlen-=tcplen;
            next_layer=APPLICATION_LAYER;
        }else if(expected==HEADER_TYPE_UDP){
            if(PKTPARSERDEBUG)puts("Expected Layer=UDP");
            if(udp.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (udplen=udp.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            expected=HEADER_TYPE_RAW_DATA;
            this_packet[current_header].length=udplen;
            this_packet[current_header++].type=HEADER_TYPE_UDP;
            udp.reset();
            curr_pkt+=udplen;
            curr_pktlen-=udplen;
            next_layer=APPLICATION_LAYER;
        }else if(expected==HEADER_TYPE_ICMPv4){
            if(PKTPARSERDEBUG)puts("Expected Layer=ICMPv4");
            if(icmp4.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (icmplen=icmp4.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            switch( icmp4.getType() ){
                /* Types that include an IPv4 packet as payload */
                case ICMP_UNREACH:
                case ICMP_TIMXCEED:
                case ICMP_PARAMPROB:
                case ICMP_SOURCEQUENCH:
                case ICMP_REDIRECT:
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv4;
                break;
                /* ICMP types that include misc payloads (or no payload) */
                default:
                    expected=HEADER_TYPE_RAW_DATA;
                    next_layer=APPLICATION_LAYER;
                break;
            }
            this_packet[current_header].length=icmplen;
            this_packet[current_header++].type=HEADER_TYPE_ICMPv4;
            icmp4.reset();
            curr_pkt+=icmplen;
            curr_pktlen-=icmplen;
        }else if(expected==HEADER_TYPE_ICMPv6){
            if(PKTPARSERDEBUG)puts("Expected Layer=ICMPv6");
            if(icmp6.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            if( (icmplen=icmp6.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            switch( icmp6.getType() ){
                /* Types that include an IPv6 packet as payload */
                case ICMPv6_UNREACH:
                case ICMPv6_PKTTOOBIG:
                case ICMPv6_TIMXCEED:
                case ICMPv6_PARAMPROB:
                    next_layer=NETWORK_LAYER;
                    expected=HEADER_TYPE_IPv6;
                break;
                /* ICMPv6 types that include misc payloads (or no payload) */
                default:
                    expected=HEADER_TYPE_RAW_DATA;
                    next_layer=APPLICATION_LAYER;
                break;
            }
            this_packet[current_header].length=icmplen;
            this_packet[current_header++].type=HEADER_TYPE_ICMPv6;
            icmp6.reset();
            curr_pkt+=icmplen;
            curr_pktlen-=icmplen;
        }else{
            /* Wrong application layer protocol, treat as raw data. */
            next_layer=APPLICATION_LAYER;
            expected=HEADER_TYPE_RAW_DATA;
        }

    /* IPv6 Extension Headers */
    }else if(next_layer==EXTHEADERS_LAYER){
        if(PKTPARSERDEBUG)puts("Next Layer=ExtHdr");
        u8 ext_next=0;
        /* Hop-by-Hop Options */
        if(expected==HEADER_TYPE_IPv6_HOPOPT){
            if(PKTPARSERDEBUG)puts("Expected=Hopt");
            if(ext_hopt.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (exthdrlen=ext_hopt.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            ext_next=ext_hopt.getNextHeader();
            ext_hopt.reset();
        /* Routing Header */
        }else if(expected==HEADER_TYPE_IPv6_ROUTE){
            if(PKTPARSERDEBUG)puts("Expected=Route");
            if(ext_routing.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (exthdrlen=ext_routing.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            ext_next=ext_routing.getNextHeader();
            ext_routing.reset();
        /* Fragmentation Header */
        }else if(expected==HEADER_TYPE_IPv6_FRAG){
            if(PKTPARSERDEBUG)puts("Expected=Frag");
            if(ext_frag.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (exthdrlen=ext_frag.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            ext_next=ext_frag.getNextHeader();
            ext_frag.reset();
        /* Destination Options Header */
        }else if(expected==HEADER_TYPE_IPv6_OPTS){
            if(PKTPARSERDEBUG)puts("Expected=Dopts");
            if(ext_dopts.storeRecvData(curr_pkt, curr_pktlen)==OP_FAILURE ){
                unknown_hdr=true;
                break;
            }
            if( (exthdrlen=ext_dopts.validate())==OP_FAILURE){
                unknown_hdr=true;
                break;
            }
            ext_next=ext_dopts.getNextHeader();
            ext_dopts.reset();
        }else{
            /* Should never happen. */
            unknown_hdr=true;
            break;
        }

        /* Update the info for this header */
        this_packet[current_header].length=exthdrlen;
        this_packet[current_header++].type=expected;
        curr_pkt+=exthdrlen;
        curr_pktlen-=exthdrlen;

        /* Lets's see what comes next */
        switch(ext_next){
            case HEADER_TYPE_ICMPv6:
                next_layer=TRANSPORT_LAYER;
                expected=HEADER_TYPE_ICMPv6;
            break;
            case HEADER_TYPE_IPv4: /* IPv4 in IPv6 */
                next_layer=NETWORK_LAYER;
                expected=HEADER_TYPE_IPv4;
            break;
            case HEADER_TYPE_TCP:
                next_layer=TRANSPORT_LAYER;
                expected=HEADER_TYPE_TCP;
            break;
            case HEADER_TYPE_UDP:
                next_layer=TRANSPORT_LAYER;
                expected=HEADER_TYPE_UDP;
            break;
            case HEADER_TYPE_IPv6: /* IPv6 in IPv6 */
                next_layer=NETWORK_LAYER;
                expected=HEADER_TYPE_IPv6;
            break;
            case HEADER_TYPE_IPv6_HOPOPT:
                next_layer=EXTHEADERS_LAYER;
                expected=HEADER_TYPE_IPv6_HOPOPT;
            break;
            case HEADER_TYPE_IPv6_OPTS:
                next_layer=EXTHEADERS_LAYER;
                expected=HEADER_TYPE_IPv6_OPTS;
            break;
            case HEADER_TYPE_IPv6_ROUTE:
                next_layer=EXTHEADERS_LAYER;
                expected=HEADER_TYPE_IPv6_ROUTE;
            break;
            case HEADER_TYPE_IPv6_FRAG:
                next_layer=EXTHEADERS_LAYER;
                expected=HEADER_TYPE_IPv6_FRAG;
            break;
            default:
                next_layer=APPLICATION_LAYER;
                expected=HEADER_TYPE_RAW_DATA;
            break;
        }

    /* Miscellaneous payloads *************************************************/
    }else{ // next_layer==APPLICATION_LAYER
        if(PKTPARSERDEBUG)puts("Next Layer=Application");
        if(curr_pktlen>0){
            
            /* If we get here it is possible that the packet is ARP but 
             * we have no access to the original Ethernet header. We 
             * determine if this header is ARP by checking its size 
             * and checking for some common values. */          
            if(arp.storeRecvData(curr_pkt, curr_pktlen)!=OP_FAILURE){
              if( (arplen=arp.validate())!=OP_FAILURE){
                if(arp.getHardwareType()==HDR_ETH10MB){
                  if(arp.getProtocolType()==0x0800){
                    if(arp.getHwAddrLen()==ETH_ADDRESS_LEN){
                      if(arp.getProtoAddrLen()==IPv4_ADDRESS_LEN){
                        this_packet[current_header].length=arplen;
                        this_packet[current_header++].type=HEADER_TYPE_ARP;
                        arp.reset();
                        curr_pkt+=arplen;
                        curr_pktlen-=arplen;
                        if(curr_pktlen>0){
                            next_layer=APPLICATION_LAYER;
                            expected=HEADER_TYPE_RAW_DATA;
                        }else{
                            finished=true;
                        }
                      }
                    }
                  }
                }
              }
            }
                      
            //if(expected==HEADER_TYPE_DNS){
            //}else if(expected==HEADER_TYPE_HTTP){
            //}... ETC
            this_packet[current_header].length=curr_pktlen;
            this_packet[current_header++].type=HEADER_TYPE_RAW_DATA;
            curr_pktlen=0;
        }
        finished=true;
    }
  } /* End of header processing loop */

  /* If we couldn't validate some header, treat that header and any remaining
   * data, as raw application data. */
  if (unknown_hdr==true){
    if(curr_pktlen>0){
        if(PKTPARSERDEBUG)puts("Unknown layer found. Treating it as raw data.");
        this_packet[current_header].length=curr_pktlen;
        this_packet[current_header++].type=HEADER_TYPE_RAW_DATA;
    }
  }

  return this_packet;
} /* End of parse_received_packet() */


/* TODO: remove */
int PacketParser::dummy_print_packet_type(const u8 *pkt, size_t pktlen, bool eth_included){
  pkt_type_t *packetheaders=PacketParser::parse_packet(pkt, pktlen, eth_included);
  for(int i=0; packetheaders[i].length!=0; i++){
    printf("%s:", header_type2string(packetheaders[i].type));
  }
  printf("\n");
  return OP_SUCCESS;
} /* End of dummy_print_packet_type() */


int PacketParser::dummy_print_packet(const u8 *pkt, size_t pktlen, bool eth_included){
  PacketElement *me=NULL, *aux=NULL;
  if( (me=split(pkt, pktlen, eth_included))==NULL )
    return OP_FAILURE;
  else{
    me->print(stdout, PRINT_DETAIL_HIGH);
    printf("\n");
  }
  /* Free the structs */
  while(me!=NULL){
    aux=me->getNextElement();
    delete me;
    me=aux;
  }
  return OP_SUCCESS;
} /* End of dummy_print_packet() */



/** For a given packet, this method determines where the application layer data
  * begins. It returs a positive offset if any application data was found, zero
  * if the packet did not contain application data and a negative integer in
  * case of error. */
int PacketParser::payload_offset(const u8 *pkt, size_t pktlen, bool link_included){
  PacketElement *me=NULL, *aux=NULL;
  size_t offset=pktlen; /* Initially, point to the end of the packet. */

  /* Safe checks*/
  if(pkt==NULL || pktlen<=0)
      return -1;

  dummy_print_packet_type(pkt, pktlen, link_included);

  /* Split the packet into separate protocol headers */
  if( (me=split(pkt, pktlen, link_included))==NULL )
    return -2;
  else{
      aux=me;
  }

  /* Find if there is application data and where it begins */
  while(me!=NULL){
    /* When we find application data, we compute the offset by substacting the
       length of the application data from the packet's total length */
    if(me->protocol_id()==HEADER_TYPE_RAW_DATA){
        offset=pktlen-me->getLen();
        break;
        me=me->getNextElement();
    }else{
        me=me->getNextElement();
    }
  }

  /* Free the structs */
  me=aux;
  while(me!=NULL){
    aux=me->getNextElement();
    delete me;
    me=aux;
  }

  /* Return 0 if we didn't find any application data */
  if(offset==pktlen){
      return 0;
  }else{
      return offset;
  }
} /* End of payload_offset() */




PacketElement *PacketParser::split(const u8 *pkt, size_t pktlen){
  return split(pkt, pktlen, false);
} /* End of split() */


PacketElement *PacketParser::split(const u8 *pkt, size_t pktlen, bool eth_included){
  pkt_type_t *packetheaders=NULL;
  const u8 *curr_pkt=pkt;
  PacketElement *first=NULL;
  PacketElement *last=NULL;
  IPv4Header *ip4=NULL;
  IPv6Header *ip6=NULL;
  DestOptsHeader *ext_dopts=NULL;
  FragmentHeader *ext_frag=NULL;
  HopByHopHeader *ext_hopt=NULL;
  RoutingHeader *ext_routing=NULL;
  TCPHeader *tcp=NULL;
  UDPHeader *udp=NULL;
  ICMPv4Header *icmp4=NULL;
  ICMPv6Header *icmp6=NULL;
  EthernetHeader *eth=NULL;
  ARPHeader *arp=NULL;
  RawData *raw=NULL;

  /* Analyze the packet. This returns a list of header types and lengths */
  if((packetheaders=PacketParser::parse_packet(pkt, pktlen, eth_included))==NULL)
    return NULL;

  /* Store each header in its own PacketHeader object type */
  for(int i=0; packetheaders[i].length!=0; i++){

    switch(packetheaders[i].type){

        case HEADER_TYPE_ETHERNET:
            eth=new EthernetHeader();
            eth->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=eth;
            }else{
                last->setNextElement(eth);
            }
            last=eth;
        break;

        case HEADER_TYPE_ARP:
            arp=new ARPHeader();
            arp->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=arp;
            }else{
                last->setNextElement(arp);
            }
            last=arp;
        break;

        case HEADER_TYPE_IPv4:
            ip4=new IPv4Header();
            ip4->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ip4;
            }else{
                last->setNextElement(ip4);
            }
            last=ip4;
        break;

        case HEADER_TYPE_IPv6:
            ip6=new IPv6Header();
            ip6->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ip6;
            }else{
                last->setNextElement(ip6);
            }
            last=ip6;
        break;

        case HEADER_TYPE_TCP:
            tcp=new TCPHeader();
            tcp->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=tcp;
            }else{
                last->setNextElement(tcp);
            }
            last=tcp;
        break;

        case HEADER_TYPE_UDP:
            udp=new UDPHeader();
            udp->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=udp;
            }else{
                last->setNextElement(udp);
            }
            last=udp;
        break;

        case HEADER_TYPE_ICMPv4:
            icmp4=new ICMPv4Header();
            icmp4->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=icmp4;
            }else{
                last->setNextElement(icmp4);
            }
            last=icmp4;
        break;

        case HEADER_TYPE_ICMPv6:
            icmp6=new ICMPv6Header();
            icmp6->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=icmp6;
            }else{
                last->setNextElement(icmp6);
            }
            last=icmp6;
        break;

        case HEADER_TYPE_IPv6_HOPOPT:
            ext_hopt=new HopByHopHeader();
            ext_hopt->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ext_hopt;
            }else{
                last->setNextElement(ext_hopt);
            }
            last=ext_hopt;
        break;

        case HEADER_TYPE_IPv6_ROUTE:
            ext_routing=new RoutingHeader();
            ext_routing->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ext_routing;
            }else{
                last->setNextElement(ext_routing);
            }
            last=ext_routing;
        break;

        case HEADER_TYPE_IPv6_FRAG:
            ext_frag=new FragmentHeader();
            ext_frag->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ext_frag;
            }else{
                last->setNextElement(ext_frag);
            }
            last=ext_frag;
        break;

        case HEADER_TYPE_IPv6_OPTS:
            ext_dopts=new DestOptsHeader();
            ext_dopts->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=ext_dopts;
            }else{
                last->setNextElement(ext_dopts);
            }
            last=ext_dopts;
        break;

        case HEADER_TYPE_RAW_DATA:
        default:
            raw=new RawData();
            raw->storeRecvData(curr_pkt, packetheaders[i].length);
            if(first==NULL){
                first=raw;
            }else{
                last->setNextElement(raw);
            }
            last=raw;
        break;
    }
    curr_pkt+=packetheaders[i].length;
  }
  return first;
} /* End of split() */


/* This method frees a chain of PacketElement objects. Note that objects in
 * the chain are freed by calling "delete" on them, so only those instances
 * that have been obtained through a call to "new" should be passed to this
 * method. Chains returned by PacketParser::split() are safe to use with this.*/
int PacketParser::freePacketChain(PacketElement *first){
  PacketElement *curr=first;
  PacketElement *next=NULL;
  while(curr!=NULL){
    next=curr->getNextElement();
    delete curr;
    curr=next;
  }
  return OP_SUCCESS;
} /* End of freePacketChain() */


/* This method is for debugging purposes only. It tests the packet parser and
 * the PacketElement class family. Basically it checks that the supplied
 * chain of PacketElements can be serialized and de-serialized correctly.
 * Returns NULL on success or an error string in case of failure. */
const char *PacketParser::test_packet_parser(PacketElement *test_pkt){
  const char *errmsg=NULL;
  PacketElement *parsed_pkt=NULL;
  PacketElement *orig_pkt=NULL;
  PacketElement *new_pkt=NULL;
  u8 *mypktbuff2=NULL;
  u8 *mypktbuff=NULL;

  if(test_pkt==NULL){
    errmsg="NULL pointer supplied";
    goto end;
  }

  /* Generate a serialized version of the packet */
  mypktbuff=(u8 *)safe_malloc(test_pkt->getLen());
  test_pkt->dumpToBinaryBuffer(mypktbuff, test_pkt->getLen());

  /* Generate a chain of PacketElement objects from the serialized version. */
  parsed_pkt=PacketParser::split(mypktbuff, test_pkt->getLen());

  if(parsed_pkt==NULL){
    errmsg="PacketParser::split() returned NULL";
    goto end;
  }
  if(parsed_pkt->getLen()!=test_pkt->getLen()){
    errmsg="Packets have different lengths";
    goto end;
  }

  /* Generate a serialized version of the new chain */
  mypktbuff2=(u8 *)safe_malloc(parsed_pkt->getLen());
  parsed_pkt->dumpToBinaryBuffer(mypktbuff2, parsed_pkt->getLen());

  /* Make sure both packets produce the exact same binary buffer */
  if(memcmp(mypktbuff, mypktbuff2, parsed_pkt->getLen())!=0){
    errmsg="The two packets do not result in the same binary buffer";
    goto end;
  }

  /* Now let's check that both chains have the same number and type of
   * PacketElements. */
  orig_pkt=test_pkt;
  new_pkt=parsed_pkt;
  while(orig_pkt!=NULL && new_pkt!=NULL){
    if(orig_pkt->protocol_id() != new_pkt->protocol_id() ){
        errmsg="Protocol IDs do not match";
        goto end;
    }
    orig_pkt=orig_pkt->getNextElement();
    new_pkt=new_pkt->getNextElement();
  }

  if(orig_pkt!=NULL || new_pkt!=NULL){
    errmsg="The two packets do not have the same number of chained elements.";
    goto end;
  }

  end:
    /* Free our allocations */
    if(mypktbuff!=NULL)
      free(mypktbuff);
    if(mypktbuff2!=NULL)
      free(mypktbuff2);
    if(parsed_pkt!=NULL)
      PacketParser::freePacketChain(parsed_pkt);

    /* If everything went well, errmsg should still be NULL. Otherwise it
     * should point to an error message.*/
    return errmsg;
}



/* Returns true if the supplied "rcvd" packet is a response to the "sent" packet.
 * This method currently handles IPv4, IPv6, ICMPv4, ICMPv6, TCP and UDP. Here 
 * some examples of what can be matched using it:
 * 
 * Probe: TCP SYN  -> Response TCP SYN|ACK
 * Probe: TCP SYN  -> Response TCP RST|ACK
 * Probe: UDP:53   -> Response UDP from port 53.
 * Probe ICMP Echo -> Response ICMP Echo reply
 * Probe ICMPv6 Neighbor Solicitation -> Response ICMPv6 Neighbor Advert
 * Probe Malformed IPv6 -> Response ICMPv6 Parameter Problem
 * Probe MLDv1 Query -> Response MLDv1 Report
 * Probe ICMP Timestamp request -> Response ICMP timestamp response
 * etc...
 *
 * Note that ICMP error messages are matched against sent probes (e.g: an ICMP
 * Parameter Problem generated as a result of an invalid TCP segment is matched
 * positively with the original TCP segment). Therefore, the caller must ensure 
 * that the received packet is what it expects before using it (e.g: the packet
 * is an actual TCP packet, not an ICMP error). 
 *
 * Warning: this method assumes that the probes you send are reasonably
 * different from each other. Don't expect a 100% accuracy if you send a bunch
 * of TCP segments with the same source and destination port numbers, or a
 * bunch of ICMP messages with the same identifier and sequence number. */
bool PacketParser::is_response(PacketElement *sent, PacketElement *rcvd){
  if(PKTPARSERDEBUG)printf("%s(): called\n", __func__);

  if(sent==NULL || rcvd==NULL)
    return false;
  
  /* If any of the packets is encapsulated in an Ethernet frame, strip the 
   * link layer header before proceeding with the matching process. */
  if(rcvd->protocol_id()==HEADER_TYPE_ETHERNET)
    if( (rcvd=rcvd->getNextElement())==NULL)
      return false;
  if(sent->protocol_id()==HEADER_TYPE_ETHERNET)
    if( (sent=sent->getNextElement())==NULL)
      return false;
  
  /* Make sure both packets have the same network layer */
  if(rcvd->protocol_id()!=sent->protocol_id())
    return false;
    
  /* The packet could be ARP */
  if(rcvd->protocol_id()==HEADER_TYPE_ARP){
    ARPHeader *sent_arp=(ARPHeader *)sent;
    ARPHeader *rcvd_arp=(ARPHeader *)rcvd;
    switch(sent_arp->getOpCode()){
      case OP_ARP_REQUEST:
        if(rcvd_arp->getOpCode()==OP_ARP_REPLY){
          /* TODO @todo: getTargetIP() and getSenderIP() should 
           * either return struct in_addr or IPAddress but not u32. */
          if(sent_arp->getTargetIP()==rcvd_arp->getSenderIP())
            if(sent_arp->getSenderIP()==rcvd_arp->getTargetIP())
              return true;
        }
        return false;
      break;
           
      /* We only support ARP, not RARP or other weird stuff. Also, if 
       * we didn't send a request, then we don't expect any response */
      case OP_RARP_REQUEST:
      case OP_DRARP_REQUEST:
      case OP_INARP_REQUEST:
      default:
        return false;
      break;
    
    }
    return false;
  }
  
  /* The packet is IPv4 or IPv6 */
  if(rcvd->protocol_id()!=HEADER_TYPE_IPv6 && rcvd->protocol_id()!=HEADER_TYPE_IPv4)
    return false;
  if(PKTPARSERDEBUG)printf("%s(): Both packets use IP.\n", __func__);

  /* Handle the network layer with a more specific class */
  NetworkLayerElement *rcvd_ip=(NetworkLayerElement *)rcvd;
  NetworkLayerElement *sent_ip=(NetworkLayerElement *)sent;

  /* Ensure the packet comes from the host we sent the probe to */
  if( memcmp(rcvd_ip->getSourceAddress(), sent_ip->getDestinationAddress(), rcvd_ip->getAddressLength())!=0 )
    return false;
  /* Ensure the received packet is destined to us */
  if( memcmp(rcvd_ip->getDestinationAddress(), sent_ip->getSourceAddress(), rcvd_ip->getAddressLength())!=0 )
    return false;

  if(PKTPARSERDEBUG)printf("%s(): Src and Dst addresses make sense.\n", __func__);
  
  /* Skip layers until we find ICMP or a transport protocol */
  PacketElement *rcvd_layer4=rcvd_ip->getNextElement();
  PacketElement *sent_layer4=sent_ip->getNextElement();
  while(rcvd_layer4!=NULL){
    if(rcvd_layer4->protocol_id()==HEADER_TYPE_UDP    || rcvd_layer4->protocol_id()==HEADER_TYPE_TCP ||
       rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv4 || rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv6 ){
        break;
    }else{
        rcvd_layer4=rcvd_layer4->getNextElement();
    }
  }
  while(sent_layer4!=NULL){
    if(sent_layer4->protocol_id()==HEADER_TYPE_UDP    || sent_layer4->protocol_id()==HEADER_TYPE_TCP ||
       sent_layer4->protocol_id()==HEADER_TYPE_ICMPv4 || sent_layer4->protocol_id()==HEADER_TYPE_ICMPv6 ){
        break;
    }else{
        sent_layer4=sent_layer4->getNextElement();
    }
  }
  if(rcvd_layer4==NULL || sent_layer4==NULL)
    return false;
  
  if(PKTPARSERDEBUG)printf("%s(): Layer 4 found for both packets.\n", __func__);

  /* If we get here it means that both packets have a proper layer4 protocol
   * header. Now we have to check which type are they and see if a probe-response
   * relation can be established. */
  if(sent_layer4->protocol_id()==HEADER_TYPE_ICMPv6 || sent_layer4->protocol_id()==HEADER_TYPE_ICMPv4){
      
    if(PKTPARSERDEBUG)printf("%s(): Sent packet is ICMP.\n", __func__);

    /* Make sure received packet is ICMP (we only expect ICMP responses for
     * ICMP probes) */
     if(rcvd_layer4->protocol_id()!=HEADER_TYPE_ICMPv6 && rcvd_layer4->protocol_id()!=HEADER_TYPE_ICMPv4 )
       return false;
    
    /* Make sure both packets have the same ICMP version */
    if(sent_layer4->protocol_id()!=rcvd_layer4->protocol_id())
      return false;

    if(PKTPARSERDEBUG)printf("%s(): Received packet is ICMP too.\n", __func__);    
    
    /* Check if the received ICMP is an error message. We don't care which kind
     * of error message it is. The only important thing is that error messages
     * contain a copy of the original datagram, and that's what we want to
     * match against the sent probe. */
    if( ((ICMPHeader *)rcvd_layer4)->isError() ){
      NetworkLayerElement *iperror=(NetworkLayerElement *)rcvd_layer4->getNextElement();
      
      if(PKTPARSERDEBUG)printf("%s(): Received ICMP is an error message.\n", __func__);

      /* ICMP error message must contain the original datagram */
      if(iperror==NULL)
        return false;

      /* The first header must be IP */
      if(iperror->protocol_id()!=HEADER_TYPE_IPv6 && iperror->protocol_id()!=HEADER_TYPE_IPv4)
        return false;

      /* The IP version must match the probe's */
      if(iperror->protocol_id()!=sent_ip->protocol_id())
        return false;

      /* Source and destination addresses must match the probe's */
      if( memcmp(iperror->getSourceAddress(), sent_ip->getSourceAddress(), iperror->getAddressLength())!=0 )
        return false;
      if( memcmp(iperror->getDestinationAddress(), sent_ip->getDestinationAddress(), iperror->getAddressLength())!=0 )
        return false;

      /* So far we've verified that the ICMP error contains an IP datagram that matches
       * what we sent. Now, let's find the upper layer ICMP header (skip extension
       * headers until we find ICMP) */
      ICMPHeader *inner_icmp=(ICMPHeader *)iperror->getNextElement();
      while(inner_icmp!=NULL){
        if(inner_icmp->protocol_id()==HEADER_TYPE_ICMPv4 || inner_icmp->protocol_id()==HEADER_TYPE_ICMPv6 ){
            break;
        }else{
            inner_icmp=(ICMPHeader *)inner_icmp->getNextElement();
        }
      }
      if(inner_icmp==NULL)
        return false;

      /* If we get here it means that we've found an ICMP header inside the
       * ICMP error message that we received. First of all, check that the
       * ICMP version matches what we sent. */
      if(sent_layer4->protocol_id() != inner_icmp->protocol_id())
        return false;

      /* Make sure ICMP type and code match  */
      if( ((ICMPHeader*)sent_layer4)->getType() != inner_icmp->getType() )
        return false;
      if( ((ICMPHeader*)sent_layer4)->getCode() != inner_icmp->getCode() )
        return false;

      /* Now go into a bit of detail and try to determine if both headers
       * are equal, comparing the values of specific fields.  */
      if(sent_layer4->protocol_id()==HEADER_TYPE_ICMPv6){
          ICMPv6Header *sent_icmp6=(ICMPv6Header *)sent_layer4;
          ICMPv6Header *inner_icmp6=(ICMPv6Header *)inner_icmp;

          switch(sent_icmp6->getType()){
            case ICMPv6_UNREACH:
            case ICMPv6_TIMXCEED :
              /* For these we cannot guarantee that the received ICMPv6 error
               * packet included data beyond the inner ICMPv6 header, so we just
               * assume that they are a match to the sent probe. (We shouldn't
               * really be sending ICMPv6 error messages and expect ICMPv6 error
               * responses that contain our ICMv6P error messages, should we?
               * Well, even if we do, there is a good chance we are able to match
               * those responses with the original probe) */
            break;

            case ICMPv6_PKTTOOBIG:
              if(sent_icmp6->getMTU() != inner_icmp6->getMTU())
                return false;
            break;

            case ICMPv6_PARAMPROB:
              if(sent_icmp6->getPointer() != inner_icmp6->getPointer())
                return false;
            break;

            case ICMPv6_ECHO:
            case ICMPv6_ECHOREPLY:
              if(sent_icmp6->getIdentifier() != inner_icmp6->getIdentifier())
                return false;
              if(sent_icmp6->getSequence() != inner_icmp6->getSequence())
                return false;
            break;

            case ICMPv6_ROUTERSOLICIT:
              /* Here we do not have much to compare, so we just test that
               * the reserved field contains the same value, usually zero. */
              if(sent_icmp6->getReserved()!=inner_icmp6->getReserved())
                return false;
            break;

            case ICMPv6_ROUTERADVERT:
              if(sent_icmp6->getCurrentHopLimit() != inner_icmp6->getCurrentHopLimit() )
                return false;
              if(sent_icmp6->getRouterLifetime() != inner_icmp6->getRouterLifetime() )
                return false;
              if(sent_icmp6->getReachableTime() != inner_icmp6->getReachableTime() )
                return false;
              if(sent_icmp6->getRetransmissionTimer() != inner_icmp6->getRetransmissionTimer() )
                return false;
            break;

            case ICMPv6_REDIRECT:
              if( memcmp(sent_icmp6->getTargetAddress().s6_addr, inner_icmp6->getTargetAddress().s6_addr, 16) !=0 )
                return false;
              if( memcmp(sent_icmp6->getDestinationAddress().s6_addr, inner_icmp6->getDestinationAddress().s6_addr, 16) !=0 )
                return false;
            break;

            case ICMPv6_NGHBRSOLICIT:
            case ICMPv6_NGHBRADVERT:
              if( memcmp(sent_icmp6->getTargetAddress().s6_addr, inner_icmp6->getTargetAddress().s6_addr, 16) !=0 )
                return false;
            break;

            case ICMPv6_RTRRENUM:
              if(sent_icmp6->getSequence() != inner_icmp6->getSequence() )
                return false;
              if(sent_icmp6->getSegmentNumber() != inner_icmp6->getSegmentNumber() )
                return false;
              if(sent_icmp6->getMaxDelay() != inner_icmp6->getMaxDelay() )
                return false;
              if(sent_icmp6->getFlags() != inner_icmp6->getFlags() )
                return false;
            break;

            case ICMPv6_NODEINFOQUERY:
            case ICMPv6_NODEINFORESP:
              if(sent_icmp6->getNodeInfoFlags() != inner_icmp6->getNodeInfoFlags() )
                return false;
              if(sent_icmp6->getNonce() != inner_icmp6->getNonce())
                return false;
              if(sent_icmp6->getQtype() != inner_icmp6->getQtype() )
                return false;
            break;


            case ICMPv6_GRPMEMBQUERY:
            case ICMPv6_GRPMEMBREP:
            case ICMPv6_GRPMEMBRED:
            case ICMPv6_INVNGHBRSOLICIT:
            case ICMPv6_INVNGHBRADVERT:
            case ICMPv6_MLDV2:
            case ICMPv6_AGENTDISCOVREQ:
            case ICMPv6_AGENTDISCOVREPLY:
            case ICMPv6_MOBPREFIXSOLICIT:
            case ICMPv6_MOBPREFIXADVERT:
            case ICMPv6_CERTPATHSOLICIT:
            case ICMPv6_CERTPATHADVERT:
            case ICMPv6_EXPMOBILITY:
            case ICMPv6_MRDADVERT:
            case ICMPv6_MRDSOLICIT:
            case ICMPv6_MRDTERMINATE:
            case ICMPv6_FMIPV6:
                /* All these types are not currently implemented but since the
                 * sent_icmp.getType() has returned such type, we assume
                 * that there is a match (don't return false here). */
            break;

            default:
              /* Do not match ICMPv6 types we don't know about */
              return false;
            break;
          }
      }else if(sent_layer4->protocol_id()==HEADER_TYPE_ICMPv4){
          ICMPv4Header *sent_icmp4=(ICMPv4Header *)sent_layer4;
          ICMPv4Header *inner_icmp4=(ICMPv4Header *)inner_icmp;

          switch(sent_icmp4->getType()){
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TSTAMP:
            case ICMP_TSTAMPREPLY:
            case ICMP_INFO:
            case ICMP_INFOREPLY:
            case ICMP_MASK:
            case ICMP_MASKREPLY:
            case ICMP_DOMAINNAME:
            case ICMP_DOMAINNAMEREPLY:
              /* Check the message identifier and sequence number */
              if(sent_icmp4->getIdentifier() != inner_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != inner_icmp4->getSequence())
                return false;
            break;

            case ICMP_ROUTERADVERT:
              /* Check only the main fields, no need to parse the whole list
               * of addresses (maybe we didn't even get enough octets to
               * check that). */
              if(sent_icmp4->getNumAddresses() != inner_icmp4->getNumAddresses() )
                return false;
              if(sent_icmp4->getAddrEntrySize() != inner_icmp4->getAddrEntrySize())
                return false;
              if(sent_icmp4->getLifetime() != inner_icmp4->getLifetime() )
                return false;
            break;

            case ICMP_ROUTERSOLICIT:
              /* Here we do not have much to compare, so we just test that
               * the reserved field contains the same value, usually zero. */
              if(sent_icmp4->getReserved()!=inner_icmp4->getReserved())
                return false;
            break;

            case ICMP_UNREACH:
            case ICMP_SOURCEQUENCH:
            case ICMP_TIMXCEED:
              /* For these we cannot guarantee that the received ICMP error
               * packet included data beyond the inner ICMP header, so we just
               * assume that they are a match to the sent probe. (We shouldn't
               * really be sending ICMP error messages and expect ICMP error
               * responses that contain our ICMP error messages, should we?
               * Well, even if we do, there is a good chance we are able to match
               * those responses with the original probe) */
            break;

            case ICMP_REDIRECT:
              if(sent_icmp4->getGatewayAddress().s_addr != inner_icmp4->getGatewayAddress().s_addr)
                return false;
            break;

            case ICMP_PARAMPROB:
              if(sent_icmp4->getParameterPointer() != inner_icmp4->getParameterPointer())
                return false;
            break;

            case ICMP_TRACEROUTE:
              if(sent_icmp4->getIDNumber() != inner_icmp4->getIDNumber())
                return false;
              if(sent_icmp4->getOutboundHopCount() != inner_icmp4->getOutboundHopCount())
                return false;
              if(sent_icmp4->getOutputLinkSpeed() != inner_icmp4->getOutputLinkSpeed() )
                return false;
              if(sent_icmp4->getOutputLinkMTU() != inner_icmp4->getOutputLinkMTU() )
                return false;
            break;

            case ICMP_SECURITYFAILURES:
              /* Check the pointer and the reserved field */
              if(sent_icmp4->getSecurityPointer() != inner_icmp4->getSecurityPointer())
                return false;
              if(sent_icmp4->getReserved() != inner_icmp4->getReserved())
                return false;
            break;

            default:
              /* Do not match ICMP types we don't know about */
              return false;
            break;
          }
      }else{
        return false; // Should never happen, though.
      }
    }else{ /* Received ICMP is informational. */
        
      if(PKTPARSERDEBUG)printf("%s(): Received ICMP is an informational message.\n", __func__);
        
      /* If we get here it means that we received an informational ICMPv6
       * message. So now we have to check if the received message is the
       * expected reply to the probe we sent (like an Echo reply for an Echo
       * request, etc). */

        if(sent_layer4->protocol_id()==HEADER_TYPE_ICMPv6 && rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv6){
          ICMPv6Header *sent_icmp6=(ICMPv6Header *)sent_layer4;
          ICMPv6Header *rcvd_icmp6=(ICMPv6Header *)rcvd_layer4;

          switch( sent_icmp6->getType() ){

            case ICMPv6_UNREACH:
            case ICMPv6_TIMXCEED :
            case ICMPv6_PKTTOOBIG:
            case ICMPv6_PARAMPROB:
                /* This should never happen. If we got here, the received type
                 * should be of an informational message, not an error message. */
                printf("Error in isResponse()\n");
                return false;
            break;

            case ICMPv6_ECHO:
              /* For Echo request, we expect echo replies  */
              if(rcvd_icmp6->getType()!=ICMPv6_ECHOREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp6->getIdentifier() != rcvd_icmp6->getIdentifier())
                return false;
              if(sent_icmp6->getSequence() != rcvd_icmp6->getSequence())
                return false;
            break;

            case ICMPv6_ECHOREPLY:
              /* We don't expect replies to Echo replies */
              return false;
            break;

            case ICMPv6_ROUTERSOLICIT:
              /* For Router solicitations, we expect Router advertisements.
               * We only check if the received ICMP is a router advert because
               * there is nothing else that can be used to match the solicitation
               * with the response. */
              if(rcvd_icmp6->getType()!=ICMPv6_ROUTERADVERT)
                return false;
            break;

            case ICMPv6_ROUTERADVERT:
              /* We don't expect replies to router advertisements */
              return false;
            break;

            case ICMPv6_REDIRECT:
              /* We don't expect replies to Redirect messages */
              return false;
            break;

            case ICMPv6_NGHBRSOLICIT:
              if(PKTPARSERDEBUG)printf("%s(): Sent ICMP is an ICMPv6 Neighbor Solicitation.\n", __func__);
              /* For Neighbor solicitations, we expect Neighbor advertisements
               * with the "S" flag set (solicited flag) and the same address
               * in the "TargetAddress" field. */
              if(rcvd_icmp6->getType()!=ICMPv6_NGHBRADVERT)
                return false;
              if(PKTPARSERDEBUG)printf("%s(): Received ICMP is an ICMPv6 Neighbor Advertisement.\n", __func__);
              if( !(rcvd_icmp6->getFlags() & 0x40) )
                  return false;
              if( memcmp(sent_icmp6->getTargetAddress().s6_addr, rcvd_icmp6->getTargetAddress().s6_addr, 16) !=0 )
                return false;
            break;

            case ICMPv6_NGHBRADVERT:
              /* We don't expect replies to Neighbor advertisements */
              return false;
            break;

            case ICMPv6_NODEINFOQUERY:
              /* For Node Information Queries we expect Node Information
               * responses with the same Nonce value that we used in the query. */
              if(rcvd_icmp6->getType()!=ICMPv6_NODEINFORESP)
                return false;
              if(sent_icmp6->getNonce() != rcvd_icmp6->getNonce())
                return false;
            break;

            case ICMPv6_NODEINFORESP:
                /* Obviously, we do not expect responses to a response */
                return false;
            break;

            case ICMPv6_INVNGHBRSOLICIT:
              /* For Inverse Neighbor Discovery Solicitations we expect
               * advertisements in response. We don't do any additional
               * validation since any advert can be considered a response
               * to the solicitation. */
              if(rcvd_icmp6->getType()!=ICMPv6_INVNGHBRADVERT)
                return false;
            break;

            case ICMPv6_INVNGHBRADVERT:
              /* We don't expect responses to advertisements */
              return false;
            break;


            case ICMPv6_RTRRENUM:
              /* We don't expect specific responses to router renumbering
               * messages. */
              return false;
            break;

            case ICMPv6_GRPMEMBQUERY:
              /* For Multicast Listener Discovery (MLD) queries, we expect
               * either MLD Responses or MLD Done messages. We can't handle MLDv2
               * yet, so we don't match it. TODO: Implement support for MLDv2 */
              if(rcvd_icmp6->getType()!=ICMPv6_GRPMEMBREP && rcvd_icmp6->getType()!=ICMPv6_GRPMEMBRED)
                return false;
              /* Now we have two possibilities:
               * a) The query is a "General Query" where the multicast address
               *    is set to zero.
               * b) The query is a "Multicast-Address-Specific Query", where
               *    the multicast address field is set to an actual multicast
               *    address.
               * In the first case, we match any query response to the request,
               * as we don't have a multicast address to compare. In the second
               * case, we verify that the target mcast address of the query
               * matches the one in the response. */
              struct in6_addr zeroaddr;
              memset(&zeroaddr, 0, sizeof(struct in6_addr));
              if( memcmp( sent_icmp6->getMulticastAddress().s6_addr, zeroaddr.s6_addr, 16) != 0 ){  /* Case B: */
                 if (memcmp( sent_icmp6->getMulticastAddress().s6_addr, rcvd_icmp6->getMulticastAddress().s6_addr, 16)!=0 )
                     return false;
              }
            break;

            case ICMPv6_GRPMEMBREP:
            case ICMPv6_GRPMEMBRED:
              /* We don't expect responses to MLD reports */
              return false;
            break;

            case ICMPv6_MLDV2:
            case ICMPv6_AGENTDISCOVREQ:
            case ICMPv6_AGENTDISCOVREPLY:
            case ICMPv6_MOBPREFIXSOLICIT:
            case ICMPv6_MOBPREFIXADVERT:
            case ICMPv6_CERTPATHSOLICIT:
            case ICMPv6_CERTPATHADVERT:
            case ICMPv6_EXPMOBILITY:
            case ICMPv6_MRDADVERT:
            case ICMPv6_MRDSOLICIT:
            case ICMPv6_MRDTERMINATE:
            case ICMPv6_FMIPV6:
            default:
              /* Do not match ICMPv6 types we don't implement or know about *
               * TODO: Implement these ICMPv6 types. */
              return false;
            break;

          }

        }else if(sent_layer4->protocol_id()==HEADER_TYPE_ICMPv4 && rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv4){
          ICMPv4Header *sent_icmp4=(ICMPv4Header *)sent_layer4;
          ICMPv4Header *rcvd_icmp4=(ICMPv4Header *)rcvd_layer4;

          switch( sent_icmp4->getType() ){

            case ICMP_ECHOREPLY:
              /* We don't expect replies to Echo replies. */
              return false;
            break;

            case ICMP_UNREACH:
            case ICMP_SOURCEQUENCH:
            case ICMP_REDIRECT:
            case ICMP_TIMXCEED:
            case ICMP_PARAMPROB:
              /* Nodes are not supposed to respond to error messages, so
               * we don't expect any replies. */
              return false;
            break;

            case ICMP_ECHO:
              /* For Echo request, we expect echo replies  */
              if(rcvd_icmp4->getType()!=ICMP_ECHOREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp4->getIdentifier() != rcvd_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != rcvd_icmp4->getSequence())
                return false;
            break;

            case ICMP_ROUTERSOLICIT:
              /* For ICMPv4 router solicitations, we expect router advertisements.
               * We don't validate anything else because in IPv4 any advert that
               * comes from the host we sent the solicitation to can be
               * considered a response. */
              if(rcvd_icmp4->getType()!=ICMP_ROUTERADVERT)
                return false;
            break;

            case ICMP_ROUTERADVERT:
              /* We don't expect responses to advertisements */
              return false;
            break;

            case ICMP_TSTAMP:
              /* For Timestampt requests, we expect timestamp replies  */
              if(rcvd_icmp4->getType()!=ICMP_TSTAMPREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp4->getIdentifier() != rcvd_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != rcvd_icmp4->getSequence())
                return false;
            break;

            case ICMP_TSTAMPREPLY:
              /* We do not expect responses to timestamp replies */
              return false;
            break;

            case ICMP_INFO:
              /* For Information requests, we expect Information replies  */
              if(rcvd_icmp4->getType()!=ICMP_INFOREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp4->getIdentifier() != rcvd_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != rcvd_icmp4->getSequence())
                return false;
            break;

            case ICMP_INFOREPLY:
              /* We do not expect responses to Information replies */
              return false;
            break;

            case ICMP_MASK:
              /* For Netmask requests, we expect Netmask replies  */
              if(rcvd_icmp4->getType()!=ICMP_MASKREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp4->getIdentifier() != rcvd_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != rcvd_icmp4->getSequence())
                return false;
            break;

            case ICMP_MASKREPLY:
              /* We do not expect responses to netmask replies */
              return false;
            break;

            case ICMP_TRACEROUTE:
              /* We don't expect replies to a traceroute message as it is
               * sent as a response to an IP datagram that contains the
               * IP traceroute option. Also, note that this function does
               * not take this into account when processing IPv4 datagrams
               * so if we receive an ICMP_TRACEROUTE we'll not be able
               * to match it with the original IP datagram. */
              return false;
            break;

            case ICMP_DOMAINNAME:
              /* For Domain Name requests, we expect Domain Name replies  */
              if(rcvd_icmp4->getType()!=ICMP_DOMAINNAMEREPLY)
                return false;
              /* And we expect the ID and sequence number of the reply to
               * match the ID and seq of the request. */
              if(sent_icmp4->getIdentifier() != rcvd_icmp4->getIdentifier())
                return false;
              if(sent_icmp4->getSequence() != rcvd_icmp4->getSequence())
                return false;
            break;

            case ICMP_DOMAINNAMEREPLY:
              /* We do not expect replies to DN replies */
              return false;
            break;

            case ICMP_SECURITYFAILURES:
              /* Nodes are not expected to send replies to this message, as it
               * is an ICMP error. */
              return false;
            break;
          }
        }else{
          return false; // Should never happen
        }
    }
  }else if(sent_layer4->protocol_id()==HEADER_TYPE_TCP || sent_layer4->protocol_id()==HEADER_TYPE_UDP){
      
      if(PKTPARSERDEBUG)printf("%s(): Sent packet has a transport layer header.\n", __func__);

      /* Both are TCP or both UDP */
      if(sent_layer4->protocol_id()==rcvd_layer4->protocol_id()){
          
        if(PKTPARSERDEBUG)printf("%s(): Received packet has a transport layer header too.\n", __func__);

        /* Probe source port must equal response target port */
        if( ((TransportLayerElement *)sent_layer4)->getSourcePort() != ((TransportLayerElement *)rcvd_layer4)->getDestinationPort() )
          return false;
        /* Probe target port must equal response source port */
        if( ((TransportLayerElement *)rcvd_layer4)->getSourcePort() != ((TransportLayerElement *)sent_layer4)->getDestinationPort() )
          return false;

      /* If we sent TCP or UDP and got ICMP in response, we need to find a copy of our packet in the
       * ICMP payload, providing it is an ICMP error message. */
      }else if(rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv6 || rcvd_layer4->protocol_id()==HEADER_TYPE_ICMPv4){
          
        if(PKTPARSERDEBUG)printf("%s(): Received packet does not have transport layer header but an ICMP header.\n", __func__);
         
        /* We only expect ICMP error messages */
        if( !(((ICMPHeader *)rcvd_layer4)->isError()) )
          return false;

        /* Let's validate the original header */
        NetworkLayerElement *iperror=(NetworkLayerElement *)rcvd_layer4->getNextElement();

        /* ICMP error message must contain the original datagram */
        if(iperror==NULL)
          return false;

        /* The first header must be IP */
        if(iperror->protocol_id()!=HEADER_TYPE_IPv6 && iperror->protocol_id()!=HEADER_TYPE_IPv4)
          return false;

        /* The IP version must match the probe's */
        if(iperror->protocol_id()!=sent_ip->protocol_id())
          return false;

        /* Source and destination addresses must match the probe's (NATs are
         * supposed to rewrite them too, so this should be OK) */
        if( memcmp(iperror->getSourceAddress(), sent_ip->getSourceAddress(), iperror->getAddressLength())!=0 )
          return false;
        if( memcmp(iperror->getDestinationAddress(), sent_ip->getDestinationAddress(), iperror->getAddressLength())!=0 )
          return false;

        /* So far we've verified that the ICMP error contains an IP datagram that matches
         * what we sent. Now, let's find the upper layer protocol (skip extension
         * headers and the like until we find some transport protocol). */
        TransportLayerElement *layer4error=(TransportLayerElement *)iperror->getNextElement();
        while(layer4error!=NULL){
          if(layer4error->protocol_id()==HEADER_TYPE_UDP || layer4error->protocol_id()==HEADER_TYPE_TCP ){
              break;
          }else{
              layer4error=(TransportLayerElement *)layer4error->getNextElement();
          }
        }
        if(layer4error==NULL)
          return false;

        /* Now make sure we see the same port numbers */
        if( layer4error->getSourcePort() != ((TransportLayerElement *)sent_layer4)->getSourcePort() )
          return false;
        if( layer4error->getDestinationPort() != ((TransportLayerElement *)sent_layer4)->getDestinationPort() )
          return false;
      } else {
        return false;
      }
  }else{
    /* We sent a layer 4 other than ICMP, ICMPv6, TCP, or UDP. We return false
     * as we cannot match responses for protocols we don't understand */
    return false;
  }

  /* If we get there it means the packet passed all the tests. Return true
   * to indicate that the packet is a response to this FPProbe. */
  if(PKTPARSERDEBUG)printf("%s(): The received packet was successfully matched with the sent packet.\n", __func__);
  return true;
}

/* Tries to find a transport layer header in the supplied chain of
 * protocol headers. On success it returns a pointer to a PacketElement
 * of one of these types:
 * 
 * HEADER_TYPE_TCP
 * HEADER_TYPE_UDP
 * HEADER_TYPE_ICMPv4 
 * HEADER_TYPE_ICMPv6
 * HEADER_TYPE_SCTP
 * HEADER_TYPE_ARP
 * 
 * It returns NULL if no transport layer header is found.
 * 
 * Note that this method onyl understands IPv4, IPv6 (and its 
 * extension headers) and Ethernet. If the supplied packet contains
 * something different before the tranport layer, NULL will be returned.
 * */
PacketElement *PacketParser::find_transport_layer(PacketElement *chain){
  PacketElement *aux=chain;
  /* Traverse the chain of PacketElements */
  while(aux!=NULL){
    switch(aux->protocol_id()){
      /* If we have a link or a network layer header, skip it. */
      case HEADER_TYPE_IPv6_HOPOPT:
      case HEADER_TYPE_IPv4:
      case HEADER_TYPE_IPv6:
      case HEADER_TYPE_IPv6_ROUTE:
      case HEADER_TYPE_IPv6_FRAG:
      case HEADER_TYPE_IPv6_NONXT:
      case HEADER_TYPE_IPv6_OPTS:
      case HEADER_TYPE_ETHERNET:
      case HEADER_TYPE_IPv6_MOBILE:
        aux=aux->getNextElement();
      break;
      
      /* If we found the transport layer, return it. */
      case HEADER_TYPE_TCP:
      case HEADER_TYPE_UDP:
      case HEADER_TYPE_ICMPv4:
      case HEADER_TYPE_ICMPv6:
      case HEADER_TYPE_SCTP:
      case HEADER_TYPE_ARP:
        return aux;
      break;
      
      /* Otherwise, the packet contains headers we don't understand
       * so we just return NULL to indicate that no valid transport 
       * layer was found. */
      default:
        return NULL;
      break;
    }
  }
  return NULL;
} /* End of find_transport_layer() */
