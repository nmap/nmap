/***************************************************************************
 * TransportLayerElement.cc -- Class TransportLayerElement is a generic    *
 * class that represents a transport layer protocol header. Classes like   *
 * TCPHeader or UDPHeader inherit from it.                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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

#include "TransportLayerElement.h"
#include "IPv4Header.h"
#include "IPv6Header.h"


/** Computes and returns the Internet checksum.
 * @warning  This method requires the object to be linked to either an IPv6Header
 * object or an IPv4Header one, so the caller must ensure that objects are
 * properly linked with calls to setNextElement() like this:
 *
 * IPv6Header ip6;
 * TCPHeader tcp;
 * [...] # Set header fields
 * ip6.setNextElement(&tcp);
 * tcp.setSum();
 *
 * Note that there can be a number of other headers (like IPv6 extension headers)
 * between the transport header and the network one, but all of them need to
 * be linked in order for this method to traverse the list of headers and find
 * the IP source and destination address, required to compute the checksum. So
 * things like the following are OK:
 *
 * IPv6Header ip6;
 * HopByHopHeader hop;
 * RoutingHeader rte;
 * FragmentHeader frg;
 * UDPHeader udp;
 * [...] # Set whatever header fields you need
 * ip6.setNextElement(&hop);
 * hop.setNextElement(&rte);
 * rte.setNextElement(&frg);
 * frg.setNextElement(&udp);
 * udp.setSum(); # setSum() will be able to reach the IPv6Header. */
u16 TransportLayerElement::compute_checksum(){
  PacketElement *hdr;
  hdr=this->getPrevElement();
  u16 final_sum=0;
  /* Traverse the list of headers backwards until we find an IP header */
  while(hdr!=NULL){
      if (hdr->protocol_id()==HEADER_TYPE_IPv6){
            IPv6Header *v6hdr=(IPv6Header *)hdr;
            struct in6_addr i6src, i6dst;
            memcpy(i6src.s6_addr, v6hdr->getSourceAddress(), 16);
            memcpy(i6dst.s6_addr, v6hdr->getDestinationAddress(), 16);
            u8 *buff=(u8 *)safe_malloc(this->getLen());
            this->dumpToBinaryBuffer(buff, this->getLen());
            final_sum=ipv6_pseudoheader_cksum(&i6src, &i6dst, this->protocol_id(), this->getLen(), buff);
            free(buff);
            return final_sum;
      }else if(hdr->protocol_id()==HEADER_TYPE_IPv4){
            IPv4Header *v4hdr=(IPv4Header *)hdr;
            struct in_addr i4src, i4dst;
            memcpy(&(i4src.s_addr), v4hdr->getSourceAddress(), 4);
            memcpy(&(i4dst.s_addr), v4hdr->getDestinationAddress(), 4);
            u8 *buff=(u8 *)safe_malloc(this->getLen());
            this->dumpToBinaryBuffer(buff, this->getLen());
            final_sum=ipv4_pseudoheader_cksum(&i4src, &i4dst, this->protocol_id(), this->getLen(), buff);
            free(buff);
            return final_sum;
      }else{
          hdr=hdr->getPrevElement();
      }
  }
  return 0;
} /* End of setSum() */
