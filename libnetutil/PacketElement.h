
/***************************************************************************
 * PacketElement.h -- The PacketElement Class is a generic class that      *
 * represents a protocol header or a part of a network packet. Many other  *
 * classes inherit from it (NetworkLayerElement, TransportLayerElement,    *
 * etc).                                                                   *
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

#ifndef PACKETELEMENT_H
#define PACKETELEMENT_H  1

#include "nbase.h"
#include "netutil.h"

#define HEADER_TYPE_IPv6_HOPOPT   0  /* IPv6 Hop-by-Hop Option                */
#define HEADER_TYPE_ICMPv4        1  /* ICMP Internet Control Message         */
#define HEADER_TYPE_IGMP          2  /* IGMP Internet Group Management        */
#define HEADER_TYPE_IPv4          4  /* IPv4 IPv4 encapsulation               */
#define HEADER_TYPE_TCP           6  /* TCP Transmission Control              */
#define HEADER_TYPE_EGP           8  /* EGP Exterior Gateway Protocol         */
#define HEADER_TYPE_UDP           17 /* UDP User Datagram                     */
#define HEADER_TYPE_IPv6          41 /* IPv6 IPv6 encapsulation               */
#define HEADER_TYPE_IPv6_ROUTE    43 /* IPv6-Route Routing Header for IPv6    */
#define HEADER_TYPE_IPv6_FRAG     44 /* IPv6-Frag Fragment Header for IPv6    */
#define HEADER_TYPE_GRE           47 /* GRE General Routing Encapsulation     */
#define HEADER_TYPE_ESP           50 /* ESP Encap Security Payload            */
#define HEADER_TYPE_AH            51 /* AH Authentication Header              */
#define HEADER_TYPE_ICMPv6        58 /* IPv6-ICMP ICMP for IPv6               */
#define HEADER_TYPE_IPv6_NONXT    59 /* IPv6-NoNxt No Next Header for IPv6    */
#define HEADER_TYPE_IPv6_OPTS     60 /* IPv6-Opts IPv6 Destination Options    */
#define HEADER_TYPE_EIGRP         88 /* EIGRP                                 */
#define HEADER_TYPE_ETHERNET      97 /* Ethernet                              */
#define HEADER_TYPE_L2TP         115 /* L2TP Layer Two Tunneling Protocol     */
#define HEADER_TYPE_SCTP         132 /* SCTP Stream Control Transmission P.   */
#define HEADER_TYPE_IPv6_MOBILE  135 /* Mobility Header                       */
#define HEADER_TYPE_MPLS_IN_IP   137 /* MPLS-in-IP                            */
#define HEADER_TYPE_ARP         2054 /* ARP Address Resolution Protocol       */
#define HEADER_TYPE_ICMPv6_OPTION 9997 /* ICMPv6 option                       */
#define HEADER_TYPE_NEP         9998 /* Nping Echo Protocol                   */
#define HEADER_TYPE_RAW_DATA    9999 /* Raw unknown data                      */

#define PRINT_DETAIL_LOW   1
#define PRINT_DETAIL_MED   2
#define PRINT_DETAIL_HIGH  3

#define DEFAULT_PRINT_DETAIL (PRINT_DETAIL_LOW)
#define DEFAULT_PRINT_DESCRIPTOR stdout

class PacketElement {

  protected:

    int length;
    PacketElement *next;    /**< Next PacketElement (next proto header)      */
    PacketElement *prev;    /**< Prev PacketElement (previous proto header)  */

  public:

    PacketElement();
    
    virtual ~PacketElement(){

    } /* End of PacketElement destructor */

    /** This function MUST be overwritten on ANY class that inherits from
      *  this one. Otherwise getBinaryBuffer will fail */
    virtual u8 * getBufferPointer(){
        netutil_fatal("getBufferPointer(): Attempting to use superclass PacketElement method.\n");
        return NULL;
     } /* End of getBufferPointer() */


    /** Returns a buffer that contains the header of the packet + all the
     *  lower level headers and payload. Returned buffer should be ok to be
     *  passes to a send() call to be transferred trough a socket.
     *  @return a pointer to a free()able buffer that contains packet's binary
     *  data.
     *  @warning If there are linked elements, their getBinaryBuffer() method
     *  will be called recursively and the buffers that they return WILL be
     *  free()d as soon as we copy the data in our own allocated buffer.
     *  @warning Calls to this method may not ve very efficient since they
     *  always involved a few malloc()s and free()s. If you want efficiency
     *  use dumpToBinaryBuffer(); */
    virtual u8 * getBinaryBuffer(){
      u8 *ourbuff=NULL;
      u8 *othersbuff=NULL;
      u8 *totalbuff=NULL;
      long otherslen=0;

      /* Get our own buffer address */
      if ( (ourbuff=getBufferPointer()) == NULL ){
          netutil_fatal("getBinaryBuffer(): Couldn't get own data pointer\n");
      }
      if( next != NULL ){ /* There is some other packet element */
        othersbuff = next->getBinaryBuffer();
        otherslen=next->getLen();
        totalbuff=(u8 *)safe_zalloc(otherslen + length);
        memcpy(totalbuff, ourbuff, length);
        memcpy(totalbuff+length, othersbuff, otherslen);
        free(othersbuff);
      }else{
           totalbuff=(u8 *)safe_zalloc(length);
           memcpy(totalbuff, ourbuff, length);
      }
      return totalbuff;
    } /* End of getBinaryBuffer() */


    virtual int dumpToBinaryBuffer(u8* dst, int maxlen){
      u8 *ourbuff=NULL;
      long ourlength=0;
      /* Get our own buffer address and length */
      if ( (ourbuff=getBufferPointer()) == NULL ||  (ourlength=this->length) < 0 )
            netutil_fatal("getBinaryBuffer(): Couldn't get own data pointer\n");
      /* Copy our part of the buffer */
      if ( maxlen < ourlength )
            netutil_fatal("getBinaryBuffer(): Packet exceeds maximum length %d\n", maxlen);
      memcpy( dst, ourbuff, ourlength);
       /* If there are more elements, tell them to copy their part */
       if( next!= NULL ){
            next->dumpToBinaryBuffer(dst+ourlength, maxlen-ourlength);
       }
       return this->getLen();
    } /* End of dumpToBinaryBuffer() */


    /** Does the same as the previous one but it stores the length of the
     *  return buffer on the memory pointed by the supplied int pointer.     */
    virtual u8 * getBinaryBuffer(int *len){
      u8 *buff = getBinaryBuffer();
      if( len != NULL )
         *len = getLen();
      return buff;
    } /* End of getBinaryBuffer() */


    /** Returns the lenght of this PacketElement + the length of all the
     *  PacketElements that are next to it (are linked trough the "next"
     *  attribute). So for example, if we have IPv4Header p1, linked to
     *  a TCPHeader p2, representing a simple TCP SYN with no options,
     *  a call to p1.getLen() will return 20 (IP header with no options) + 20
     *  (TCP header with no options) = 40 bytes.                             */
    int getLen() const {
        /* If we have some other packet element linked, get its length */
        if (next!=NULL)
            return length + next->getLen();
        else
            return length;
    } /* End of getLen() */


    /** Returns the address of the next PacketElement that is linked to this */
    virtual PacketElement *getNextElement() const {
      return next;
    } /* End of getNextElement() */


    /** Links current object with the next header in the protocol chain. Note
     * that this method also links the next element with this one, calling
     * setPrevElement(). */
    virtual int setNextElement(PacketElement *n){
      next=n;
      if(next!=NULL)
          next->setPrevElement(this);
      return OP_SUCCESS;
    } /* End of setNextElement() */

    /** Sets attribute prev with the supplied pointer value.
     *  @warning Supplied pointer must point to a PacketElement object or
     *  an object that inherits from it.                                     */
    virtual int setPrevElement(PacketElement *n){
      this->prev=n;
      return OP_SUCCESS;
    } /* End of setPrevElement() */


    /** Returns the address of the previous PacketElement that is linked to
     *  this one.
     *  @warning In many cases this function will return NULL since there is
     *  a high probability that the user of this class does not link
     *  PacketElements in both directions. Normally one would set attribute
     *  "next" of an IPHeader object to the TCPHeader that follows it, but
     *  not the other way around. */
    virtual PacketElement *getPrevElement(){
      return prev;
    } /* End of getPrevElement() */

    /** This method should be overwritten by any class that inherits from
      * PacketElement. It should print the object contents and then call
      * this->next->print(), providing this->next!=NULL */
    virtual int print(FILE *output, int detail) const {
        if(this->next!=NULL)
            this->next->print(output, detail);
        return OP_SUCCESS;
    } /* End of printf() */

    virtual int print() const {
        return print(DEFAULT_PRINT_DESCRIPTOR, DEFAULT_PRINT_DETAIL);
    }

    virtual int print(int detail) const {
        return print(DEFAULT_PRINT_DESCRIPTOR, detail);
    }

    virtual void print_separator(FILE *output, int detail) const {
        fprintf(output, " ");
    }

    /* Returns the type of protocol an object represents. This method MUST
     * be overwritten by all children. */
    virtual int protocol_id() const = 0;
};

#endif
