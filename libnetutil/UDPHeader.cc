
/***************************************************************************
 * UDPHeader.cc -- The UDPHeader Class represents a UDP packet. It         *
 * contains methods to set the different header fields. These methods      *
 * tipically perform the necessary error checks and byte order             *
 * conversions.                                                            *
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

#include "UDPHeader.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
UDPHeader::UDPHeader(){
  this->reset();
} /* End of UDPHeader constructor */


UDPHeader::~UDPHeader(){

} /* End of UDPHeader destructor */


/** Sets every attribute to its default value */
void UDPHeader::reset(){
  this->length=UDP_HEADER_LEN;
  this->setSourcePort(UDP_DEFAULT_SPORT);
  this->setDestinationPort(UDP_DEFAULT_DPORT);
  this->setTotalLength(UDP_HEADER_LEN);
  this->setSum(0);
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * UDPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The UDPHeader class is able to hold a maximum of 8 bytes. If the
  * supplied buffer is longer than that, only the first 8 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (UDP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int UDPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<UDP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=UDP_HEADER_LEN;
    memcpy(&(this->h), buf, UDP_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int UDPHeader::protocol_id() const {
    return HEADER_TYPE_UDP;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int UDPHeader::validate(){
  if( this->length!=UDP_HEADER_LEN)
      return OP_FAILURE;
  else
      return UDP_HEADER_LEN;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int UDPHeader::print(FILE *output, int detail) const {
  fprintf(output, "UDP[");
  fprintf(output, "%d", this->getSourcePort());
  fprintf(output, " >");
  fprintf(output, " %d", this->getDestinationPort());
  if(detail>=PRINT_DETAIL_HIGH)
    fprintf(output, " len=%d", (int)this->getTotalLength() );
  if(detail>=PRINT_DETAIL_MED)
    fprintf(output, " csum=0x%04X", ntohs( this->getSum() ));
  fprintf(output, "]");
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Sets source port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int UDPHeader::setSourcePort(u16 p){
  h.uh_sport = htons(p);
  return OP_SUCCESS;
} /* End of setSrcPort() */


/** Returns source port in HOST byte order */
u16 UDPHeader::getSourcePort() const {
  return ntohs(h.uh_sport);
} /* End of getSrcPort() */


/** Sets destination port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int UDPHeader::setDestinationPort(u16 p){
  h.uh_dport = htons(p);
  return OP_SUCCESS;
} /* End of setDstPort() */


/** Returns destination port in HOST byte order */
u16 UDPHeader::getDestinationPort() const {
  return ntohs(h.uh_dport);
} /* End of getDstPort() */


int UDPHeader::setSum(struct in_addr src, struct in_addr dst){
  int bufflen;
  u8 aux[ 65535-8 ];
 /* FROM: RFC 5405 Unicast UDP Usage Guidelines, November 2008
  *  "A UDP datagram is carried in a single IP packet and is hence limited to
  *   a maximum payload of 65,507 bytes for IPv4 and 65,527 bytes for IPv6"
  *
  * So, UDP is supposed to be able to carry 65535-8 bytes but in fact it can
  * only carry 65,507 or 65,527. However, we are not taking that into account
  * here because UDP is supposed to be independent of IPv4, IPv6 or
  * whatever other network layer protocol is used to carry the UDP datagrams.*/
  h.uh_sum = 0;

  /* Copy packet contents to a buffer */
  bufflen=dumpToBinaryBuffer(aux, 65536-8 );

  /* Compute checksum */
  h.uh_sum = ipv4_pseudoheader_cksum(&src, &dst, IPPROTO_UDP,bufflen, (char *) aux);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed. */
int UDPHeader::setSum(u16 s){
  h.uh_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


int UDPHeader::setSum(){
  this->h.uh_sum=0;
  this->h.uh_sum = this->compute_checksum();
  return OP_SUCCESS;
} /* End of setSum() */


/** Set the UDP checksum field to a random value, which may accidentally
  * match the correct checksum */
int UDPHeader::setSumRandom(){
  h.uh_sum=(1 + (get_random_u16()%(65535-1))); /* Discard value zero */
  return OP_SUCCESS;
} /* End of setSumRandom() */


/** Set the UDP checksum field to a random value. It takes the source and
  * destination address to make sure the random generated sum does not
  * accidentally match the correct checksum. This function only handles
  * IPv4 address. */
int UDPHeader::setSumRandom(struct in_addr source, struct in_addr destination){
  u16 correct_csum=0;
  /* Compute the correct checksum */
  this->setSum(source, destination);
  correct_csum=this->getSum();
  /* Generate numbers until one does not match the correct sum */
  while( (h.uh_sum=(1 + (get_random_u16()%(65535-1))))==correct_csum);
  return OP_SUCCESS;
} /* End of setSumRandom() */


u16 UDPHeader::getSum() const {
  return h.uh_sum;
} /* End of getSum() */


int UDPHeader::setTotalLength(){
  int mylen = 8;
  int otherslen=0;

  if (next!=NULL)
      otherslen=next->getLen();

 /* FROM: RFC 5405 Unicast UDP Usage Guidelines, November 2008
  *  "A UDP datagram is carried in a single IP packet and is hence limited to
  *   a maximum payload of 65,507 bytes for IPv4 and 65,527 bytes for IPv6"
  *
  * So, UDP is supposed to be able to carry 65535-8 bytes but in fact it can
  * only carry 65,507 or 65,527. However, we are not taking that into account
  * here because UDP is supposed to be independent of IPv4, IPv6 or
  * whatever other network layer protocol is used to carry the UDP datagrams.*/
  if ((mylen+otherslen) > 65535 || (mylen+otherslen)<8 ){
    printf("UDPHeader::setTotalLenght(): Invalid length.\n");
    return OP_FAILURE;
  }

  h.uh_ulen=htons( mylen+otherslen );

  return OP_SUCCESS;
} /* End of setTotalLenght() */


/** @warning Supplied value MUST be in HOST byte order */
int UDPHeader::setTotalLength(u16 l){
  this->h.uh_ulen=htons(l);
  return OP_SUCCESS;
} /* End of setTotalLenght() */


/** @warning Returned value is in HOST byte order */
u16 UDPHeader::getTotalLength() const {
  return ntohs(this->h.uh_ulen);
} /* End of getTotalLenght() */


