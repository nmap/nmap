/***************************************************************************
 * UDPHeader.cc -- The UDPHeader Class represents a UDP packet. It         *
 * contains methods to set the different header fields. These methods      *
 * tipically perform the necessary error checks and byte order             *
 * conversions.                                                            *
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
  if (otherslen < 0 || otherslen > 65535 || (mylen+otherslen) > 65535){
    printf("UDPHeader::setTotalLength(): Invalid length.\n");
    return OP_FAILURE;
  }

  h.uh_ulen=htons( mylen+otherslen );

  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Supplied value MUST be in HOST byte order */
int UDPHeader::setTotalLength(u16 l){
  this->h.uh_ulen=htons(l);
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Returned value is in HOST byte order */
u16 UDPHeader::getTotalLength() const {
  return ntohs(this->h.uh_ulen);
} /* End of getTotalLength() */


