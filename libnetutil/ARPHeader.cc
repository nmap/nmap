
/***************************************************************************
 * ARPHeader.cc -- The ARPHeader Class represents an ARP packet. It        *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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

#include "ARPHeader.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
ARPHeader::ARPHeader() {
  this->reset();
} /* End of ARPHeader constructor */


ARPHeader::~ARPHeader() {

} /* End of ARPHeader destructor */


/** Sets every attribute to its default value */
void ARPHeader::reset(){
  memset (&this->h, 0, sizeof(nping_arp_hdr_t));
  this->length=ARP_HEADER_LEN;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ARPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ARPHeader class is able to hold a maximum of 28 bytes.
  * If the supplied buffer is longer than that, only the first 28 bytes will be
  * stored in the internal buffer.
  * @warning Supplied len MUST be at least 28 bytes (ARP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ARPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ARP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=ARP_HEADER_LEN;
    memcpy(&(this->h), buf, ARP_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int ARPHeader::protocol_id() const {
    return HEADER_TYPE_ARP;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int ARPHeader::validate(){
  if( this->length!=ARP_HEADER_LEN)
    return OP_FAILURE;
  else
    return ARP_HEADER_LEN;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int ARPHeader::print(FILE *output, int detail) const {
  fprintf(output, "ARP[]");
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Sets HardwareType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setHardwareType(u16 val){
  this->h.ar_hrd=htons(val);
  return OP_SUCCESS;
} /* End of setHardwareType() */


/** Sets HardwareType to ETHERNET.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setHardwareType(){
  this->h.ar_hrd=htons(HDR_ETH10MB);
  return OP_SUCCESS;
} /* End of setHardwareType() */


/** Returns value of attribute h.ar_hrd */
u16 ARPHeader::getHardwareType(){
  return ntohs(this->h.ar_hrd);
} /* End of getHardwareType() */


/** Sets ProtocolType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setProtocolType(u16 val){
  this->h.ar_pro=htons(val);
  return OP_SUCCESS;
} /* End of setProtocolType() */


/** Sets ProtocolType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setProtocolType(){
  this->h.ar_pro=htons(0x0800); /* DEFAULT: IPv4 */
  return OP_SUCCESS;
} /* End of setProtocolType() */


/** Returns value of attribute h.ar_pro */
u16 ARPHeader::getProtocolType(){
  return ntohs(this->h.ar_pro);
} /* End of getProtocolType() */


/** Sets HwAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setHwAddrLen(u8 val){
  this->h.ar_hln=val;
  return OP_SUCCESS;
} /* End of setHwAddrLen() */


/** Sets HwAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setHwAddrLen(){
  this->h.ar_hln=ETH_ADDRESS_LEN;
  return OP_SUCCESS;
} /* End of setHwAddrLen() */


/** Returns value of attribute h.ar_hln */
u8 ARPHeader::getHwAddrLen(){
  return this->h.ar_hln;
} /* End of getHwAddrLen() */


/** Sets ProtoAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setProtoAddrLen(u8 val){
  this->h.ar_pln=val;
  return OP_SUCCESS;
} /* End of setProtoAddrLen() */


/** Sets ProtoAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setProtoAddrLen(){
  this->h.ar_pln=IPv4_ADDRESS_LEN; /* DEFAULT: IPv4 */
  return OP_SUCCESS;
} /* End of setProtoAddrLen() */


/** Returns value of attribute h.ar_pln */
u8 ARPHeader::getProtoAddrLen(){
  return this->h.ar_pln;
} /* End of getProtoAddrLen() */


/** Sets OpCode.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setOpCode(u16 val){
  this->h.ar_op=htons(val);
  return OP_SUCCESS;
} /* End of setOpCode() */


/** Returns value of attribute h.ar_op */
u16 ARPHeader::getOpCode(){
  return ntohs(this->h.ar_op);
} /* End of getOpCode() */


/** Sets SenderMAC.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setSenderMAC(const u8 * val){
  if(val==NULL)
    return OP_FAILURE;
  memcpy(this->h.data, val, ETH_ADDRESS_LEN);
  return OP_SUCCESS;
} /* End of setSenderMAC() */


/** Returns value of attribute h.ar_sha */
u8 * ARPHeader::getSenderMAC(){
  return this->h.data;
} /* End of getSenderMAC() */


/** Sets SenderIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setSenderIP(struct in_addr val){
  memcpy(this->h.data+6, &val.s_addr, 4);
  return OP_SUCCESS;
} /* End of setSenderIP() */


/** Returns value of attribute h.ar_sip */
u32 ARPHeader::getSenderIP(){
  u32 *p = (u32 *)(this->h.data+6);
  return *p;
} /* End of getSenderIP() */


/** Sets TargetMAC.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setTargetMAC(u8 * val){
  if(val==NULL)
    return OP_FAILURE;
  memcpy(this->h.data+10, val, ETH_ADDRESS_LEN);
  return OP_SUCCESS;
} /* End of setTargetMAC() */


/** Returns value of attribute h.ar_tha */
u8 * ARPHeader::getTargetMAC(){
  return this->h.data+10;
} /* End of getTargetMAC() */


/** Sets TargetIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ARPHeader::setTargetIP(struct in_addr val){
  memcpy(this->h.data+16, &val.s_addr, 4);
  return OP_SUCCESS;
} /* End of setTargetIP() */


/** Returns value of attribute h.ar_tip */
u32 ARPHeader::getTargetIP(){
  u32 *p = (u32 *)(this->h.data+16);
  return *p;
} /* End of getTargetIP() */
