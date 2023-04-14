/***************************************************************************
 * ARPHeader.cc -- The ARPHeader Class represents an ARP packet. It        *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
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
