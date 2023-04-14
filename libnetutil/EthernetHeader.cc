/***************************************************************************
 * EthernetHeader.cc -- The EthernetHeader Class represents an Ethernet    *
 * header and footer. It contains methods to set the different header      *
 * fields. These methods tipically perform the necessary error checks and  *
 * byte order conversions.                                                 *
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

#include "EthernetHeader.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
EthernetHeader::EthernetHeader(){
  this->reset();
} /* End of EthernetHeader constructor */


EthernetHeader::~EthernetHeader(){

} /* End of EthernetHeader destructor */


/** Sets every attribute to its default value */
void EthernetHeader::reset(){
  memset(&this->h, 0, sizeof(nping_eth_hdr_t));
  this->length=ETH_HEADER_LEN;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * EthernetHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The EthernetHeader class is able to hold a maximum of 14 bytes.
  * If the supplied buffer is longer than that, only the first 14 bytes will be
  * stored in the internal buffer.
  * @warning Supplied len MUST be at least 14 bytes (Ethernet header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int EthernetHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ETH_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=ETH_HEADER_LEN;
    memcpy(&(this->h), buf, ETH_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int EthernetHeader::protocol_id() const {
    return HEADER_TYPE_ETHERNET;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int EthernetHeader::validate(){
  if( this->length!=ETH_HEADER_LEN)
    return OP_FAILURE;
  else
    return ETH_HEADER_LEN;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EthernetHeader::print(FILE *output, int detail) const {

    fprintf(output, "Eth[");

    for(int i=0; i<6; i++){
        fprintf(output, "%02x", this->h.eth_smac[i]);
        if(i<5)
          fprintf(output, ":");
    }

    fprintf(output, " > ");

    for(int i=0; i<6; i++){
        fprintf(output, "%02x", this->h.eth_dmac[i]);
        if(i<5)
          fprintf(output, ":");
    }

    if(detail>=PRINT_DETAIL_MED)
        fprintf(output, " Type=%04x", this->getEtherType());

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

/** Sets Source MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setSrcMAC(const u8 *m){
  if(m==NULL)
    netutil_fatal("EthernetHeader::setSrcMAC(u8*): NULL value supplied ");
  memcpy(h.eth_smac, m, 6);
  return OP_SUCCESS;
} /* End of setSrcMAC() */


/** Returns source port in HOST byte order
 *  @warning Returned pointer points directly to a Class internal buffer. If
 *  contents are changed, the instance of the class will be affected. */
const u8* EthernetHeader::getSrcMAC() const {
  return this->h.eth_smac;
} /* End of getSrcMAC() */


/** Sets Destination MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setDstMAC(u8 *m){
  if(m==NULL)
    netutil_fatal("EthernetHeader::setDstMAC(u8 *): NULL value supplied ");
  memcpy(h.eth_dmac, m, 6);
  return OP_SUCCESS;
} /* End of setDstMAC() */



/** Returns destination port in HOST byte order */
const u8 *EthernetHeader::getDstMAC() const {
  return this->h.eth_dmac;
} /* End of getDstMAC() */


int EthernetHeader::setEtherType(u16 val){
  h.eth_type=htons(val);
  return OP_SUCCESS;
} /* End of setEtherType() */


/** Returns destination port in HOST byte order */
u16 EthernetHeader::getEtherType() const {
  return ntohs(this->h.eth_type);
} /* End of getEtherType() */

