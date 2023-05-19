/***************************************************************************
 * FragmentHeader.cc -- The FragmentHeader Class represents an IPv6        *
 * Hop-by-Hop extension header.                                            *
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

#include "FragmentHeader.h"
#include <assert.h>

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
FragmentHeader::FragmentHeader() {
  this->reset();
} /* End of FragmentHeader constructor */


FragmentHeader::~FragmentHeader() {

} /* End of FragmentHeader destructor */


/** Sets every attribute to its default value */
void FragmentHeader::reset(){
  memset(&this->h, 0, sizeof(nping_ipv6_ext_fragment_hdr_t));
  this->length=8;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *FragmentHeader::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The FragmentHeader class is able to hold a maximum of
  * sizeof(nping_icmpv6_hdr_t) bytes. If the supplied buffer is longer than
  * that, only the first 1508 bytes will be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int FragmentHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<FRAGMENT_HEADER_LEN){
    this->length=0;
    return OP_FAILURE;
  }else{
    int stored_len = MIN(FRAGMENT_HEADER_LEN, len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int FragmentHeader::protocol_id() const {
    return HEADER_TYPE_IPv6_FRAG;
} /* End of protocol_id() */



/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int FragmentHeader::validate(){
  /* Check the object's length makes sense*/
  if(this->length != FRAGMENT_HEADER_LEN){
      return OP_FAILURE;
  }
  /* There is not much to check for here, since header fields may take any
   * value. We could certainly check the NextHeader value, but let's leave
   * that for the class user. */
  return this->length;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int FragmentHeader::print(FILE *output, int detail) const {
  fprintf(output, "Fragment[%d, %d]", this->h.nh, this->h.id);
  // TODO: @todo : Implement this
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Set Next Header field */
int FragmentHeader::setNextHeader(u8 val){
  this->h.nh = val;
  return OP_SUCCESS;
} /* End of setNextHeader() */


/** Returns next header id */
u8 FragmentHeader::getNextHeader(){
  return this->h.nh;
} /* End of getNextHeader() */


/** Set Offset field */
int FragmentHeader::setOffset(u16 val){
  this->h.off_res_flag[0]=(u8)(val >> 8);
  this->h.off_res_flag[1]=(u8)((this->h.off_res_flag[1] & 0x7) | (val & ~0x7));
  return OP_SUCCESS;
} /* End of setOffset() */


/** Returns fragment offset */
u16 FragmentHeader::getOffset(){
  return ((this->h.off_res_flag[0] << 8) + this->h.off_res_flag[1]) & 0xfff8;
} /* End of getOffset() */


/* Sets the "More Fragments" flag. */
int FragmentHeader::setM(bool m_flag){
  if(m_flag)
    this->h.off_res_flag[1]= (u8)((this->h.off_res_flag[1] & ~0x01) | 0x01);
  else
      this->h.off_res_flag[1]= (u8)((this->h.off_res_flag[1] & ~0x1));
  return OP_SUCCESS;
} /* End of setM() */


/* Returns true if the "More Fragments" flag is set; false otherwise. */
bool FragmentHeader::getM(){
  return (this->h.off_res_flag[1] & 0x01);
} /* End of getM() */


/** Set the fragment identifier */
int FragmentHeader::setIdentification(u32 val){
  this->h.id=htonl(val);
  return OP_SUCCESS;
} /* End of setIdentification() */


/** Returns the fragment identifier*/
u32 FragmentHeader::getIdentification(){
  return ntohl(this->h.id);
} /* End of getIdentification.() */
