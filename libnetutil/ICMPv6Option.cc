/***************************************************************************
 * ICMPv6Option.cc -- The ICMPv6Option Class represents an ICMP version 6  *
 * option. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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

#include "ICMPv6Option.h"


ICMPv6Option::ICMPv6Option() {
  this->reset();
} /* End of ICMPv6Option constructor */


ICMPv6Option::~ICMPv6Option() {

} /* End of ICMPv6Option destructor */


/** Sets every class attribute to zero */
void ICMPv6Option::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv6_option_t));
  h_la  = (link_addr_option_t   *)this->h.data;
  h_pi  = (prefix_info_option_t *)this->h.data;
  h_r   = (redirect_option_t    *)this->h.data;
  h_mtu = (mtu_option_t         *)this->h.data;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv6Option::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv6Option class is able to hold a maximum of
  * sizeof(nping_icmpv6_option_t) bytes. If the supplied buffer is longer than
  * that, only the first sizeof(nping_icmpv6_option_t) bytes will be stored in
  * the internal buffer.
  * @warning Supplied len MUST be at least ICMPv6_OPTION_MIN_HEADER_LEN bytes
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv6Option::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMPv6_OPTION_MIN_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN( sizeof(nping_icmpv6_option_t), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */

int ICMPv6Option::protocol_id() const {
  return HEADER_TYPE_ICMPv6_OPTION;
}


int ICMPv6Option::setType(u8 val){
  this->h.type=val;
  this->length = getHeaderLengthFromType(val);
  this->h.length = this->length / 8;
  return OP_SUCCESS;
} /* End of setType() */

u8 ICMPv6Option::getType(){
  return this->h.type;
} /* End of getType() */


bool ICMPv6Option::validateType(u8 val){
  switch( val ){
    case ICMPv6_OPTION_SRC_LINK_ADDR:
    case ICMPv6_OPTION_TGT_LINK_ADDR:
    case ICMPv6_OPTION_PREFIX_INFO:
    case ICMPv6_OPTION_REDIR_HDR:
    case ICMPv6_OPTION_MTU:
        return true;
    break;

    default:
        return false;
    break;
  }
  return false;
} /* End of validateType() */



int ICMPv6Option::setLength(u8 val){
  this->h.length=val;
  return OP_SUCCESS;
} /* End of setLength() */

u8 ICMPv6Option::getLength(){
  return this->h.length;
} /* End of getLength() */


int ICMPv6Option::setLinkAddress(u8* val){
  if(val==NULL)
      return OP_FAILURE;
  switch(this->h.type){
      case ICMPv6_OPTION_SRC_LINK_ADDR:
      case ICMPv6_OPTION_TGT_LINK_ADDR:
          memcpy(this->h_la->link_addr, val, ICMPv6_OPTION_LINK_ADDRESS_LEN);
          return OP_SUCCESS;
      break;

      default:
          return OP_FAILURE;
      break;
  }
} /* End of setLinkAddress() */


u8 *ICMPv6Option::getLinkAddress(){
  switch(this->h.type){
      case ICMPv6_OPTION_SRC_LINK_ADDR:
      case ICMPv6_OPTION_TGT_LINK_ADDR:
          return this->h_la->link_addr;
      break;

      default:
          return NULL;
      break;
  }
} /* End of getLinkAddress() */


int ICMPv6Option::setPrefixLength(u8 val){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return OP_FAILURE;
  this->h_pi->prefix_length=val;
  return OP_SUCCESS;
} /* End of setPrefixLength() */


u8 ICMPv6Option::getPrefixLength(){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return 0;
  else
    return this->h_pi->prefix_length;
} /* End of getPrefixLength() */


int ICMPv6Option::setFlags(u8 val){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return OP_FAILURE;
  this->h_pi->flags=val;
  return OP_SUCCESS;
} /* End of setFlags() */


u8 ICMPv6Option::getFlags(){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return 0;
  else
    return this->h_pi->flags;
} /* End of getFlags() */


int ICMPv6Option::setValidLifetime(u32 val){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return OP_FAILURE;
  this->h_pi->valid_lifetime=htonl(val);
  return OP_SUCCESS;
} /* End of setValidLifetime() */


u32 ICMPv6Option::getValidLifetime(){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return 0;
  else
    return ntohl(this->h_pi->valid_lifetime);
} /* End of getValidLifetime() */


int ICMPv6Option::setPreferredLifetime(u32 val){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return OP_FAILURE;
  this->h_pi->preferred_lifetime=htonl(val);
  return OP_SUCCESS;
} /* End of setPreferredLifetime() */


u32 ICMPv6Option::getPreferredLifetime(){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return 0;
  else
    return ntohl(this->h_pi->preferred_lifetime);
} /* End of getPreferredLifetime() */


int ICMPv6Option::setPrefix(u8 *val){
  if(val==NULL || this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return OP_FAILURE;
  else
    memcpy(this->h_pi->prefix, val, 16);
  return OP_SUCCESS;
} /* End of setPrefix() */


u8 *ICMPv6Option::getPrefix(){
  if(this->h.type!=ICMPv6_OPTION_PREFIX_INFO)
    return NULL;
  else
    return this->h_pi->prefix;
} /* End of getPrefix() */


int ICMPv6Option::setMTU(u32 val){
  if(this->h.type!=ICMPv6_OPTION_MTU)
    return OP_FAILURE;
  this->h_mtu->mtu=htonl(val);
  return OP_SUCCESS;
} /* End of setMTU() */


u32 ICMPv6Option::getMTU(){
  if(this->h.type!=ICMPv6_OPTION_MTU)
    return 0;
  else
    return ntohl(this->h_mtu->mtu);
} /* End of getMTU() */



/******************************************************************************/
/* MISCELLANEOUS STUFF                                                        */
/******************************************************************************/

/** Returns the standard ICMPv6 optiom length for the supplied option type.
  * @warning Return value corresponds strictly to the ICMPv7 option header, this
  * is, the minimum length of the OPTION, variable length payload is never
  * included. For example, an ICMPv6 Redirect option has a fixed header of 8
  * bytes but then it may contain an IPv6 header. We only return 8
  * because we don't know in advance the total number of bytes for the message.
  * Same applies to the rest of types. */
int ICMPv6Option::getHeaderLengthFromType(u8 type){
  switch( type ){
    case ICMPv6_OPTION_SRC_LINK_ADDR:
        return ICMPv6_OPTION_SRC_LINK_ADDR_LEN;
    break;

    case ICMPv6_OPTION_TGT_LINK_ADDR:
        return ICMPv6_OPTION_TGT_LINK_ADDR_LEN;
    break;

    case ICMPv6_OPTION_PREFIX_INFO:
        return ICMPv6_OPTION_PREFIX_INFO_LEN;
    break;

    case ICMPv6_OPTION_REDIR_HDR:
        return ICMPv6_OPTION_REDIR_HDR_LEN;
    break;

    case ICMPv6_OPTION_MTU:
        return ICMPv6_OPTION_MTU_LEN;
    break;

    /* Packets with non RFC-Compliant option types will be represented as an
     * 8-byte ICMPv6 option. */
    default:
        return ICMPv6_OPTION_MIN_HEADER_LEN;
    break;
  }
} /* End of getHeaderLengthFromType() */
