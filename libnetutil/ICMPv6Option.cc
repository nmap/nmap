
/***************************************************************************
 * ICMPv6Option.cc -- The ICMPv6Option Class represents an ICMP version 6  *
 * option. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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
