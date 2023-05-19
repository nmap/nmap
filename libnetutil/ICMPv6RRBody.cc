/***************************************************************************
 * ICMPv6RRBody.h -- The ICMPv6RRBody Class represents an ICMP version 6   *
 * Router Renumbering message body. It contains methods to set any header  *
 * field. In general, these  methods do error checkings and byte order     *
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

#include "ICMPv6RRBody.h"


ICMPv6RRBody::ICMPv6RRBody() {
  this->reset();
} /* End of ICMPv6RRBody constructor */


ICMPv6RRBody::~ICMPv6RRBody() {

} /* End of ICMPv6RRBody destructor */


/** Sets every class attribute to zero */
void ICMPv6RRBody::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv6_rr_body_t));
  h_mp = (rr_match_prefix_t *)this->h.data;
  h_up = (rr_use_prefix_t   *)this->h.data;
  h_r  = (rr_result_msg_t   *)this->h.data;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv6RRBody::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv6RRBody class is able to hold a maximum of
  * sizeof(nping_icmpv6_rr_body_t) bytes. If the supplied buffer is longer than
  * that, only the first sizeof(nping_icmpv6_rr_body_t) bytes will be stored in
  * the internal buffer.
  * @warning Supplied len MUST be at least ICMPv6_RR_MIN_LENGTH bytes
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv6RRBody::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMPv6_RR_MIN_LENGTH){
    return OP_FAILURE;
  }else{
    int stored_len = MIN( sizeof(nping_icmpv6_rr_body_t), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */

