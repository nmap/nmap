
/***************************************************************************
 * ICMPv6Header.cc -- The ICMPv6Header Class represents an ICMP version 6  *
 * packet. It contains methods to set any header field. In general, these  *
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

#include "ICMPv6Header.h"
#include "IPv6Header.h"
#include <assert.h>

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
ICMPv6Header::ICMPv6Header() {
  this->reset();
} /* End of ICMPv6Header constructor */


ICMPv6Header::~ICMPv6Header() {

} /* End of ICMPv6Header destructor */


/** Sets every attribute to its default value */
void ICMPv6Header::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv6_hdr_t));
  h_du = (dest_unreach_msg_t       *)this->h.data;
  h_ptb= (pkt_too_big_msg_t        *)this->h.data;
  h_te = (time_exceeded_msg_t      *)this->h.data;
  h_pp = (parameter_problem_msg_t  *)this->h.data;
  h_e  = (echo_msg_t               *)this->h.data;
  h_ra = (router_advert_msg_t      *)this->h.data;
  h_rs = (router_solicit_msg_t     *)this->h.data;
  h_na = (neighbor_advert_msg_t    *)this->h.data;
  h_ns = (neighbor_solicit_msg_t   *)this->h.data;
  h_r  = (redirect_msg_t           *)this->h.data;
  h_rr = (router_renumbering_msg_t *)this->h.data;
  h_ni = (nodeinfo_msg_t           *)this->h.data;
  h_mld= (mld_msg_t                *)this->h.data;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv6Header::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv6Header class is able to hold a maximum of 
  * sizeof(nping_icmpv6_hdr_t) bytes. If the supplied buffer is longer than
  * that, only the first 1508 bytes will be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv6Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMPv6_MIN_HEADER_LEN){
    this->length=0;
    return OP_FAILURE;
  }else{
    int stored_len = MIN( sizeof(nping_icmpv6_hdr_t), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int ICMPv6Header::protocol_id() const {
    return HEADER_TYPE_ICMPv6;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int ICMPv6Header::validate(){
  int should_have=this->getHeaderLengthFromType( this->getType() );
  if(this->length < should_have){
      return OP_FAILURE;
  }else{
      /* WARNING: If we extend this class to support new ICMPv6 types with
       * a variable length header (not even sure they exist), we need to
       * parse the objects data and return our actual size, not this size that
       * is obtained from the type. */
      return should_have;
  }
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int ICMPv6Header::print(FILE *output, int detail) const {
  u8 type=this->getType();
  u8 code=this->getCode();
  const char *typestr=this->type2string(type, code);

  fprintf(output, "ICMPv6[%s", typestr);
  if(detail>=PRINT_DETAIL_MED)
    fprintf(output, " (type=%u/code=%u)", type, code);

  switch(type) {
    
    case ICMPv6_UNREACH:
    case ICMPv6_TIMXCEED:
      if(detail>=PRINT_DETAIL_HIGH)
        fprintf(output, " unused=%lu", (long unsigned int)this->getUnused());
    break;
    
    case ICMPv6_ROUTERSOLICIT:
      if(detail>=PRINT_DETAIL_HIGH)
        fprintf(output, " reserved=%lu", (long unsigned int)this->getReserved());
    break;
  
    case ICMPv6_PKTTOOBIG:
      fprintf(output, " mtu=%lu", (long unsigned int)this->getMTU());
    break;
    
    case ICMPv6_PARAMPROB:
      fprintf(output, " pointer=%lu", (long unsigned int)this->getPointer());
    break;
    
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
      fprintf(output, " id=%u seq=%u", this->getIdentifier(), this->getSequence());
    break;
    
    case ICMPv6_NODEINFOQUERY:
    case ICMPv6_NODEINFORESP:
      if(this->getNodeInfoFlags()!=0){
        fprintf(output, " flags=");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_T)
          fprintf(output, "T");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_A)
          fprintf(output, "A");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_C)
          fprintf(output, "C");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_L)
          fprintf(output, "L");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_G)
          fprintf(output, "G");
        if(this->getNodeInfoFlags() & ICMPv6_NI_FLAG_S)
          fprintf(output, "S");
        }
      if(detail>=PRINT_DETAIL_HIGH){
        #ifdef WIN32
          fprintf(output, " nonce=%I64u",  (long long unsigned int)this->getNonce());
        #else
          fprintf(output, " nonce=%llu",  (long long unsigned int)this->getNonce());
        #endif
      }
    break;

    default:
        /* Print nothing */
    break;
  }

  if(detail>=PRINT_DETAIL_HIGH)
      fprintf(output, " csum=0x%04X", ntohs(this->getSum()));
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

/******************************************************************************/
/* ICMPv6 COMMON HEADER                                                       */
/******************************************************************************/

/** Set ICMPv6 type field */
int ICMPv6Header::setType(u8 val){
  this->h.type = val;
  this->length = getHeaderLengthFromType(val);
  return OP_SUCCESS;
} /* End of setType() */


/** Returns ICMPv6 type field */
u8 ICMPv6Header::getType() const {
  return this->h.type;
} /* End of getType() */


/* Returns true if the supplied ICMPv6 type is supported by this class */
bool ICMPv6Header::validateType(u8 val){
  switch( val ){
    case ICMPv6_UNREACH:
    case ICMPv6_PKTTOOBIG:
    case ICMPv6_TIMXCEED:
    case ICMPv6_PARAMPROB:
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
    case ICMPv6_ROUTERSOLICIT:
    case ICMPv6_ROUTERADVERT:
    case ICMPv6_NGHBRSOLICIT:
    case ICMPv6_NGHBRADVERT:
    case ICMPv6_REDIRECT:
    case ICMPv6_RTRRENUM:
        return true;
    break;

    default:
        return false;
    break;
  }
  return false;
} /* End of validateType() */


bool ICMPv6Header::validateType(){
  return validateType(this->h.type);
} /* End of validateType() */


/** Set ICMPv6 code field */
int ICMPv6Header::setCode(u8 val){
  this->h.code = val;
  return OP_SUCCESS;
} /* End of setCode() */


/** Returns ICMPv6 code field */
u8 ICMPv6Header::getCode() const {
  return this->h.code;
} /* End of getCode() */


/** Given an ICMP Type and a code, determines whether the code corresponds to
  * a RFC compliant code (eg: code 0x03  for "port unreachable" in ICMP
  * Unreachable messages) or just some other bogus code. */
bool ICMPv6Header::validateCode(u8 type, u8 code){
//    switch (type){
//
//        case ICMPv6_UNREACH:
//            return (code==0);
//        break;
//
//        case ICMPv6_PKTTOOBIG:
//            switch( code ){
//                case XXXXXXXXXXXX:
//                case YYYYYYYYYYYY:
//                case ZZZZZZZZZZZZ:
//                    return true;
//                break;
//            }
//        break;
//
//        case ICMPv6_TIMXCEED:
//
//        break;
//
//        case ICMPv6_PARAMPROB:
//
//        break;
//
//        case ICMPv6_ECHO:
//
//        break;
//
//        case ICMPv6_ECHOREPLY:
//
//        break;
//
//        case ICMPv6_ROUTERSOLICIT:
//        case ICMPv6_ROUTERADVERT:
//        case ICMPv6_NGHBRSOLICIT:
//        case ICMPv6_NGHBRADVERT:
//        case ICMPv6_REDIRECT:
//        break;
//
//        default:
//            return false;
//        break;
//    }
    return false;
} /* End of validateCode() */


/** Computes the ICMP header checksum and sets the checksum field to the right
 *  value.
 * @warning  This method requires the ICMPv6Object to be linked to an IPv6Header
 * object, so make sure setNextElement() has been called like this:
 *
 * IPv6Header ip6;
 * ICMPv6Header icmp6;
 * [...] # Set header fields
 * ip6.setNextElement(&icmp6);
 * icmp6.setSum();
 *
 * Note that there can be a number of extension headers between the ICMPv6
 * header and the IPv6 one, but all of them need to be linked in order for this
 * method to traverse the list of headers and find the IPv6 source and
 * destination address, required to compute the checksum. So things like the
 * following are OK:
 *
 * IPv6Header ip6;
 * HopByHopHeader hop;
 * RoutingHeader rte;
 * FragmentHeader frg;
 * ICMPv6Header icmp6;
 * [...] # Set whatever header fields you need
 * ip6.setNextElement(&hop);
 * hop.setNextElement(&rte);
 * rte.setNextElement(&frg);
 * frg.setNextElement(&icmp6);
 * icmp6.setSum(); # setSum() will be able to reach the IPv6Header.
 *
 */
int ICMPv6Header::setSum(){
  PacketElement *hdr;
  hdr=this->getPrevElement();
  /* Traverse the list of headers backwards until we find the IPv6 header */
  while(hdr!=NULL){
      if (hdr->protocol_id()==HEADER_TYPE_IPv6){
            IPv6Header *v6hdr=(IPv6Header *)hdr;
            struct in6_addr i6src, i6dst;
            this->h.checksum=0;
            memcpy(i6src.s6_addr, v6hdr->getSourceAddress(), 16);
            memcpy(i6dst.s6_addr, v6hdr->getDestinationAddress(), 16);
            u8 *buff=(u8 *)safe_malloc(this->getLen());
            this->dumpToBinaryBuffer(buff, this->getLen());
            this->h.checksum=ipv6_pseudoheader_cksum(&i6src, &i6dst, this->protocol_id(), this->getLen(), buff);
            free(buff);
          return OP_SUCCESS;
      }else{
          hdr=hdr->getPrevElement();
      }
  }
  return OP_FAILURE;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int ICMPv6Header::setSum(u16 s){
  this->h.checksum=s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 ICMPv6Header::getSum() const{
  return this->h.checksum;
} /* End of getSum() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv6Header::setReserved(u32 val){
  u32 aux32=0;
  u8 *auxpnt=(u8 *)&aux32;

  switch(this->h.type){

    case ICMPv6_UNREACH:
        this->h_du->unused=htonl(val);
    break;
        
    case ICMPv6_TIMXCEED:
        this->h_te->unused=htonl(val);
    break;
    
    case ICMPv6_ROUTERSOLICIT:
        this->h_rs->reserved=htonl(val);
    break;
    
    case ICMPv6_NGHBRSOLICIT:
        this->h_ns->reserved=htonl(val);
    break;

    case ICMPv6_REDIRECT:
        this->h_r->reserved=htonl(val);
    break;


    case ICMPv6_NGHBRADVERT:
        /* The reserved field in Neighbor Advertisement messages is only
         * 24-bits long so we convert the supplied value to big endian and
         * use only the 24 least significant bits. */
        aux32=htonl(val);
        this->h_na->reserved[0]=auxpnt[1];
        this->h_na->reserved[1]=auxpnt[2];
        this->h_na->reserved[2]=auxpnt[3];
    break;

    case ICMPv6_RTRRENUM:
        this->h_rr->reserved=htonl(val);
    break;
    
    /* Types that don't have a reserved field */
    case ICMPv6_ROUTERADVERT:
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
    case ICMPv6_PARAMPROB:
    case ICMPv6_PKTTOOBIG:
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setReserved() */


/** @warning Returned value is in host byte order */
u32 ICMPv6Header::getReserved() const {
  u32 aux32=0;
  u8 *auxpnt=(u8 *)&aux32;

  switch(this->h.type){

    case ICMPv6_UNREACH:
        return ntohl(this->h_du->unused);
    break;

    case ICMPv6_TIMXCEED:
        return ntohl(this->h_te->unused);
    break;

    case ICMPv6_ROUTERSOLICIT:
        return ntohl(this->h_rs->reserved);
    break;

    case ICMPv6_NGHBRSOLICIT:
        return ntohl(this->h_ns->reserved);
    break;

    case ICMPv6_REDIRECT:
        return ntohl(this->h_r->reserved);
    break;

    case ICMPv6_NGHBRADVERT:
        /* The reserved field in Neighbor Advertisement messages is only
         * 24-bits long so we extract the stored value and convert it to host
         * byte order. */
        auxpnt[0]=0;
        auxpnt[1]=this->h_na->reserved[0];
        auxpnt[2]=this->h_na->reserved[1];
        auxpnt[3]=this->h_na->reserved[2];
        return ntohl(aux32);
    break;

    case ICMPv6_RTRRENUM:
        return ntohl(this->h_rr->reserved);
    break;

    /* Types that don't have a reserved field */
    case ICMPv6_ROUTERADVERT:
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
    case ICMPv6_PARAMPROB:
    case ICMPv6_PKTTOOBIG:
    default:
        return 0;
    break;
  }
} /* End of setReserved() */

int ICMPv6Header::setUnused(u32 val){
  return this->setReserved(val);
} /* End of setUnused() */


u32 ICMPv6Header::getUnused() const {
  return this->getReserved();
} /* End of getUnused() */


int ICMPv6Header::setFlags(u8 val){
  switch(this->h.type){

    case ICMPv6_ROUTERADVERT:
        this->h_ra->autoconfig_flags=val;
    break;

    case ICMPv6_NGHBRADVERT:
        this->h_na->flags=val;
    break;

    case ICMPv6_RTRRENUM:
        this->h_rr->flags=val;
    break;

    case ICMPv6_NODEINFOQUERY:
    case ICMPv6_NODEINFORESP:
        netutil_fatal("setFlags() cannot be used in NI, use setNodeInfoFlags() instead\n");
    break;

    /* Types that don't have a flags field */
    case ICMPv6_TIMXCEED:
    case ICMPv6_UNREACH:
    case ICMPv6_ROUTERSOLICIT:
    case ICMPv6_NGHBRSOLICIT:
    case ICMPv6_REDIRECT:
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
    case ICMPv6_PARAMPROB:
    case ICMPv6_PKTTOOBIG:
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setFlags() */


u8 ICMPv6Header::getFlags() const {
  switch(this->h.type){

    case ICMPv6_ROUTERADVERT:
        return this->h_ra->autoconfig_flags;
    break;

    case ICMPv6_NGHBRADVERT:
        return this->h_na->flags;
    break;

    case ICMPv6_RTRRENUM:
        return this->h_rr->flags;
    break;

    case ICMPv6_NODEINFOQUERY:
    case ICMPv6_NODEINFORESP:
        netutil_fatal("getFlags() cannot be used in NI, use getNodeInfoFlags() instead\n");
        return 0;
    break;

    /* Types that don't have a flags field */
    case ICMPv6_TIMXCEED:
    case ICMPv6_UNREACH:
    case ICMPv6_ROUTERSOLICIT:
    case ICMPv6_NGHBRSOLICIT:
    case ICMPv6_REDIRECT:
    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
    case ICMPv6_PARAMPROB:
    case ICMPv6_PKTTOOBIG:
    default:
        return 0;
    break;
  }
} /* End of getFlags() */

/******************************************************************************/
/* ICMPv6 DESTINATION UNREACHABLE                                             */
/******************************************************************************/

/******************************************************************************/
/* ICMPv6 PACKET TOO BIG                                                      */
/******************************************************************************/
int ICMPv6Header::setMTU(u32 mtu){
  this->h_ptb->mtu=htonl(mtu);
  return OP_SUCCESS;
} /* End of setMTU() */

u32 ICMPv6Header::getMTU() const {
  return ntohl(this->h_ptb->mtu);
} /* End of getMTU() */

/******************************************************************************/
/* ICMPv6 TIME EXCEEDED                                                       */
/******************************************************************************/

/******************************************************************************/
/* ICMPv6 PARAMETER PROBLEM                                                   */
/******************************************************************************/
int ICMPv6Header::setPointer(u32 pnt){
  this->h_pp->pointer=htonl(pnt);
  return OP_SUCCESS;
} /* End of setPointer() */


u32 ICMPv6Header::getPointer() const {
  return ntohl(this->h_pp->pointer);
} /* End of getPointer() */

/******************************************************************************/
/* ICMPv6 ECHO                                                                */
/******************************************************************************/
int ICMPv6Header::setIdentifier(u16 val){
  this->h_e->id=htons(val);
  return OP_SUCCESS;
} /* End of setIdentifier() */


u16 ICMPv6Header::getIdentifier() const{
  return ntohs(this->h_e->id);
} /* End of getIdentifier() */


int ICMPv6Header::setSequence(u16 val){
  switch(this->h.type){
    case ICMPv6_RTRRENUM:
        this->h_rr->seq=htonl( ((u32)val) );
    break;

    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
        this->h_e->seq=htons(val);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setSequence() */


int ICMPv6Header::setSequence(u32 val){
  switch(this->h.type){
    case ICMPv6_RTRRENUM:
        this->h_rr->seq=htonl(val);
    break;

    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
        this->h_e->seq=htons( ((u16)val) );
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setSequence() */


u32 ICMPv6Header::getSequence() const{
  switch(this->h.type){
    case ICMPv6_RTRRENUM:
        return ntohl(this->h_rr->seq);
    break;

    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
        return (u32)ntohs(this->h_e->seq);
    break;
  }
  return 0;
} /* End of getSequence() */


/******************************************************************************/
/* ICMPv6 ROUTER ADVERTISEMENT                                                */
/******************************************************************************/
int ICMPv6Header::setCurrentHopLimit(u8 val){
  this->h_ra->current_hop_limit=val;
  return OP_SUCCESS;
} /* End of setCurrentHopLimit() */

u8 ICMPv6Header::getCurrentHopLimit() const {
  return this->h_ra->current_hop_limit;
} /* End of getCurrentHopLimit() */

int ICMPv6Header::setRouterLifetime(u16 val){
  this->h_ra->router_lifetime=val;
  return OP_SUCCESS;
} /* End of setRouterLifetime() */

u16 ICMPv6Header::getRouterLifetime() const {
  return this->h_ra->router_lifetime;
} /* End of getRouterLifetime() */

int ICMPv6Header::setReachableTime(u32 val){
  this->h_ra->reachable_time=val;
  return OP_SUCCESS;
} /* End of setReachableTime() */

u32 ICMPv6Header::getReachableTime() const {
    return this->h_ra->reachable_time;
} /* End of getReachableTime() */

int ICMPv6Header::setRetransmissionTimer(u32 val){
  this->h_ra->retransmission_timer=val;
  return OP_SUCCESS;
} /* End of setRetransmissionTimer() */

u32 ICMPv6Header::getRetransmissionTimer() const {
  return this->h_ra->retransmission_timer;
} /* End of getRetransmissionTimer() */

/******************************************************************************/
/* ICMPv6 ROUTER SOLICITATION                                                 */
/******************************************************************************/

/******************************************************************************/
/* ICMPv6 NEIGHBOR ADVERTISEMENT                                              */
/******************************************************************************/

int ICMPv6Header::setTargetAddress(struct in6_addr addr){
  switch(this->h.type){
    case ICMPv6_NGHBRADVERT:
        memcpy(this->h_na->target_address, addr.s6_addr, 16);
    break;

    case ICMPv6_NGHBRSOLICIT:
        memcpy(this->h_ns->target_address, addr.s6_addr, 16);
    break;

    case ICMPv6_REDIRECT:
         memcpy(this->h_r->target_address, addr.s6_addr, 16);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setTargetAddress() */


struct in6_addr ICMPv6Header::getTargetAddress() const {
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));

  switch(this->h.type){
    case ICMPv6_NGHBRADVERT:
        memcpy(addr.s6_addr, this->h_na->target_address, 16);
    break;

    case ICMPv6_NGHBRSOLICIT:
        memcpy(addr.s6_addr, this->h_ns->target_address, 16);
    break;

    case ICMPv6_REDIRECT:
         memcpy(addr.s6_addr, this->h_r->target_address, 16);
    break;
  }
  return addr;
} /* End of setTargetAddress() */


int ICMPv6Header::setDestinationAddress(struct in6_addr addr){
  switch(this->h.type){
    case ICMPv6_REDIRECT:
         memcpy(this->h_r->destination_address, addr.s6_addr, 16);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setDestinationAddress() */


struct in6_addr ICMPv6Header::getDestinationAddress() const {
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));

  switch(this->h.type){
    case ICMPv6_REDIRECT:
         memcpy(addr.s6_addr, this->h_r->destination_address, 16);
    break;
  }
  return addr;
} /* End of setTargetAddress() */


/******************************************************************************/
/* ICMPv6 NEIGHBOR SOLICITATION                                               */
/******************************************************************************/

/******************************************************************************/
/* ICMPv6 REDIRECT                                                            */
/******************************************************************************/

/******************************************************************************/
/* ICMPv6 ROUTER RENUMBERING                                                  */
/******************************************************************************/
int ICMPv6Header::setSegmentNumber(u8 val){
  this->h_rr->segment_number=val;
  return OP_SUCCESS;
} /* End of setSegmentNumber() */

u8 ICMPv6Header::getSegmentNumber() const {
  return this->h_rr->segment_number;
} /* End of getSegmentNumber() */

int ICMPv6Header::setMaxDelay(u16 val){
  switch(this->h.type){
    case ICMPv6_RTRRENUM:
      this->h_rr->max_delay=htons(val);
      return OP_SUCCESS;
    break;

    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
      this->h_mld->max_response_delay=htons(val);
      return OP_SUCCESS;
    break;

    default:
      return OP_FAILURE;
    break;
  }
} /* End of setMaxDelay() */


u16 ICMPv6Header::getMaxDelay() const {
  switch(this->h.type){
    case ICMPv6_RTRRENUM:
      return ntohs(this->h_rr->max_delay);
    break;

    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
      return ntohs(this->h_mld->max_response_delay);
    break;

    default:
      return 0;
    break;
  }
} /* End of getMaxDelay() */



/******************************************************************************/
/* ICMPv6 NODE INFORMATION QUERIES                                            */
/******************************************************************************/
/** Set NI Qtype */
int ICMPv6Header::setQtype(u16 val){
  this->h_ni->qtype = htons(val);
  return OP_SUCCESS;
} /* End of setQtype() */


/** Returns NI Qtype */
u16 ICMPv6Header::getQtype() const {
  return ntohs(this->h_ni->qtype);
} /* End of getQtype() */


/** Set NI Flags */
int ICMPv6Header::setNodeInfoFlags(u16 val){
  this->h_ni->flags = htons(val);
  return OP_SUCCESS;
} /* End of setNodeInfoFlags() */


/** Returns NI Flags */
u16 ICMPv6Header::getNodeInfoFlags() const {
  return ntohs(this->h_ni->flags);
} /* End of getNodeInfoFlags() */


/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       unused      |G|S|L|C|A|T|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Set NI Flag G */
int ICMPv6Header::setG(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0020;
  else
    current_flags = current_flags & ~0x0020;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setG() */


/* Get NI Flag G */
bool ICMPv6Header::getG() const {
  return this->getNodeInfoFlags() & 0x0020;
} /* End of getG() */


/* Set NI Flag S */
int ICMPv6Header::setS(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0010;
  else
    current_flags = current_flags & ~0x0010;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setS() */


/* Get NI Flag  S */
bool ICMPv6Header::getS() const {
  return this->getNodeInfoFlags() & 0x0010;
} /* End of getS() */


/* Set NI Flag L */
int ICMPv6Header::setL(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0008;
  else
    current_flags = current_flags & ~0x0008;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setL() */


/* Get NI Flag L */
bool ICMPv6Header::getL() const {
  return this->getNodeInfoFlags() & 0x0008;
} /* End of getL() */


/* Set NI Flag C */
int ICMPv6Header::setC(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0004;
  else
    current_flags = current_flags & ~0x0004;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setC() */


/* Get NI Flag C */
bool ICMPv6Header::getC() const {
  return this->getNodeInfoFlags() & 0x0004;
} /* End of getC() */


/* Set NI Flag A */
int ICMPv6Header::setA(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0002;
  else
    current_flags = current_flags & ~0x0002;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setA() */


/* Get NI Flag A */
bool ICMPv6Header::getA() const {
  return this->getNodeInfoFlags() & 0x0002;
} /* End of getA() */


/* Set NI Flag T */
int ICMPv6Header::setT(bool flag_value){
  u16 current_flags = this->getNodeInfoFlags();
  if(flag_value)
    current_flags = current_flags | 0x0001;
  else
    current_flags = current_flags & ~0x0001;
  this->setNodeInfoFlags(current_flags);
  return OP_SUCCESS;
} /* End of setT() */


/* Get NI Flag T */
bool ICMPv6Header::getT() const {
  return this->getNodeInfoFlags() & 0x0001;
} /* End of getT() */


/* Set the Nonce field. */
int ICMPv6Header::setNonce(u64 nonce_value){
  this->h_ni->nonce=nonce_value;
  return OP_SUCCESS;
} /* End of setNonce() */


/* Set the Nonce field.
 * @warning: Supplied buffer must contain 8 bytes. */
int ICMPv6Header::setNonce(const u8 *nonce){
  if(nonce==NULL)
    return OP_FAILURE;
  memcpy(&(this->h_ni->nonce), nonce, NI_NONCE_LEN);
  return OP_SUCCESS;
} /* End of setNonce() */


/* Returns a pointer to the nonce buffer.
 * @warning: The returned pointer is guaranteed to point to an 8-byte buffer.
 * However, what comes after the 8th byte is unspecified. */
u64 ICMPv6Header::getNonce() const {
  return this->h_ni->nonce;
} /* End of getNonce() */


/******************************************************************************/
/* MULTICAST LISTENER DISCOVERY                                               */
/******************************************************************************/

int ICMPv6Header::setMulticastAddress(struct in6_addr addr){
  switch(this->h.type){
    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
       memcpy(this->h_mld->mcast_address, addr.s6_addr, 16);
    break;

    default:
        return OP_FAILURE;
    break;
  }

  return OP_SUCCESS;
} /* End of setMulticastAddress() */


struct in6_addr ICMPv6Header::getMulticastAddress() const {
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));

  switch(this->h.type){
    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
       memcpy(addr.s6_addr, this->h_mld->mcast_address, 16);
    break;
  }
  return addr;
} /* End of setMulticastAddress() */


/******************************************************************************/
/* MISCELLANEOUS STUFF                                                        */
/******************************************************************************/

/** Returns the standard ICMPv6 header length for the supplied ICMP message type.
  * @warning Return value corresponds strictly to the ICMP header, this is,
  * the minimum length of the ICMP header, variable length payload is never
  * included. For example, an ICMPv6 Redirect has a fixed header of 40
  * bytes but then the packet may contain ICMPv6 options. We only return 40
  * because we don't know in advance the total number of bytes for the message.
  * Same applies to the rest of types. */
int ICMPv6Header::getHeaderLengthFromType(u8 type) const {

  switch( type ){
    case ICMPv6_UNREACH:
        return ICMPv6_UNREACH_LEN;
    break;
    case ICMPv6_PKTTOOBIG:
        return ICMPv6_PKTTOOBIG_LEN;
    break;

    case ICMPv6_TIMXCEED:
        return ICMPv6_TIMXCEED_LEN;
    break;

    case ICMPv6_PARAMPROB:
        return ICMPv6_PARAMPROB_LEN;
    break;

    case ICMPv6_ECHO:
        return ICMPv6_ECHO_LEN;
    break;

    case ICMPv6_ECHOREPLY:
        return ICMPv6_ECHOREPLY_LEN;
    break;

    case ICMPv6_ROUTERSOLICIT:
        return ICMPv6_ROUTERSOLICIT_LEN;
    break;

    case ICMPv6_ROUTERADVERT:
        return ICMPv6_ROUTERADVERT_LEN;
    break;

    case ICMPv6_NGHBRSOLICIT:
        return ICMPv6_NGHBRSOLICIT_LEN;
    break;

    case ICMPv6_NGHBRADVERT:
        return ICMPv6_NGHBRADVERT_LEN;
    break;

    case ICMPv6_REDIRECT:
        return ICMPv6_REDIRECT_LEN;
    break;

    case ICMPv6_RTRRENUM:
        return ICMPv6_RTRRENUM_LEN;
    break;

    case ICMPv6_NODEINFOQUERY:
    case ICMPv6_NODEINFORESP:
        return ICMPv6_NODEINFO_LEN;
    break;

    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
        return ICMPv6_MLD_LEN;
    break;

    /* Packets with non RFC-Compliant types will be represented as an 8-byte
     * ICMPv6 header, just like the types that don't include additional info */
    default:
        return ICMPv6_MIN_HEADER_LEN;
    break;
  }
} /* End of getHeaderLengthFromType() */


/* Returns true if the packet is an ICMPv6 error message. */
bool ICMPv6Header::isError() const {
  switch( this->getType() ){
    case ICMPv6_UNREACH:
    case ICMPv6_PKTTOOBIG:
    case ICMPv6_TIMXCEED:
    case ICMPv6_PARAMPROB:
      return true;
    break;

    default:
      return false;
    break;
  }
} /* End of isError() */


const char *ICMPv6Header::type2string(int type, int code) const {
  switch(type) {

    case ICMPv6_UNREACH:
      switch(code) {
        case ICMPv6_UNREACH_NO_ROUTE: return "Network unreachable"; break;
        case ICMPv6_UNREACH_PROHIBITED: return "Comm prohibited"; break;
        case ICMPv6_UNREACH_BEYOND_SCOPE: return "Beyond scope"; break;
        case ICMPv6_UNREACH_ADDR_UNREACH: return "Address unreachable"; break;
        case ICMPv6_UNREACH_PORT_UNREACH: return "Port unreachable"; break;
        case ICMPv6_UNREACH_SRC_ADDR_FAILED: return "Source address failed"; break;
        case ICMPv6_UNREACH_REJECT_ROUTE: return "Reject route"; break;
        default: return "Destination unreachable (unknown code)"; break;
      }
    break;   
    
    case ICMPv6_PKTTOOBIG:
      return "Packet too big"; 
    break;

    case ICMPv6_TIMXCEED:
      switch(code){
        case ICMPv6_TIMXCEED_HOP_EXCEEDED: return "HopLimit=0 in transit"; break;
        case ICMPv6_TIMXCEED_REASS_EXCEEDED: return "Reassembly time exceeded"; break;
        default: return "Time exceeded (unknown code)"; break;
      }
    break;
    
    case ICMPv6_PARAMPROB:
      switch(code){
        case ICMPv6_PARAMPROB_FIELD: return "Parameter problem (bad field)"; break;
        case ICMPv6_PARAMPROB_NEXT_HDR: return "Parameter problem (next header unknown)"; break;
        case ICMPv6_PARAMPROB_OPTION: return "Parameter problem (bad option)"; break;
        default: return "Parameter problem (unknown code)"; break;
      }
    break;

    case ICMPv6_ECHO:
      return "Echo request"; 
    break;
    case ICMPv6_ECHOREPLY:
      return "Echo reply"; 
    break;
    case ICMPv6_GRPMEMBQUERY:
      return "Group membership query"; 
    break;
    case ICMPv6_GRPMEMBREP:
      return "Group membership report"; 
    break;
    case ICMPv6_GRPMEMBRED:
      return "Group membership reduction"; 
    break;
    case ICMPv6_ROUTERSOLICIT:
      return "Router sol"; 
    break;
    case ICMPv6_ROUTERADVERT:
      return "Router advert"; 
    break;
    case ICMPv6_NGHBRSOLICIT:
      return "Neighbor sol"; 
    break;
    case ICMPv6_NGHBRADVERT:
      return "Neighbor advert"; 
    break;
    case ICMPv6_REDIRECT:
      return "Redirect"; 
    break;
    case ICMPv6_RTRRENUM:
      switch(code){
        case ICMPv6_RTRRENUM_COMMAND: return "Renumbering command"; break;
        case ICMPv6_RTRRENUM_RESULT: return "Renumbering result"; break;
        case ICMPv6_RTRRENUM_SEQ_RESET: return "Renumbering reset"; break;
        default: return "Router Renumbering (unknown code)"; break;
      }
    break;
    case ICMPv6_NODEINFOQUERY:
      switch(code){
        case ICMPv6_NODEINFOQUERY_IPv6ADDR: return "Node info query (IPv6 addr)"; break;
        case ICMPv6_NODEINFOQUERY_NAME: return "Node info query (name)"; break;
        case ICMPv6_NODEINFOQUERY_IPv4ADDR: return "Node info query (IPv4 addr)"; break;
        default: return "Node info query (unknown code)"; break;
      }
    break;

    case ICMPv6_NODEINFORESP:
      switch(code){
        case ICMPv6_NODEINFORESP_SUCCESS: return "Node info reply (success)"; break;
        case ICMPv6_NODEINFORESP_REFUSED: return "Node info reply (refused)"; break;
        case ICMPv6_NODEINFORESP_UNKNOWN: return "Node info reply (qtype unknown)"; break;
        default: return "Node info reply (unknown code)"; break;
      }
    break;

    case ICMPv6_INVNGHBRSOLICIT:
      return "Inverse neighbor sol"; 
    break;

    case ICMPv6_INVNGHBRADVERT:
      return "Inverse neighbor advert"; 
    break;

    case ICMPv6_MLDV2:
      return "MLDv2 report"; 
    break;

    case ICMPv6_AGENTDISCOVREQ:
      return "Home agent request"; 
    break;

    case ICMPv6_AGENTDISCOVREPLY:
      return "Home agent reply"; 
    break;

    case ICMPv6_MOBPREFIXSOLICIT:
      return "Prefix sol"; 
    break;

    case ICMPv6_MOBPREFIXADVERT:
      return "Prefix advert"; 
    break;

    case ICMPv6_CERTPATHSOLICIT:
      return "Cert path sol"; 
    break;

    case ICMPv6_CERTPATHADVERT:
      return "Cert path advert"; 
    break;

    case ICMPv6_EXPMOBILITY:
      return "Experimental mobility"; 
    break;

    case ICMPv6_MRDADVERT:
      return "Multicast router advert"; 
    break;

    case ICMPv6_MRDSOLICIT:
      return "Multicast router sol"; 
    break;

    case ICMPv6_MRDTERMINATE:
      return "Multicast router term"; 
    break;

    case ICMPv6_FMIPV6:
      return "FMIPv6"; 
    break;
         
    default:
      return "Unknown ICMPv6 type";
    break;
  } /* End of ICMP Type switch */
  return "Unknown ICMPv6 type";
} /* End of type2string() */



