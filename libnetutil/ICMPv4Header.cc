
/***************************************************************************
 * ICMPv4Header.cc -- The ICMPv4Header Class represents an ICMP version 4  *
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

#include "ICMPv4Header.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
ICMPv4Header::ICMPv4Header() {
  this->reset();
} /* End of ICMPv4Header constructor */


ICMPv4Header::~ICMPv4Header() {

} /* End of ICMPv4Header destructor */


/** Sets every attribute to its default value */
void ICMPv4Header::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv4_hdr_t));
  h_du  = (icmp4_dest_unreach_msg_t        *)this->h.data;
  h_te  = (icmp4_time_exceeded_msg_t       *)this->h.data;
  h_pp  = (icmp4_parameter_problem_msg_t   *)this->h.data;
  h_sq  = (icmp4_source_quench_msg_t       *)this->h.data;
  h_r   = (icmp4_redirect_msg_t            *)this->h.data;
  h_e   = (icmp4_echo_msg_t                *)this->h.data;
  h_t   = (icmp4_timestamp_msg_t           *)this->h.data;
  h_i   = (icmp4_information_msg_t         *)this->h.data;
  h_ra  = (icmp4_router_advert_msg_t       *)this->h.data;
  h_rs  = (icmp4_router_solicit_msg_t      *)this->h.data;
  h_sf  = (icmp4_security_failures_msg_t   *)this->h.data;
  h_am  = (icmp4_address_mask_msg_t        *)this->h.data;
  h_trc = (icmp4_traceroute_msg_t          *)this->h.data;
  h_dn  = (icmp4_domain_name_request_msg_t *)this->h.data;
  h_dnr = (icmp4_domain_name_reply_msg_t   *)this->h.data;
  this->routeradventries=0;
  this->domainnameentries=0;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv4Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv4Header class is able to hold a maximum of 1508 bytes.
  * If the supplied buffer is longer than that, only the first 1508 bytes will
  * be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv4 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv4Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMP_STD_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((ICMP_MAX_PAYLOAD_LEN+4), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int ICMPv4Header::protocol_id() const {
    return HEADER_TYPE_ICMPv4;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int ICMPv4Header::validate(){
  int should_have=this->getICMPHeaderLengthFromType( this->getType() );
  if(this->length < should_have){
      return OP_FAILURE;
  }else{
      /* WARNING: TODO: @todo This does not work for those messages whose
       * length is variable (e.g: router advertisements). */
      return should_have;
  }
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int ICMPv4Header::print(FILE *output, int detail) const {
  u8 type=this->getType();
  u8 code=this->getCode();
  char auxstr[64];
  struct in_addr auxaddr;
  const char *typestr=this->type2string(type, code);

  fprintf(output, "ICMPv4[%s", typestr);
  if(detail>=PRINT_DETAIL_MED)
    fprintf(output, " (type=%u/code=%u)", type, code);

  switch(type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_INFO:
    case ICMP_INFOREPLY:
        fprintf(output, " id=%u seq=%u", this->getIdentifier(), this->getSequence());
    break;

    case ICMP_UNREACH:
    case ICMP_SOURCEQUENCH:
    case ICMP_ROUTERSOLICIT:
        if(detail>=PRINT_DETAIL_HIGH)
            fprintf(output, " unused=%u", this->getUnused());
    break;

    case ICMP_REDIRECT:
        auxaddr=this->getGatewayAddress();
        inet_ntop(AF_INET, &auxaddr, auxstr, sizeof(auxstr)-1);
        fprintf(output, " addr=%s", auxstr);
    break;

    case ICMP_ROUTERADVERT:
        fprintf(output, " addrs=%u addrlen=%u lifetime=%d",
                this->getNumAddresses(),
                this->getAddrEntrySize(),
                this->getLifetime()
               );
    break;

    case ICMP_PARAMPROB:
        fprintf(output, " pointer=%u", this->getParameterPointer());
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        fprintf(output, " id=%u seq=%u", this->getIdentifier(), this->getSequence());
        fprintf(output, " orig=%lu recv=%lu trans=%lu",
                (unsigned long)this->getOriginateTimestamp(),
                (unsigned long)this->getReceiveTimestamp(),
                (unsigned long)this->getTransmitTimestamp() );
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        fprintf(output, " id=%u seq=%u", this->getIdentifier(), this->getSequence());
        auxaddr=this->getAddressMask();
        inet_ntop(AF_INET, &auxaddr, auxstr, sizeof(auxstr)-1);
        fprintf(output, " mask=%s", auxstr);
    break;

    case ICMP_TRACEROUTE:
        fprintf(output, " id=%u", this->getIDNumber());
        if(detail>=PRINT_DETAIL_HIGH)
            fprintf(output, " unused=%u", this->getUnused());
        if(detail>=PRINT_DETAIL_MED){
            fprintf(output, " outhops=%u", this->getOutboundHopCount() );
            fprintf(output, " rethops=%u", this->getReturnHopCount() );
        }
        if(detail>=PRINT_DETAIL_HIGH){
            fprintf(output, " speed=%lu", (unsigned long)this->getOutputLinkSpeed() );
            fprintf(output, " mtu=%lu", (unsigned long)this->getOutputLinkMTU());
        }
    break;

    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
        fprintf(output, " id=%u seq=%u", this->getIdentifier(), this->getSequence());
        /* TODO: print TTL and domain names in replies */
        // UNIMPLEMENTED
    break;

    case ICMP_SECURITYFAILURES:
        if(detail>=PRINT_DETAIL_HIGH)
            fprintf(output, " reserved=%u",this->getReserved());
        fprintf(output, " pointer=%u",this->getSecurityPointer());
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

/* ICMPv4 common fields  *****************************************************/
int ICMPv4Header::setType(u8 val){
  h.type = val;
  length = getICMPHeaderLengthFromType( val );
  return OP_SUCCESS;
} /* End of setType() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getType() const {
  return h.type;
} /* End of getType() */

/** Returns true if the supplied type is an RFC compliant type */
bool ICMPv4Header::validateType(u8 val){
    switch( val ){
        case ICMP_ECHOREPLY:
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
        case ICMP_REDIRECT:
        case ICMP_ECHO:
        case ICMP_ROUTERADVERT:
        case ICMP_ROUTERSOLICIT:
        case ICMP_TIMXCEED:
        case ICMP_PARAMPROB:
        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_TRACEROUTE:
        case ICMP_DOMAINNAME:
        case ICMP_DOMAINNAMEREPLY:
            return true;
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateType() */


/** Returns true if the type fields contains an RFC compliant ICMP message 
  * type. */
bool ICMPv4Header::validateType(){
    return validateType( this->h.type );
} /* End of validateType() */


/** Set ICMP code field */
int ICMPv4Header::setCode(u8 val){
  h.code = val;
  return OP_SUCCESS;
} /* End of setCode() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getCode() const {
  return h.code;
} /* End of getCode() */


/** Given an ICMP Type and a code, determines whether the code corresponds to
  * a RFC compliant code (eg: code 0x03  for "port unreachable" in ICMP
  * Unreachable messages) or just some other bogus code. */
bool ICMPv4Header::validateCode(u8 type, u8 code){
    switch (type){
        case ICMP_ECHOREPLY:
            return (code==0);
        break;

        case ICMP_UNREACH:
            switch( code ){
                case ICMP_UNREACH_NET:
                case ICMP_UNREACH_HOST:
                case ICMP_UNREACH_PROTOCOL:
                case ICMP_UNREACH_PORT:
                case ICMP_UNREACH_NEEDFRAG:
                case ICMP_UNREACH_SRCFAIL:
                case ICMP_UNREACH_NET_UNKNOWN:
                case ICMP_UNREACH_HOST_UNKNOWN:
                case ICMP_UNREACH_ISOLATED:
                case ICMP_UNREACH_NET_PROHIB:
                case ICMP_UNREACH_HOST_PROHIB:
                case ICMP_UNREACH_TOSNET:
                case ICMP_UNREACH_TOSHOST:
                case ICMP_UNREACH_COMM_PROHIB:
                case ICMP_UNREACH_HOSTPRECEDENCE:
                case ICMP_UNREACH_PRECCUTOFF:
                    return true;
            }
        break;

        case ICMP_REDIRECT:
            switch( code ){
                case ICMP_REDIRECT_NET:
                case ICMP_REDIRECT_HOST:
                case ICMP_REDIRECT_TOSNET:
                case ICMP_REDIRECT_TOSHOST:
                    return true;
            }
        break;

        case ICMP_ROUTERADVERT:
            switch( code ){
                case 0:
                case ICMP_ROUTERADVERT_MOBILE:
                    return true;
            }
        break;

        case ICMP_TIMXCEED:
            switch( code ){
                case ICMP_TIMXCEED_INTRANS:
                case ICMP_TIMXCEED_REASS:
                    return true;
            }
        break;

        case ICMP_PARAMPROB:
            switch( code ){
                case ICMM_PARAMPROB_POINTER:
                case ICMP_PARAMPROB_OPTABSENT:
                case ICMP_PARAMPROB_BADLEN:
                    return true;
            }
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_ROUTERSOLICIT:
        case ICMP_SOURCEQUENCH:
        case ICMP_ECHO:
            return (code==0);
        break;

        case ICMP_TRACEROUTE:
            switch( code ){
                case ICMP_TRACEROUTE_SUCCESS:
                case ICMP_TRACEROUTE_DROPPED:
                    return true;
            }
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateCode() */


/** Computes the ICMP header checksum and sets the checksum field to the right
 *  value. */
int ICMPv4Header::setSum(){
  u8 buffer[65535];
  int total_len=0;
  h.checksum = 0;
  
  memcpy(buffer, &h, length);
  
  if( this->getNextElement() != NULL)
    total_len=next->dumpToBinaryBuffer(buffer+length, 65535-length);   
  total_len+=length;
  
  h.checksum = in_cksum((unsigned short *)buffer, total_len);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int ICMPv4Header::setSum(u16 s){
  h.checksum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 ICMPv4Header::getSum() const {
  return h.checksum;
} /* End of getSum() */



/* Dest unreach/Source quench/Time exceeded **********************************/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReserved(u32 val){
  u32 aux32=0;
  u8 *auxpnt=(u8 *)&aux32;

  switch(this->h.type){

    case ICMP_UNREACH:
        this->h_du->unused=htonl(val);
    break;

    case ICMP_TIMXCEED:
        this->h_te->unused=htonl(val);
    break;

    case ICMP_PARAMPROB:
        /* The reserved field in Parameter Problem messages is only
         * 24-bits long so we convert the supplied value to big endian and
         * use only the 24 least significant bits. */
        aux32=htonl(val);
        this->h_pp->unused[0]=auxpnt[1];
        this->h_pp->unused[1]=auxpnt[2];
        this->h_pp->unused[2]=auxpnt[3];
    break;

    case ICMP_SOURCEQUENCH:
        this->h_sq->unused=htonl(val);
    break;

    case ICMP_ROUTERSOLICIT:
        this->h_rs->reserved=htonl(val);
    break;

    case ICMP_SECURITYFAILURES:
        /* The reserved field in Security failure messages is only
         * 16-bits long so we cast it to u16 first (callers are not supposed to
         * pass values higher than 2^16) */
        this->h_sf->reserved= htons((u16)val);
    break;

    case ICMP_TRACEROUTE:
        /* The reserved field in Traceroute messages is only
         * 16-bits long so we cast it to u16 first (callers are not supposed to
         * pass values higher than 2^16) */
        this->h_trc->unused=htons((u16)val);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setReserved() */


/** @warning Returned value is in host byte order */
u32 ICMPv4Header::getReserved() const {
  u32 aux32=0;
  u8 *auxpnt=(u8 *)&aux32;

  switch(this->h.type){

    case ICMP_UNREACH:
        return ntohl(this->h_du->unused);
    break;

    case ICMP_TIMXCEED:
        return ntohl(this->h_te->unused);
    break;

    case ICMP_PARAMPROB:
        /* The unused field in Parameter Problem messages is only
         * 24-bits long so we extract the stored value and convert it to host
         * byte order. */
        auxpnt[0]=0;
        auxpnt[1]=this->h_pp->unused[0];
        auxpnt[2]=this->h_pp->unused[1];
        auxpnt[3]=this->h_pp->unused[2];
        return ntohl(aux32);
    break;

    case ICMP_SOURCEQUENCH:
        return ntohl(this->h_sq->unused);
    break;

    case ICMP_ROUTERSOLICIT:
        return ntohl(this->h_rs->reserved);
    break;

    case ICMP_SECURITYFAILURES:
        /* The unused field in Security Failures messages is only
         * 16-bits long so we extract the stored value and cast it to an u32 in
         * host byte order */
        return (u32)ntohs(h_sf->reserved);
    break;

    case ICMP_TRACEROUTE:
        /* The reserved field in Traceroute messages is only
         * 16-bits long so we extract the stored value and cast it to an u32 in
         * host byte order */
        return (u32)ntohs(h_trc->unused);
    break;
    
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setReserved() */


int ICMPv4Header::setUnused(u32 val){
  return this->setReserved(val);
} /* End of setUnused() */


u32 ICMPv4Header::getUnused() const {
  return this->getReserved();
} /* End of getUnused() */


/* Redirect ******************************************************************/
/** @warning Supplied IP MUST be in NETWORK byte order */
int ICMPv4Header::setGatewayAddress(struct in_addr ipaddr){
  h_r->gateway_address=ipaddr;
  return OP_SUCCESS;
} /* End of setPreferredRouter() */


struct in_addr ICMPv4Header::getGatewayAddress() const {
  return h_r->gateway_address;
} /* End of getPreferredRouter() */



/* Parameter problem *********************************************************/
/** Sets pointer value in Parameter Problem messages */
int ICMPv4Header::setParameterPointer(u8 val){
  h_pp->pointer=val;
  return OP_SUCCESS;
} /* End of setParameterPointer() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getParameterPointer() const {
  return h_pp->pointer;
} /* End of getParameterPointer() */


/* Router Advertisement ******************************************************/
int ICMPv4Header::setNumAddresses(u8 val){
  h_ra->num_addrs=val;
  return OP_SUCCESS;
} /* End of setNumAddresses() */


u8 ICMPv4Header::getNumAddresses() const {
  return h_ra->num_addrs;
} /* End of getNumAddresses() */


int ICMPv4Header::setAddrEntrySize(u8 val){
  h_ra->addr_entry_size=val;
  return OP_SUCCESS;
} /* End of setAddrEntrySize() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getAddrEntrySize() const {
  return h_ra->addr_entry_size;
} /* End of getAddrEntrySize() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setLifetime(u16 val){
  h_ra->lifetime= htons(val);
  return OP_SUCCESS;
} /* End of setLifetime() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getLifetime() const {
  return ntohs( h_ra->lifetime );
} /* End of getLifetime() */


/** @warning Asummes entries have a length of 2*32bits and consist of
 *  two 32bit values.
 *  @warning This method automatically updates field "Number of addreses"
 *  calling this->setNumAddresses(). If you want to place a bogus number
 *  on such field, setNumAddresses() must be called AFTER any calls to
 *  addRouterAdvEntry()
 * */
int ICMPv4Header::addRouterAdvEntry(struct in_addr raddr, u32 pref){
  if ( this->routeradventries >= MAX_ROUTER_ADVERT_ENTRIES )
    return OP_FAILURE;
  h_ra->adverts[this->routeradventries].router_addr=raddr;
  h_ra->adverts[this->routeradventries].preference_level=htonl(pref);
  this->routeradventries++; /* Update internal entry count */
  length += 8;              /* Update total length of the ICMP packet */
  this->setNumAddresses( this->routeradventries ); /* Update number of addresses */
  return OP_SUCCESS;
} /* End of addRouterAdEntry() */


u8 *ICMPv4Header::getRouterAdvEntries(int *num) const {
  if( this->routeradventries <= 0 )
    return NULL;
  if (num!=NULL)
    *num = this->routeradventries;
  return (u8*)h_ra->adverts;
} /* End of getRouterEntries() */


/* Echo/Timestamp/Mask *******************************************************/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setIdentifier(u16 val){
  switch(this->h.type){
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        h_e->identifier=htons(val);
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        h_t->identifier=htons(val);
    break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        h_i->identifier=htons(val);
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        h_am->identifier=htons(val);
    break;

    case ICMP_DOMAINNAME:
        h_dn->identifier=htons(val);
    break;

    case ICMP_DOMAINNAMEREPLY:
        h_dnr->identifier=htons(val);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setIdentifier() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getIdentifier() const {
  switch(this->h.type){
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        return ntohs(h_e->identifier);
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return ntohs(h_t->identifier);
    break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        return ntohs(h_i->identifier);
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        return ntohs(h_am->identifier);
    break;

    case ICMP_DOMAINNAME:
        return ntohs(h_dn->identifier);
    break;

    case ICMP_DOMAINNAMEREPLY:
        return ntohs(h_dnr->identifier);
    break;

    default:
        return 0;
    break;
  }
  return 0;
} /* End of getIdentifier() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setSequence(u16 val){
  switch(this->h.type){
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        h_e->sequence=htons(val);
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        h_t->sequence=htons(val);
    break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        h_i->sequence=htons(val);
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        h_am->sequence=htons(val);
    break;

    case ICMP_DOMAINNAME:
        h_dn->sequence=htons(val);
    break;

    case ICMP_DOMAINNAMEREPLY:
        h_dnr->sequence=htons(val);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setSequence() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getSequence() const {
  switch(this->h.type){
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        return ntohs(h_e->sequence);
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return ntohs(h_t->sequence);
    break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        return ntohs(h_i->sequence);
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        return ntohs(h_am->sequence);
    break;

    case ICMP_DOMAINNAME:
        return ntohs(h_dn->sequence);
    break;

    case ICMP_DOMAINNAMEREPLY:
        return ntohs(h_dnr->sequence);
    break;

    default:
        return 0;
    break;
  }
  return 0;
} /* End of getSequence() */



/* Timestamp only ************************************************************/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setOriginateTimestamp(u32 val){
  h_t->originate_ts=htonl(val);
  return OP_SUCCESS;
} /* End of setOriginateTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getOriginateTimestamp() const {
  return ntohl(h_t->originate_ts);
} /* End of getOriginateTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReceiveTimestamp(u32 val){
  h_t->receive_ts=htonl(val);
  return OP_SUCCESS;
} /* End of setReceiveTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getReceiveTimestamp() const {
  return ntohl(h_t->receive_ts);
} /* End of getReceiveTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setTransmitTimestamp(u32 val){
  h_t->transmit_ts=htonl(val);
  return OP_SUCCESS;
} /* End of setTransmitTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getTransmitTimestamp() const {
  return ntohl(h_t->transmit_ts);
} /* End of getTransmitTimestamp() */



/* Mask only ****************************************************************/
int ICMPv4Header::setAddressMask(struct in_addr ipaddr){
  h_am->address_mask=ipaddr;
  return OP_SUCCESS;
} /* End of AddressMask() */


struct in_addr ICMPv4Header::getAddressMask() const {
  return h_am->address_mask;
} /* End of getAddressMask() */



/* Security Failures *********************************************************/
int ICMPv4Header::setSecurityPointer(u16 val){
    h_sf->pointer=htons(val);
  return OP_SUCCESS;
} /* End of setSecurityPointer() */


u16 ICMPv4Header::getSecurityPointer() const {
  return ntohs(h_sf->pointer);
} /* End of getSecurityPointer() */



/* Traceroute ****************************************************************/
int ICMPv4Header::setIDNumber(u16 val){
  h_trc->id_number = htons(val);
  return OP_SUCCESS;
} /* End of setIDNumber() */


u16 ICMPv4Header::getIDNumber() const {
  return ntohs(h_trc->id_number);
} /* End of getIDNumber() */


int ICMPv4Header::setOutboundHopCount(u16 val){
  h_trc->outbound_hop_count = htons(val);
  return OP_SUCCESS;
} /* End of setOutboundHopCount() */


u16 ICMPv4Header::getOutboundHopCount() const {
  return ntohs(h_trc->outbound_hop_count);
} /* End of getOutboundHopCount() */


int ICMPv4Header::setReturnHopCount(u16 val){
  h_trc->return_hop_count = htons(val);
  return OP_SUCCESS;
} /* End of seReturnHopCountt() */


u16 ICMPv4Header::getReturnHopCount() const {
  return ntohs(h_trc->return_hop_count);
} /* End of getReturnHopCount() */


int ICMPv4Header::setOutputLinkSpeed(u32 val){
  h_trc->output_link_speed = htonl(val);
  return OP_SUCCESS;
} /* End of setOutputLinkSpeed() */


u32 ICMPv4Header::getOutputLinkSpeed() const {
  return ntohl(h_trc->output_link_speed);
} /* End of getOutputLinkSpeed() */


int ICMPv4Header::setOutputLinkMTU(u32 val){
  h_trc->output_link_mtu = htonl(val);
  return OP_SUCCESS;
} /* End of setOutputLinkMTU() */


u32 ICMPv4Header::getOutputLinkMTU() const {
  return ntohl(h_trc->output_link_mtu);
} /* End of getOutputLinkMTU() */


/* Miscellanious *************************************************************/
/** Returns the standard ICMP header length for the supplied ICMP message type.
 *  @warning Return value corresponds strictly to the ICMP header, this is,
 *  the minimum length of the ICMP header, variable length payload is never
 *  included. For example, an ICMP Router Advertising has a fixed header of 8
 *  bytes but then the packet contains a variable number of Router Addresses
 *  and Preference Levels, so while the length of that ICMP packet is
 *  8bytes + ValueInFieldNumberOfAddresses*8, we only return 8 because we
 *  cannot guarantee that the NumberOfAddresses field has been set before
 *  the call to this method. Same applies to the rest of types.              */
int ICMPv4Header::getICMPHeaderLengthFromType( u8 type ) const {

  switch( type ){

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            return 8; /* (+ optional data) */
        break;

        case ICMP_UNREACH:
            return 8; /* (+ payload) */
        break;

        case ICMP_SOURCEQUENCH:
            return 8; /* (+ payload) */
        break;

        case ICMP_REDIRECT:
            return 8; /* (+ payload) */
        break;

        case ICMP_ROUTERADVERT:
            return 8; /* (+ value of NumAddr field * 8 ) */
        break;

        case ICMP_ROUTERSOLICIT:
            return 8;
        break;

        case ICMP_TIMXCEED:
            return 8; /* (+ payload) */
        break;

        case ICMP_PARAMPROB:
            return 8; /* (+ payload) */
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
            return 20;
        break;

        case ICMP_INFO:
        case ICMP_INFOREPLY:
            return 8;
        break;

        case ICMP_MASK:
        case ICMP_MASKREPLY:
            return 12;
        break;

        case ICMP_TRACEROUTE:
            return 20;
        break;
        
        case ICMP_DOMAINNAME:
        case ICMP_DOMAINNAMEREPLY:
            return 8;
        break;

        /* Packets with non RFC-Compliant types will be represented as
           an 8-byte ICMP header, just like the types that don't include
           additional info (time exceeded, router solicitation, etc)  */
        default:
            return 8;
        break;
  }
  return 8;
} /* End of getICMPHeaderLengthFromType() */


const char *ICMPv4Header::type2string(int type, int code) const {
     switch(type) {
        case ICMP_ECHOREPLY:
            return "Echo reply";
        break;

        case ICMP_UNREACH:
            switch(code) {
                case ICMP_UNREACH_NET: return "Network unreachable"; break;
                case ICMP_UNREACH_HOST: return "Host unreachable"; break;
                case ICMP_UNREACH_PROTOCOL: return "Protocol unreachable"; break;
                case ICMP_UNREACH_PORT: return "Port unreachable"; break;
                case ICMP_UNREACH_NEEDFRAG: return "Fragmentation required"; break;
                case ICMP_UNREACH_SRCFAIL: return "Source route failed"; break;
                case ICMP_UNREACH_NET_UNKNOWN: return "Destination network unknown"; break;
                case ICMP_UNREACH_HOST_UNKNOWN: return "Destination host unknown"; break;
                case ICMP_UNREACH_ISOLATED: return "Source host isolated"; break;
                case ICMP_UNREACH_NET_PROHIB: return "Network prohibited"; break;
                case ICMP_UNREACH_HOST_PROHIB: return "Host prohibited"; break;
                case ICMP_UNREACH_TOSNET: return "Network unreachable for TOS"; break;
                case ICMP_UNREACH_TOSHOST: return "Host unreachable for TOS"; break;
                case ICMP_UNREACH_COMM_PROHIB: return "Communication prohibited"; break;
                case ICMP_UNREACH_HOSTPRECEDENCE: return "Precedence violation"; break;
                case ICMP_UNREACH_PRECCUTOFF: return "Precedence cutoff"; break;
                default: return "Destination unreachable (unknown code)"; break;
            } /* End of ICMP Code switch */
        break;

        case ICMP_SOURCEQUENCH:
            return "Source quench";
        break;

        case ICMP_REDIRECT:
            switch(code){
                case ICMP_REDIRECT_NET: return "Redirect for network"; break;
                case ICMP_REDIRECT_HOST: return "Redirect for host"; break;
                case ICMP_REDIRECT_TOSNET: return "Redirect for TOS and network"; break;
                case ICMP_REDIRECT_TOSHOST: return "Redirect for TOS and host"; break;
                default: return "Redirect (unknown code)"; break;
            }
        break;

        case ICMP_ECHO:
          return "Echo request";
        break;

        case ICMP_ROUTERADVERT:
            switch(code){
                case ICMP_ROUTERADVERT_MOBILE: return "Router advertisement (Mobile Agent Only)"; break;
                default: return "Router advertisement"; break;
            }
        break;

        case ICMP_ROUTERSOLICIT:
          return "Router solicitation";
        break;

        case ICMP_TIMXCEED:
            switch(code){
                case ICMP_TIMXCEED_INTRANS: return "TTL=0 during transit"; break;
                case ICMP_TIMXCEED_REASS: return "Reassembly time exceeded"; break;
                default: return "TTL exceeded (unknown code)"; break;
            }
        break;

        case ICMP_PARAMPROB:
            switch(code){
                    case ICMM_PARAMPROB_POINTER: return "Parameter problem (pointer indicates error)"; break;
                    case ICMP_PARAMPROB_OPTABSENT: return "Parameter problem (option missing)"; break;
                    case ICMP_PARAMPROB_BADLEN: return "Parameter problem (bad length)"; break;
                    default: return "Parameter problem (unknown code)"; break;
            }
        break;

        case ICMP_TSTAMP:
            return "Timestamp request";
        break;

        case ICMP_TSTAMPREPLY:
            return "Timestamp reply";
        break;

        case ICMP_INFO:
            return "Information request";
        break;

        case ICMP_INFOREPLY:
            return "Information reply";
        break;

        case ICMP_MASK:
            return "Address mask request ";
        break;

        case ICMP_MASKREPLY:
            return "Address mask reply";
        break;
        
        case ICMP_TRACEROUTE:
            return "Traceroute";
        break;

        case ICMP_DOMAINNAME:
          return "Domain name request";
        break;

         case ICMP_DOMAINNAMEREPLY:
          return "Domain name reply";
        break;

        case ICMP_SECURITYFAILURES:
          return "Security failures";
        break;

        default:
          return "Unknown ICMP type";
        break;
    } /* End of ICMP Type switch */
  return "Unknown ICMP type";
} /* End of type2string() */


/* Returns true if the packet is an ICMPv4 error message. */
bool ICMPv4Header::isError() const {
  switch( this->getType() ){
    case ICMP_UNREACH:
    case ICMP_TIMXCEED:
    case ICMP_PARAMPROB:
    case ICMP_SOURCEQUENCH:
    case ICMP_REDIRECT:
    case ICMP_SECURITYFAILURES:
      return true;
    break;

    default:
      return false;
    break;
  }
} /* End of isError() */
