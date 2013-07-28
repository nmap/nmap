
/***************************************************************************
 * IPv6Header.cc -- The IPv6Header Class represents an IPv4 datagram. It   *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
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

#include "IPv6Header.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
IPv6Header::IPv6Header() {
  this->reset();
} /* End of IPv6Header constructor */


IPv6Header::~IPv6Header() {

} /* End of IPv6Header destructor */


/** Sets every attribute to its default value */
void IPv6Header::reset(){
  memset(&this->h, 0, sizeof(nping_ipv6_hdr_t));
  this->length=IPv6_HEADER_LEN;
  this->setVersion();
  this->setTrafficClass(IPv6_DEFAULT_TCLASS);
  this->setFlowLabel(IPv6_DEFAULT_FLABEL);
  this->setHopLimit(IPv6_DEFAULT_HOPLIM);
  this->setNextHeader(IPv6_DEFAULT_NXTHDR); /* No next header */
  this->setPayloadLength(0);
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *IPv6Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The IPv6Header class is able to hold a maximum of 40 bytes. If the
  * supplied buffer is longer than that, only the first 40 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 40 bytes (IPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int IPv6Header::storeRecvData(const u8 *buf, size_t len){ 
  if(buf==NULL || len<IPv6_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=IPv6_HEADER_LEN;
    memcpy(&(this->h), buf, IPv6_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int IPv6Header::protocol_id() const {
    return HEADER_TYPE_IPv6;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int IPv6Header::validate(){
  if( this->length!=IPv6_HEADER_LEN)
      return OP_FAILURE;
  else
      return IPv6_HEADER_LEN;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int IPv6Header::print(FILE *output, int detail) const {
  static char ipstring[256];
  memset(ipstring, 0, 256);
  struct in6_addr addr;
  char ipinfo[512] = "";                /* Temp info about IP.               */

  fprintf(output, "IPv6[");
  this->getSourceAddress(&addr);
  inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
  fprintf(output, "%s", ipstring);
  fprintf(output, " >");
  this->getDestinationAddress(&addr);
  inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
  fprintf(output, " %s", ipstring);

  /* Create a string with information relevant to the specified level of detail */
  if( detail == PRINT_DETAIL_LOW ){
      Snprintf(ipinfo, sizeof(ipinfo), "hlim=%d", this->getHopLimit());
  }else if( detail == PRINT_DETAIL_MED ){
      Snprintf(ipinfo, sizeof(ipinfo), "hlim=%d tclass=%d flow=%d", 
               this->getHopLimit(), this->getTrafficClass(), this->getFlowLabel() );
  }else if( detail>=PRINT_DETAIL_HIGH ){
      Snprintf(ipinfo, sizeof(ipinfo), "ver=%d hlim=%d tclass=%d flow=%d plen=%d nh=%d", 
               this->getVersion(), this->getHopLimit(), this->getTrafficClass(), 
               this->getFlowLabel(), this->getPayloadLength(), this->getNextHeader() );
  }
  fprintf(output, " %s]", ipinfo); 
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Set Version field (4 bits).  */
int IPv6Header::setVersion(u8 val){
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass:4;
        #else
            u8 tclass:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;

  header1stbyte.fullbyte = h.ip6_start[0];
  header1stbyte.halfbyte.ver=val;
  h.ip6_start[0]=header1stbyte.fullbyte;
  return OP_SUCCESS;
} /* End of setVersion() */


/** Set Version field to value 6.  */
int IPv6Header::setVersion(){
  this->setVersion(6);
  return OP_SUCCESS;
} /* End of setVersion() */


/** Returns an 8bit number containing the value of the Version field.  */
u8 IPv6Header::getVersion() const {
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass:4;
        #else
            u8 tclass:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;

  header1stbyte.fullbyte = h.ip6_start[0];  
  return (u8)header1stbyte.halfbyte.ver;  
} /* End of getVersion() */


int IPv6Header::setTrafficClass(u8 val){
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass1:4;
        #else
            u8 tclass1:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  /* Store old contents */
  header1stbyte.fullbyte = h.ip6_start[0];
  header2ndbyte.fullbyte = h.ip6_start[1];

  /* Fill the two 4bit halves */
  header1stbyte.halfbyte.tclass1=val>>4;
  header2ndbyte.halfbyte.tclass2=val;

  /* Write the bytes back to the header */
  h.ip6_start[0]=header1stbyte.fullbyte;
  h.ip6_start[1]=header2ndbyte.fullbyte;
  
  return OP_SUCCESS;
} /* End of setTrafficClass() */


u8 IPv6Header::getTrafficClass() const {
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass1:4;
        #else
            u8 tclass1:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass1:4;
            u8 tclass2:4;
        #else
            u8 tclass2:4;
            u8 tclass1:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }finalbyte;

  header1stbyte.fullbyte = h.ip6_start[0];
  header2ndbyte.fullbyte = h.ip6_start[1];
  finalbyte.halfbyte.tclass1=header1stbyte.halfbyte.tclass1;
  finalbyte.halfbyte.tclass2=header2ndbyte.halfbyte.tclass2;
  return finalbyte.fullbyte;
} /* End of getTrafficClass() */


int IPv6Header::setFlowLabel(u32 val){
  u32 netbyte = htonl(val);
  u8 *pnt=(u8*)&netbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  header2ndbyte.fullbyte = h.ip6_start[1];
  header2ndbyte.halfbyte.flow=pnt[1];
  h.ip6_start[1]=header2ndbyte.fullbyte;
  h.ip6_start[2]=pnt[2];
  h.ip6_start[3]=pnt[3];
  return OP_SUCCESS;
} /* End of setFlowLabel() */


u32 IPv6Header::getFlowLabel() const {
  u32 hostbyte=0;
  u8 *pnt=(u8*)&hostbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  header2ndbyte.fullbyte = h.ip6_start[1];
  pnt[0]=0;
  pnt[1]=header2ndbyte.halfbyte.flow;
  pnt[2]=h.ip6_start[2];
  pnt[3]=h.ip6_start[3];
  hostbyte=ntohl(hostbyte);
  return hostbyte;
} /* End of getFlowLabel() */


int IPv6Header::setPayloadLength(u16 val){
  this->h.ip6_len = htons(val);
  return OP_SUCCESS;
} /* End of setPayloadLength() */


int IPv6Header::setPayloadLength(){
  int otherslen=0;
  if (next!=NULL)
      otherslen=next->getLen();
  setPayloadLength( otherslen );
  return OP_SUCCESS;
} /* End of setTotalLength() */


u16 IPv6Header::getPayloadLength() const {
  return ntohs(this->h.ip6_len);
} /* End of getPayloadLength() */


int IPv6Header::setNextHeader(u8 val){
  this->h.ip6_nh = val;
  return OP_SUCCESS;
} /* End of setNextHeader() */


u8 IPv6Header::getNextHeader() const {
  return this->h.ip6_nh;
} /* End of getNextHeader() */


/** Sets field "next header" to the number that corresponds to the supplied
 *  protocol name. Currently onyl TCP, UDP and ICMP are supported. Any
 *  help to extend this functionality would be appreciated. For a list of all
 *  proto names and numbers check:
 *  http://www.iana.org/assignments/protocol-numbers/                        */
int IPv6Header::setNextHeader(const char *p){

  if (p==NULL){
    printf("setNextProto(): NULL pointer supplied\n");
    return OP_FAILURE;
  }
  if( !strcasecmp(p, "TCP") )
    setNextHeader(6);   /* 6=IANA number for proto TCP */
  else if( !strcasecmp(p, "UDP") )
    setNextHeader(17);  /* 17=IANA number for proto UDP */
  else if( !strcasecmp(p, "ICMPv6"))
    setNextHeader(58);  /* 58=IANA number for proto ICMPv6 */
  else
    netutil_fatal("setNextProto(): Invalid protocol number\n");
  return OP_SUCCESS;  
} /* End of setNextHeader() */


int IPv6Header::setHopLimit(u8 val){
  this->h.ip6_hopl = val;
  return OP_SUCCESS;
} /* End of setHopLimit() */


u8 IPv6Header::getHopLimit() const {
  return this->h.ip6_hopl;
} /* End of getHopLimit() */


int IPv6Header::setSourceAddress(u8 *val){
  if(val==NULL)
    netutil_fatal("setSourceAddress(): NULL value supplied.");
  memcpy(this->h.ip6_src, val, 16);
  return OP_SUCCESS;
} /* End of setSourceAddress() */


int IPv6Header::setSourceAddress(struct in6_addr val){
  memcpy(this->h.ip6_src, val.s6_addr, 16);
  return OP_SUCCESS;
} /* End of setSourceAddress() */


const u8 *IPv6Header::getSourceAddress() const {
  return this->h.ip6_src;
} /* End of getSourceAddress() */


/** Returns source IPv6 address
 *  @warning Returned value is in NETWORK byte order. */
struct in6_addr IPv6Header::getSourceAddress(struct in6_addr *result) const {
  struct in6_addr myaddr;
  memset(&myaddr, 0, sizeof(myaddr));
  memcpy(myaddr.s6_addr, this->h.ip6_src, 16);

  if(result!=NULL)
      *result=myaddr;
  return myaddr;
} /* End of getSourceAddress() */


int IPv6Header::setDestinationAddress(u8 *val){
  if(val==NULL)
    netutil_fatal("setDestinationAddress(): NULL value supplied.");
  memcpy(this->h.ip6_dst, val, 16);
  return OP_SUCCESS;
} /* End of setDestinationAddress() */


int IPv6Header::setDestinationAddress(struct in6_addr val){
  memcpy(this->h.ip6_dst, val.s6_addr, 16);
  return OP_SUCCESS;
} /* End of setDestinationAddress() */


/** Returns destination IPv6 address. */
const u8 *IPv6Header::getDestinationAddress() const {
  return this->h.ip6_dst;
} /* End of getDestinationAddress() */


/** Returns destination IPv6 address
 *  @warning Returned value is in NETWORK byte order. */
struct in6_addr IPv6Header::getDestinationAddress(struct in6_addr *result) const {
  struct in6_addr myaddr;
  memset(&myaddr, 0, sizeof(myaddr));
  memcpy(myaddr.s6_addr, this->h.ip6_dst, 16);

  if(result!=NULL)
      *result=myaddr;
  return myaddr;
} /* End of getDestinationAddress() */


/** Returns the length of an IPv4 address. */
u16 IPv6Header::getAddressLength() const {
    return 16;
} /* End of getAddressLength()*/

