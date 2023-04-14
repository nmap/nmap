/***************************************************************************
 * IPv6Header.cc -- The IPv6Header Class represents an IPv4 datagram. It   *
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
 *  protocol name. Currently only TCP, UDP and ICMP are supported. Any
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

