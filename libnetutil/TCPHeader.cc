
/***************************************************************************
 * TCPHeader.cc -- The TCPHeader Class represents a TCP packet. It         *
 * contains methods to set the different header fields. These methods      *
 * tipically perform the necessary error checks and byte order             *
 * conversions.                                                            *
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

#include "TCPHeader.h"
#include <assert.h>
/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
TCPHeader::TCPHeader(){
  this->reset();
} /* End of TCPHeader constructor */


TCPHeader::~TCPHeader(){

} /* End of TCPHeader destructor */

/** Sets every attribute to its default value */
void TCPHeader::reset(){
  memset(&this->h, 0, sizeof(nping_tcp_hdr_t));
  this->length=TCP_HEADER_LEN; /* Initial value 20. This will be incremented if options are used */
  this->tcpoptlen=0;
  this->setSourcePort(TCP_DEFAULT_SPORT);
  this->setDestinationPort(TCP_DEFAULT_DPORT);
  this->setSeq(TCP_DEFAULT_SEQ);
  this->setAck(TCP_DEFAULT_ACK);
  this->setFlags(TCP_DEFAULT_FLAGS);
  this->setWindow(TCP_DEFAULT_WIN);
  this->setUrgPointer(TCP_DEFAULT_URP);
  this->setOffset();
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * TCPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The TCPHeader class is able to hold a maximum of 60 bytes. If the
  * supplied buffer is longer than that, only the first 60 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 20 bytes (min TCP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int TCPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<TCP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((TCP_HEADER_LEN + MAX_TCP_OPTIONS_LEN), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    if(stored_len>TCP_HEADER_LEN)
        this->tcpoptlen=stored_len-TCP_HEADER_LEN;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int TCPHeader::protocol_id() const {
  return HEADER_TYPE_TCP;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @warning If the information stored in the object has been set through a
  * call to storeRecvData(), the object's internal length count may be updated
  * if the validation is successful.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int TCPHeader::validate(){
  if(this->getOffset()<5)
    return OP_FAILURE;
  else if(this->getOffset()*4 > this->length)
    return OP_FAILURE;
  this->length=this->getOffset()*4;
  return this->length;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int TCPHeader::print(FILE *output, int detail) const {
  char optinfo[256];
  fprintf(output, "TCP[");
  fprintf(output, "%d", this->getSourcePort());
  fprintf(output, " >");
  fprintf(output, " %d", this->getDestinationPort());
  fprintf(output, " %s%s%s%s%s%s%s%s",
          !this->getSYN() ? "" : "S",
          !this->getFIN() ? "" : "F",
          !this->getRST() ? "" : "R",
          !this->getPSH() ? "" : "P",
          !this->getACK() ? "" : "A",
          !this->getURG() ? "" : "U",
          !this->getECN() ? "" : "E",
          !this->getCWR() ? "" : "C"
         );
  fprintf(output, " seq=%lu", (long unsigned int)this->getSeq() );
  if(detail>=PRINT_DETAIL_HIGH){
    fprintf(output, " ack=%lu", (long unsigned int)this->getAck() );
    fprintf(output, " off=%d", this->getOffset() );
    fprintf(output, " res=%d", this->h.th_x2);
  }
  fprintf(output, " win=%hu", this->getWindow() );
  if(detail>=PRINT_DETAIL_MED)
    fprintf(output, " csum=0x%04X", ntohs( this->getSum() ));
  if(detail>=PRINT_DETAIL_HIGH)
    fprintf(output, " urp=%d", this->getUrgPointer() );

  if(this->tcpoptlen>0 && (this->length >= TCP_HEADER_LEN+this->tcpoptlen) && this->tcpoptlen<=MAX_TCP_OPTIONS_LEN){
    this->__tcppacketoptinfo(this->h.options, this->tcpoptlen, optinfo, sizeof(optinfo)-1);
    optinfo[255]='\0';
    fprintf(output, " %s", optinfo);
  }
  fprintf(output, "]");

  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/* Get an ASCII information about a tcp option which is pointed by
   optp, with a length of len. The result is stored in the result
   buffer. The result may look like "<mss 1452,sackOK,timestamp
   45848914 0,nop,wscale 7>" */
void TCPHeader::__tcppacketoptinfo(const u8 *optp, int len, char *result, int bufsize) const {
  assert(optp);
  assert(result);
  char *p, ch;
  const u8 *q;
  int opcode;
  u16 tmpshort;
  u32 tmpword1, tmpword2;
  unsigned int i=0;

  p = result;
  *p = '\0';
  q = optp;
  ch = '<';

  while (len > 0 && bufsize > 2) {
    Snprintf(p, bufsize, "%c", ch);
    bufsize--;
    p++;
    opcode = *q++;
    if (!opcode) { /* End of List */

      Snprintf(p, bufsize, "eol");
      bufsize -= strlen(p);
      p += strlen(p);

      len--;

    } else if (opcode == 1) { /* No Op */
      Snprintf(p, bufsize, "nop");
      bufsize -= strlen(p);
      p += strlen(p);

      len--;
    } else if (opcode == 2) { /* MSS */
      if (len < 4)
        break; /* MSS has 4 bytes */

      q++;
      memcpy(&tmpshort, q, 2);

      Snprintf(p, bufsize, "mss %u", ntohs(tmpshort));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 2;
      len -= 4;
    } else if (opcode == 3) { /* Window Scale */
      if (len < 3)
        break; /* Window Scale option has 3 bytes */

      q++;

      Snprintf(p, bufsize, "wscale %u", *q);
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 3;
    } else if (opcode == 4) { /* SACK permitted */
      if (len < 2)
        break; /* SACK permitted option has 2 bytes */

      Snprintf(p, bufsize, "sackOK");
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 2;
    } else if (opcode == 5) { /* SACK */
      unsigned sackoptlen = *q;
      if ((unsigned) len < sackoptlen)
        break;

      /* This would break parsing, so it's best to just give up */
      if (sackoptlen < 2)
        break;

      q++;

      if ((sackoptlen - 2) == 0 || ((sackoptlen - 2) % 8 != 0)) {
        Snprintf(p, bufsize, "malformed sack");
        bufsize -= strlen(p);
        p += strlen(p);
      } else {
        Snprintf(p, bufsize, "sack %d ", (sackoptlen - 2) / 8);
        bufsize -= strlen(p);
        p += strlen(p);
        for (i = 0; i < sackoptlen - 2; i += 8) {
          memcpy(&tmpword1, q + i, 4);
          memcpy(&tmpword2, q + i + 4, 4);
          Snprintf(p, bufsize, "{%u:%u}", tmpword1, tmpword2);
          bufsize -= strlen(p);
          p += strlen(p);
        }
      }

      q += sackoptlen - 2;
      len -= sackoptlen;
    } else if (opcode == 8) { /* Timestamp */
      if (len < 10)
        break; /* Timestamp option has 10 bytes */

      q++;
      memcpy(&tmpword1, q, 4);
      memcpy(&tmpword2, q + 4, 4);

      Snprintf(p, bufsize, "timestamp %u %u", ntohl(tmpword1),
               ntohl(tmpword2));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 8;
      len -= 10;
    }

    ch = ',';
  }

  if (len > 0) {
    *result = '\0';
    return;
  }

  Snprintf(p, bufsize, ">");
}



/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Sets source port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setSourcePort(u16 p){
  h.th_sport = htons(p);
  return OP_SUCCESS;
} /* End of setSourcePort() */


/** Returns source port in HOST byte order */
u16 TCPHeader::getSourcePort() const {
  return ntohs(h.th_sport);
} /* End of getSourcePort() */


/** Sets destination port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setDestinationPort(u16 p){
  h.th_dport = htons(p);
  return OP_SUCCESS;
} /* End of setDestinationPort() */


/** Returns destination port in HOST byte order  */
u16 TCPHeader::getDestinationPort() const {
  return ntohs(h.th_dport);
} /* End of getDestinationPort() */


/** Sets sequence number.
 *  @warning Seq number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setSeq(u32 p){
  h.th_seq = htonl(p);
  return OP_SUCCESS;
} /* End of setSeq() */


/** Returns sequence number in HOST byte order */
u32 TCPHeader::getSeq() const {
  return ntohl(h.th_seq);
} /* End of getSeq() */


/** Sets acknowledgement number.
 *  @warning ACK number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setAck(u32 p){
  h.th_ack = htonl(p);
  return OP_SUCCESS;
} /* End of setAck() */


/** Returns ACK number in HOST byte order */
u32 TCPHeader::getAck() const {
  return ntohl(h.th_ack);
} /* End of getAck() */


/* TODO: Test this method. It may not work becuasse th_off is supposed to
 * be 4 bits long and arg o is 8.
 * UPDATE: It seems to work just fine. However, let's keep this note just
 * in case problems arise. */
int TCPHeader::setOffset(u8 o){
  h.th_off = o;
  return OP_SUCCESS;
} /* End of setOffset() */


int TCPHeader::setOffset(){
  h.th_off = 5 + tcpoptlen/4;
  return OP_SUCCESS;
} /* End of setOffset() */


/** Returns offset value */
u8 TCPHeader::getOffset() const {
  return h.th_off;
} /* End of getOffset() */


/* Sets the 4-bit reserved field (Note that there are not 4 reserved bits anymore
 * as RFC 3540 introduces a new TCP flag, so calling this will overwrite
 * the value of such flag. */
int TCPHeader::setReserved(u8 r){
  h.th_x2 = r;
  return OP_SUCCESS;
}


u8 TCPHeader::getReserved() const {
  return h.th_x2;
}


/** Sets TCP flags */
int TCPHeader::setFlags(u8 f){
  h.th_flags = f;
  return OP_SUCCESS;
} /* End of setFlags() */


/** Returns the 8bit flags field of the TCP header */
u8 TCPHeader::getFlags() const {
  return h.th_flags;
} /* End of getFlags() */


/* Returns the 16bit flags field of the TCP header. As RFC 3540 defines a new
 * flag (NS), we no longer can store all TCP flags in a single octet, so
 * this method returns the flags as a two-octet unsigned integer. */
u16 TCPHeader::getFlags16() const {
  /* Obtain the value of dataoff+reserved+flags in host byte order */
  u16 field=ntohs(*(u16 *)(((u8 *)&this->h)+12));
  /* Erase the contents of the data offset field */
  field = field & 0x0FFF;
  return field;
} /* End of getFlags16() */


/** Sets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::setCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags |= TH_CWR;
  return prev;
} /* End of setCWR() */


/** Unsets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::unsetCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags ^= TH_CWR;
  return prev;
} /* End of unsetCWR() */


/** Get CWR flag */
bool TCPHeader::getCWR() const {
  return h.th_flags & TH_CWR;
} /* End of getCWR() */


/** Sets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::setECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECE() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECE() */


/** Get CWR flag */
bool TCPHeader::getECE() const {
  return  h.th_flags & TH_ECN;
} /* End of getECE() */


/** Same as setECE() but with a different name since there are two possible
 *  ways to call this flag
 *  @return Previous state of the flag */
bool TCPHeader::setECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECN() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECN() */


/** Get ECN flag */
bool TCPHeader::getECN() const {
  return  h.th_flags & TH_ECN;
} /* End of getECN() */


/** Sets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::setURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags |= TH_URG;
  return prev;
} /* End of setURG() */


/** Unsets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::unsetURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags ^= TH_URG;
  return prev;
} /* End of unsetURG() */


/** Get URG flag */
bool TCPHeader::getURG() const {
  return  h.th_flags & TH_URG;
} /* End of getURG() */


/** Sets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::setACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags |= TH_ACK;
  return prev;
} /* End of setACK() */


/** Unsets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::unsetACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags ^= TH_ACK;
  return prev;
} /* End of unsetACK() */


/** Get ACK flag */
bool TCPHeader::getACK() const {
  return  h.th_flags & TH_ACK;
} /* End of getACK() */


/** Sets flag PSH
 *  @return Previous state of the flag */
bool TCPHeader::setPSH(){
  u8 prev = h.th_flags & TH_PSH;
  h.th_flags |= TH_PSH;
  return prev;
} /* End of setPSH() */


/** Unsets flag PSH
 *  @return Previous state of the flag */
bool TCPHeader::unsetPSH(){
  u8 prev = h.th_flags & TH_PSH;
  h.th_flags ^= TH_PSH;
  return prev;
} /* End of unsetPSH() */


/** Get PSH flag */
bool TCPHeader::getPSH() const {
  return  h.th_flags & TH_PSH;
} /* End of getPSH() */


/** Sets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::setRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags |= TH_RST;
  return prev;
} /* End of setRST() */


/** Unsets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::unsetRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags ^= TH_RST;
  return prev;
} /* End of unsetRST() */


/** Get RST flag */
bool TCPHeader::getRST() const {
  return  h.th_flags & TH_RST;
} /* End of getRST() */


/** Sets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::setSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags |= TH_SYN;
  return prev;
} /* End of setSYN() */


/** Unsets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::unsetSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags ^= TH_SYN;
  return prev;
} /* End of unsetSYN() */


/** Get SYN flag */
bool TCPHeader::getSYN() const {
  return  h.th_flags & TH_SYN;
} /* End of getSYN() */


/** Sets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::setFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags |= TH_FIN;
  return prev;
} /* End of setFIN() */


/** Unsets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::unsetFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags ^= TH_FIN;
  return prev;
} /* End of unsetFIN() */


/** Get FIN flag */
bool TCPHeader::getFIN() const {
  return  h.th_flags & TH_FIN;
} /* End of getFIN() */


/** Sets window size.
 *  @warning Win number must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setWindow(u16 p){
   h.th_win = htons(p);
  return OP_SUCCESS;
} /* End of setWindow() */


/** Returns window size in HOST byte order. */
u16 TCPHeader::getWindow() const {
  return ntohs(h.th_win);
} /* End of getWindow() */


/** Sets urgent pointer.
 *  @warning Pointer must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setUrgPointer(u16 l){
  h.th_urp = htons(l);
  return OP_SUCCESS;
} /* End of setUrgPointer() */


/** Returns Urgent Pointer in HOST byte order. */
u16 TCPHeader::getUrgPointer() const {
  return ntohs(h.th_urp);
} /* End of getUrgPointer() */


int TCPHeader::setSum(struct in_addr src, struct in_addr dst){
  int bufflen;
  u8 aux[ MAX_TCP_PAYLOAD_LEN ];
  /* FROM: RFC 1323: TCP Extensions for High Performance, March 4, 2009
   *
   * "With IP Version 4, the largest amount of TCP data that can be sent in
   *  a single packet is 65495 bytes (64K - 1 - size of fixed IP and TCP
   *  headers)".
   *
   *  In theory TCP should not worry about the practical max payload length
   *  because it is supposed to be independent of the network layer. However,
   *  since TCP does not have any length field and we need to allocate a
   *  buffer, we are using that value. (Note htat in UDPHeader.cc we do just
   *  the opposite, forget about the practical limitation and allow the
   *  theorical limit for the payload.                                       */
  h.th_sum = 0;

  /* Copy packet contents to a buffer */
  bufflen=dumpToBinaryBuffer(aux, MAX_TCP_PAYLOAD_LEN);

  /* Compute checksum */
  h.th_sum = ipv4_pseudoheader_cksum(&src, &dst, IPPROTO_TCP, bufflen, (char *)aux);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed. */
int TCPHeader::setSum(u16 s){
  h.th_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


int TCPHeader::setSum(){
  this->h.th_sum=0;
  this->h.th_sum = this->compute_checksum();
  return OP_SUCCESS;
} /* End of setSum() */


/** Set the TCP checksum field to a random value, which may accidentally
  * match the correct checksum */
int TCPHeader::setSumRandom(){
  h.th_sum=get_random_u16();
  return OP_SUCCESS;
} /* End of setSumRandom() */

/** Set the TCP checksum field to a random value. It takes the source and
  * destination address to make sure the random generated sum does not
  * accidentally match the correct checksum. This function only handles
  * IPv4 address. */
int TCPHeader::setSumRandom(struct in_addr source, struct in_addr destination){
  u16 correct_csum=0;
  /* Compute the correct checksum */
  this->setSum(source, destination);
  correct_csum=this->getSum();
  /* Generate numbers until one does not match the correct sum */
  while( (h.th_sum=get_random_u16())==correct_csum);
  return OP_SUCCESS;
} /* End of setSumRandom() */


/** Returns the TCP checksum field in NETWORK byte order */
u16 TCPHeader::getSum() const {
  return h.th_sum;
} /* End of getSum() */


/* Copies the supplied buffer into the TCP options field. Note that the supplied
 * buffer MUST NOT exceed MAX_TCP_OPTIONS_LEN octets and should be a multiple of
 * four. If it is not a multiple of four, no error will be returned but the
 * behaviour is unspecified. If this method is called passing NULL and zero
 * ( t.setOptions(NULL, 0), any existing options are cleared, and the object's
 * internal length is updated accordingly. Also, note that a call to setOptions()
 * involves an automatic call to setOffset(), which updates the Offset field
 * to take into account the new header length. If you need to set a bogus
 * data offset, you can do so after calling setOptions(), but not before.
 * It returns OP_SUCCESS on success and OP_FAILURE in case of error */
int TCPHeader::setOptions(const u8 *optsbuff, size_t optslen){
  /* NULL and length=0 means delete existing options */
  if(optsbuff==NULL && optslen==0){
    this->tcpoptlen=0;
    this->length=TCP_HEADER_LEN;
    memset(this->h.options, 0, MAX_TCP_OPTIONS_LEN);
    return OP_SUCCESS;

  /* Make sure params are safe to use */
  }else if(optsbuff==NULL || optslen==0 || optslen>MAX_TCP_OPTIONS_LEN){
    return OP_FAILURE;

  /* Copy supplied buffer into the options field, and update the offset field. */
  }else{
    memcpy(this->h.options, optsbuff, optslen);
    this->tcpoptlen=optslen;
    this->length=TCP_HEADER_LEN+optslen;
    this->setOffset();
    return OP_SUCCESS;
  }
} /* End of setOptions() */


/* Returns a pointer to the start of the TCP options field. If the supplied
 * "optslen" pointer is not NULL, the length of the options will be stored
 * there. */
const u8 *TCPHeader::getOptions(size_t *optslen) const {
  if(optslen!=NULL)
    *optslen=this->tcpoptlen;
  return this->h.options;
} /* End of getOptions() */


/* Returns the index-th option in the TCP header. On success it returns a
 * structure filled with option information. If there is no index-th option,
 * it returns a structure with st.value==NULL. Note that this function does 
 * not perform strict validity checking. It does check that the length claimed 
 * by the options does not exceed the available buffer but it does not check, 
 * for example, that the MSS option always contains a length of 4. Also, 
 * if the returned option type is TCPOPT_EOL or TCPOPT_NOOP, the len field
 * would be set to zero and the "value" field should NOT be accessed, as it 
 * will not contain reliable information. */
nping_tcp_opt_t TCPHeader::getOption(unsigned int index) const {
  nping_tcp_opt_t *curr_opt=NULL;
  u8 *curr_pnt=(u8 *)this->h.options;
  int bytes_left=this->length - TCP_HEADER_LEN;
  assert((this->length - TCP_HEADER_LEN) == this->tcpoptlen);
  unsigned int optsfound=0;
  nping_tcp_opt_t result;
  memset(&result, 0, sizeof(nping_tcp_opt_t));

  while(bytes_left>0){
      /* Use the opts structure as a template to access current option. It is
       * OK to use it because we only access the first two elements. */
      curr_opt=(nping_tcp_opt_t *)curr_pnt;

      /* If we are right in the option that the caller wants, just return it */
      if(optsfound==index){
        result.type=curr_opt->type;
        if(result.type==TCPOPT_EOL || result.type==TCPOPT_NOOP)
          result.len=1;
        else
          result.len=curr_opt->len;
        result.value=(u8 *)curr_pnt+2;
        return result;
      }

      /* Otherwise, we have to parse it, so we can skip it and access the next
       * option */
      switch(curr_opt->type){

        /* EOL or NOOP
        +-+-+-+-+-+-+-+-+
        |       X       |
        +-+-+-+-+-+-+-+-+  */
        case TCPOPT_EOL:
          goto out;

        case TCPOPT_NOOP:
          curr_pnt++; /* Skip one octet */
          bytes_left--;
        break;

        /* TLV encoded option */
        default:
          /* If we don't have as many octets as the option advertises, the
           * option is bogus. Return failure. */
          if(bytes_left<curr_opt->len)
            return result;
          curr_pnt+=curr_opt->len;
          bytes_left-=curr_opt->len;
        break;
      }
      optsfound++;
  }

out:
  return result;
}


/* Returns a textual representation of a TCP Options code */
const char *TCPHeader::optcode2str(u8 optcode){
  switch(optcode){
    case TCPOPT_EOL:
      return "EOL";
    case TCPOPT_NOOP:
      return "NOOP";
    case TCPOPT_MSS:
      return "MSS";
    case TCPOPT_WSCALE:
      return "WScale";
    case TCPOPT_SACKOK:
     return "SAckOK";
    case TCPOPT_SACK:
      return "SAck";
    case TCPOPT_ECHOREQ:
     return "EchoReq";
    case TCPOPT_ECHOREP:
     return "EchoRep";
    case TCPOPT_TSTAMP:
     return "TStamp";
    case TCPOPT_POCP:
      return "POCP";
    case TCPOPT_POSP:
     return "POSP";
    case TCPOPT_CC:
     return "CC";
    case TCPOPT_CCNEW:
     return "CC.NEW";
    case TCPOPT_CCECHO:
     return "CC.ECHO";
    case TCPOPT_ALTCSUMREQ:
      return "AltSumReq";
    case TCPOPT_ALTCSUMDATA:
     return "AltSumData";
    case TCPOPT_MD5:
      return "MD5";
    case TCPOPT_SCPS:
      return "SCPS";
    case TCPOPT_SNACK:
      return "SNAck";
    case TCPOPT_QSRES:
     return "QStart";
    case TCPOPT_UTO:
     return "UTO";
    case TCPOPT_AO:
     return "AO";
    default:
      return "Unknown";
  }
} /* End of optcode2str() */


