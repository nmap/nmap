
/***************************************************************************
 * EchoHeader.cc -- The EchoHeader Class represents packets of the Nping   *
 * Echo Protocol. It contains the appropriate methods to set/get all       *
 * header fields. In general these methods do error checking and perform   *
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

#include "EchoHeader.h"
#include "nping.h"
#include "output.h"
#include <time.h>
#include <assert.h>
#include "Crypto.h"

EchoHeader::EchoHeader(){
    this->reset();
} /* End of EchoHeader constructor */


EchoHeader::~EchoHeader(){

} /* End of EchoHeader destructor */


/** Sets every attribute to its default value. */
void EchoHeader::reset() {
  memset(&this->h, 0, sizeof(echohdr_t) );
  this->data_hsserv=(nep_hs_serv_data_t *)this->h.data;
  this->data_hsclnt=(nep_hs_clnt_data_t *)this->h.data;
  this->data_hsfinal=(nep_hs_final_data_t *)this->h.data;
  this->data_pspec=(nep_packet_spec_data_t *)this->h.data;
  this->data_ready=(nep_ready_data_t *)this->h.data;
  this->data_echo=(nep_echo_data_t *)this->h.data;
  this->data_error=(nep_error_data_t *)this->h.data;
  this->fs_off=(u8 *)this->data_pspec->packetspec;
  this->fs_bytes=0;
  this->echo_mac=(u8 *)this->data_echo->payload_and_mac;
  this->echo_bytes=0;

  /* Some safe initializations */
  this->setVersion(ECHO_CURRENT_PROTO_VER);
  this->setTotalLength(STD_NEP_HEADER_LEN + MAC_LENGTH);
  this->length=STD_NEP_HEADER_LEN + MAC_LENGTH; /* Sets length in PacketElement superclass */
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing. */
u8 * EchoHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods. */
int EchoHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len>(STD_NEP_HEADER_LEN+MAX_DATA_LEN)){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=len;
    memcpy(&(this->h), buf, len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing functions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int EchoHeader::protocol_id() const {
  return HEADER_TYPE_NEP;
} /* End of protocol_id() */


/** Sets Version.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setVersion(u8 val){
  this->h.echo_ver=val;
  return OP_SUCCESS;
} /* End of setVersion() */


/** Returns value of attribute h.echo_ver */
u8 EchoHeader::getVersion(){
  return this->h.echo_ver;
} /* End of getVersion() */


/** Sets MessageType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setMessageType(u8 val){
  this->h.echo_mtype=val;
  return OP_SUCCESS;
} /* End of setMessageType() */


/** Returns value of attribute h.echo_mtype */
u8 EchoHeader::getMessageType(){
  return this->h.echo_mtype;
} /* End of getsetMessageType() */


/** Sets Total Length.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.
 *  @warning the length is expressed in 32bit words. */
int EchoHeader::setTotalLength(u16 val){
  this->h.echo_tlen=htons(val);
  this->length=val*4; /* Also, set superclass length attribute */
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** Sets Total Length.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setTotalLength(){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_SERVER:
        this->setTotalLength(NEP_HANDSHAKE_SERVER_LEN/4);
    break;
    case TYPE_NEP_HANDSHAKE_CLIENT:
        this->setTotalLength(NEP_HANDSHAKE_CLIENT_LEN/4);
    break;
    case TYPE_NEP_HANDSHAKE_FINAL:
        this->setTotalLength(NEP_HANDSHAKE_FINAL_LEN/4);
    break;
    case TYPE_NEP_PACKET_SPEC:
        this->setTotalLength(NEP_PACKETSPEC_LEN/4);
    break;
    case TYPE_NEP_READY:
        this->setTotalLength(NEP_READY_LEN/4);
    break;
    case TYPE_NEP_ECHO:
        this->setTotalLength( (STD_NEP_HEADER_LEN + 4 + MAC_LENGTH + this->echo_bytes)/4 );
    break;
    case TYPE_NEP_ERROR:
        this->setTotalLength(NEP_ERROR_LEN/4);
    break;
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** Returns value of attribute h.echo_tlen 
  * @warning Returned length is expressed in 32bit words. To get a byte count
  * it must be multiplied by four */
u16 EchoHeader::getTotalLength(){
  return ntohs(this->h.echo_tlen);
} /* End of getTotalLength() */


/** Sets SequenceNumber.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setSequenceNumber(u32 val){
  this->h.echo_seq=htonl(val);
  return OP_SUCCESS;
} /* End of setSequenceNumber() */


/** Returns value of attribute h.echo_seq */
u32 EchoHeader::getSequenceNumber(){
  return ntohl(this->h.echo_seq);
} /* End of getSequenceNumber() */


/** Sets Timestamp.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setTimestamp(u32 val){
  this->h.echo_ts=htonl(val);
  return OP_SUCCESS;
} /* End of setTimestamp() */


/** Sets Timestamp.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setTimestamp(){
  u32 t=(u32)time(NULL);  /* TODO: Make sure this does not cause problems */
  this->h.echo_ts=htonl(t);
  return OP_SUCCESS;
} /* End of setTimestamp() */


/** Returns value of attribute h.echo_ts*/
u32 EchoHeader::getTimestamp(){
  return ntohl(this->h.echo_ts);
} /* End of getTimestamp() */


/** Sets Reserved.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoHeader::setReserved(u32 val){
  this->h.echo_res=htonl(val);
  return OP_SUCCESS;
} /* End of setReserved() */


/** Returns value of attribute h.echo_res */
u32 EchoHeader::getReserved(){
  return this->h.echo_res;
} /* End of getReserved() */


int EchoHeader::setMessageAuthenticationCode(u8 *key, size_t keylen){
  u8 *macpnt=NULL;
  u8 *from=(u8 *)&(this->h);
  size_t bytes=0;

  /* Determine where the MAC field is and the length of the data that needs
   * to be authenticated, based on message type. */
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_SERVER:
        macpnt=this->data_hsserv->mac;
        bytes=NEP_HANDSHAKE_SERVER_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_HANDSHAKE_CLIENT:
        macpnt=this->data_hsclnt->mac;
        bytes=NEP_HANDSHAKE_CLIENT_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_HANDSHAKE_FINAL:
        macpnt=this->data_hsfinal->mac;
        bytes=NEP_HANDSHAKE_FINAL_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_PACKET_SPEC:
        macpnt=this->data_pspec->mac;
        bytes=NEP_PACKETSPEC_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_READY:
        macpnt=this->data_ready->mac;
        bytes=NEP_READY_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_ECHO:
        macpnt=this->echo_mac;
        bytes=STD_NEP_HEADER_LEN + 4 + this->echo_bytes;
    break;
    case TYPE_NEP_ERROR:
        macpnt=this->data_error->mac;
        bytes=NEP_ERROR_LEN-MAC_LENGTH;
    break;
    default:
        return OP_FAILURE;
    break;
  }
  /* Compute the code */
  Crypto::hmac_sha256(from, bytes, macpnt, key, keylen);
  return OP_SUCCESS;
} /* End of setMessageAuthenticationCode() */


u8 *EchoHeader::getMessageAuthenticationCode(){
switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_SERVER:
        return this->data_hsserv->mac;
    break;
    case TYPE_NEP_HANDSHAKE_CLIENT:
        return this->data_hsclnt->mac;
    break;
    case TYPE_NEP_HANDSHAKE_FINAL:
        return this->data_hsfinal->mac;
    break;
    case TYPE_NEP_PACKET_SPEC:
        return this->data_pspec->mac;
    break;
    case TYPE_NEP_READY:
        return this->data_ready->mac;
    break;
    case TYPE_NEP_ECHO:
        this->updateEchoInternals();
        return this->echo_mac;
    break;
    case TYPE_NEP_ERROR:
        return this->data_error->mac;
    break;
    default:
        return NULL;
    break;
  }
  return NULL;
} /* End of getMessageAuthenticationCode() */



int EchoHeader::verifyMessageAuthenticationCode(u8 *key, size_t keylen){
  u8 mac_backup[MAC_LENGTH];
  u8 *aux;

  /* Make a copy of the current MAC */
  if( (aux=this->getMessageAuthenticationCode())==NULL )
      return OP_FAILURE;
  memcpy(mac_backup, aux, MAC_LENGTH);

  /* Recompute the MAC */
  memset(aux, 0, MAC_LENGTH);
  this->setMessageAuthenticationCode(key, keylen);

  /* Try to match both MACs*/
  if( (aux=this->getMessageAuthenticationCode())==NULL )
      return OP_FAILURE;
  if( memcmp(mac_backup, aux, MAC_LENGTH)==0  ){
    return OP_SUCCESS;
  }else{
    /* Restore original MAC */
    memcpy(aux, mac_backup, MAC_LENGTH);
    return OP_FAILURE;
  }
} /* End of verifyMessageAuthenticationCode() */

/******************************************************************************/
/* NEP_HANDSHAKE methods                                                      */
/******************************************************************************/

int EchoHeader::setServerNonce(u8 *nonce){
  assert(nonce);
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_SERVER:
        memcpy(this->data_hsserv->server_nonce, nonce, NONCE_LEN);
    break;

    case TYPE_NEP_HANDSHAKE_CLIENT:
        memcpy(this->data_hsclnt->server_nonce, nonce, NONCE_LEN);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of getServerNonce() */


u8 *EchoHeader::getServerNonce(){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_SERVER:
        return this->data_hsserv->server_nonce;
    break;

    case TYPE_NEP_HANDSHAKE_CLIENT:
        return this->data_hsclnt->server_nonce;
    break;

    default:
        return NULL;
    break;
  }
} /* End of getServerNonce() */


int EchoHeader::setClientNonce(u8 *nonce){
  assert(nonce);
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        memcpy(this->data_hsclnt->client_nonce, nonce, NONCE_LEN);
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        memcpy(this->data_hsfinal->client_nonce , nonce, NONCE_LEN);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of getClientNonce() */


u8 *EchoHeader::getClientNonce(){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        return this->data_hsclnt->client_nonce;
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        return this->data_hsfinal->client_nonce;
    break;

    default:
        return NULL;
    break;
  }
} /* End of getClientNonce() */


int EchoHeader::setPartnerAddress(struct in_addr val){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        memset(this->data_hsclnt->partner_ip, 0, 16);
        memcpy(this->data_hsclnt->partner_ip , &val, sizeof(struct in_addr));
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        memset(this->data_hsfinal->partner_ip, 0, 16);
        memcpy(this->data_hsfinal->partner_ip , &val, sizeof(struct in_addr));
    break;

    default:
        return OP_FAILURE;
    break;
  }
  this->setIPVersion(0x04);
  return OP_SUCCESS;
} /* End of setPartnerAddress() */


int EchoHeader::setPartnerAddress(struct in6_addr val){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        memset(this->data_hsclnt->partner_ip, 0, 16);
        memcpy(this->data_hsclnt->partner_ip , &val, sizeof(struct in6_addr));
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        memset(this->data_hsfinal->partner_ip, 0, 16);
        memcpy(this->data_hsfinal->partner_ip , &val, sizeof(struct in6_addr));
    break;

    default:
        return OP_FAILURE;
    break;
  }
  this->setIPVersion(0x06);
  return OP_SUCCESS;
} /* End of setPartnerAddress() */


int EchoHeader::getPartnerAddress(struct in_addr *dst){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        memcpy(dst, this->data_hsclnt->partner_ip,sizeof(struct in_addr));
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        memcpy(dst, this->data_hsfinal->partner_ip,sizeof(struct in_addr));
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of getPartnerAddress() */


int EchoHeader::getPartnerAddress(struct in6_addr *dst){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:        
        memcpy(dst, this->data_hsclnt->partner_ip,sizeof(struct in6_addr));
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        memcpy(dst, this->data_hsfinal->partner_ip,sizeof(struct in6_addr));
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of getPartnerAddress() */


/* On failure, it returns 0xAB */
u8 EchoHeader::getIPVersion(){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        return this->data_hsclnt->ip_version;
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        return this->data_hsfinal->ip_version;
    break;

    case TYPE_NEP_PACKET_SPEC:
        return this->data_pspec->ip_version;
    break;

    default:
        return 0xAB;
    break;
  }
} /* End of getIPVersion() */


int EchoHeader::setIPVersion(u8 ver){
  switch( this->getMessageType() ){
    case TYPE_NEP_HANDSHAKE_CLIENT:
        this->data_hsclnt->ip_version=ver;
    break;

    case TYPE_NEP_HANDSHAKE_FINAL:
        this->data_hsfinal->ip_version=ver;
    break;

    case TYPE_NEP_PACKET_SPEC:
        this->data_pspec->ip_version=ver;
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setIPVersion() */



/******************************************************************************/
/* NEP_PACKET_SPEC methods                                                    */
/******************************************************************************/

int EchoHeader::setProtocol(u8 proto){
  switch( this->getMessageType() ){
    case TYPE_NEP_PACKET_SPEC:
        this->data_pspec->protocol=proto;
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setProtocol() */


/* On failure, it returns 0xAB */
u8 EchoHeader::getProtocol(){
  switch( this->getMessageType() ){
    case TYPE_NEP_PACKET_SPEC:
        return this->data_pspec->protocol;
    break;

    default:
        return 0xAB;
    break;
  }
} /* End of setProtocol() */


int EchoHeader::setPacketCount(u16 c){
  switch( this->getMessageType() ){
    case TYPE_NEP_PACKET_SPEC:
        this->data_pspec->packet_count=htons(c);
    break;

    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of setPacketCount() */


/* On failure, it returns 0 */
u16 EchoHeader::getPacketCount(){
  switch( this->getMessageType() ){
    case TYPE_NEP_PACKET_SPEC:
        return ntohs(this->data_pspec->packet_count);
    break;

    default:
        return 0;
    break;
  }
} /* End of getPacketCount() */


int EchoHeader::getFieldLength(u8 field){
  switch(field){
    /* 8bit fields */
    case PSPEC_IPv4_TOS:
    case PSPEC_IPv4_PROTO:
    case PSPEC_IPv6_FLOW:
    case PSPEC_IPv6_NHDR:
    case PSPEC_TCP_FLAGS:
    case PSPEC_ICMP_TYPE:
    case PSPEC_ICMP_CODE:
        return 1;
    break;

    /* 16bit fields */
    case PSPEC_IPv4_ID:
    case PSPEC_IPv4_FRAGOFF:
    case PSPEC_TCP_SPORT:
    case PSPEC_TCP_DPORT:
    case PSPEC_TCP_WIN:
    case PSPEC_TCP_URP:
    case PSPEC_UDP_SPORT:
    case PSPEC_UDP_DPORT:
    case PSPEC_UDP_LEN:
        return 2;
    break;

    /* 24bit fields */
    case PSPEC_IPv6_TCLASS:
        return 3;
    break;

    /* 32bit fields */
    case PSPEC_TCP_SEQ:
    case PSPEC_TCP_ACK:
        return 4;
    break;

    /* Error */
    case PSPEC_PAYLOAD_MAGIC:
    default:
        return -1;
    break;
  }
} /* End of getFieldLength() */


int EchoHeader::addFieldSpec(u8 field, u8 *val){
  int flen;
  /* Determine the length of the field */
  if( (flen=this->getFieldLength(field))==-1 || val==NULL )
      return OP_FAILURE;
  else{
      return this->addFieldSpec(field, val, flen);
  }
} /* End of addFieldSpec() */


int EchoHeader::addFieldSpec(u8 field, u8 *val, size_t flen){
  if( val==NULL ){
      return OP_FAILURE;
  }else{
    /* Store the field spec and update internal pointers and counts */
    if( (this->fs_bytes+flen) < PACKETSPEC_FIELD_LEN ){
        *(this->fs_off)=field;
        if(field==PSPEC_PAYLOAD_MAGIC){
            /* Check length again since this field requires an extra byte */
            if(this->fs_bytes+flen+1 < PACKETSPEC_FIELD_LEN){
                *(this->fs_off+1)=flen;
                memcpy(this->fs_off+2, val, flen);
                this->fs_off+=(flen+2);
                this->fs_bytes+=(flen+2);
            }else{
                return OP_FAILURE;
            }
        }else{
            memcpy(this->fs_off+1, val, flen);
            this->fs_off+=(flen+1);
            this->fs_bytes+=(flen+1);
        }
    }else{
        return OP_FAILURE;
    }
  }
  return OP_SUCCESS;
} /* End of addFieldSpec() */


int EchoHeader::rewindFieldSpecCounters(){
  this->fs_off=(u8 *)this->data_pspec->packetspec;
  this->fs_bytes=0;
  return OP_SUCCESS;
} /* rewindFieldSpecCounters */

/** @warning dst_buff must be able to hold at least (PACKETSPEC_FIELD_LEN-2) bytes. */
int EchoHeader::getNextFieldSpec(u8 *field, u8 *dst_buff, size_t *final_len){
    u8 nfield=0;
    int nlen=0;
    if(field==NULL || dst_buff==NULL || this->fs_bytes>=PACKETSPEC_FIELD_LEN)
        return OP_FAILURE;
    /* Determine which is the next field specifier */
    nfield=*(this->fs_off);
    if(nfield==PSPEC_PAYLOAD_MAGIC){
        nlen=(int)*(this->fs_off+1); /* Read length from the packet */
        if(nlen<=0 || nlen>(PACKETSPEC_FIELD_LEN-2) )
            return OP_FAILURE;
        else if( this->fs_bytes+2+nlen>PACKETSPEC_FIELD_LEN)
            return OP_FAILURE;
        else
            memcpy(dst_buff, this->fs_off+2, nlen);
        this->fs_off+=(nlen+2);
        this->fs_bytes+=(nlen+2);
    }else{
        if((nlen=this->getFieldLength(nfield))<=0) /* Determine field length */
            return OP_FAILURE;
        else if(this->fs_bytes+1+nlen>PACKETSPEC_FIELD_LEN)
            return OP_FAILURE;
        else
            memcpy(dst_buff, this->fs_off+1, nlen);
        this->fs_off+=(nlen+1);
        this->fs_bytes+=(nlen+2);
    }
    /* Store data */
    *field=nfield;
    if(final_len!=NULL)
        *final_len=nlen;
    return OP_SUCCESS;
} /* End of getNextFieldSpec() */


/******************************************************************************/
/* NEP_PACKET_ECHO methods                                                    */
/******************************************************************************/
int EchoHeader::setDLT(u16 dlt){
  this->data_echo->dlt_type=htons(dlt);
  return OP_SUCCESS;
} /* End of setDLT() */


u16 EchoHeader::getDLT(){
    return ntohs(this->data_echo->dlt_type);
} /* End of getDLT() */


int EchoHeader::setPacketLength(u16 len){
  this->data_echo->packet_len=htons(len);
  return OP_SUCCESS;
} /* End of setPacketLength() */


u16 EchoHeader::getPacketLength(){
    return ntohs(this->data_echo->packet_len);
} /* End of setPacketLength() */


int EchoHeader::setEchoedPacket(const u8 *pkt, size_t pktlen){
  int padding=0;
  if(pkt==NULL)
    return OP_FAILURE;
  if(pktlen>MAX_ECHOED_PACKET_LEN){
    pktlen=MAX_ECHOED_PACKET_LEN;
  }
  memcpy(this->data_echo->payload_and_mac, pkt, pktlen);
  if((pktlen+4)%16!=0){
      padding=16-((pktlen+4)%16);
      memset(this->data_echo->payload_and_mac+pktlen, 0, padding);
  }
  this->echo_bytes=pktlen+padding;
  this->echo_mac+=pktlen+padding;
  /* Set the packet length field automatically */
  this->setPacketLength((u16)pktlen);
  this->length = STD_NEP_HEADER_LEN + 4 + this->echo_bytes + MAC_LENGTH;
  assert(this->length%16==0);
  return OP_SUCCESS;
} /* End of setEchoedPacket() */


/* @warning value stored in final_len is not exactly the actual length of the
 * returned buffer but the value stored in the "Packet Length" field of the
 * NEP_ECHO message. The caller is supposed to validate received packets before
 * trusting that length */
u8 *EchoHeader::getEchoedPacket(u16 *final_len){
    if(final_len!=NULL)
        *final_len=this->getPacketLength();
    return this->data_echo->payload_and_mac;
} /* End of getEchoedPacket() */


u8 *EchoHeader::getEchoedPacket(){
    return this->getEchoedPacket(NULL);
} /* End of getEchoedPacket() */


/** This method tries to update the object's internal counters for a NEP_ECHO
  * packet. This should be used when storing a received NEP_ECHO message in
  * the object. In that case, the internal pointers will not be set up
  * correctly, as the object did not construct the message. Calling this method
  * should fix the internal state of the object and make things like
  * verifyMessageAuthenticationCode() work. */
int EchoHeader::updateEchoInternals(){
  if( this->getMessageType()!=TYPE_NEP_ECHO )
    return OP_FAILURE;

  /* Fix echo bytes length */
  this->echo_bytes=this->getPacketLength();
  if((this->echo_bytes+4)%16!=0){
      this->echo_bytes+=16-((this->echo_bytes+4)%16);
  }
  /* Fix MAC offset */
  this->echo_mac=((u8 *)this->data_echo->payload_and_mac)+this->echo_bytes;
  return OP_SUCCESS;
} /* End of updateEchoInternals() */


/******************************************************************************/
/* NEP_ERROR methods                                                          */
/******************************************************************************/

/** @warning error strings longer than MAX_NEP_ERROR_MSG_LEN-1 will be truncated */
int EchoHeader::setErrorMessage(const char *err){
  if(err==NULL){
    return OP_FAILURE;
  }else{
    strncpy((char *)this->data_error->errmsg, err, ERROR_MSG_LEN);
    this->data_error->errmsg[ERROR_MSG_LEN-1]='\0';
  }
  return OP_SUCCESS;
} /* End of setErrorMessage() */

/* @warning Returned pointer, points to the start of the "Error Message" field
 * of the NEP_ERROR message. When receiving this kind of messages, there is no
 * guarantee that the field contains printable characters, or that it is NULL
 * terminated. The caller should validate it's contents. It is safe to read
 * MAX_NEP_ERROR_MSG_LEN bytes from the start of the returned buffer pointer. */
char *EchoHeader::getErrorMessage(){
  return (char *)this->data_error->errmsg;
} /* End of getErrorMessage() */


/******************************************************************************/
/* CRYPTOGRAPHY                                                               */
/******************************************************************************/



u8 *EchoHeader::getCiphertextBounds(size_t *final_len){
    return this->getCiphertextBounds(final_len, this->getMessageType());
}


u8 *EchoHeader::getCiphertextBounds(size_t *final_len, int message_type){
  u8 *start=NULL;
  size_t len=0;

  switch( message_type ){
    case TYPE_NEP_HANDSHAKE_SERVER: /* this msg is never transmitted encrypted */
        len=0;
        start=(u8 *)&this->h;
    break;
    case TYPE_NEP_HANDSHAKE_CLIENT:
        start=this->data_hsclnt->partner_ip;
        len=32;
    break;
    case TYPE_NEP_HANDSHAKE_FINAL:
        start=this->data_hsfinal->partner_ip;
        len=32;
    break;
    case TYPE_NEP_PACKET_SPEC:
        start=(u8 *)(&this->h);
        len=NEP_PACKETSPEC_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_READY:
        start=(u8 *)(&this->h);
        len=NEP_READY_LEN-MAC_LENGTH;
    break;
    case TYPE_NEP_ECHO:
        start=(u8 *)(&this->h);
        len=this->length-MAC_LENGTH;
    break;
    case TYPE_NEP_ERROR:
        start=(u8 *)(&this->h);
        len=NEP_ERROR_LEN-MAC_LENGTH;
    break;
    default:
        return NULL;
    break;
  }

  if(final_len!=NULL)
      *final_len=len;
  return start;
} /* End of getCiphertextBounds() */



/** Encrypts the NEP message using the supplied key and initialization vector.
  * On success it returns a pointer to the beginning of the last ciphertext
  * block. This should be stored by the caller and used as the IV for the
  * next encrypted data. It returns NULL in case of error. */
u8 *EchoHeader::encrypt(u8 *key, size_t key_len, u8 *iv){
  nping_print(DBG_4, "%s(%p, %lu, %p)", __func__, key, (long unsigned)key_len, iv);
  u8 *start=NULL;
  size_t len=0;

  if(key==NULL || key_len==0 || iv==NULL)
    return NULL;

  if((start=this->getCiphertextBounds(&len))==NULL)
    return NULL;

  if(len>=CIPHER_BLOCK_SIZE){
    if( Crypto::aes128_cbc_encrypt(start, len, (u8 *)(&this->h_tmp), key, key_len, iv) != OP_SUCCESS )
        return NULL;
    else{
        memcpy(start, &this->h_tmp, len);
        return (start+(len-CIPHER_BLOCK_SIZE));
    }
  }else{
    return NULL;
  }
} /* End of encrypt() */


u8 *EchoHeader::decrypt(u8 *key, size_t key_len, u8 *iv, int message_type){
  nping_print(DBG_4, "%s(%p, %lu, %p)", __func__, key, (long unsigned)key_len, iv);
  u8 *start=NULL;
  size_t len=0;
  static u8 lastblock[CIPHER_BLOCK_SIZE];

  if(key==NULL || key_len==0 || iv==NULL)
    return NULL;

  if((start=this->getCiphertextBounds(&len, message_type))==NULL)
    return NULL;

  if(len>=CIPHER_BLOCK_SIZE){
    /* Keep a copy of the last ciphertext block */
    memcpy(lastblock, start+len-CIPHER_BLOCK_SIZE, CIPHER_BLOCK_SIZE);
    if( Crypto::aes128_cbc_decrypt(start, len, (u8 *)(&this->h_tmp), key, key_len, iv) != OP_SUCCESS )
        return NULL;
    else{
        memcpy(start, &this->h_tmp, len);
        return lastblock;
    }
  }else{
    return NULL;
  }
} /* End of decrypt() */
