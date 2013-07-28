
/***************************************************************************
 * EchoClient.cc --                                                        *
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

#include "nping.h"
#include "EchoClient.h"
#include "EchoHeader.h"
#include "output.h"
#include "NEPContext.h"
#include "NpingOps.h"
#include "nsock.h"
#include "Crypto.h"

extern NpingOps o;
extern EchoClient ec;


EchoClient::EchoClient() {
  this->reset();
} /* End of EchoClient constructor */


EchoClient::~EchoClient() {
  this->reset();
} /* End of EchoClient destructor */


/** Sets every attribute to its default value- */
void EchoClient::reset() {
  memset(&this->srvaddr4, 0, sizeof(struct sockaddr_in));
  memset(&this->srvaddr6, 0, sizeof(struct sockaddr_in6));
  memset(this->lasthdr, 0, MAX_NEP_PACKET_LENGTH);
  this->readbytes=0;
  this->af=AF_INET;
} /* End of reset() */


/** Closes current connection and destroys Nsock handlers */
int EchoClient::cleanup(){
  this->probe.cleanup();
  return OP_SUCCESS;
} /* End of cleanup() */


/** This is the main method, the boss of it all. It sets up nsock, establishes
  * a TCP connection with the server, performs the NEP authentication handshake,
  * sends the appropriate packet specs and handles raw packet transmission and 
  * NEP_ECHO reception and display. */
int EchoClient::start(NpingTarget *target, u16 port){
  nping_print(DBG_4, "%s(%p, %u)", __func__, target, port);

  /* Init Nsock in the probe engine */
  if( this->probe.init_nsock() != OP_SUCCESS ){
    nping_warning(QT_2, "Couln't initialize Nsock.");
    return OP_FAILURE;
  }else{
    /* Extract the nsock pool handler and store it here */
    this->nsp=this->probe.getNsockPool();
    this->nsi=nsi_new(this->nsp, NULL);
  }

  /* Schedule a TCP connection attempt */
  if( this->nep_connect(target, port) != OP_SUCCESS ){
    nping_warning(QT_2, "Connection failed.");
    return OP_FAILURE;
  }

  /* Perform NEP authentication handshake */
  if( this->nep_handshake() != OP_SUCCESS ){
    nping_warning(QT_2, "Handshake failed.");
    return OP_FAILURE;
  }

  /* Send packet specification */
  if( this->nep_send_packet_spec() != OP_SUCCESS ){
    nping_warning(QT_2, "Couldn't send packet specification.");
    return OP_FAILURE;
  }

  /* Wait for confirmation */
  if( this->nep_recv_ready() != OP_SUCCESS ){
    nping_warning(QT_2, "Didn't receive server's OK.");
    return OP_FAILURE;
  }

  /* Schedule read of the first 16 bytes to determine the full packet length */
  nsock_readbytes(this->nsp, this->nsi, recv_std_header_handler, NSOCK_INFINITE, NULL, STD_NEP_HEADER_LEN);

  /* Start the probe mode engine */
  probe.start();

  return OP_SUCCESS; 
} /* End of start() */


/** Attempts to establish a TCP connection to "target:port". On success it
  * returns OP_SUCCESS. OP_FAILURE is returned when it was impossible to
  * connect to the remote host (this can be because the server rejected the
  * connection or because the connect() timed out). */
int EchoClient::nep_connect(NpingTarget *target, u16 port){
  nping_print(DBG_4, "%s(%p, %u)", __func__, target, port);
  struct sockaddr_storage ss;
  struct sockaddr_storage src;
  size_t ss_len;
  struct sockaddr_in *s4=(struct sockaddr_in *)&ss;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ss;
  enum nsock_loopstatus loopstatus;
  
  if(target==NULL)
    nping_fatal(QT_3, "nep_connect(): NULL parameter supplied.");
  else
    target->getTargetSockAddr(&ss, &ss_len);

  /* AF_INET6 */
  if( s6->sin6_family==AF_INET6 ){
    this->af=AF_INET6;
    this->srvaddr6.sin6_family = AF_INET6;
    this->srvaddr6.sin6_port = htons(port);
    this->srvaddr6.sin6_addr = s6->sin6_addr;
    this->srvaddr6.sin6_flowinfo = 0;
    #ifdef HAVE_SOCKADDR_IN6_SIN6_LEN
        this->srvaddr6.sin6_len = sizeof(struct sockaddr_in6);
    #endif

   /* Try to bind the IOD to the IP address supplied by the user */
   nsi_set_localaddr(this->nsi, o.getSourceSockAddr(&src), sizeof(sockaddr_in6));

   /* Schedule a connect event */
   nsock_connect_tcp(this->nsp, this->nsi, connect_done_handler, ECHO_CONNECT_TIMEOUT,
                     NULL, (struct sockaddr *) &this->srvaddr6, sizeof(this->srvaddr6), port);

  /* AF_INET */
  }else{
    this->af=AF_INET;
    this->srvaddr4.sin_family = AF_INET;
    this->srvaddr4.sin_port = htons(port);
    this->srvaddr4.sin_addr = s4->sin_addr;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
    this->srvaddr4.sin_len = sizeof(struct sockaddr_in);
#endif

   /* Try to bind the IOD to the IP address supplied by the user */
   nsi_set_localaddr(this->nsi, o.getSourceSockAddr(&src), sizeof(sockaddr_in));

   /* Schedule a connect event */
   nsock_connect_tcp(this->nsp, this->nsi, connect_done_handler, ECHO_CONNECT_TIMEOUT,
                     NULL, (struct sockaddr *) &this->srvaddr4, sizeof(this->srvaddr4), port);

  }
  /* Try to connect or timeout */
  loopstatus=nsock_loop(this->nsp, ECHO_CONNECT_TIMEOUT-1);
  /* If nsock tells us that the handler asked to quit the loop, then the connect was successful */
  return (loopstatus==NSOCK_LOOP_QUIT) ? OP_SUCCESS : OP_FAILURE;
} /* End of nep_connect() */


/** Attempts to perform the NEP authentication handshake with the server.
  * Returns OP_SUCCESS if the authentication went well and OP_FAILURE otherwise */
int EchoClient::nep_handshake(){
  nping_print(DBG_4, "%s()", __func__);
  enum nsock_loopstatus loopstatus;
  EchoHeader h;
  
  /* Receive NEP_HANDSHAKE_SERVER message */
  nsock_readbytes(this->nsp, this->nsi, recv_hs_server_handler, ECHO_READ_TIMEOUT, NULL, NEP_HANDSHAKE_SERVER_LEN);
  loopstatus=nsock_loop(this->nsp, ECHO_READ_TIMEOUT-1);
  if(loopstatus!=NSOCK_LOOP_QUIT)
    return OP_FAILURE;

  /* Generate client nonces and the session cryptographic keys*/
  this->ctx.generateInitialClientSequence();
  this->ctx.generateClientNonce();
  this->ctx.generateCipherKeyC2S();
  this->ctx.generateCipherKeyS2C();
  this->ctx.generateMacKeyC2S();
  this->ctx.generateMacKeyS2C();

  nping_print(DBG_4,"Session Key MAC_C2S:"); print_hexdump(DBG_4,ctx.getMacKeyC2S(), MAC_KEY_LEN);
  nping_print(DBG_4,"Session Key MAC_S2C:"); print_hexdump(DBG_4,ctx.getMacKeyS2C(), MAC_KEY_LEN);
  nping_print(DBG_4,"Session Key CIPHER_C2S:"); print_hexdump(DBG_4,ctx.getCipherKeyC2S(), MAC_KEY_LEN);
  nping_print(DBG_4,"Session Key CIPHER_S2C:"); print_hexdump(DBG_4,ctx.getCipherKeyS2C(), MAC_KEY_LEN);


  /* Send NEP_HANDSHAKE_CLIENT message */
  if( this->generate_hs_client(&h)!=OP_SUCCESS )
    return OP_FAILURE;
  nsock_write(this->nsp, this->nsi, write_done_handler, ECHO_WRITE_TIMEOUT, NULL, (char *)h.getBinaryBuffer(), h.getLen());
  loopstatus=nsock_loop(this->nsp, ECHO_WRITE_TIMEOUT-1);
  if(loopstatus!=NSOCK_LOOP_QUIT)
    return OP_FAILURE;

  /* Receive NEP_HANDSHAKE_FINAL message */
  nsock_readbytes(this->nsp, this->nsi, recv_hs_final_handler, ECHO_READ_TIMEOUT, NULL, NEP_HANDSHAKE_FINAL_LEN);
  loopstatus=nsock_loop(this->nsp, ECHO_READ_TIMEOUT-1);
  if(loopstatus!=NSOCK_LOOP_QUIT)
    return OP_FAILURE;
  
  nping_print(DBG_1, "===NEP Handshake completed successfully===");
  return OP_SUCCESS;
} /* End of nep_handshake() */


/** Sends the appropriate NEP_PACKET_SPEC message to the server. Returns
  * OP_SUCCESS on success and OP_FAILURE in case of error. */
int EchoClient::nep_send_packet_spec(){
  nping_print(DBG_4, "%s()", __func__);
  enum nsock_loopstatus loopstatus;
  EchoHeader h;

  if (this->generate_packet_spec(&h)!=OP_SUCCESS)
    return OP_FAILURE;

   /* Send NEP_PACKET_SPEC message */
  nsock_write(this->nsp, this->nsi, write_done_handler, ECHO_WRITE_TIMEOUT, NULL, (const char*)h.getBinaryBuffer(),  h.getLen());
  loopstatus=nsock_loop(this->nsp, ECHO_WRITE_TIMEOUT-1);
  if(loopstatus!=NSOCK_LOOP_QUIT)
    return OP_FAILURE;
  else
    return OP_SUCCESS;
} /* End of nep_send_packetspec() */


/** Receives and parses a NEP_READY message from the server. Returns OP_SUCCESS
  * on success and OP_FAILURE in case of error. */
int EchoClient::nep_recv_ready(){
  nping_print(DBG_4, "%s()", __func__);
  enum nsock_loopstatus loopstatus;
  /* Receive NEP_READY message */
  nsock_readbytes(this->nsp, this->nsi, recv_ready_handler, ECHO_READ_TIMEOUT, NULL, NEP_READY_LEN);
  loopstatus=nsock_loop(this->nsp, ECHO_READ_TIMEOUT-1);
  if(loopstatus!=NSOCK_LOOP_QUIT)
    return OP_FAILURE;
  else
    return OP_SUCCESS;
} /* End of nep_recv_ready(){ */


/** Reads and parses a NEP_ECHO message from the server. Returns OP_SUCCESS
  * on success and OP_FAILURE in case of error. */
int EchoClient::nep_recv_echo(u8 *packet, size_t packetlen){
  nping_print(DBG_4, "%s(%p, %lu)", __func__, packet, (unsigned long)packetlen);
  EchoHeader pkt_in;
  char *delayedstr=NULL;
  nsock_event_id ev_id;
  u8 *pkt=NULL;
  u16 pktlen=0;
  u8 pktinfobuffer[512+1];
  struct timeval *t = (struct timeval *)nsock_gettimeofday();
  memset(pktinfobuffer, 0, sizeof(pktinfobuffer));

  /* Verify the received packet (this covers authentication etc) */
  if(this->parse_echo(packet, packetlen)!=OP_SUCCESS){
    return OP_FAILURE;
  }

  /* Once we have authenticated the received message, extract the echoed packet */
  if(pkt_in.storeRecvData(packet, packetlen)==OP_FAILURE){
    nping_print(VB_0, "Unexpected error dealing with the NEP_ECHO message,");
    return OP_FAILURE;
  }
  if((pkt=pkt_in.getEchoedPacket(&pktlen))==NULL){
    nping_print(VB_0, "Error displaying received NEP_ECHO message)");
    return OP_FAILURE;
  }
  o.stats.addEchoedPacket(pktlen);

  /* Guess the time the packet was captured. We do this computing the RTT
   * between the last sent packet and the received echo packet. We assume
   * the packet was captured RTT/2 seconds ago. */
  struct timeval tmp=o.getLastPacketSentTime();
  float sent_time = o.stats.elapsedRuntime(&tmp);
  float now_time = o.stats.elapsedRuntime(t);
  float rtt = now_time - sent_time;
  float final_time = sent_time + rtt/2;

  /* @todo: compute the link layer offset from the DLT type and discard
   * link layer headers */
  getPacketStrInfo("IP", pkt, pktlen, pktinfobuffer, 512);
  nping_print(VB_0,"CAPT (%.4fs) %s", final_time, pktinfobuffer );
  if( o.getVerbosity() >= VB_3)
    luis_hdump((char*)pkt, pktlen);

  /* Check if there is a delayed RCVD string that is waiting to be printed */
  if( (delayedstr=o.getDelayedRcvd(&ev_id))!=NULL ){
    printf("%s", delayedstr);
    free(delayedstr);
    nsock_event_cancel(this->nsp, ev_id, 0);
  }
  return OP_SUCCESS;
} /* End of nep_recv_echo() */


/** Processes and validates a received NEP_HANDSHAKE_SERVER message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoClient::parse_hs_server(u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader h;
  if(pkt==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen!=NEP_HANDSHAKE_SERVER_LEN){
    nping_print(DBG_1,"%s(): Unexpected length supplied.", __func__ );
    return OP_FAILURE;
  }
  h.storeRecvData(pkt, pktlen);

  /* Validate version number */
  if( h.getVersion() != ECHO_CURRENT_PROTO_VER ){
    nping_print(DBG_1, "Expected NEP version %02x but message used %02x", ECHO_CURRENT_PROTO_VER, h.getVersion() );
    return OP_FAILURE;
  }

  /* Ensure the expected message type was received */
  if(h.getMessageType()!=TYPE_NEP_HANDSHAKE_SERVER){
    nping_print(DBG_1, "Expected NEP_HANDSHAKE_SERVER but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_HANDSHAKE_SERVER timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

  /* Ensure message length is correct */
  if( h.getTotalLength()!=(NEP_HANDSHAKE_SERVER_LEN/4)){
    nping_print(DBG_1, "Received NEP_HANDSHAKE_SERVER specifies an incorrect length (%u)", h.getTotalLength()*4 );
    return OP_FAILURE;
  }

  /* Check the authenticity of the received message */
  this->ctx.setServerNonce(h.getServerNonce());
  this->ctx.generateMacKeyS2CInitial();
  if( h.verifyMessageAuthenticationCode(this->ctx.getMacKeyS2C(), MAC_KEY_LEN )!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_HANDSHAKE_SERVER authentication failed" );
      return OP_FAILURE;
  }
  this->ctx.setLastServerSequence( h.getSequenceNumber() );
  return OP_SUCCESS;
} /* End of parse_hs_server() */


/** Processes and validates a received NEP_HANDSHAKE_FINAL message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoClient::parse_hs_final(u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader h;
  u8 *next_iv=NULL;
  if(pkt==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen!=NEP_HANDSHAKE_FINAL_LEN){
    nping_print(DBG_1,"%s(): Unexpected length supplied.", __func__ );
    return OP_FAILURE;
  }
  h.storeRecvData(pkt, pktlen);

  /* Validate version number */
  if( h.getVersion() != ECHO_CURRENT_PROTO_VER ){
    nping_print(DBG_1, "Expected NEP version %02x but message used %02x", ECHO_CURRENT_PROTO_VER, h.getVersion() );
    return OP_FAILURE;
  }

  /* Ensure the expected message type was received */
  if(h.getMessageType()!=TYPE_NEP_HANDSHAKE_FINAL){
    nping_print(DBG_1, "Expected NEP_HANDSHAKE_FINAL but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received sequence number is the previous+1 */
  if( h.getSequenceNumber()!=(this->ctx.getLastServerSequence()+1)){
    nping_print(DBG_1, "Expected sequence number %d but received %d", this->ctx.getLastServerSequence()+1, h.getSequenceNumber() );
    return OP_FAILURE;
  }else{
    /* Increment next expected sequence number*/
    this->ctx.getNextServerSequence();
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_HANDSHAKE_FINAL timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

  /* Ensure message length is correct */
  if( h.getTotalLength()!=(NEP_HANDSHAKE_FINAL_LEN/4)){
    nping_print(DBG_1, "Received NEP_HANDSHAKE_FINAL specifies an incorrect length (%u)", h.getTotalLength()*4 );
    return OP_FAILURE;
  }

  /* Ensure the server echoed the nonce we sent in our NEP_HANDSHAKE_CLIENT */
  if( memcmp(h.getClientNonce(), this->ctx.getClientNonce(), NONCE_LEN)!=0 ){
    nping_print(DBG_1, "Echoed nonce in NEP_HANDSHAKE_FINAL message does not match client generate nonce");
    return OP_FAILURE;
  }

  /* Decrypt the encrypted part of the message before validating the MAC */
  if((next_iv=h.decrypt(this->ctx.getCipherKeyS2C(), CIPHER_KEY_LEN, this->ctx.getServerNonce(), TYPE_NEP_HANDSHAKE_FINAL))==NULL){
      nping_print(DBG_1, "Failed to decrypt NEP_HANDSHAKE_FINAL data." );
      return OP_FAILURE;
  }
  this->ctx.setNextDecryptionIV(next_iv);

  /* Check the authenticity of the received message */
  if( h.verifyMessageAuthenticationCode(this->ctx.getMacKeyS2C(), MAC_KEY_LEN )!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_HANDSHAKE_FINAL authentication failed" );
      return OP_FAILURE;
  }

  return OP_SUCCESS;
} /* End of parse_hs_final() */


/** Processes and validates a received NEP_READY message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoClient::parse_ready(u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader h;
  u8 *next_iv=NULL;
  if(pkt==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen!=NEP_READY_LEN){
    nping_print(DBG_1,"%s(): Unexpected length supplied.", __func__ );
    return OP_FAILURE;
  }
  h.storeRecvData(pkt, pktlen);

  /* Decrypt message */
  if((next_iv=h.decrypt(this->ctx.getCipherKeyS2C(), CIPHER_KEY_LEN, this->ctx.getNextDecryptionIV(), TYPE_NEP_READY))==NULL){
      nping_print(DBG_1, "Failed to decrypt NEP_READY data." );
      return OP_FAILURE;
  }
  this->ctx.setNextDecryptionIV(next_iv);

  /* Validate version number */
  if( h.getVersion() != ECHO_CURRENT_PROTO_VER ){
    nping_print(DBG_1, "Expected NEP version %02x but message used %02x", ECHO_CURRENT_PROTO_VER, h.getVersion() );
    return OP_FAILURE;
  }

  /* Ensure the expected message type was received */
  if(h.getMessageType()!=TYPE_NEP_READY){
    nping_print(DBG_1, "Expected NEP_READY but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received sequence number is the previous+1 */
  if( h.getSequenceNumber()!=(this->ctx.getLastServerSequence()+1)){
    nping_print(DBG_1, "Expected sequence number %d but received %d", this->ctx.getLastServerSequence()+1, h.getSequenceNumber() );
    return OP_FAILURE;
  }else{
    /* Increment next expected sequence number*/
    this->ctx.getNextServerSequence();
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_READY timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

  /* Ensure message length is correct */
  if( h.getTotalLength()!=(NEP_READY_LEN/4)){
    nping_print(DBG_1, "Received NEP_READY specifies an incorrect length (%u)", h.getTotalLength()*4 );
    return OP_FAILURE;
  }

  /* Check the authenticity of the received message */
  if( h.verifyMessageAuthenticationCode(this->ctx.getMacKeyS2C(), MAC_KEY_LEN )!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_READY authentication failed" );
      return OP_FAILURE;
  }

  return OP_SUCCESS;
} /* End of parse_hs_final() */


/** Processes and validates a received NEP_ECHO message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoClient::parse_echo(u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader h;
  u8 *next_iv=NULL;
  if(pkt==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen<NEP_ECHO_MIN_LEN){
    nping_print(DBG_1,"%s(): Unexpected length supplied.", __func__ );
    return OP_FAILURE;
  }
  h.storeRecvData(pkt, pktlen);

  /* Decrypt message */
  if((next_iv=h.decrypt(this->ctx.getCipherKeyS2C(), CIPHER_KEY_LEN, this->ctx.getNextDecryptionIV(), TYPE_NEP_ECHO))==NULL){
      nping_print(DBG_1, "Failed to decrypt NEP_ECHO data." );
      return OP_FAILURE;
  }
  this->ctx.setNextDecryptionIV(next_iv);

  /* Validate version number */
  if( h.getVersion() != ECHO_CURRENT_PROTO_VER ){
    nping_print(DBG_1, "Expected NEP version %02x but message used %02x", ECHO_CURRENT_PROTO_VER, h.getVersion() );
    return OP_FAILURE;
  }

  /* Ensure the expected message type was received */
  if(h.getMessageType()!=TYPE_NEP_ECHO){
    nping_print(DBG_1, "Expected NEP_ECHO but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received sequence number is the previous+1 */
  if( h.getSequenceNumber()!=(this->ctx.getLastServerSequence()+1)){
    nping_print(DBG_1, "Expected sequence number %d but received %d", this->ctx.getLastServerSequence()+1, h.getSequenceNumber() );
    return OP_FAILURE;
  }else{
    /* Increment next expected sequence number*/
    this->ctx.getNextServerSequence();
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_ECHO timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

//  /* Ensure message length is correct */
//  if( h.getTotalLength()!=(pktlen/4)){
//    nping_print(DBG_1, "Received NEP_ECHO specifies an incorrect length (%u)", h.getTotalLength()*4 );
//    return OP_FAILURE;
//  }

  /* Fix the object's internal state, since the ECHO message was not created
   * by the object but from received data. */
  h.updateEchoInternals();

  /* Check the authenticity of the received message */
  if( h.verifyMessageAuthenticationCode(this->ctx.getMacKeyS2C(), MAC_KEY_LEN )!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_ECHO authentication failed" );
      return OP_FAILURE;
  }else{
      nping_print(DBG_1, "Received NEP_ECHO was authenticated successfully");
  }

  /* Overwrite the received buffer with the decrypted data */
  h.dumpToBinaryBuffer(pkt, pktlen);

  return OP_SUCCESS;
} /* End of parse_hs_final() */


/** Processes and validates a received NEP_ERROR message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoClient::parse_error(u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s()", __func__);
  return OP_SUCCESS;
} /* End of parse_hs_final() */


/** Generates a NEP_HANDSHAKE_CLIENT message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error. */
int EchoClient::generate_hs_client(EchoHeader *h){
  nping_print(DBG_4, "%s()", __func__);
  u8 *next_iv=NULL;
  if(h==NULL)
    return OP_FAILURE;

  /* Craft NEP_HANDSHAKE_CLIENT message */
  h->setMessageType(TYPE_NEP_HANDSHAKE_CLIENT);
  h->setSequenceNumber( this->ctx.getLastClientSequence() );
  h->setTimestamp();
  h->setServerNonce( this->ctx.getServerNonce() );
  h->setClientNonce( this->ctx.getClientNonce() );
  if(this->af==AF_INET6){
      h->setPartnerAddress(this->srvaddr6.sin6_addr);
  }else{
      h->setPartnerAddress(this->srvaddr4.sin_addr);
  }
  h->setTotalLength();
  h->setMessageAuthenticationCode( this->ctx.getMacKeyC2S(), MAC_KEY_LEN);

  if( (next_iv=h->encrypt(this->ctx.getCipherKeyC2S(), CIPHER_KEY_LEN, this->ctx.getClientNonce()))==NULL )
      return OP_FAILURE;
  this->ctx.setNextEncryptionIV(next_iv);

  return OP_SUCCESS;
} /* End of generate_hs_client() */

/** Generates a NEP_PACKET_SPEC message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error. */
int EchoClient::generate_packet_spec(EchoHeader *h){
  nping_print(DBG_4, "%s()", __func__);
  int ports=-1;
  u8 nxthdr=0;
  u8 aux8=0;
  u16 aux16=0;
  u16 *p16=NULL;
  u32 aux32=0;
  u8 *next_iv=NULL;

  if(h==NULL)
    return OP_FAILURE;

  h->setMessageType(TYPE_NEP_PACKET_SPEC);
  h->setSequenceNumber( this->ctx.getNextClientSequence() );
  h->setTimestamp();
  h->setIPVersion( o.getIPVersion()==AF_INET6 ? 0x06: 0x04 );
  h->setPacketCount( (o.getPacketCount()>0xFFFF) ? 0xFFFF : o.getPacketCount() );
    
  /** Insert packet field specifiers */
  if(o.ipv6()){ /* AF_INET6 */
    /* Traffic class */
    aux8=o.getTrafficClass();
    h->addFieldSpec(PSPEC_IPv6_TCLASS, (u8*)&aux8);
    /* Flow label */
    aux32=htonl(o.getFlowLabel());
    h->addFieldSpec(PSPEC_IPv6_FLOW, (u8*)&aux32);
  }else{ /* AF_INET */
    /* IP Identification */
    aux16=htons(o.getIdentification());
    h->addFieldSpec(PSPEC_IPv4_ID, (u8*)&aux16);
    /* Type of Service */
    aux8=o.getTOS();
    h->addFieldSpec(PSPEC_IPv4_TOS, (u8*)&aux8);
    /* Fragment Offset */
    /** @todo Implement this. Nping does not currently offer --fragoff */
  }

  switch( o.getMode() ){

      case TCP:
          nxthdr=6;
          h->setProtocol(PSPEC_PROTO_TCP);
          /* Source TCP Port */
          aux16=htons(o.getSourcePort());
          h->addFieldSpec(PSPEC_TCP_SPORT, (u8*)&aux16);
          /* Destination TCP Port */
          if( (p16=o.getTargetPorts(&ports))!=NULL && ports==1 ){
              aux16=htons(*p16);
                h->addFieldSpec(PSPEC_TCP_DPORT, (u8*)&aux16);
          }
          /* Sequence number */
          aux32=htonl(o.getTCPSequence());
          h->addFieldSpec(PSPEC_TCP_SEQ, (u8*)&aux32);
          /* Acknowledgment */
          aux32=htonl(o.getTCPAck());
          h->addFieldSpec(PSPEC_TCP_ACK, (u8*)&aux32);
          /* Flags */
          aux8=o.getTCPFlags();
          h->addFieldSpec(PSPEC_TCP_FLAGS, (u8*)&aux8);
          /* Window size */
          aux16=htons(o.getTCPWindow());
          h->addFieldSpec(PSPEC_TCP_WIN, (u8*)&aux16);
          /* Urgent pointer */
          /** @todo Implement this. Nping does not currently offer --urp */
      break;

      case UDP:
          nxthdr=17;
          h->setProtocol(PSPEC_PROTO_UDP);
          /* Source UDP Port */
          aux16=htons(o.getSourcePort());
          h->addFieldSpec(PSPEC_UDP_SPORT, (u8*)&aux16);
          /* Destination TCP Port */
          if( (p16=o.getTargetPorts(&ports))!=NULL && ports==1 ){
              aux16=htons(*p16);
              h->addFieldSpec(PSPEC_UDP_DPORT, (u8*)&aux16);
          }
          /* Packet length */
          aux16=htons(8+o.getPayloadLen());
          h->addFieldSpec(PSPEC_UDP_LEN, (u8*)&aux16);
      break;

      case ICMP:
          nxthdr=1;
          h->setProtocol(PSPEC_PROTO_ICMP);
          aux8=o.getICMPType();
          h->addFieldSpec(PSPEC_ICMP_TYPE, (u8*)&aux8);
          aux8=o.getICMPCode();
          h->addFieldSpec(PSPEC_ICMP_CODE, (u8*)&aux8);
      break;

      case UDP_UNPRIV:
      case TCP_CONNECT:
      case ARP:
      default:
          nping_fatal(QT_3, "%s packets are not supported in Echo Mode", o.mode2Ascii(o.getMode()) );
      break;
  }
  /* Next protocol number */
  if(o.ipv4())
    h->addFieldSpec(PSPEC_IPv4_PROTO, (u8*)&nxthdr);
  else
    h->addFieldSpec(PSPEC_IPv6_NHDR, (u8*)&nxthdr);

  if( o.issetPayloadBuffer() && o.getPayloadLen()>0){
    h->addFieldSpec(PSPEC_PAYLOAD_MAGIC, (u8*)o.getPayloadBuffer(), MIN(o.getPayloadLen(), NEP_PAYLOADMAGIC_MAX_BYTES));
  }
  /* Done inserting packet field specifiers, now finish the packet */
  h->setTotalLength();
  h->setMessageAuthenticationCode(this->ctx.getMacKeyC2S(), MAC_KEY_LEN);

  /* Encrypt message */
  if( (next_iv=h->encrypt(this->ctx.getCipherKeyC2S(), CIPHER_KEY_LEN, this->ctx.getNextEncryptionIV()))==NULL )
      return OP_FAILURE;
  this->ctx.setNextEncryptionIV(next_iv);

  return OP_SUCCESS;
} /* End of generate_packet_spec() */


/** Handles reception of a full NEP message. (the common NEP header). Basically
  * it stores received data in the internal buffer and passes the control to
  * the nep_recv_echo() method, which is the one in charge of processing
  * NEP_ECHO packets */
int EchoClient::nep_echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader pkt_in;
  u8 *recvbuff=NULL;
  int recvbytes=0;
  u8 aux[128];
  u8 *pkt_start=this->lasthdr;
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
      if(status!=NSE_STATUS_KILL){
          nping_warning(QT_2, "===========================================================================");
          nping_warning(QT_2, "ERROR: Server closed the connection. No more CAPT packets will be received.");
          nping_warning(QT_2, "===========================================================================");
      }
      return OP_FAILURE;
  }
  
  /* Read the remaining data */
  if( (recvbuff=(u8 *)nse_readbuf(nse, &recvbytes))==NULL ){
    nping_print(DBG_4,"nep_echoed_packet_handler(): nse_readbuf failed!\n");
    return OP_FAILURE;
  }else{
    nping_print(DBG_4, "%s() Received %d bytes", __func__, recvbytes);
  }

 /* When we get here we'll have part of the packet stored in this->lasthdr and
  * part of it (and possible more packets) stored in recvbuff. */
  while(recvbytes>0){

    /* Determine if we received the expected number of bytes or we received more
    * than that. For that we need to decrypt the first 16 bytes so we can have
    * a look at packet length */
    Crypto::aes128_cbc_decrypt(pkt_start, 16, aux, this->ctx.getCipherKeyS2C(), CIPHER_KEY_LEN, this->ctx.getNextDecryptionIV());
    pkt_in.storeRecvData(aux, 16);
    int plen=pkt_in.getTotalLength()*4;
    nping_print(DBG_4, "%s() Packet claims to have a length of %d bytes", __func__, plen);

    /* If the packet is bigger than the maximum NEP packet, discard it. */
    if(plen>MAX_NEP_PACKET_LENGTH){
        nping_warning(DBG_1,"Warning. Received NEP packet (%dB) is bigger than %d bytes.", plen, MAX_NEP_PACKET_LENGTH);
        return OP_FAILURE;
    }

    /* If we have read the whole packet, give it to nep_recv_echo for processing */
    if (plen==((int)this->readbytes+recvbytes)){
        memcpy(this->lasthdr+this->readbytes, recvbuff, recvbytes);
        this->readbytes+=recvbytes;
        nping_print(DBG_4,"%s(): Received exact length (%d).", __func__, recvbytes);
        this->nep_recv_echo(this->lasthdr, this->readbytes);
        nsock_readbytes(this->nsp, this->nsi, recv_std_header_handler, NSOCK_INFINITE, NULL, STD_NEP_HEADER_LEN);
        return OP_SUCCESS;

    /* This one can't happen in the first iteration since we scheduled the
     * event with the exact amount of bytes, but may happen after that if we
     * received more data and one of the packets is incomplete */
    }else if(recvbytes<plen){
        memcpy(this->lasthdr, recvbuff, recvbytes);
        this->readbytes=recvbytes;
        nping_print(DBG_4,"%s(): Missing %d bytes. Scheduled read operation for remaining bytes", __func__, plen-recvbytes);
        nsock_readbytes(nsp, nsi, echoed_packet_handler, NSOCK_INFINITE, NULL, plen-recvbytes);
        return OP_SUCCESS;

    }else{ /* Received more than one packet */
      nping_print(DBG_4,"%s(): Received more than one packet", __func__);
      memcpy(this->lasthdr+this->readbytes, recvbuff, plen-this->readbytes);
      this->nep_recv_echo(this->lasthdr, plen);
      recvbuff+=plen-this->readbytes;
      recvbytes-=plen-this->readbytes;
      this->readbytes=0;
      pkt_start=recvbuff;
    }

  }
  return OP_SUCCESS;
} /* End of nep_echoed_packet_handler() */


/** Handles reception of the first 16 bytes (the common NEP header). Basically
  * it checks the Total Length field of the header to determine how many bytes
  * are left to read to get the entire packet. If there are more bytes to be
  * receives, a read event is scheduled. However, we may have read them all when
  * this handler is called (due to nsock behaviour) so in that case we just pass
  * control to nep_recv_echo(), which is the one in charge of processing
  * NEP_ECHO packets */
int EchoClient::nep_recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  EchoHeader pkt_in;
  u8 *recvbuff=NULL;
  int recvbytes=0;
  u8 aux[128];
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
      if(status!=NSE_STATUS_KILL){
          nping_warning(QT_2, "===========================================================================");
          nping_warning(QT_2, "ERROR: Server closed the connection. No more CAPT packets will be received.");
          nping_warning(QT_2, "===========================================================================");
      }
      return OP_FAILURE;
  }
  /* Read data */
  if( (recvbuff=(u8 *)nse_readbuf(nse, &recvbytes))==NULL ){
    nping_print(DBG_4,"%s(): nse_readbuf failed.", __func__);
    return OP_FAILURE;
  }else{
    nping_print(DBG_4, "%s() Received %d bytes", __func__, recvbytes);
  }

  /* Here there are different possibilites. We may have received exactly one
   * packet, we may have received more than one packet (as there is no way to
   * make Nsock return an exact amount of bytes), or we may have received
   * less than one packet. In the last case, we determine the number of bytes
   * left and schedule another read event. */
  while(recvbytes>0){

    /* Decrypt the first 16 bytes so we can have a look at packet length */
    Crypto::aes128_cbc_decrypt(recvbuff, 16, aux, this->ctx.getCipherKeyS2C(), CIPHER_KEY_LEN, this->ctx.getNextDecryptionIV());
    pkt_in.storeRecvData(aux, 16);
    int plen=pkt_in.getTotalLength()*4;

    /* If the packet is bigger than the maximum NEP packet, discard it. */
    if(plen>MAX_NEP_PACKET_LENGTH){
        nping_warning(DBG_1,"Warning. Received NEP packet (%dB) is bigger than %d bytes.", plen, MAX_NEP_PACKET_LENGTH);
        return OP_FAILURE;
    }

    /* If we have read the whole packet, give it to nep_recv_echo for processing */
    if (plen==recvbytes){
        nping_print(DBG_4,"%s(): Received exact length (%d).", __func__, recvbytes);
        this->nep_recv_echo(recvbuff, recvbytes);
        nsock_readbytes(this->nsp, this->nsi, recv_std_header_handler, NSOCK_INFINITE, NULL, STD_NEP_HEADER_LEN);
        return OP_SUCCESS;

    }else if(recvbytes<plen){
        memcpy(this->lasthdr, recvbuff, recvbytes);
        this->readbytes=recvbytes;
        nping_print(DBG_4,"%s(): Missing %d bytes. Scheduled read operation for remaining bytes", __func__, plen-recvbytes);
        nsock_readbytes(nsp, nsi, echoed_packet_handler, NSOCK_INFINITE, NULL, plen-recvbytes);
        return OP_SUCCESS;

    }else{ /* Received more than one packet */
      nping_print(DBG_4,"%s(): Received more than one packet", __func__);
      this->nep_recv_echo(recvbuff, plen);
      recvbuff+=plen;
      recvbytes-=plen;
    }

  }

  /* Schedule another read event for the next echo packet */
  nsock_readbytes(this->nsp, this->nsi, recv_std_header_handler, NSOCK_INFINITE, NULL, STD_NEP_HEADER_LEN);

  return OP_SUCCESS;
} /* End of nep_recv_std_header_handler() */


/** Handles reception of NEP_HANDSHAKE_SERVER message. It handles the received
  * data provided by nsock and passes it to the parse_hs_server() which is the
  * one in charge of validating NEP_HANDSHAKE_SERVER packets and updating
  * the internal context accordingly. Returns OP_SUCCESS on success and
  * OP_FAILURE in case of error. */
int EchoClient::nep_recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  u8 *inbuff=NULL;
  int inlen=0;
  /* Ask nsock to provide received data */
  if( (inbuff=(u8 *)nse_readbuf(nse, &inlen))==NULL )
    return OP_FAILURE;
  /* Process the NEP_HANDSHAKE_SERVER message */
  if ( this->parse_hs_server(inbuff, (size_t)inlen)!=OP_SUCCESS ){
    return OP_FAILURE;
  }
  return OP_SUCCESS;
} /* End of nep_recv_hs_server_handler() */


/** Handles reception of NEP_HANDSHAKE_FINAL message. It handles the received
  * data provided by nsock and passes it to the parse_hs_final() which is the
  * one in charge of validating NEP_HANDSHAKE_FINAL packets and updating
  * the internal context accordingly. Returns OP_SUCCESS on success and
  * OP_FAILURE in case of error. */
int EchoClient::nep_recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  u8 *inbuff=NULL;
  int inlen=0;
  /* Ask nsock to provide received data */
  if( (inbuff=(u8 *)nse_readbuf(nse, &inlen))==NULL )
    return OP_FAILURE;
  /* Process the NEP_HANDSHAKE_SERVER message */
  if ( this->parse_hs_final(inbuff, (size_t)inlen)!=OP_SUCCESS ){
    return OP_FAILURE;
  }
  return OP_SUCCESS;
} /* End of nep_recv_hs_final_handler() */


/** Handles reception of NEP_READY message. It handles the received
  * data provided by nsock and passes it to the parse_readyl() which is the
  * one in charge of validating NEP_HANDSHAKE_FINAL packets and updating
  * the internal context accordingly. Returns OP_SUCCESS on success and
  * OP_FAILURE in case of error. */
int EchoClient::nep_recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  u8 *inbuff=NULL;
  int inlen=0;
  /* Ask nsock to provide received data */
  if( (inbuff=(u8 *)nse_readbuf(nse, &inlen))==NULL )
    return OP_FAILURE;
  /* Process the NEP_HANDSHAKE_SERVER message */
  if ( this->parse_ready(inbuff, (size_t)inlen)!=OP_SUCCESS ){
    return OP_FAILURE;
  }
  return OP_SUCCESS;
} /* End of nep_recv_ready_handler() */



/******************************************************************************/
/**** HANDLER WRAPPERS ********************************************************/
/******************************************************************************/

/** This handler is a wrapper for the EchoClient::nep_echoed_packet_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for things like signal() or the Nsock lib. */
void echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ec.nep_echoed_packet_handler(nsp, nse, arg);
  return;
} /* End of echoed_packet_handler() */


/** This handler is a wrapper for the EchoClient::nep_recv_std_header_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for things like signal() or the Nsock lib. */
void recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ec.nep_recv_std_header_handler(nsp, nse, arg);
  return;
} /* End of recv_std_header_handler() */


/** Simple wrapper for TCP connection establishment. In this case we don't need
  * to do anything special, just detect it the connection was successful. If
  * it was, we call nsock_loop_quit(), which indicates the success to
  * the method that scheduled the event and called nsock_loop() */
void connect_done_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_4, "%s(): Failed to connect.", __func__);
  }else{
    nsock_loop_quit(nsp);
  }
  return;
} /* End of connect_done_handler() */


/** Really simple wrapper for write calls where we don't need to perform any
  * special operations. It just checks if the write even was successful and
  * in that case it calls nsock_loop_quit(), which indicates the success to
  * the method that scheduled the event and called nsock_loop() */
void write_done_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_4, "%s(): Write operation failed.", __func__);
  }else{
    nsock_loop_quit(nsp);
  }
  return;
} /* End of connect_done_handler() */


/** This handler is a wrapper for the EchoClient::recv_hs_server_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for things like signal() or the Nsock lib. */
void recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_4, "%s(): Read operation failed.", __func__);
  }else if(ec.nep_recv_hs_server_handler(nsp, nse, arg)==OP_SUCCESS){
    nsock_loop_quit(nsp);
  }
  return;
} /* End of recv_hs_server_handler() */


/** This handler is a wrapper for the EchoClient::recv_hs_final_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for things like signal() or the Nsock lib. */
void recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_4, "%s(): Read operation failed.", __func__);
  }else if(ec.nep_recv_hs_final_handler(nsp, nse, arg)==OP_SUCCESS){
    nsock_loop_quit(nsp);
  }
  return;
} /* End of recv_hs_server_handler() */



/** This handler is a wrapper for the EchoClient::nep_recv_ready_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for things like signal() or the Nsock lib. */
void recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_4, "%s(): Read operation failed.", __func__);
  }else if(ec.nep_recv_ready_handler(nsp, nse, arg)==OP_SUCCESS){
    nsock_loop_quit(nsp);
  }
  return;
} /* End of recv_hs_server_handler() */

