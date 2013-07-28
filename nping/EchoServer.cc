
/***************************************************************************
 * EchoServer.cc --                                                        *
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
#include "EchoServer.h"
#include "EchoHeader.h"
#include "NEPContext.h"
#include <vector>
#include "nsock.h"
#include "output.h"
#include "NpingOps.h"
#include "ProbeMode.h"
#include <signal.h>

extern NpingOps o;
extern EchoServer es;
  
EchoServer::EchoServer() {
  this->reset();
} /* End of EchoServer constructor */


EchoServer::~EchoServer() {
} /* End of EchoServer destructor */


/** Sets every attribute to its default value- */
void EchoServer::reset() {
  this->client_ctx.clear();
  this->client_id_count=-1;
} /* End of reset() */


/** Adds a new client context object to the server context list */
int EchoServer::addClientContext(NEPContext ctx){
  nping_print(DBG_4, "%s(ctx->id=%d)", __func__, ctx.getIdentifier());
  this->client_ctx.push_back(ctx);
  return OP_SUCCESS;
} /* End of addClientContext() */


/** Looks up the context of a given client, based on the supplied client ID.
  * On success, it returns a pointer to the client's context object. NULL is
  * returned when no context could be found.  */
NEPContext *EchoServer::getClientContext(clientid_t clnt){
  nping_print(DBG_4, "%s(%d) %lu", __func__, clnt, (unsigned long)this->client_ctx.size());
  for(unsigned int i=0; i<this->client_ctx.size(); i++){
    if(this->client_ctx[i].getIdentifier() == clnt ){
        nping_print(DBG_3, "Found client with ID #%d at p%d. Total clients %lu", clnt, i, (unsigned long)this->client_ctx.size());
        return &(this->client_ctx[i]);
    }
  }
  nping_print(DBG_3, "No client with ID #%d was found. Total clients %lu", clnt, (unsigned long)this->client_ctx.size());
  return NULL;
} /* End of getClientContext() */


/** Looks up the context of a given client, based on the supplied nsock IOD.
  * On success, it returns a pointer to the client's context object. NULL is
  * returned when no context could be found.  */
NEPContext *EchoServer::getClientContext(nsock_iod iod){
  nping_print(DBG_4, "%s()", __func__);
  clientid_t *id=NULL;
  if( (id=(clientid_t *)nsi_getud(iod))==NULL )
    return NULL;
  else
    return this->getClientContext(*id);
} /* End of getClientContext() */


/** Deletes context information associated with a given client. Returns
  * OP_SUCCESS if the context object was successfully deleted or OP_FAILURE if
  * the context could not be found.  */
int EchoServer::destroyClientContext(clientid_t clnt){
  bool deleted=false;
  vector<NEPContext>::iterator it;
  /* Iterate through the context array and delete the one that belongs to clnt */
  for ( it=this->client_ctx.begin(); it<this->client_ctx.end(); it++){
      if(it->getIdentifier()==clnt){
        this->client_ctx.erase(it);
        deleted=true;
        break;
      }
  }
  return (deleted) ? OP_SUCCESS : OP_FAILURE;
} /* End of destroyClientContext() */


/** Returns the Nsock IOD associated with a given client ID. */
nsock_iod EchoServer::getClientNsockIOD(clientid_t clnt){
  nping_print(DBG_4, "%s(%d)", __func__, clnt);
  NEPContext *ctx;
  if((ctx=this->getClientContext(clnt))==NULL )
    return NULL;
  else
    return ctx->getNsockIOD();
} /* End of getClientNsockIOD() */


/** Generates a new client identifier. This is used internally by the echo
  * server, but this value is never sent over the wire (it has nothing to do
  * with the NEP protocol). Each call to getNewClientID() generates a new
  * identifier, so it should only be called once per client session.
  * Warning: This code checks for an overflow and wraps the client id count back
  * to zero if necessary. A given execution of a server should be able to handle
  * 4,294,967,296 client sessions. Practically there is no way to achieve that
  * number (it would be something like receiving one client session per second
  * for 136 years, so relax!) However, it should be noted that this
  * implementation makes no effort to handle re-used client identifiers, so
  * there is a tiny chance that after the 4,294,967,296th client, the assigned
  * number conflicts with an active session ;-) */
clientid_t EchoServer::getNewClientID(){
  nping_print(DBG_4, "%s()", __func__);
  if(this->client_id_count==0xFFFF)  /* Wrap back to zero. */
      this->client_id_count=0;
  else
    this->client_id_count++;
  return this->client_id_count;
} /* End of getNewClientID() */


/** Returns a socket suitable to be passed to accept() */
int EchoServer::nep_listen_socket(){
  nping_print(DBG_4, "%s()", __func__);
  int one=1;                 /**< Dummy var for setsockopt() call      */
  int master_sd=-1;          /**< Master socket. Server listens on it  */
  struct sockaddr_in server_addr4;  /**< For our own IPv4 address      */
  struct sockaddr_in6 server_addr6; /**< For our own IPv6 address      */
  int port = o.getEchoPort();

  /* Ignore SIGPIPE signal, received when a client disconnects suddenly and
   *data is sent to it before noticing. */
  #ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
  #endif

  /* AF_INET6 */
  if( o.ipv6() ){

    /* Obtain a regular TCP socket for IPv6 */
    if( (master_sd=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP))<0 )
        nping_fatal(QT_3, "Could not obtain AF_INET/SOCK_STREAM/IPPROTO_TCP socket");

    /* Set SO_REUSEADDR on socket so the bind does not fail if we had used
     * this port in a previous execution, not long ago. */
    if( setsockopt(master_sd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int))!=0 )
        nping_warning(QT_3, "Failed to set SO_REUSEADDR on master socket.");
      
    memset(&server_addr6, 0, sizeof(struct sockaddr_in6));
    server_addr6.sin6_addr = (o.spoofSource()) ? o.getIPv6SourceAddress() : in6addr_any;
    server_addr6.sin6_family = AF_INET6;
    server_addr6.sin6_port = htons(port);
    server_addr6.sin6_flowinfo = 0;
    #ifdef HAVE_SOCKADDR_IN6_SIN6_LEN
        server_addr6.sin6_len = sizeof(struct sockaddr_in6);
    #endif
    /* Bind to local address and the specified port */
    if( bind(master_sd, (struct sockaddr *)&server_addr6, sizeof(server_addr6)) != 0 ){
        nping_warning(QT_3, "Failed to bind to source address %s. Trying to bind to port %d...", IPtoa(server_addr6.sin6_addr), port);
        /* If the bind failed for the supplied address, just try again with in6addr_any */
        if( o.spoofSource() ){
            server_addr6.sin6_addr = in6addr_any;
            if( bind(master_sd, (struct sockaddr *)&server_addr6, sizeof(server_addr6)) != 0 ){
                nping_fatal(QT_3, "Could not bind to port %d (%s).", port, strerror(errno));
            }else{ 
                nping_print(VB_1, "Server bound to port %d", port);
            }
        }
    }else{
        nping_print(VB_1, "Server bound to %s:%d", IPtoa(server_addr6.sin6_addr), port);
    }


  /* AF_INET */
  }else{

    /* Obtain a regular TCP socket for IPv4 */
    if( (master_sd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0 )
        nping_fatal(QT_3, "Could not obtain AF_INET/SOCK_STREAM/IPPROTO_TCP socket");
        
    /* Set SO_REUSEADDR on socket so the bind does not fail if we had used
     * this port in a previous execution, not long ago. */
    if( setsockopt(master_sd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int))!=0 )
        nping_warning(QT_3, "Failed to set SO_REUSEADDR on master socket.");


    memset(&server_addr4, 0, sizeof(struct sockaddr_in));
    server_addr4.sin_family = AF_INET;
    server_addr4.sin_port = htons(port);
    server_addr4.sin_addr.s_addr = (o.spoofSource()) ? o.getIPv4SourceAddress().s_addr : INADDR_ANY;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
    server_addr4.sin_len = sizeof(struct sockaddr_in);
#endif
    
    /* Bind to local address and the specified port */
    if( bind(master_sd, (struct sockaddr *)&server_addr4, sizeof(server_addr4)) != 0 ){
        nping_warning(QT_3, "Failed to bind to source address %s. Trying to bind to port %d...", IPtoa(server_addr4.sin_addr), port);
        /* If the bind failed for the supplied address, just try again with in6addr_any */
        if( o.spoofSource() ){
            server_addr4.sin_addr.s_addr=INADDR_ANY;
            if( bind(master_sd, (struct sockaddr *)&server_addr4, sizeof(server_addr4)) != 0 ){
                nping_fatal(QT_3, "Could not bind to port %d (%s).", port, strerror(errno));
            }else{
                nping_print(VB_1, "Server bound to port %d", port);
            }
        }
    }else{
        nping_print(VB_1, "Server bound to %s:%d", IPtoa(server_addr4.sin_addr), port);
    }

  }

   /* Listen for incoming TCP connections... */
   if( listen(master_sd, LISTEN_QUEUE_SIZE) != 0 ){
       nping_fatal(QT_3, "[E] Failed to listen() on port %d (%s)", port, strerror(errno));
   }
  return master_sd;
} /* End of nep_listen() */



/* Weighting factors */
#define FACTOR_IPv4_TOS       1.0
#define FACTOR_IPv4_PROTO     0.9
#define FACTOR_IPv4_ID        2.5
#define FACTOR_IPv4_FRAGOFF   1.0
#define FACTOR_IPv6_TCLASS    1.0
#define FACTOR_IPv6_FLOW      2.5
#define FACTOR_IPv6_NHDR      0.9
#define FACTOR_TCP_SPORT      1.5
#define FACTOR_TCP_DPORT      1.0
#define FACTOR_TCP_SEQ        2.0
#define FACTOR_TCP_ACK        1.0
#define FACTOR_TCP_FLAGS      1.0
#define FACTOR_TCP_WIN        1.0
#define FACTOR_TCP_URP        1.0
#define FACTOR_ICMP_TYPE      1.0
#define FACTOR_ICMP_CODE      1.0
#define FACTOR_UDP_SPORT      1.0
#define FACTOR_UDP_DPORT      1.0
#define FACTOR_UDP_LEN        1.0
#define FACTOR_PAYLOAD_MAGIC  1.0

#define ZERO_PENALTY    0.3

#define MIN_ACCEPTABLE_SCORE_TCP  10.0
#define MIN_ACCEPTABLE_SCORE_UDP  8.0
#define MIN_ACCEPTABLE_SCORE_ICMP 6.0

clientid_t EchoServer::nep_match_headers(IPv4Header *ip4, IPv6Header *ip6, TCPHeader *tcp, UDPHeader *udp, ICMPv4Header *icmp4, RawData *payload){
  nping_print(DBG_4, "%s(%p,%p,%p,%p,%p,%p)", __func__, ip4, ip6, tcp, udp, icmp4, payload);
    unsigned int i=0, k=0;
    u8 *buff=NULL;
    int bufflen=-1;
    NEPContext *ctx;
    fspec_t *fspec;
    float current_score=0;
    float candidate_score=-1;
    float minimum_score=0;
    clientid_t candidate=-1;

    /* Iterate through the list of connected clients */
    for(i=0; i<this->client_ctx.size(); i++ ){
        current_score=0;
        ctx=&(this->client_ctx[i]);
        nping_print(DBG_2, "%s() Trying to match packet against client #%d", __func__, ctx->getIdentifier());
        if( ctx->ready() ){
            /* Iterate through client's list of packet field specifiers */
            for(k=0; (fspec=ctx->getClientFieldSpec(k))!=NULL; k++){
                switch(fspec->field){
                    case PSPEC_IPv4_TOS:
                        if(ip4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IP TOS", __func__);
                        if( ip4->getTOS()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] IP TOS=%02x", ip4->getTOS());
                            current_score += 1 * FACTOR_IPv4_TOS * ((ip4->getTOS()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_IPv4_PROTO:
                        if(ip4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IP Next Protocol", __func__);
                        if( ip4->getNextProto()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] IP Proto=%02x", ip4->getNextProto());
                            current_score += 1 * FACTOR_IPv4_PROTO;
                        }
                    break;
                    case PSPEC_IPv4_ID:
                        if(ip4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IP Identification", __func__);
                        if( ip4->getIdentification()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] IP Id=%u", ip4->getIdentification());
                            current_score += 2 * FACTOR_IPv4_ID;
                        }
                    break;
                    case PSPEC_IPv4_FRAGOFF:
                        if(ip4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IP Fragment offset", __func__);
                        if( ip4->getFragOffset()==ntohs( *((u16 *)fspec->value)) ){
                            nping_print(DBG_3, "[Match] IP FragOff=%u", ip4->getFragOffset() );
                            current_score += 2 * FACTOR_IPv4_FRAGOFF * ((ip4->getFragOffset()==0) ? ZERO_PENALTY : 1);
                        }
                    break;

                    case PSPEC_IPv6_TCLASS:
                        if(ip6==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IPv6 Traffic Class", __func__);
                        if( ip6->getTrafficClass()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] IPv6 TClass=%u", ip6->getTrafficClass() );
                            current_score += 1 * FACTOR_IPv6_TCLASS  * ((ip6->getTrafficClass()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_IPv6_FLOW:
                        if(ip6==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IPv6 Flow Label", __func__);
                        if( ip6->getFlowLabel()==ntohl( *((u32 *)fspec->value)) ){
                            nping_print(DBG_3, "[Match] IPv6 Flow=%lu", (long unsigned)ip6->getFlowLabel() );
                            current_score += 3 * FACTOR_IPv6_FLOW  * ((ip6->getFlowLabel()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_IPv6_NHDR:
                        if(ip6==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match IPv6 Next Header", __func__);
                        if( ip6->getNextHeader()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] IPv6 NextHdr=%02x", ip6->getNextHeader());
                            current_score += 1 * FACTOR_IPv6_NHDR;
                        }
                    break;
                    case PSPEC_TCP_SPORT:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Source Port", __func__);
                        if( tcp->getSourcePort()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Src=%u", tcp->getSourcePort());
                            current_score += 2 * FACTOR_TCP_SPORT;
                        }
                    break;
                    case PSPEC_TCP_DPORT:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Destination Port", __func__);
                        if( tcp->getDestinationPort()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Dst=%u", tcp->getDestinationPort());
                            current_score += 2 * FACTOR_TCP_DPORT;
                        }
                    break;
                    case PSPEC_TCP_SEQ:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Sequence Number", __func__);
                        if( tcp->getSeq()==ntohl( *((u32 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Seq=%u", tcp->getSeq());
                            current_score += 4 * FACTOR_TCP_SEQ  * ((tcp->getSeq()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_TCP_ACK:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Acknowledgment", __func__);
                        if( tcp->getAck()==ntohl( *((u32 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Ack=%u", tcp->getAck());
                            current_score += 4 * FACTOR_TCP_ACK  * ((tcp->getAck()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_TCP_FLAGS:
                        if(tcp==NULL)break;
                        if( tcp->getFlags()==fspec->value[0] ){
                            nping_print(DBG_3, "%s() Trying to match TCP Flags", __func__);
                            nping_print(DBG_3, "[Match] TCP Flags=%02x", tcp->getFlags());
                            current_score += 1 * FACTOR_TCP_FLAGS;
                        }
                    break;
                    case PSPEC_TCP_WIN:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Window", __func__);
                        if( tcp->getWindow()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Win=%u", tcp->getWindow());
                            current_score += 2 * FACTOR_TCP_WIN  * ((tcp->getWindow()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_TCP_URP:
                        if(tcp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match TCP Urgent Pointer", __func__);
                        if( tcp->getUrgPointer()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] TCP Win=%u", tcp->getUrgPointer());
                            current_score += 2 * FACTOR_TCP_URP  * ((tcp->getUrgPointer()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_ICMP_TYPE:
                        if(icmp4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match ICMPv4 Type", __func__);
                        if( icmp4->getType()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] ICMPv4 Type=%02x", icmp4->getType());
                            current_score += 1 * FACTOR_ICMP_TYPE;
                        }
                    break;
                    case PSPEC_ICMP_CODE:
                        if(icmp4==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match ICMPv4 Code", __func__);
                        if( icmp4->getCode()==fspec->value[0] ){
                            nping_print(DBG_3, "[Match] ICMPv4 Code=%02x", icmp4->getCode());
                            current_score += 1 * FACTOR_ICMP_CODE  * ((icmp4->getCode()==0) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_UDP_SPORT:
                        if(udp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match UDP Source Port", __func__);
                        if( udp->getSourcePort()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] UDP Src=%u", udp->getSourcePort());
                            current_score += 2 * FACTOR_UDP_SPORT;
                        }
                    break;
                    case PSPEC_UDP_DPORT:
                        if(udp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match UDP Destination Port", __func__);
                        if( udp->getDestinationPort()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] UDP Dst=%u", udp->getDestinationPort());
                            current_score += 2 * FACTOR_UDP_DPORT;
                        }
                    break;
                    case PSPEC_UDP_LEN:
                        if(udp==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match UDP Length", __func__);
                        if( udp->getTotalLength()==ntohs( *((u16 *)fspec->value) ) ){
                            nping_print(DBG_3, "[Match] UDP Len=%u", udp->getTotalLength());
                            current_score += 2 * FACTOR_UDP_LEN * ((udp->getTotalLength()==8) ? ZERO_PENALTY : 1);
                        }
                    break;
                    case PSPEC_PAYLOAD_MAGIC:
                        if(payload==NULL)break;
                        nping_print(DBG_3, "%s() Trying to match Payload Magic value", __func__);
                        buff=payload->getBinaryBuffer(&bufflen);
                        if(buff==NULL || bufflen<=0 || fspec->len>bufflen)
                            break;
                        if( memcmp(buff, fspec->value, fspec->len)==0 ){
                            nping_print(DBG_3|NO_NEWLINE, "[Match] Payload magic=0x");
                            for(unsigned int i=0; i<fspec->len; i++)
                                nping_print(DBG_3|NO_NEWLINE,"%02x", fspec->value[i]);
                            nping_print(DBG_3, ";");
                            /* The payload magic may affect the score only between
                             * zero and 4 bytes. This is done to prevent long
                             * common strings like "GET / HTTP/1.1\r\n" 
                             * increasing the score a lot and cause problems for
                             * the matching logic. */
                            current_score+= MIN(4, fspec->len)*FACTOR_PAYLOAD_MAGIC;
                        }
                    break;

                    default:
                        nping_warning(QT_2, "Bogus field specifier found in client #%d context. Please report a bug", ctx->getIdentifier());
                    break;
                }           
            } /* End of field specifiers loop */

            nping_print(DBG_3, "%s() current_score=%.02f candidate_score=%.02f", __func__, current_score, candidate_score);
            if( (current_score>0) && (current_score>=candidate_score)){
                candidate_score=current_score;
                candidate=ctx->getIdentifier();
                nping_print(DBG_3, "%s() Found better candidate (client #%d; score=%.02f)", __func__, candidate, candidate_score);
            }
        }
    } /* End of connected clients loop */

    if( tcp!=NULL )
        minimum_score=MIN_ACCEPTABLE_SCORE_TCP;
    else if (udp!=NULL)
        minimum_score=MIN_ACCEPTABLE_SCORE_UDP;
    else if(icmp4!=NULL)
        minimum_score=MIN_ACCEPTABLE_SCORE_ICMP;
    else
        minimum_score=10000;
        
    /* Check if we managed to match packet and client */
    if (candidate>=0 && candidate_score>=minimum_score){
        nping_print(DBG_2, "%s() Packet matched successfully with client #%d", __func__, candidate);
        return candidate;
    }else{
        if(candidate<0)
            nping_print(DBG_2, "%s() Couldn't match packet with any client.", __func__);
        else
            nping_print(DBG_2, "%s() Found matching client but score is too low. Discarded.", __func__);
        return CLIENT_NOT_FOUND;
    }
    return CLIENT_NOT_FOUND;
} /* End of nep_match_ipv4() */


clientid_t EchoServer::nep_match_packet(const u8 *pkt, size_t pktlen){
  nping_print(DBG_4, "%s(%p, %lu)", __func__, pkt, (long unsigned)pktlen);
  int iplen=0, ip6len=0, tcplen=0, udplen=0;
  bool payload_included=false;
  IPv4Header ip4;
  IPv6Header ip6;
  TCPHeader tcp;
  UDPHeader udp;
  ICMPv4Header icmp4;
  RawData payload;

  if(this->client_id_count<0){
    nping_print(DBG_1, "Error trying to match the packet. No clients connected.");
    return CLIENT_NOT_FOUND;
  }else if(pktlen<IP_HEADER_LEN){
    nping_print(DBG_1, "Error trying to match the packet. Bogus packet received (too short)");
    return CLIENT_NOT_FOUND;
  }

  /* Determine IP version */
  if (ip4.storeRecvData(pkt, pktlen)==OP_FAILURE)
    return CLIENT_NOT_FOUND;

  if(ip4.getVersion()==0x04){

    nping_print(DBG_2, "Recv packet is IPv4. Trying to find a matching client.");
    if( (iplen=ip4.validate())==OP_FAILURE){
        return CLIENT_NOT_FOUND;
    }else{
        switch( ip4.getNextProto() ){
            case 1: // ICMP
                if( icmp4.storeRecvData(pkt+iplen, pktlen-iplen)==OP_FAILURE )
                    return CLIENT_NOT_FOUND;
                else
                    return this->nep_match_headers(&ip4, NULL, NULL, NULL, &icmp4, NULL);
            break;

            case 6: // TCP
                if( tcp.storeRecvData(pkt+iplen, pktlen-iplen)==OP_FAILURE ){
                    return CLIENT_NOT_FOUND;
                }else{
                    if( (tcplen=tcp.validate())==OP_FAILURE){
                        return CLIENT_NOT_FOUND;
                    }else{                        
                        if( (int)pktlen > (iplen+tcplen) ){
                           if( payload.storeRecvData(pkt+iplen+tcplen, pktlen-iplen-tcplen)!=OP_FAILURE)
                               payload_included=true;
                        }
                        if(payload_included)
                            return this->nep_match_headers(&ip4, NULL, &tcp, NULL, NULL, &payload);
                        else
                            return this->nep_match_headers(&ip4, NULL, &tcp, NULL, NULL, NULL);
                    }
                }
            break;

            case 17: // UDP
                if( udp.storeRecvData(pkt+iplen, pktlen-iplen)==OP_FAILURE ){
                    return CLIENT_NOT_FOUND;
                }else{
                    if( (udplen=udp.validate())==OP_FAILURE){
                        return CLIENT_NOT_FOUND;
                    }else{
                        if( (int)pktlen > (iplen+udplen) ){
                           if( payload.storeRecvData(pkt+iplen+udplen, pktlen-iplen-udplen)!=OP_FAILURE)
                               payload_included=true;
                        }
                        if(payload_included)
                            return this->nep_match_headers(&ip4, NULL, NULL, &udp, NULL, &payload);
                        else
                            return this->nep_match_headers(&ip4, NULL, NULL, &udp, NULL, NULL);
                    }
                }
            break;

            case 41: /* IPv6 encapsulated in the IPv4 datagram! */
                if( ip6.storeRecvData(pkt+iplen, pktlen-iplen)==OP_FAILURE ){
                    return CLIENT_NOT_FOUND;
                }else{
                    if( (ip6len=ip6.validate())==OP_FAILURE){
                        return CLIENT_NOT_FOUND;
                    }else{
                        switch( ip6.getNextHeader() ){
                            case 58: // ICMPv6
                                nping_print(DBG_4, "Encapsulated IPv4{ IPv6{ ICMPv6 } } received. Not supported.");
                                return CLIENT_NOT_FOUND;
                            break;

                            case 6: // TCP
                                if( tcp.storeRecvData(pkt+ip6len+iplen, pktlen-ip6len-iplen)==OP_FAILURE ){
                                    return CLIENT_NOT_FOUND;
                                }else{
                                    if( (tcplen=tcp.validate())==OP_FAILURE){
                                        return CLIENT_NOT_FOUND;
                                    }else{
                                        if( (int)pktlen > (ip6len+iplen+tcplen) ){
                                           if( payload.storeRecvData(pkt+ip6len+iplen+tcplen, pktlen-ip6len-iplen-tcplen)!=OP_FAILURE)
                                               payload_included=true;
                                        }
                                        if(payload_included)
                                            return this->nep_match_headers(&ip4, &ip6, &tcp, NULL, NULL, &payload);
                                        else
                                            return this->nep_match_headers(&ip4, &ip6, &tcp, NULL, NULL, NULL);
                                    }
                                }
                            break;

                            case 17: // UDP
                                if( udp.storeRecvData(pkt+ip6len+iplen, pktlen-ip6len-iplen)==OP_FAILURE ){
                                    return CLIENT_NOT_FOUND;
                                }else{
                                    if( (udplen=udp.validate())==OP_FAILURE){
                                        return CLIENT_NOT_FOUND;
                                    }else{
                                        if( (int)pktlen > (ip6len+iplen+udplen) ){
                                           if( payload.storeRecvData(pkt+ip6len+iplen+udplen, pktlen-ip6len-iplen-udplen)!=OP_FAILURE)
                                               payload_included=true;
                                        }
                                        if(payload_included)
                                            return this->nep_match_headers(&ip4, &ip6, NULL, &udp, NULL, &payload);
                                        else
                                            return this->nep_match_headers(&ip4, &ip6, NULL, &udp, NULL, NULL);
                                    }
                                }
                            break;

                            default:
                                return CLIENT_NOT_FOUND;
                            break;
                        }
                    }
                }
            break;
            
            default:
                return CLIENT_NOT_FOUND;
            break;
        }
    }
  }else if(ip4.getVersion()==0x06){

    nping_print(DBG_2, "Recv packet is IPv6. Trying to find a matching client.");
    if (ip6.storeRecvData(pkt, pktlen)==OP_FAILURE)
        return CLIENT_NOT_FOUND;

    if( (ip6len=ip6.validate())==OP_FAILURE )
        return CLIENT_NOT_FOUND;

    switch( ip6.getNextHeader() ){
        case 58: // ICMPv6
            nping_print(DBG_4, "Received ICMPv6 packet. Not yet supported.");
            return CLIENT_NOT_FOUND;
        break;

        case 6: // TCP
            if( tcp.storeRecvData(pkt+ip6len, pktlen-ip6len)==OP_FAILURE ){
                return CLIENT_NOT_FOUND;
            }else{
                if( (tcplen=tcp.validate())==OP_FAILURE){
                    return CLIENT_NOT_FOUND;
                }else{
                    if( (int)pktlen > (ip6len+tcplen) ){
                       if( payload.storeRecvData(pkt+ip6len+tcplen, pktlen-ip6len-tcplen)!=OP_FAILURE)
                           payload_included=true;
                    }
                    if(payload_included)
                        return this->nep_match_headers(NULL, &ip6, &tcp, NULL, NULL, &payload);
                    else
                        return this->nep_match_headers(NULL, &ip6, &tcp, NULL, NULL, NULL);
                }
            }
        break;

        case 17: // UDP
            if( udp.storeRecvData(pkt+ip6len, pktlen-ip6len)==OP_FAILURE ){
                return CLIENT_NOT_FOUND;
            }else{
                if( (udplen=udp.validate())==OP_FAILURE){
                    return CLIENT_NOT_FOUND;
                }else{
                    if( (int)pktlen > (ip6len+udplen) ){
                       if( payload.storeRecvData(pkt+ip6len+udplen, pktlen-ip6len-udplen)!=OP_FAILURE)
                           payload_included=true;
                    }
                    if(payload_included)
                        return this->nep_match_headers(NULL, &ip6, NULL, &udp, NULL, &payload);
                    else
                        return this->nep_match_headers(NULL, &ip6, NULL, &udp, NULL, NULL);
                }
            }
        break;

        case 4: /* IPv4 encapsulated in the IPv6 datagram */
            if( ip4.storeRecvData(pkt+ip6len, pktlen-ip6len)==OP_FAILURE ){
                return CLIENT_NOT_FOUND;
            }else{
                if( (iplen=ip4.validate())==OP_FAILURE){
                    return CLIENT_NOT_FOUND;
                }else{
                    switch( ip4.getNextProto() ){
                        case 1: // ICMP
                            if( icmp4.storeRecvData(pkt+ip6len+iplen, pktlen-ip6len-iplen)==OP_FAILURE )
                                return CLIENT_NOT_FOUND;
                            else
                                return this->nep_match_headers(&ip4, &ip6, NULL, NULL, &icmp4, NULL);
                        break;

                        case 6: // TCP
                            if( tcp.storeRecvData(pkt+ip6len+iplen, pktlen-ip6len-iplen)==OP_FAILURE ){
                                return CLIENT_NOT_FOUND;
                            }else{
                                if( (tcplen=tcp.validate())==OP_FAILURE){
                                    return CLIENT_NOT_FOUND;
                                }else{
                                    if( (int)pktlen > (ip6len+iplen+tcplen) ){
                                       if( payload.storeRecvData(pkt+ip6len+iplen+tcplen, pktlen-ip6len-iplen-tcplen)!=OP_FAILURE)
                                           payload_included=true;
                                    }
                                    if(payload_included)
                                        return this->nep_match_headers(&ip4, &ip6, &tcp, NULL, NULL, &payload);
                                    else
                                        return this->nep_match_headers(&ip4, &ip6, &tcp, NULL, NULL, NULL);
                                }
                            }
                        break;

                        case 17: // UDP
                            if( udp.storeRecvData(pkt+ip6len+iplen, pktlen-ip6len-iplen)==OP_FAILURE ){
                                return CLIENT_NOT_FOUND;
                            }else{
                                if( (udplen=udp.validate())==OP_FAILURE){
                                    return CLIENT_NOT_FOUND;
                                }else{
                                    if( (int)pktlen > (ip6len+iplen+udplen) ){
                                       if( payload.storeRecvData(pkt+ip6len+iplen+udplen, pktlen-ip6len-iplen-udplen)!=OP_FAILURE)
                                           payload_included=true;
                                    }
                                    if(payload_included)
                                        return this->nep_match_headers(&ip4, &ip6, NULL, &udp, NULL, &payload);
                                    else
                                        return this->nep_match_headers(&ip4, &ip6, NULL, &udp, NULL, NULL);
                                }
                            }
                        break;

                        default:
                            return CLIENT_NOT_FOUND;
                        break;
                    }
                }
            }
        break;

        default:
            return CLIENT_NOT_FOUND;
        break;
    }
  }else{
    nping_print(DBG_2, "Received packet is not IP: Discarded.");
    return CLIENT_NOT_FOUND;
  }
  return CLIENT_NOT_FOUND;
} /* End of nep_match_packet() */


int EchoServer::nep_capture_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  clientid_t clnt=CLIENT_NOT_FOUND;
  const unsigned char *packet=NULL;
  const unsigned char *link=NULL;
  nsock_iod nsi = nse_iod(nse);
  struct timeval pcaptime;
  nsock_iod clnt_iod=NULL;
  NEPContext *ctx=NULL;
  EchoHeader pkt_out;
  size_t linklen=0;
  size_t packetlen=0;
  handler_arg_t arg;
  arg.me=this;
  arg.param=NULL;

  /* If there are connected clients, schedule another packet capture event */
  if(this->client_ctx.size()>0){
    nsock_pcap_read_packet(nsp, nsi, capture_handler, NSOCK_INFINITE, &arg);
    nping_print(DBG_3, "Scheduled next capture event");
  }

  /* Get the actual captured packet */
  nse_readpcap(nse, &link, &linklen, &packet, &packetlen, NULL, &pcaptime);
  nping_print(DBG_3, "Captured %lu bytes", (unsigned long)packetlen);

  /* Update Rx stats */
  o.stats.addRecvPacket(packetlen);

  /* Try to match received packet with a connected client. */
  if( (clnt=this->nep_match_packet(packet, packetlen)) == CLIENT_NOT_FOUND ){
    nping_print(DBG_3, "Couldn't match captured packet with a client");
    return OP_FAILURE;
  }else{
    nping_print(DBG_4, "Captured packet belongs to client #%d", clnt);
  }

  /* Fetch client context */
  if( (ctx=this->getClientContext(clnt)) == NULL ){
    nping_print(DBG_2, "Error: no context found for client #%d", clnt);
    return OP_FAILURE;
  }

  /* Lookup client's IOD */
  if( (clnt_iod=ctx->getNsockIOD()) == NULL ){
    nping_print(DBG_2, "Error: no IOD found for client #%d", clnt);
    return OP_FAILURE;
  }

  if( ctx->ready() ){
      this->generate_echo(&pkt_out, packet, packetlen, ctx);
      nsock_write(nsp, clnt_iod, echo_handler, NSOCK_INFINITE, NULL, (const char *)pkt_out.getBinaryBuffer(), pkt_out.getLen());
      o.stats.addEchoedPacket(packetlen);
  }
  return OP_SUCCESS;
} /* End of nep_capture_handler() */


int EchoServer::nep_echo_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
      nping_print(DBG_1, "Couldn't send NEP_ECHO. Terminating client session\n");
      this->nep_session_ended_handler(nsp, nse, param);
  }else{
    nping_print(DBG_1, "SENT: NEP_ECHO");
  }
  return OP_SUCCESS;
} /* End of nep_echo_handler() */


int EchoServer::nep_hs_server_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  NEPContext *ctx=NULL;
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
      nping_print(DBG_1, "Couldn't send NEP_HANDSHAKE_SERVER. Terminating client session\n");
      this->nep_session_ended_handler(nsp, nse, param);
      return OP_FAILURE;
  }
  /* Lookup client context and schedule a read operation to receive a
   * NEP_HANDSHAKE_CLIENT message */
  if( (ctx=this->getClientContext(nsi))!=NULL ){
      ctx->setState(STATE_HS_SERVER_SENT);
      nping_print(DBG_1, "SENT: NEP_HANDSHAKE_SERVER to %s", IPtoa(ctx->getAddress()));
      nsock_readbytes(nsp, nsi, hs_client_handler, NSOCK_INFINITE, NULL, NEP_HANDSHAKE_CLIENT_LEN);
  }
  return OP_SUCCESS;
} /* End of nep_hs_server_handler() */


int EchoServer::nep_hs_client_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  NEPContext *ctx=NULL;
  EchoHeader pkt_out;
  u8 *inbuff=NULL;
  int inlen=0;
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_1, "Failed to receive NEP_HANDSHAKE_CLIENT. Terminating client session");
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }else{
    nping_print(DBG_1, "RCVD: NEP_HANDSHAKE_CLIENT");
  }

  /* Lookup client context */
  if( (ctx=this->getClientContext(nsi))==NULL ){
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }

  /* Ask nsock to provide received data */
  if( (inbuff=(u8 *)nse_readbuf(nse, &inlen))==NULL ){
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }

  /* Validate received NEP_HANDSHAKE_CLIENT */
  if( this->parse_hs_client(inbuff, inlen, ctx)!=OP_SUCCESS ){
      this->nep_session_ended_handler(nsp, nse, param);
      return OP_FAILURE;
  }
  ctx->setState(STATE_HS_FINAL_SENT);

  /* Craft a NEP_HANDSHAKE_FINAL message and send it to the client */
  if( this->generate_hs_final(&pkt_out, ctx)!=OP_SUCCESS ){
      this->nep_session_ended_handler(nsp, nse, param);
      return OP_FAILURE;
  }
  nsock_write(nsp, nsi, hs_final_handler, NSOCK_INFINITE, NULL, (const char *)pkt_out.getBinaryBuffer(), pkt_out.getLen());
  return OP_SUCCESS;
} /* End of nep_hs_client_handler() */


int EchoServer::nep_hs_final_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  nping_print(DBG_1, "SENT: NEP_HANDSHAKE_FINAL");
  /* Receive NEP_PACKETSPEC */
  nsock_readbytes(nsp, nsi, packetspec_handler, NSOCK_INFINITE, NULL, NEP_PACKETSPEC_LEN);
  return OP_SUCCESS;
} /* End of nep_hs_final_handler() */


int EchoServer::nep_packetspec_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  EchoHeader pkt_in;
  EchoHeader pkt_out;
  NEPContext *ctx=NULL;
  u8 *recvbuff=NULL;
  int recvbytes=0;
  enum nse_status status=nse_status(nse);
  if (status!=NSE_STATUS_SUCCESS){
    nping_print(DBG_1, "Failed to receive NEP_PACKET_SPEC message. Terminating client session\n");
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }else{
    nping_print(DBG_1, "RCVD: NEP_PACKETSPEC");
  }

  /* Lookup client context */
  if( (ctx=this->getClientContext(nsi))==NULL ){
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }

  /* Ask nsock to provide received data */
  if( (recvbuff=(u8 *)nse_readbuf(nse, &recvbytes))==NULL ){
    this->nep_session_ended_handler(nsp, nse, param);
    return OP_FAILURE;
  }

  /* Validate received NEP_PACKET_SPEC message */
  if( this->parse_packet_spec(recvbuff, recvbytes, ctx)!=OP_SUCCESS ){
      this->nep_session_ended_handler(nsp, nse, param);
      nping_print(VB_1, "[%lu] Couldn't establish NEP session with client #%d (%s:%d).", (unsigned long)time(NULL), ctx->getIdentifier(), IPtoa(ctx->getAddress()), sockaddr2port(ctx->getAddress()));
      return OP_FAILURE;
  }
  ctx->setState(STATE_READY_SENT);
  nping_print(VB_1, "[%lu] NEP handshake with client #%d (%s:%d) was performed successfully", (unsigned long)time(NULL), ctx->getIdentifier(), IPtoa(ctx->getAddress()), sockaddr2port(ctx->getAddress()));

  /* Craft response and send it */
  this->generate_ready(&pkt_out, ctx);
  nsock_write(nsp, nsi, ready_handler, NSOCK_INFINITE, NULL, (const char *)pkt_out.getBinaryBuffer(), pkt_out.getLen());

  /* From this point, the client is not supposed to send anything to the server
   * through the side channel. However, we now schedule a read operation so
   * we detect when the client disconnects (because Nsock will tell us). */
  nsock_readbytes(nsp, nsi, session_ended_handler, NSOCK_INFINITE, NULL, 65535);

  /* At this point, we consider the NEP session fully established and therefore
   * we update the count of served clients */
  o.stats.addEchoClientServed();
  
  return OP_SUCCESS;
} /* End of nep_packetspec_handler() */


int EchoServer::nep_ready_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nping_print(DBG_1, "SENT: NEP_READY");
  return OP_SUCCESS;
} /* End of nep_ready_handler() */


int EchoServer::nep_session_ended_handler(nsock_pool nsp, nsock_event nse, void *param){
  nping_print(DBG_4, "%s()", __func__);
  nsock_iod nsi = nse_iod(nse);
  clientid_t clnt;
  NEPContext *ctx=NULL;

  /* Lookup client context */
  if( (ctx=this->getClientContext(nsi))!=NULL ){
    nping_print(VB_0, "[%lu] Client #%d (%s:%d) disconnected", (unsigned long)time(NULL), ctx->getIdentifier(), IPtoa(ctx->getAddress()), sockaddr2port(ctx->getAddress()));
    clnt=ctx->getIdentifier();
    if(this->destroyClientContext(clnt)!=OP_SUCCESS)
        nping_print(DBG_2, "Client #%d disconnected but no context found. This may be a bug.", clnt);
    else
        nping_print(DBG_2, "Deleted client #%d context.", clnt);
  }
  nsi_delete(nsi, NSOCK_PENDING_SILENT);

  /* Exit the server if --once has been set */
  if(o.once()){
    o.displayStatistics();
    o.displayNpingDoneMsg();
    o.cleanup();
    exit(EXIT_SUCCESS);
  }
  return OP_SUCCESS;
} /* End of nep_session_ended_handler() */



/** Processes and validates a received NEP_HANDSHAKE_CLIENT message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoServer::parse_hs_client(u8 *pkt, size_t pktlen, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  u8 *next_iv=NULL;
  EchoHeader h;
  if(pkt==NULL || ctx==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen!=NEP_HANDSHAKE_CLIENT_LEN){
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
  if(h.getMessageType()!=TYPE_NEP_HANDSHAKE_CLIENT){
    nping_print(DBG_1, "Expected NEP_HANDSHAKE_CLIENT but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_HANDSHAKE_CLIENT timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

  /* Ensure message length is correct */
  if( h.getTotalLength()!=(NEP_HANDSHAKE_CLIENT_LEN/4)){
    nping_print(DBG_1, "Received NEP_HANDSHAKE_CLIENT specifies an incorrect length (%u)", h.getTotalLength()*4 );
    return OP_FAILURE;
  }

  /* Ensure the client echoed the nonce we sent in our NEP_HANDSHAKE_SERVER */
  if( memcmp(h.getServerNonce(), ctx->getServerNonce(), NONCE_LEN)!=0 ){
    nping_print(DBG_1, "Echoed nonce in NEP_HANDSHAKE_CLIENT message does not match client generate nonce");
    return OP_FAILURE;
  }
  /* Store the received nonce */
  ctx->setClientNonce(h.getClientNonce());

  /* Store client's sequence number */
  ctx->setLastClientSequence( h.getSequenceNumber() );

  /* Generate all session keys */
  ctx->generateCipherKeyC2S();
  ctx->generateCipherKeyS2C();
  ctx->generateMacKeyC2S();
  ctx->generateMacKeyS2C();

  nping_print(DBG_3,"Session Key MAC_C2S:"); print_hexdump(DBG_3,ctx->getMacKeyC2S(), MAC_KEY_LEN);
  nping_print(DBG_3,"Session Key MAC_S2C:"); print_hexdump(DBG_3,ctx->getMacKeyS2C(), MAC_KEY_LEN);
  nping_print(DBG_3,"Session Key CIPHER_C2S:"); print_hexdump(DBG_3,ctx->getCipherKeyC2S(), MAC_KEY_LEN);
  nping_print(DBG_3,"Session Key CIPHER_S2C:"); print_hexdump(DBG_3,ctx->getCipherKeyS2C(), MAC_KEY_LEN);
  

  /* Decrypt the encrypted part of the message before validating the MAC */
  if((next_iv=h.decrypt(ctx->getCipherKeyC2S(), CIPHER_KEY_LEN, ctx->getClientNonce(), TYPE_NEP_HANDSHAKE_CLIENT))==NULL){
      nping_print(DBG_1, "Failed to decrypt NEP_HANDSHAKE_CLIENT data." );
      return OP_FAILURE;
  }
  ctx->setNextDecryptionIV(next_iv);

  /* Check the authenticity of the received message */
  if( h.verifyMessageAuthenticationCode( ctx->getMacKeyC2S(), MAC_KEY_LEN)!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_HANDSHAKE_CLIENT authentication failed" );
      return OP_FAILURE;
  }

  return OP_SUCCESS;
} /* End of parse_hs_client() */


/** Processes and validates a received NEP_PACKET_SPEC message. On success
  * it returns OP_SUCCESS. OP_FAILURE is returned in case the received packet
  * is not valid. */
int EchoServer::parse_packet_spec(u8 *pkt, size_t pktlen, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  EchoHeader h;
  int recvspecs=0;
  bool id_received=false;
  u8 field=0;
  size_t len=0;
  u8 *next_iv=NULL;
  u8 specbuff[PACKETSPEC_FIELD_LEN];
  if(pkt==NULL){
    nping_print(DBG_1,"%s(): NULL parameter supplied.", __func__ );
    return OP_FAILURE;
  }
  if(pktlen!=NEP_PACKETSPEC_LEN){
    nping_print(DBG_1,"%s(): Unexpected length supplied.", __func__ );
    return OP_FAILURE;
  }
  h.storeRecvData(pkt, pktlen);

  /* Decrypt message */
  if((next_iv=h.decrypt(ctx->getCipherKeyC2S(), CIPHER_KEY_LEN, ctx->getNextDecryptionIV(), TYPE_NEP_PACKET_SPEC))==NULL){
      nping_print(DBG_1, "Failed to decrypt NEP_PACKET_SPEC data." );
      return OP_FAILURE;
  }
  ctx->setNextDecryptionIV(next_iv);

  /* Validate version number */
  if( h.getVersion() != ECHO_CURRENT_PROTO_VER ){
    nping_print(DBG_1, "Expected NEP version %02x but message used %02x", ECHO_CURRENT_PROTO_VER, h.getVersion() );
    return OP_FAILURE;
  }

  /* Ensure the expected message type was received */
  if(h.getMessageType()!=TYPE_NEP_PACKET_SPEC){
    nping_print(DBG_1, "Expected NEP_PACKET_SPEC but received %02X", h.getMessageType() );
    return OP_FAILURE;
  }

  /* Ensure the received timestamp falls into the allowed time window */
  //if( h.verifyTimestamp()!=OP_SUCCESS ){
  //    nping_print(DBG_1, "NEP_PACKET_SPEC timestamp is too old", h.getMessageType() );
  //    return OP_FAILURE;
  //}

  /* Ensure message length is correct */
  if( h.getTotalLength()!=(NEP_PACKETSPEC_LEN/4)){
    nping_print(DBG_1, "Received NEP_PACKET_SPEC specifies an incorrect length (%u)", h.getTotalLength()*4 );
    return OP_FAILURE;
  }

  /* Ensure the received sequence number is the previous+1 */
  if( h.getSequenceNumber()!=(ctx->getLastClientSequence()+1)){
    nping_print(DBG_1, "Expected sequence number %d but received %d", ctx->getLastClientSequence()+1, h.getSequenceNumber() );
    return OP_FAILURE;
  }else{
    /* Increment next expected sequence number*/
    ctx->getNextClientSequence();
  }

  /* Check the authenticity of the received message */
  if( h.verifyMessageAuthenticationCode( ctx->getMacKeyC2S(), MAC_KEY_LEN)!=OP_SUCCESS ){
      nping_print(DBG_1, "NEP_PACKET_SPEC authentication failed" );
      return OP_FAILURE;
  }

  /* Now that we have verified the authenticity of the message, let's process
   * the field specifiers */
  while(1){
    if( h.getNextFieldSpec(&field, specbuff, &len)==OP_FAILURE ){
          break;
    }else{

        /* Ensure the field spec is unique. Malicious users could try to supply
         * the same spec more than once in order to get higher packet scores. */
        if( ctx->isDuplicateFieldSpec(field) ){
          nping_print(DBG_1, "Detected duplicate field specs in NEP_PACKET_SPEC message" );
          return OP_FAILURE;
        }else{
            ctx->addClientFieldSpec(field, len, specbuff);
            recvspecs++;
        }
        /* Set a flag to indicate that mandatory IPv4 ID or IPv6 Flow has been
         * supplied by the client */
        if(h.getIPVersion()==0x04 && field==PSPEC_IPv4_ID)
          id_received=true;
        else if(h.getIPVersion()==0x06 && field==PSPEC_IPv6_FLOW)
          id_received=true;
        nping_print(DBG_3|NO_NEWLINE,"RCVD FieldSpec: Type=%02X Len=%02x Data=0x", field, (u8)len);
        for(unsigned int i=0; i<len; i++)
            nping_print(DBG_3|NO_NEWLINE,"%02x", specbuff[i]);
        nping_print(DBG_3, ";");
    }
  }
  /* Check client provided mandatory IP ID (or Flow) spec and at least one other spec */
  if(id_received && recvspecs>=4){
    nping_print(VB_2, "[%lu] Good packet specification received from client #%d (Specs=%d,IP=%d,Proto=%d,Cnt=%d)",
      (unsigned long)time(NULL), ctx->getIdentifier(), recvspecs, h.getIPVersion(), h.getProtocol(), h.getPacketCount()
            );
    return OP_SUCCESS;
  }else{
    return OP_FAILURE;
  }
} /* End of parse_packet_spec() */


/** Generates a NEP_HANDSHAKE_SERVER message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error.
  * @warning the caller must ensure that the supplied context object
  * already contains an initial sequence number and a server nonce. */
int EchoServer::generate_hs_server(EchoHeader *h, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  if(h==NULL || ctx==NULL)
    return OP_FAILURE;

  /* Craft NEP_HANDSHAKE_SERVER message */
  h->setMessageType(TYPE_NEP_HANDSHAKE_SERVER);
  h->setSequenceNumber( ctx->getLastServerSequence() );
  h->setTimestamp();
  h->setServerNonce( ctx->getServerNonce() );
  h->setTotalLength();
  h->setMessageAuthenticationCode( ctx->getMacKeyS2C(), MAC_KEY_LEN);
  return OP_SUCCESS;
} /* End of generate_hs_server() */


/** Generates a NEP_HANDSHAKE_FINAL message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error. */
int EchoServer::generate_hs_final(EchoHeader *h, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  struct sockaddr_storage ss;
  u8 *next_iv=NULL;
  if(h==NULL || ctx==NULL)
    return OP_FAILURE;

  /* Craft NEP_HANDSHAKE_CLIENT message */
  h->setMessageType(TYPE_NEP_HANDSHAKE_FINAL);
  h->setSequenceNumber(ctx->getNextServerSequence() );
  h->setTimestamp();
  h->setClientNonce( ctx->getClientNonce() );
  ss=ctx->getAddress();
  if(ss.ss_family==AF_INET6){
      struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ss;
      h->setPartnerAddress(s6->sin6_addr);
  }else{
      struct sockaddr_in *s4=(struct sockaddr_in *)&ss;
      h->setPartnerAddress(s4->sin_addr);
  }
  h->setTotalLength();
  h->setMessageAuthenticationCode( ctx->getMacKeyS2C(), MAC_KEY_LEN);

  /* Encrypt message */
  if( (next_iv=h->encrypt(ctx->getCipherKeyS2C(), CIPHER_KEY_LEN, ctx->getServerNonce()))==NULL )
      return OP_FAILURE;
  ctx->setNextEncryptionIV(next_iv);


  return OP_SUCCESS;
} /* End of generate_hs_final() */


/** Generates a NEP_READY message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error. */
int EchoServer::generate_ready(EchoHeader *h, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  u8 *next_iv=NULL;
  if(h==NULL || ctx==NULL)
    return OP_FAILURE;

  /* Craft NEP_READY message */
  h->setMessageType(TYPE_NEP_READY);
  h->setSequenceNumber( ctx->getNextServerSequence() );
  h->setTimestamp();
  h->setTotalLength();
  h->setMessageAuthenticationCode(ctx->getMacKeyS2C(), MAC_KEY_LEN);

  /* Encrypt message */
  if( (next_iv=h->encrypt(ctx->getCipherKeyS2C(), CIPHER_KEY_LEN, ctx->getNextEncryptionIV()))==NULL )
      return OP_FAILURE;
  ctx->setNextEncryptionIV(next_iv);
  
  return OP_SUCCESS;
} /* End of generate_ready() */


/** Generates a NEP_ECHO message. On success it returns OP_SUCCESS.
  * OP_FAILURE is returned in case of error. */
int EchoServer::generate_echo(EchoHeader *h, const u8 *pkt, size_t pktlen, NEPContext *ctx){
  nping_print(DBG_4, "%s()", __func__);
  u8 *next_iv=NULL;
  if(h==NULL || ctx==NULL || pkt==NULL || pktlen==0)
    return OP_FAILURE;

  /* Craft NEP_ECHO message */
  h->setMessageType(TYPE_NEP_ECHO);
  h->setSequenceNumber( ctx->getNextServerSequence() );
  h->setTimestamp();
  h->setDLT(DLT_NODATALINKHEADERINCLUDED);

  /* If allowed, echo the whole packet, including any application layer data */
  if( o.echoPayload() ){
      h->setEchoedPacket(pkt, pktlen);
  /* Otherwise, find if the packet contains application layer data and erase it */
  }else{
    /* Determine where the application data starts */
    int offset=PacketParser::payload_offset(pkt, pktlen, false);
    
    /* If the packet does not have application data, don't touch it */
    if(offset==0){
        nping_print(DBG_3, "No payload found. Echoing the whole packet\n");
        h->setEchoedPacket(pkt, pktlen);
    /* If we found application data, zero it */
    }else{
        nping_print(DBG_3, "Erasing %d payload bytes\n", (int)pktlen-offset);
        /* Allocate a new buffer, big enough to hold the packet */
        u8 *new_pkt=(u8 *)safe_zalloc(pktlen);
        /* Copy the initial header, and leave the rest as 0x00 bytes */
        if(offset>0 && offset<(int)pktlen){
            memcpy(new_pkt, pkt, offset);
        /* If there was some error trying to find application data, include a
         * default amount of data */
        }else{
            memcpy(new_pkt, pkt, MIN(pktlen, PAYLOAD_ECHO_BYTES_IN_DOUBT));
        }
        h->setEchoedPacket(new_pkt, pktlen);
        free(new_pkt);
    }
  }

  h->setTotalLength();
  h->setMessageAuthenticationCode(ctx->getMacKeyS2C(), MAC_KEY_LEN);

  if( (next_iv=h->encrypt(ctx->getCipherKeyS2C(), CIPHER_KEY_LEN, ctx->getNextEncryptionIV()))==NULL )
      return OP_FAILURE;
  ctx->setNextEncryptionIV(next_iv);

  return OP_SUCCESS;
} /* End of generate_echo() */


/** This is the server's main method. It sets up nsock and pcap, waits for
  * client connections and handles all the events of the client sessions. */
int EchoServer::start() {
  nping_print(DBG_4, "%s()", __func__);
  nsock_pool nsp;                  /**< Nsock pool                           */
  enum nsock_loopstatus loopret;   /**< Stores nsock_loop returned status    */
  nsock_iod client_nsi;            /**< Stores connected client IOD          */
  nsock_iod pcap_nsi;              /**< Stores Pcap IOD                      */
  char pcapdev[128];               /**< Device name passed to pcap_open_live */
  char *auxpnt=NULL;               /**< Aux str pointer                      */
  struct timeval now;              /**< For timestamps                       */
  struct sockaddr_storage ss;      /**< New client socket address            */
  socklen_t sslen=sizeof(ss);      /**< New client socket address len        */
  int listen_sd=-1;                /**< Socket descriptor for listening      */
  int client_sd=-1;                /**< Socket descriptor for new clients    */
  clientid_t *idpnt=NULL;          /**< For new client assigned identifiers  */
  NEPContext ctx;                  /**< Context for the new client           */
  EchoHeader h;

  /* Create a new nsock pool */
  if ((nsp = nsp_new(NULL)) == NULL)
    nping_fatal(QT_3, "Failed to create new pool.  QUITTING.\n");

  /* Set nsock trace level */
  gettimeofday(&now, NULL);
  if( o.getDebugging() == DBG_5 )
    nsock_set_loglevel(nsp, NSOCK_LOG_INFO);
  else if( o.getDebugging() > DBG_5 )
    nsock_set_loglevel(nsp, NSOCK_LOG_DBG_ALL);

  /* Create new IOD for pcap */
  if ((pcap_nsi = nsi_new(nsp, NULL)) == NULL)
    nping_fatal(QT_3, "Failed to create new nsock_iod.  QUITTING.\n");
        
  /* Open pcap */
  nping_print(DBG_2,"Opening pcap device %s", o.getDevice() );
  Strncpy(pcapdev, o.getDevice(), sizeof(pcapdev));
  if( (auxpnt=nsock_pcap_open(nsp, pcap_nsi, pcapdev, MAX_ECHOED_PACKET_LEN, 1, ProbeMode::getBPFFilterString() )) != NULL )
    nping_fatal(QT_3, "Error opening capture device %s --> %s\n", o.getDevice(), auxpnt);
  else
    nping_print(VB_0,"Packet capture will be performed using network interface %s.", o.getDevice());
  nping_print(VB_0,"Waiting for connections...");

  /* Get a socket suitable for an accept() call */
  listen_sd=this->nep_listen_socket();

  while(1){
    /* If --once is enabled, just allow the first client */
    if(o.once()==false || this->client_id_count==-1){
        /* Check if we have received a connection*/
        unblock_socket(listen_sd);
        if ((client_sd=accept(listen_sd, (struct sockaddr *)&ss, &sslen)) >= 0){
            nping_print(VB_0, "[%lu] Connection received from %s:%d", (unsigned long)time(NULL), IPtoa(&ss), sockaddr2port(&ss));
            /* Assign a new client identifier. The ID is bound to the IOD */
            if( (idpnt=(clientid_t *)calloc(1, sizeof(clientid_t)))==NULL ){
                nping_warning(QT_2, "Not enough memory for new clients.");
                return OP_FAILURE;
            }
            *idpnt=this->getNewClientID();
            if( (client_nsi=nsi_new2(nsp, client_sd, idpnt))==NULL ){
                nping_warning(QT_2, "Not enough memory for new clients.");
                return OP_FAILURE;
            }else{
                close(client_sd); /* nsi_new2() dups the socket */
            }

            /* Stop listening if --once is enabled */
            if(o.once()==true)
                close(listen_sd);

            /* Create a new client context object */
            ctx.setIdentifier(*idpnt);
            ctx.setAddress(ss);
            ctx.setNsockIOD(client_nsi);
            ctx.generateServerNonce();
            ctx.generateInitialServerSequence();
            ctx.generateMacKeyS2CInitial();
            nping_print(DBG_3,"Session Key MAC_S2C_INITIAL:"); print_hexdump(DBG_3,ctx.getMacKeyS2C(), MAC_KEY_LEN);

            /* Craft NEP_HANDSHAKE_SERVER message */
            if( this->generate_hs_server(&h, &ctx)!=OP_SUCCESS)
                return OP_FAILURE;
            else
                this->addClientContext(ctx);

            /* Schedule send operation */
            nsock_write(nsp, client_nsi, hs_server_handler, NSOCK_INFINITE, NULL, (const char *)h.getBufferPointer(), h.getLen() );

            /* For every client we schedule a packet capture event. */
            nsock_pcap_read_packet(nsp, pcap_nsi, capture_handler, NSOCK_INFINITE, NULL);

        }
        block_socket(listen_sd);
    }
    /* Sleep for a second until we check again for incoming connection requests */
    nsock_timer_create(nsp, empty_handler, 1000, NULL);
    loopret=nsock_loop(nsp, 1000);
    //If something went wrong in nsock_loop, let's just bail out.
    if (loopret == NSOCK_LOOP_ERROR) {
        nping_warning(QT_3, "Unexpected nsock_loop error.\n");
        return OP_FAILURE;
    }
  }
  return OP_SUCCESS;
} /* End of start() */


/** Performs cleanup functions */
int EchoServer::cleanup(){
  // For the moment there is nothing to cleanup
  return OP_SUCCESS;
} /* End of cleanup() */

/******************************************************************************/
/**** HANDLER WRAPPERS ********************************************************/
/******************************************************************************/

/* This handler is a wrapper for the EchoServer::nep_read_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void capture_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_capture_handler(nsp, nse, arg);
  return;
} /* End of capture_handler() */


/* This handler is a wrapper for the EchoServer::nep_echo_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void echo_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_echo_handler(nsp, nse, arg);
  return;
} /* End of echo_handler() */


/* This handler is a wrapper for the EchoServer::nep_hs_server_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_hs_server_handler(nsp, nse, arg);
  return;
} /* End of hs_server_handler() */


/* This handler is a wrapper for the EchoServer::nep_hs_client_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void hs_client_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_hs_client_handler(nsp, nse, arg);
  return;
} /* End of hs_client_handler() */


/* This handler is a wrapper for the EchoServer::nep_hs_final_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_hs_final_handler(nsp, nse, arg);
  return;
} /* End of hs_final_handler() */


/* This handler is a wrapper for the EchoServer::nep_packetspec_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void packetspec_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_packetspec_handler(nsp, nse, arg);
  return;
} /* End of packetspec_handler() */


/* This handler is a wrapper for the EchoServer::nep_ready_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void ready_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_ready_handler(nsp, nse, arg);
  return;
} /* End of ready_handler() */


/* This handler is a wrapper for the EchoServer::nep_ready_handler() method. We
 * need this because C++ does not allow to use class methods as callback
 * functions for things like signal() or the Nsock lib. */
void session_ended_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  es.nep_session_ended_handler(nsp, nse, arg);
  return;
} /* End of ready_handler() */


/* Void handler that does nothing */
void empty_handler(nsock_pool nsp, nsock_event nse, void *arg){
  return;
} /* End of capture_handler() */
