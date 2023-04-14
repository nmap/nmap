
/***************************************************************************
 * ProbeMode.cc -- Probe Mode is nping's default working mode. Basically,  *
 * it involves sending the packets that the user requested at regular      *
 * intervals and capturing responses from the wire.                        *
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

#include "nping.h"
#include "ProbeMode.h"
#include <vector>
#include "nsock.h"
#include "output.h"
#include "NpingOps.h"

#ifdef WIN32
/* Need DnetName2PcapName */
#include "libnetutil/netutil.h"
#endif

extern NpingOps o;


ProbeMode::ProbeMode() {
  this->reset();
} /* End of ProbeMode constructor */


ProbeMode::~ProbeMode() {
} /* End of ProbeMode destructor */


/** Sets every attribute to its default value- */
void ProbeMode::reset() {
  this->nsock_init=false;
} /* End of reset() */


/** Sets up the internal nsock pool and the nsock trace level */
int ProbeMode::init_nsock(){
  struct timeval now;
  if( nsock_init==false ){
      /* Create a new nsock pool */
      if ((nsp = nsock_pool_new(NULL)) == NULL)
        nping_fatal(QT_3, "Failed to create new pool.  QUITTING.\n");
      nsock_pool_set_device(nsp, o.getDevice());

      /* Allow broadcast addresses */
      nsock_pool_set_broadcast(nsp, 1);

      /* Set nsock trace level */
      gettimeofday(&now, NULL);
      if( o.getDebugging() == DBG_5)
        nsock_set_loglevel(NSOCK_LOG_INFO);
      else if( o.getDebugging() > DBG_5 )
        nsock_set_loglevel(NSOCK_LOG_DBG_ALL);
      /* Flag it as already initialized so we don't do it again */
      nsock_init=true;
  }
  return OP_SUCCESS;
} /* End of init() */


/** Cleans up the internal nsock pool and any other internal data that
  * needs to be taken care of before destroying the object. */
int ProbeMode::cleanup(){
  nsock_pool_delete(this->nsp);
  return OP_SUCCESS;
} /* End of cleanup() */


/** Returns the internal nsock pool.
  * @warning the caller must ensure that init_nsock() has been called before
  * calling this method; otherwise, it will fatal() */
nsock_pool ProbeMode::getNsockPool(){
  if( this->nsock_init==false)
    nping_fatal(QT_3, "getNsockPool() called before init_nsock(). Please report a bug.");
  return this->nsp;
} /* End of getNsockPool() */


/** This function handles regular ping mode. Basically it handles both
  * unprivileged modes (TCP_CONNECT and UDP_UNPRIV) and raw packet modes
  * (TCP, UDP, ICMP, ARP). This function is where the loops that iterate
  * over target hosts and target ports are located. It uses the nsock lib
  * to schedule transmissions. The actual Tx and Rx is done inside the nsock
  * event handlers, here we just schedule them, take care of the timers,
  * set up pcap and the bpf filter, etc. */
int ProbeMode::start(){
  int rc;
  int p=0, pc=-1;                  /**< Indexes for ports count              */
  u32 c=0;                         /**< Index for packet count               */
  u32 zero=0;                      /**< Empty payload                        */
  u8 pktinfobuffer[512+1];         /**< Used in ippackethdrinfo() calls      */
  u8 pkt[MAX_IP_PACKET_LEN];       /**< Holds packets returned by fillpacket */
  int pktLen=0;                    /**< Length of current packet             */
  NpingTarget *target=NULL;        /**< Current target                       */
  u16 *targetPorts=NULL;           /**< Pointer to array of target ports     */
  int numTargetPorts=0;            /**< Total number of target ports         */
  u16 currentPort=0;               /**< Current target port                  */
  char *filterstring;              /**< Stores BFP filter spec string        */
  int rawipsd=-1;                  /**< Descriptor for raw IP socket         */
  enum nsock_loopstatus loopret;   /**< Stores nsock_loop returned status    */
  nsock_iod pcap_nsi;              /**< Stores Pcap IOD                      */
  u32 packetno=0;                  /**< Total packet count                   */
  bool first_time=true;            /**< First time we run the loop?          */
  char pcapdev[128];               /**< Device name passed to pcap_open_live */
  #define MX_PKT 1024              /**< Packet structs we keep simultaneously*/
  sendpkt_t pkts2send[MX_PKT];     /**< We have a race condition here but the
  * problem is not trivial to solve because we cannot create a sendpkt_t
  * struct for every probe we send. That could be alright in most cases but
  * not when targeting large networks or when doing flooding. The problem here
  * is that we may need access to specific sendpkt_t vars inside the nsock
  * event handlers but as some operations are asynchronous, we may exhaust
  * the current array of sendpkt_t structs and overwrite some positions
  * that contain data that has not been read yet. Anyway, this bug should not
  * happen when using Nping for normal purposes. As long as you don't choose
  * to ping a 100 million hosts with an inter-probe delay of 1ms, you should be
  * fine. For more info, write to luis.mgarc@gmail.com or post a message to the
  * nmap-dev mailing list. */


  /* Some safe zero initializations */
  memset(pktinfobuffer, 0, 512+1);
  memset(pkt, 0, MAX_IP_PACKET_LEN);
  memset(&pcap_nsi, 0, sizeof(pcap_nsi));
  memset(pkts2send, 0, MX_PKT * sizeof(sendpkt_t));

  /* Get array of target ports */
  targetPorts = o.getTargetPorts( &numTargetPorts );

  /* Set up nsock */
  this->init_nsock();

 switch( o.getMode() ){

  /***************************************************************************/
  /** TCP CONNECT MODE                                                      **/
  /***************************************************************************/
  case TCP_CONNECT:
    o.stats.startClocks();
    for( c=0; c < o.getPacketCount(); c++){ /* Do requested times */
        o.targets.rewind();
        for (p=0; p < numTargetPorts; p++){   /* Iterate through all destination ports */
            o.targets.rewind();
            while( (target=o.targets.getNextTarget()) != NULL ){

                /* Store relevant info so we can pass it to the handler */
                pc=(pc+1)%MX_PKT;
                pkts2send[pc].type=PKT_TYPE_TCP_CONNECT;
                pkts2send[pc].target=target;
                pkts2send[pc].dstport=targetPorts[p];

                /* Schedule a TCP Connect attempt */
                if( first_time ){
                    nsock_timer_create(nsp, tcpconnect_event_handler, 1, &pkts2send[pc]);
                    first_time=false;
                    loopret=nsock_loop(nsp, 2);
                    if (loopret == NSOCK_LOOP_ERROR)
                        nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                }else{
                    nsock_timer_create(nsp, tcpconnect_event_handler, o.getDelay()+1, &pkts2send[pc]);
                    loopret=nsock_loop(nsp, o.getDelay()+1);
                    if (loopret == NSOCK_LOOP_ERROR)
                        nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                }
            }
        }
    }
    o.stats.stopTxClock();
    /* If there are some events pending, we'll wait for DEFAULT_WAIT_AFTER_PROBES ms,
     * otherwise nsock_loop() will return immediately */
    loopret=nsock_loop(nsp, DEFAULT_WAIT_AFTER_PROBES);
    if (loopret == NSOCK_LOOP_ERROR)
        nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
    o.stats.stopRxClock();
    return OP_SUCCESS;
  break; /* case TCP_CONNECT */


  /***************************************************************************/
  /** UDP UNPRIVILEGED MODE                                                 **/
  /***************************************************************************/
  case UDP_UNPRIV:
    o.stats.startClocks();
    for( c=0; c < o.getPacketCount(); c++){ /* Do requested times */
        o.targets.rewind();
        for (p=0; p < numTargetPorts; p++){   /* Iterate through all destination ports */
            o.targets.rewind();
            while( (target=o.targets.getNextTarget()) != NULL ){

                /* Store relevant info so we can pass it to the handler */
                pc=(pc+1)%MX_PKT;
                pkts2send[pc].type=PKT_TYPE_UDP_NORMAL;
                pkts2send[pc].target=target;
                pkts2send[pc].dstport=targetPorts[p];

                if(o.issetPayloadBuffer() ){
                    pkts2send[pc].pkt=o.getPayloadBuffer();
                    pkts2send[pc].pktLen=o.getPayloadLen();
                }else{
                    /* We send 4 bytes of value 0 because nsock does not let us send empty UDP packets */
                    pkts2send[pc].pkt=(u8*)&zero;
                    pkts2send[pc].pktLen=4;
                    /* TODO: At some point we want to support David's custom UDP payloads here*/
                }

                /* Schedule a UDP attempt */
                if( first_time ){
                    nsock_timer_create(nsp, udpunpriv_event_handler, 1, &pkts2send[pc]);
                    first_time=false;
                    loopret=nsock_loop(nsp, 2);
                    if (loopret == NSOCK_LOOP_ERROR)
                        nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                }else{
                    nsock_timer_create(nsp, udpunpriv_event_handler, o.getDelay(), &pkts2send[pc]);
                    loopret=nsock_loop(nsp, o.getDelay());
                    if (loopret == NSOCK_LOOP_ERROR)
                        nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                }
            }
        }
    }
    o.stats.stopTxClock();
    /* If there are some events pending, we'll wait for DEFAULT_WAIT_AFTER_PROBES ms,
     * otherwise nsock_loop() will return immediately */
    if(!o.disablePacketCapture()){
        loopret=nsock_loop(nsp, DEFAULT_WAIT_AFTER_PROBES);
        if (loopret == NSOCK_LOOP_ERROR)
            nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
    }
    o.stats.stopRxClock();
    return OP_SUCCESS;
  break; /* case UDP_UNPRIV */



  /***************************************************************************/
  /** TCP/UDP/ICMP/ARP MODES                                                **/
  /***************************************************************************/
  case  TCP:
  case  UDP:
  case  ICMP:
  case  ARP:

    if( o.getMode()!=ARP && o.sendEth()==false ){
        /* Get socket descriptor. No need for it in ARP since we send at eth level */
        if ((rawipsd = obtainRawSocket()) < 0 )
            nping_fatal(QT_3,"Couldn't acquire raw socket. Are you root?");
    }

    /* Check if we have enough information to get the party started */
    if((o.getMode()==TCP || o.getMode()==UDP) && targetPorts==NULL)
        nping_fatal(QT_3, "normalProbeMode(): NpingOps does not contain correct target ports\n");

    /* Set up libpcap */
    if(!o.disablePacketCapture()){
        /* Create new IOD for pcap */
        if ((pcap_nsi = nsock_iod_new(nsp, NULL)) == NULL)
            nping_fatal(QT_3, "Failed to create new nsock_iod.  QUITTING.\n");

        /* Open pcap */
        filterstring=getBPFFilterString();
        nping_print(DBG_2,"Opening pcap device %s", o.getDevice() );
        #ifdef WIN32
        /* Nping normally uses device names obtained through dnet for interfaces,
         * but Pcap has its own naming system.  So the conversion is done here */
          if (!DnetName2PcapName(o.getDevice(), pcapdev, sizeof(pcapdev))) {
               /* Oh crap -- couldn't find the corresponding dev apparently.
                * Let's just go with what we have then ... */
               Strncpy(pcapdev, o.getDevice(), sizeof(pcapdev));
          }
        #else
          Strncpy(pcapdev, o.getDevice(), sizeof(pcapdev));
        #endif

        rc = nsock_pcap_open(nsp, pcap_nsi, pcapdev, 8192,
                             (o.spoofSource()) ? 1 : 0, filterstring);
        if (rc)
            nping_fatal(QT_3, "Error opening capture device %s\n", o.getDevice());
        nping_print(DBG_2,"Pcap device %s open successfully", o.getDevice());
    }

    /* Ready? Go! */
    o.stats.startClocks();

    switch ( o.getMode() ){

        /* Modes in which we need to iterate over target ports */
        case TCP:
        case UDP:
            /* Do user requested times */
            for( c=0; c < o.getPacketCount(); c++){
                o.targets.rewind();
                o.setCurrentRound( o.issetTTL() ?  ((c%(256-o.getTTL()))+o.getTTL()) : ((c%255)+1 ) ); /* Used in traceroute mode */
                /* Iterate through all destination ports */
                for (p=0; p < numTargetPorts; p++){
                    o.targets.rewind();
                    /* Iterate trough all target IP addresses */
                    while( (target=o.targets.getNextTarget()) != NULL ){

                        currentPort=targetPorts[p];

                        if ( fillPacket( target, currentPort, pkt, MAX_IP_PACKET_LEN, &pktLen, rawipsd ) != OP_SUCCESS ){
                            nping_fatal(QT_3, "normalProbeMode(): Error in packet creation");
                        }
                        /* Safe checks */
                        if (pktLen <=0)
                            nping_fatal(QT_3, "normalProbeMode(): Invalid packet returned by fillPacket() ");

                        /* Store relevant info so we can pass it to the handler */
                        pc=(pc+1)%MX_PKT;
                        pkts2send[pc].type = (o.getMode()==TCP) ? PKT_TYPE_TCP_RAW : PKT_TYPE_UDP_RAW;
                        pkts2send[pc].pkt = pkt;
                        pkts2send[pc].target=target;
                        pkts2send[pc].pktLen = pktLen;
                        pkts2send[pc].rawfd = rawipsd;
                        pkts2send[pc].seq = ++packetno;
                        pkts2send[pc].dstport=currentPort;

                        /* Tell nsock we expect one reply. Actually we schedule 2 pcap events just in case
                         * we get more than one response. */
                        if(!o.disablePacketCapture()){
                            nsock_pcap_read_packet(nsp, pcap_nsi, nping_event_handler, o.getDelay(), NULL);
                            nsock_pcap_read_packet(nsp, pcap_nsi, nping_event_handler, o.getDelay(), NULL);
                        }

                          /* Let nsock handle probe transmission and inter-probe delay */
                        if( first_time ){
                            nsock_timer_create(nsp, nping_event_handler, 1, &pkts2send[pc]);
                            first_time=false;
                            loopret=nsock_loop(nsp, 2);
                            if (loopret == NSOCK_LOOP_ERROR)
                                nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                        }else{
                            nsock_timer_create(nsp, nping_event_handler, o.getDelay(), &pkts2send[pc]);
                            loopret=nsock_loop(nsp, o.getDelay()+1);
                            if (loopret == NSOCK_LOOP_ERROR)
                                nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                        }
                    }
                }
            }
        break; /* Nested case UDP/TCP */


        /* Modes in which we DO NOT need to iterate over target ports */
        case ICMP:
        case ARP:
            /* Do user requested times */
            for( c=0; c < o.getPacketCount(); c++){
                o.targets.rewind();
                o.setCurrentRound( o.issetTTL() ?  ((c%(256-o.getTTL()))+o.getTTL()) : ((c%255)+1 ) ); /* Used in traceroute mode */
                /* Iterate trough all target IP addresses */
                while( (target=o.targets.getNextTarget()) != NULL ){

                    if ( fillPacket( target, 0, pkt, MAX_IP_PACKET_LEN, &pktLen, rawipsd ) != OP_SUCCESS )
                        nping_fatal(QT_3, "normalProbeMode(): Error in packet creation");
                    if (pktLen <=0)
                        nping_fatal(QT_3, "normalProbeMode(): Error packet returned by createPacket() ");

                    /* Store relevant info so we can pass it to the handler */
                    pc=(pc+1)%MX_PKT;
                    pkts2send[pc].type =  (o.getMode()==ICMP) ? PKT_TYPE_ICMP_RAW : PKT_TYPE_ARP_RAW;
                    pkts2send[pc].pkt = pkt;
                    pkts2send[pc].pktLen = pktLen;
                    pkts2send[pc].target=target;
                    pkts2send[pc].rawfd = rawipsd;
                    pkts2send[pc].seq = ++packetno;

                    /* Tell nsock we expect one reply. Actually we schedule 2 pcap events just in case
                     * we get more than one response. */
                    if(!o.disablePacketCapture()){
                        nsock_pcap_read_packet(nsp, pcap_nsi, nping_event_handler, o.getDelay(), NULL);
                        nsock_pcap_read_packet(nsp, pcap_nsi, nping_event_handler, o.getDelay(), NULL);
                    }

                    /* Let nsock handle probe transmission and inter-probe delay */
                    if( first_time ){
                        nsock_timer_create(nsp, nping_event_handler, 1, &pkts2send[pc]);
                        first_time=false;
                        loopret=nsock_loop(nsp, 2);
                        if (loopret == NSOCK_LOOP_ERROR)
                            nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                    }else{
                        nsock_timer_create(nsp, nping_event_handler, o.getDelay(), &pkts2send[pc]);
                        loopret=nsock_loop(nsp, o.getDelay()+1);
                        if (loopret == NSOCK_LOOP_ERROR)
                            nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
                    }
                }
            }
        break; /* Nested case ICMP/ARP */

    } /* End of nested switch */

    o.stats.stopTxClock();
    if(!o.disablePacketCapture()){
        nsock_pcap_read_packet(nsp, pcap_nsi, nping_event_handler, DEFAULT_WAIT_AFTER_PROBES, NULL);
        loopret=nsock_loop(nsp, DEFAULT_WAIT_AFTER_PROBES);
        if (loopret == NSOCK_LOOP_ERROR)
           nping_fatal(QT_3, "Unexpected nsock_loop error.\n");
        o.stats.stopRxClock();
    }
   /* Close opened descriptors */
   if(rawipsd>=0)
     close(rawipsd);
  break; /* case TCP || case UDP || case ICMP || case ARP */

  default:
    nping_fatal(QT_3, "normalProbeMode(): Wrong mode. Please report this bug.");
  break;
 } /* End of main switch */
 return OP_SUCCESS;
} /* End of start() */





/** Creates buffer suitable to be passed to a sendto() call. The buffer
 * represents a raw network packet. The specific protocols are obtained from
 * the information stored in "NpingOps o" object. For example, if o.getMode()
 * returns TCP and o.ipv4() is true, then an IPv4-TCP packet will be generated
 * and stored in the supplied buffer.
 * @param target should contain a valid target with an IP that matches
 * NpingOps::af() returned value.
 * @param port is the destination port number. It is only necessary in TCP and
 * UDP modes. You can safely pass a dummy value in ICMP and ARP modes.
 * @param buff should point to a buffer where the generated packet can be stored.
 * @param bufflen should be the size of the supplied buffer. This function will
 * never write more than "bufflen" bytes to the buffer.
 * @param filledlen will be set to the amount of bytes actually written into
 * the buffer.
 * @param rawfd is the raw socket descriptor that will be used to send the
 * packet. This is only necessary when sending IPv6 packets at raw TCP level
 * because some IPv6 options like hop limit are tuned using calls to
 * setsockopt() */
int ProbeMode::fillPacket(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd){
  EthernetHeader e;   /* Used when sending at raw Ethernet level.           */
  u8 *pnt=buff;       /* Aux pointer to keep track of user supplied "buff". */
  int pntlen=bufflen; /* Aux counter to store how many bytes we have left.  */
  int final_len=0;
  bool eth_included=false;

  if(target==NULL || buff==NULL || bufflen<=0 || filledlen==NULL)
    return OP_FAILURE;
  else
    nping_print(DBG_4, "fillPacket(target=%p, port=%d, buff=%p, bufflen=%d, filledlen=%p rawfd=%d)", target, port, buff, bufflen, filledlen, rawfd);

/* If o.sendEth() is true that means we need to send packets at raw Ethernet
 * level (we are probably running on windows or user requested that explicitly.
 * Ethernet frames that carry ARP packets have special requirements (e.g. some
 * of them are sent to a FF:FF:FF:FF:FF:FF broadcast address). That's why we
 * don't create Ethernet frames here when ARP is used. Function fillPacketARP()
 * takes care of that already. */
  if(o.sendEth() && o.getMode()!=ARP){
    e.setNextElement( NULL );
    if( buff==NULL || filledlen==NULL)
        nping_fatal(QT_3,"fillPacketARP(): NULL pointer supplied.");
    /* Source MAC Address */
    if( o.issetSourceMAC() )
        e.setSrcMAC( o.getSourceMAC() );
    else{
        if( target->getSrcMACAddress() )
            e.setSrcMAC( (u8 *)target->getSrcMACAddress() );
        else
            nping_fatal(QT_3, "fillPacket(): Cannot determine Source MAC address.");
    }

    /* Destination MAC Address */
    if( o.issetDestMAC() )
        e.setDstMAC( o.getDestMAC() );
    else{
        if( target->getNextHopMACAddress() )
            e.setDstMAC( (u8 *)target->getNextHopMACAddress() );
        else
            nping_fatal(QT_3, "fillPacket(): Cannot determine Next Hop MAC address.");
    }

    /* Ethertype value */
    if( o.issetEtherType() )
        e.setEtherType( o.getEtherType() );
    else{
        if( o.getIPVersion() == IP_VERSION_4 )
            e.setEtherType(ETHTYPE_IPV4);
        else if ( o.getIPVersion() == IP_VERSION_6 )
            e.setEtherType(ETHTYPE_IPV6);
        else
            nping_fatal(QT_3, "Bug in fillPacket() and NpingOps::ipversion");
    }

    /* Write the ethernet header to the beginning of the original buffer */
    e.dumpToBinaryBuffer(buff, 14);

    /* Move this pointer so the fillPacketXXXX() functions start from the
     * right byte. */
    pnt+=14;
    pntlen-=14;
    eth_included=true;
  }

  switch( o.getMode() ){
    case  TCP:
        fillPacketTCP(target, port, pnt, pntlen, &final_len, rawfd);
    break;
    case  UDP:
        fillPacketUDP(target, port, pnt, pntlen, &final_len, rawfd);
    break;
    case  ICMP:
         fillPacketICMP(target, pnt, pntlen, &final_len, rawfd);
    break;
    case  ARP: /* ARP builds its own Ethernet header inside fillPacketARP() */
         fillPacketARP(target, pnt, pntlen, &final_len, rawfd);
    break;
    default:
        nping_fatal(QT_3, "Bug in fillPacket() and NpingOps::getMode()");
    break;
  }

  if( eth_included )
    final_len+=14;
  *filledlen=final_len;
  return OP_SUCCESS;
} /* End of createPacket() */



/** Fills an IPv4Header object with information obtained from the NpingOps
 * class.
 * @return OP_SUCCESS on success and fatal()s in case of failure. */
int ProbeMode::createIPv4(IPv4Header *i, PacketElement *next_element, const char *next_proto, NpingTarget *target){
  if( i==NULL || next_proto==NULL || target==NULL)
    nping_fatal(QT_3,"createIPv4(): NULL pointer supplied.");

  i->setNextElement( next_element );   /* Set datagram payload */
  i->setDestinationAddress( target->getIPv4Address() );   /* Destination IP */
  i->setSourceAddress( o.spoofSource() ? o.getIPv4SourceAddress() : target->getIPv4SourceAddress());   /* Source IP */
  i->setTOS( o.getTOS() ); /* Type of service */
  i->setIdentification( o.getIdentification() );   /* Identification */
  i->setNextProto(next_proto);

  /* Time to live */
  if(o.issetTraceroute()){
      i->setTTL( o.getCurrentRound() );
  }else{
    i->setTTL( o.getTTL() );
  }

  /* Flags */
  if( o.issetMF() && o.getMF() == true )
    i->setMF();
  if( o.issetDF() && o.getDF() == true )
    i->setDF();
  if( o.issetRF() && o.getRF() == true )
    i->setRF();

  /* IP Options */
  if( o.issetIPOptions() == true )
    i->setOpts( o.getIPOptions() );

  i->setTotalLength();

  /* Checksum */
  if( o.getBadsumIP() == true )
    i->setSumRandom();
  else
    i->setSum();

  return OP_SUCCESS;
} /* End of createIPv4() */





/** Fills an IPv6Header object with information obtained from the NpingOps
 * class.
 * @return OP_SUCCESS on success and fatal()s in case of failure. */
int ProbeMode::createIPv6(IPv6Header *i, PacketElement *next_element, const char *next_proto, NpingTarget *target){
  if( i==NULL || next_proto==NULL || target==NULL)
    nping_fatal(QT_3,"createIPv6(): NULL pointer supplied.");

  /* Set datagram payload */
  i->setNextElement( next_element );

  i->setVersion();
  i->setTrafficClass( o.getTrafficClass() );
  i->setFlowLabel( o.getFlowLabel() );
  i->setNextHeader(next_proto);
  i->setPayloadLength();
  i->setDestinationAddress( target->getIPv6Address_u8() );

  /* Hop Limit */
  if ( o.issetTraceroute() ){
    i->setHopLimit( o.getCurrentRound() );
  }else{
    i->setHopLimit( o.getHopLimit() );
  }

  /* Source IP */
  if( o.issetIPv6SourceAddress() ){
    i->setSourceAddress( o.getIPv6SourceAddress() );
  }else{
    if ( target->getIPv6SourceAddress_u8() != NULL )
      i->setSourceAddress( target->getIPv6SourceAddress_u8() );
    else
      nping_fatal(QT_3, "createIPv6(): Cannot determine Source IPv6 Address");
  }
  return OP_SUCCESS;
} /* End of createIPv6() */


/** This function is a bit tricky. The thing is that some engineer had
 * the brilliant idea to remove IP_HDRINCL support in IPv6. As a result, it's
 * a big pain in the ass to create raw IPv6 headers because we can only do it
 * if we are sending packets at raw Ethernet level. So if we want our own IPv6
 * header (for source IP spoofing, etc) we have to do things like determine
 * source and dest MAC addresses (this is even more complicated in IPv6 than
 * in IPv4 because we don't have ARP anymore, we have to use something new, the
 * NDP, Neighbor Discovery Protocol.)
 * So the thing is that, if the user does not want to play with the IPv6 header,
 * why bother with all that link layer work? So what we do is create raw
 * transport layer packets and then send them through a raw IPv6 socket. The
 * socket will encapsulate our packets into a nice clean IPv6 header
 * automatically so we don't have to worry about low level details anymore.
 *
 * So this function basically takes a raw IPv6 socket descriptor and then tries
 * to set some basic parameters (like Hop Limit) using setsockopt() calls.
 * It always returns OP_SUCCESS. However, if errors are found, they are printed
 * (QT_2 level) using nping_warning();
 * */
int ProbeMode::doIPv6ThroughSocket(int rawfd){

    /* Hop Limit */
    int hoplimit=0;
    if( o.issetHopLimit() )
       hoplimit= o.getHopLimit();
    else if ( o.issetTraceroute() ){
         hoplimit= (o.getCurrentRound()<255)? o.getCurrentRound() : (o.getCurrentRound()%255)+1;
    }else{
       hoplimit=DEFAULT_IPv6_TTL;
    }
    if( setsockopt(rawfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&hoplimit, sizeof(hoplimit)) != 0 )
        nping_warning(QT_2, "doIPv6ThroughSocket(): setsockopt() for Unicast Hop Limit on IPv6 socket failed");
    if( setsockopt(rawfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&hoplimit, sizeof(hoplimit)) != 0 )
        nping_warning(QT_2, "doIPv6ThroughSocket(): setsockopt() for Multicast Hop Limit on IPv6 socket failed");

#ifdef IPV6_CHECKSUM  /* This is not available in when compiling with MinGW */
    /* Transport layer checksum */
    /* This is totally crazy. We have to tell the kernel EXPLICITLY that we
     * want it to set the TCP/UDP checksum for us. Why the hell is this the
     * default behavior if it's so incredibly difficult to get the IPv6 source
     * address?
     * Additionally, we have to be very careful not to set this option when
     * dealing with ICMPv6 because in that case the kernel computes the
     * checksum automatically and Nping can actually crash if we've set
     * this option manually, can you believe it? */
    if( o.getMode()==TCP || o.getMode()==UDP){
        /* We don't request valid TCP checksums if the user requested bogus sums */
        if( o.getBadsum()==false ){
            int offset = 16;
            if( setsockopt (rawfd, IPPROTO_IPV6, IPV6_CHECKSUM, (char *)&offset, sizeof(offset)) != 0 )
                nping_warning(QT_2, "doIPv6ThroughSocket(): failed to set IPV6_CHECKSUM option on IPv6 socket. ");
        }
    }
#endif

    /* Bind IPv6 socket to a specific network interface */
    if ( o.issetDevice() )  {
        /* It seems that SO_BINDTODEVICE only work on Linux */
        #ifdef LINUX
        if (setsockopt(rawfd, SOL_SOCKET, SO_BINDTODEVICE, o.getDevice(), strlen(o.getDevice())+1) == -1) {
            nping_warning(QT_2, "Error binding IPv6 socket to device %s", o.getDevice() );
        }
        #endif
    }

    return OP_SUCCESS;

} /* End of doIPv6ThroughSocket() */





/** This function handles TCP packet creation. However, the final packet that
  * it produces also includes an IP header.
  * There is one exception. When we are sending IPv6 packet at raw TCP level,
  * the returned packet does not contain an IPv6 header but the supplied
  * rawfd socket descriptor is ready to go because some options have been
  * set on it by doIPv6ThroughSocket(). */
int ProbeMode::fillPacketTCP(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd){

 IPv4Header i;
 IPv6Header i6;
 TCPHeader t;
 RawData p;
 struct in_addr tip, sip;

  if( buff==NULL || filledlen==NULL || target==NULL)
    nping_fatal(QT_3,"fillPacketTCP(): NULL pointer supplied.");

  /* Add Payload if necessary */
  if ( o.issetPayloadType() ){
    switch( o.getPayloadType() ){
        case PL_RAND: case PL_HEX: case PL_STRING:
            p.store(o.getPayloadBuffer(), o.getPayloadLen());
        break;

        case PL_FILE:
        break;

        default:
        break;
    }
    t.setNextElement( &p );
  }

  /* Craft TCP Header */
  t.setSourcePort( o.getSourcePort() );
  t.setDestinationPort( port );
  t.setSeq( o.getTCPSequence() );
  t.setAck( o.getTCPAck() );
  t.setOffset();
  t.setWindow( o.getTCPWindow() );
  t.setUrgPointer(0);
  t.setFlags(0);

  /* Flags */
  if( o.getFlagTCP(FLAG_CWR) == 1 )  t.setCWR();
  if( o.getFlagTCP(FLAG_ECN) == 1 )  t.setECN();
  if( o.getFlagTCP(FLAG_URG) == 1 )  t.setURG();
  if( o.getFlagTCP(FLAG_ACK) == 1 )  t.setACK();
  if( o.getFlagTCP(FLAG_PSH) == 1 )  t.setPSH();
  if( o.getFlagTCP(FLAG_RST) == 1 )  t.setRST();
  if( o.getFlagTCP(FLAG_SYN) == 1 )  t.setSYN();
  if( o.getFlagTCP(FLAG_FIN) == 1 )  t.setFIN();


 /* Now let's encapsulate the TCP packet into an IP packet */
 switch( o.getIPVersion() ){

    case IP_VERSION_4:

        /* Fill the IPv4Header object with the info from NpingOps */
        createIPv4(&i, &t, "TCP", target);

        tip=target->getIPv4Address();
        i.getSourceAddress(&sip);
        if( o.getBadsum() == true ){
            t.setSumRandom(tip, sip);
        }else{
            t.setSum();
        }
        /* Store result in user supplied buffer */
        *filledlen = i.dumpToBinaryBuffer(buff, bufflen);

    break;

    case IP_VERSION_6:
        if( o.sendEth() ){
            /* Fill the IPv6Header object with the info from NpingOps */
            createIPv6(&i6, &t, "TCP", target);

            if( o.getBadsum() == true )
                t.setSumRandom();
            else{
                *filledlen = i6.dumpToBinaryBuffer(buff, bufflen);
                ip6_checksum(buff, *filledlen); /* Provided by dnet */
                return OP_SUCCESS;
            }

            /* Store result in user supplied buffer */
            *filledlen = i6.dumpToBinaryBuffer(buff, bufflen);
        }else{
            doIPv6ThroughSocket(rawfd);

             /* Set some bogus checksum */
             if( o.getBadsum()==true )
                t.setSumRandom();
            /* Set checksum to zero and pray for the kernel to set it to
             * the right value. Brothers and sisters:
             *
             * Our TCP/IP stack, Who is in the kernel,
             * Holy is Your Name;
             * Your kingdom come,
             * Your will be done,
             * on userland as it is in kernel space.
             * Give us this day our TCP checksum,
             * and forgive us for our raw sockets,
             * as we forgive you for your kernel panics;
             * and lead us not into /dev/null,
             * but deliver our packet to the next hop. Amen.
             * */
            else
                t.setSum(0);

            /* Since we cannot include our own header like we do in IPv4, the
             * buffer we return is the TCP one. */
            *filledlen = t.dumpToBinaryBuffer(buff, bufflen);
        }
    break;

    default:
        nping_fatal(QT_3, "fillPacketTCP(): Wrong IP version in NpingOps\n");
    break;

 }

 return OP_SUCCESS;

} /* End of fillPacketTCP() */






/** This function handles UDP packet creation. However, the final packet that
  * it produces also includes an IP header.
  * There is one exception. When we are sending IPv6 packet at raw TCP level,
  * the returned packet does not contain an IPv6 header but the supplied
  * rawfd socket descriptor is ready to go because some options have been
  * set on it by doIPv6ThroughSocket(). */
int ProbeMode::fillPacketUDP(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd){

 IPv4Header i;
 IPv6Header i6;
 UDPHeader u;
 RawData p;
 struct in_addr tip, sip;

  if( buff==NULL || filledlen==NULL || target==NULL)
    nping_fatal(QT_3,"fillPacketUDP(): NULL pointer supplied.");


  /* Add Payload if necessary */
  if ( o.issetPayloadType() ){
    switch( o.getPayloadType() ){
        case PL_RAND: case PL_HEX:  case PL_STRING:
            p.store(o.getPayloadBuffer(), o.getPayloadLen());
        break;

        case PL_FILE:
        break;

        default:
        break;
    }
    u.setNextElement( &p );
  }

  /* Craft UDP Header */
  u.setSourcePort( o.getSourcePort() );
  u.setDestinationPort( port );
  u.setTotalLength();

 /* Now let's encapsulate the TCP packet into an IP packet */
 switch( o.getIPVersion() ){

    case IP_VERSION_4:

        /* Fill the IPv4Header object with the info from NpingOps */
        createIPv4(&i, &u, "UDP", target);

        /* Set checksum */
        tip=target->getIPv4Address();
        i.getSourceAddress(&sip);
        if( o.getBadsum() == true ){
            u.setSumRandom(tip, sip);
        }else{
            u.setSum();
        }
        /* Store result in user supplied buffer */
        *filledlen = i.dumpToBinaryBuffer(buff, bufflen);

    break;

    case IP_VERSION_6:

       if( o.sendEth() ){
            /* Fill the IPv6Header object with the info from NpingOps */
            createIPv6(&i6, &u, "UDP", target);

            if( o.getBadsum() == true ){
                u.setSumRandom();
                /* Store result in user supplied buffer */
                *filledlen = i6.dumpToBinaryBuffer(buff, bufflen);
            }
            else{
                *filledlen = i6.dumpToBinaryBuffer(buff, bufflen);
                ip6_checksum(buff, *filledlen); /* Provided by dnet */
                return OP_SUCCESS;
            }
        }else{
            doIPv6ThroughSocket(rawfd);

             /* Set some bogus checksum */
             if( o.getBadsum()==true )
                u.setSumRandom();
            /* Set checksum to zero and assume the kernel is gonna set the
             * right value. If it doesn't, it's not that important since
             * UDP checksum is optional and can safely be set to zero */
            else
                u.setSum(0);

            /* Since we cannot include our own header like we do in IPv4, the
             * buffer we return is the UDP one. */
            *filledlen = u.dumpToBinaryBuffer(buff, bufflen);
        }
    break;

    default:
        nping_fatal(QT_3, "fillPacketUDP(): Wrong IP version in NpingOps\n");
    break;

 }

 return OP_SUCCESS;

} /* End of fillPacketUDP() */



/** This function handles ICMP packet creation. However, the final packet that
  * it produces also includes an IP header.
  *
  * Currently this function only supports ICMPv4 packet creation. ICMPv6 will
  * be added in the future.*/
int ProbeMode::fillPacketICMP(NpingTarget *target, u8 *buff, int bufflen, int *filledlen, int rawfd){
  IPv4Header i;
  IPv6Header i6;
  ICMPv4Header c4;
  ICMPv6Header c6;
  RawData p;

  if( buff==NULL || filledlen==NULL || target==NULL)
    nping_fatal(QT_3,"fillPacketICMP(): NULL pointer supplied.");
  nping_print(DBG_4, "fillPacketICMP(target=%p, buff=%p, bufflen=%d, filledlen=%p)", target, buff, bufflen, filledlen);

  /* Add Payload if necessary */
  if ( o.issetPayloadType() ){
    switch( o.getPayloadType() ){
        case PL_RAND: case PL_HEX: case PL_STRING:
            p.store(o.getPayloadBuffer(), o.getPayloadLen());
        break;

        case PL_FILE:
        break;

        default:
        break;
    }
    c4.setNextElement( &p );
    c6.setNextElement( &p );
  }

  if( o.ipv4() ){

    c4.setType( o.getICMPType() );
    c4.setCode( o.getICMPCode() );

    /* Lets go for type specific options */
    switch ( c4.getType() ){

        case ICMP_REDIRECT:
            c4.setGatewayAddress( o.getICMPRedirectAddress() );
        break;

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            if( o.issetICMPIdentifier() )
                c4.setIdentifier( o.getICMPIdentifier() );
            else
                c4.setIdentifier( target->getICMPIdentifier() );

            if( o.issetICMPSequence() )
                c4.setSequence( o.getICMPSequence() );
            else
                c4.setSequence( target->obtainICMPSequence() );
        break;

        case ICMP_ROUTERADVERT:
               c4.setAddrEntrySize( 2 );
               c4.setLifetime( o.getICMPRouterAdvLifetime() );

               if( o.issetICMPAdvertEntry() )
                    for (int z=0; z<o.getICMPAdvertEntryCount(); z++){
                        struct in_addr entryaddr;
                        u32 entrypref;
                        o.getICMPAdvertEntry(z, &entryaddr, &entrypref );
                        c4.addRouterAdvEntry(entryaddr, entrypref);
                    }
        break;

        case ICMP_PARAMPROB:
            c4.setParameterPointer( o.getICMPParamProblemPointer() );
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
            if( o.issetICMPIdentifier() )
                c4.setIdentifier( o.getICMPIdentifier() );
            else
                c4.setIdentifier( target->getICMPIdentifier() );

            if( o.issetICMPSequence() )
                c4.setSequence( o.getICMPSequence() );
            else
                c4.setSequence( target->obtainICMPSequence() );
            c4.setOriginateTimestamp( o.getICMPOriginateTimestamp() );
            c4.setReceiveTimestamp( o.getICMPReceiveTimestamp() );
            c4.setTransmitTimestamp( o.getICMPTransmitTimestamp() );
        break;

        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_TRACEROUTE:
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
        case ICMP_ROUTERSOLICIT:
        case ICMP_TIMXCEED:
        break;

        default:
          /* TODO: What do we do here if user specified a non standard type? */
        break;

    }
    /* Compute checksum */
    c4.setSum(); /* TODO: Do we want to implement --badsum-icmp? */

    /* Fill the IPv4Header object with the info from NpingOps */
    createIPv4(&i, &c4, "ICMP", target);

    /* Store result in user supplied buffer */
    *filledlen = i.dumpToBinaryBuffer(buff, bufflen);

  }else{

    c6.setType( o.getICMPType() );
    c6.setCode( o.getICMPCode() );

    switch( c6.getType() ){

        case ICMPv6_ECHO:
        case ICMPv6_ECHOREPLY:
            c6.setIdentifier(o.issetICMPIdentifier() ?  o.getICMPIdentifier() : target->getICMPIdentifier());
            c6.setSequence(o.issetICMPSequence() ? o.getICMPSequence() : target->obtainICMPSequence());
        break;

        case ICMPv6_UNREACH:
        case ICMPv6_PKTTOOBIG:
        case ICMPv6_TIMXCEED:
        case ICMPv6_PARAMPROB:

        case ICMPv6_ROUTERSOLICIT:
        case ICMPv6_ROUTERADVERT:
        case ICMPv6_NGHBRSOLICIT:
        case ICMPv6_NGHBRADVERT:
        case ICMPv6_REDIRECT:
        case ICMPv6_RTRRENUM:
        default:
        break;
    }

    /* Fill the IPv4Header object with the info from NpingOps */
    createIPv6(&i6, &c6, "ICMPv6", target);

    /* Compute checksum */
    c6.setSum();

    /* Store result in user supplied buffer */
    *filledlen = i6.dumpToBinaryBuffer(buff, bufflen);

  }

 return OP_SUCCESS;

} /* End of fillPacketICMP() */




/** This function handles ARP packet creation. However, the final packet that
  * it produces also includes an Ethernet header. */
int ProbeMode::fillPacketARP(NpingTarget *target, u8 *buff, int bufflen, int *filledlen, int rawfd){

    EthernetHeader e;
    ARPHeader a;

    u8 bcastmac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    u8 nullmac[6]={0x00,0x00,0x00,0x00,0x00,0x00};

    if(target==NULL || buff==NULL || filledlen==NULL)
        nping_fatal(QT_3,"fillPacketARP(): NULL pointer supplied.");

    nping_print(DBG_4, "fillPacketARP(target=%p, buff=%p, bufflen=%d, filledlen=%p)", target, buff, bufflen, filledlen);

    /* Source MAC Address */
    if( o.issetSourceMAC() )
        e.setSrcMAC( o.getSourceMAC() );
    else if( target->getSrcMACAddress()!=NULL )
        e.setSrcMAC(target->getSrcMACAddress());
    else
        e.setSrcMAC( nullmac ); /* Defaults to 00:00:00:00:00:00 */

    /* Destination MAC Address */
    if( o.issetDestMAC() )
        e.setDstMAC( o.getDestMAC() );
    else
        e.setDstMAC( bcastmac ); /* Defaults to FF:FF:FF:FF:FF:FF */

    /* Ethertype value */
    if( o.issetEtherType() )
        e.setEtherType( o.getEtherType() );
    else
        e.setEtherType(ETHTYPE_ARP);

    /* Link Ethernet header to ARP packet. */
    e.setNextElement(&a);

    /* Hardware type */
    if( o.issetARPHardwareType() )
        a.setHardwareType( o.getARPHardwareType() );
    else
        a.setHardwareType();

    /* Protocol type */
    if( o.issetARPProtocolType() )
        a.setProtocolType( o.getARPProtocolType() );
    else
        a.setProtocolType();

    /* Length of HW Address */
    if( o.issetARPHwAddrLen() )
        a.setHwAddrLen( o.getARPHwAddrLen() );
    else
        a.setHwAddrLen();  /* Defaults to length of a MAC address */

    /* Length of Protocol Address */
    if( o.issetARPProtoAddrLen() )
        a.setProtoAddrLen( o.getARPProtoAddrLen() );
    else
        a.setProtoAddrLen();   /* Defaults to length of IPv4 */

    /* ARP Operation code. */
    a.setOpCode( o.getARPOpCode() );

    /* Sender HW Address */
    if( o.issetARPSenderHwAddr() )
        a.setSenderMAC( o.getARPSenderHwAddr() );
    else
        a.setSenderMAC( e.getSrcMAC() );  /* Get Ethernet's source MAC */

    /* Sender Protocol Address */
    if( o.issetARPSenderProtoAddr() )
        a.setSenderIP( o.getARPSenderProtoAddr() );
    else if ( o.issetIPv4SourceAddress() )
        a.setSenderIP( o.getIPv4SourceAddress() );
    else
        a.setSenderIP(  target->getIPv4SourceAddress() );

    /* Target HW Address */
    if( o.issetARPTargetProtoAddr() )
        a.setTargetIP( o.getARPTargetProtoAddr() );
    else
        a.setTargetIP( target->getIPv4Address() );

    /* Target Protocol Address */
    if( o.issetARPTargetHwAddr() )
        a.setTargetMAC( o.getARPTargetHwAddr() );
    else
        a.setTargetMAC( nullmac );  /* Get Ethernet's target MAC */

    /* Store result in user supplied buffer */
    *filledlen = e.dumpToBinaryBuffer(buff, bufflen);

     return OP_SUCCESS;
}



/** This function creates a BPF filter specification, suitable to be passed to
  * pcap_compile() or nsock_pcap_open(). It reads info from "NpingOps o" and
  * creates the right BPF filter for the current operation mode. However, if
  * user has supplied a custom BPF filter through option --bpf-filter, the
  * same string stored in o.getBPFFilterSpec() is returned (so the caller
  * should not even bother to check o.issetBPFFilterSpec() because that check
  * is done here already.
  * @warning Returned pointer is a statically allocated buffer that subsequent
  *  calls will overwrite. */
char *ProbeMode::getBPFFilterString(){

 char ipstring[128];
 static char filterstring[1024];
 char *buffer=filterstring;
 u8 icmp_send_type=0;
 u8 icmp_recv_type=0;
 u16 arp_send_type=0;
 u16 arp_recv_type=0;
 bool skip_icmp_matching=false;
 bool skip_arp_matching=false;
 bool src_equals_target=false;
 NpingTarget *t=NULL;
 struct sockaddr_storage srcss;
 struct sockaddr_in  *s4=(struct sockaddr_in *)&srcss;
 struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&srcss;
 struct sockaddr_storage dstss;
 struct sockaddr_in  *d4=(struct sockaddr_in *)&dstss;
 struct sockaddr_in6 *d6=(struct sockaddr_in6 *)&dstss;
 size_t dstlen, srclen;
 memset(&srcss, 0, sizeof(struct sockaddr_storage));
 memset(&dstss, 0, sizeof(struct sockaddr_storage));
 memset(buffer, 0, 1024);
 memset(ipstring, 0, 128);

 /* If user supplied a BPF from the cmd line, use it */
 if( o.issetBPFFilterSpec() ){
    buffer=o.getBPFFilterSpec();
    /* We copy it to our internal static buffer just in case... */
    if(buffer!=NULL)
        strncpy(filterstring, buffer, sizeof(filterstring)-1);
    else
        strncpy(filterstring, "", 2);
    nping_print(DBG_1, "BPF-filter: %s", filterstring);
    return filterstring;
 }

 /* For the server in Echo mode we need a special filter */
 if( o.getRole()==ROLE_SERVER ){
    /* Capture all IP packets but the ones that belong to the side-channel */
    sprintf(filterstring, "ip and ( not (tcp and (dst port %d or src port %d) ) )", o.getEchoPort(), o.getEchoPort() );
    nping_print(DBG_1, "BPF-filter: %s", filterstring);
    return filterstring;
 }

 /* Obtain source IP address */
  if( o.spoofSource() )
    memcpy( &srcss, o.getSourceSockAddr(), sizeof(struct sockaddr_storage) );
  else  if( (t=o.targets.getNextTarget())!= NULL ){
    t->getSourceSockAddr(&srcss, &srclen);
  }else{
   /* This should never happen but if for some reason we cannot obtain
    * the target, set localhost address. */
    if ( o.ipv6() ){
        s4->sin_family=AF_INET;
        inet_pton(AF_INET, "::1", &s6->sin6_addr);
    }else{
        s4->sin_family=AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &s4->sin_addr);
    }
    nping_print(DBG_2, "Couldn't determine source address. Using address %s in BFP filter", IPtoa(&srcss) );
  }
  o.targets.rewind();

  /* Obtain the first target address */
  if(t!=NULL)
    t->getTargetSockAddr(&dstss, &dstlen);

  /* Determine if source address and target address are the same. This is a
   * special case that occurs when nping-ing localhost */
  if(s6->sin6_family==AF_INET6){
    if(memcmp(&s6->sin6_addr, &d6->sin6_addr, sizeof(d6->sin6_addr))==0)
        src_equals_target=true;
  }else if( s4->sin_family == AF_INET ){
    if(s4->sin_addr.s_addr == d4->sin_addr.s_addr)
        src_equals_target=true;
  }

 /* Convert src address to an ascii string so it can be copied to the BPF string */
 if(s6->sin6_family==AF_INET6){
    inet_ntop(AF_INET6, &s6->sin6_addr, ipstring, sizeof(ipstring));
 }else if( s4->sin_family == AF_INET ) {
    inet_ntop(AF_INET, &s4->sin_addr, ipstring, sizeof(ipstring));
 }else{
    nping_warning(QT_2, "Warning: Wrong address family (%d) in getBPFFilterString(). Please report a bug", srcss.ss_family);
    sprintf(ipstring,"127.0.0.1");
 }

 /* Tell the filter that we only want incoming packets, destined to our source IP */
 if(o.getMode()!=ARP){
     if(src_equals_target)
         Snprintf(buffer, 1024, "(src host %s and dst host %s) and (", ipstring, ipstring);
     else
         Snprintf(buffer, 1024, "(not src host %s and dst host %s) and (", ipstring, ipstring);
    buffer=filterstring+strlen(filterstring);
 }

 /* Time for protocol specific constraints */
 switch( o.getMode() ){
    case  TCP: /* Restrict to packets targeting our TCP source port */
        Snprintf(buffer, 1024-strlen(filterstring), "(tcp and dst port %d) ", o.getSourcePort());
    break;

    case  UDP: /* Restrict to packets targeting our UDP source port */
        Snprintf(buffer, 1024-strlen(filterstring), "(udp and dst port %d) ", o.getSourcePort());
    break;

    case  ICMP: /* Restrict to packets that are replies to our ICMP packets */
        icmp_send_type= o.issetICMPType() ? o.getICMPType() : DEFAULT_ICMP_TYPE;
        switch( icmp_send_type ){
            case ICMP_TSTAMP:
                icmp_recv_type=ICMP_TSTAMPREPLY;
            break;
            case ICMP_TSTAMPREPLY:          /* If we are sending replies we probably want to see */
                icmp_recv_type=ICMP_TSTAMP; /* the requests that are being put into the network  */
            break;
            case ICMP_INFO:
                icmp_recv_type=ICMP_INFOREPLY;
            break;
            case ICMP_INFOREPLY:
                icmp_recv_type=ICMP_INFO;
            break;
            case ICMP_MASK:
                icmp_recv_type=ICMP_MASKREPLY;
            break;
            case ICMP_MASKREPLY:
                icmp_recv_type=ICMP_MASK;
            break;
            case ICMP_ECHO:
                icmp_recv_type=ICMP_ECHOREPLY;
            break;
            case ICMP_ECHOREPLY:
                icmp_recv_type=ICMP_ECHO;
            break;

            /* These don't generate any response so we behave different */
            case ICMP_UNREACH:
            case ICMP_SOURCEQUENCH:
            case ICMP_REDIRECT:
            case ICMP_ROUTERADVERT:
            case ICMP_ROUTERSOLICIT:
            case ICMP_TIMXCEED:
            case ICMP_PARAMPROB:
            case ICMP_TRACEROUTE:
            default:
                skip_icmp_matching=true;
            break;
        }
        /* We have an specific ICMP type to look for */
        if(!skip_icmp_matching){
            Snprintf(buffer, 1024-strlen(filterstring), "(icmp and icmp[icmptype] = %d) ", icmp_recv_type);
        }else{
            /* If we are sending messages that don't generate responses, receive anything but the type we send.
             * This conflicts in some cases with the conditions added at the end of this functions where we
             * allow ICMP error messages to be received. However, this is not a problem since we are already
             * filtering out our own outgoing packets and the packets that are not for us. */
            Snprintf(buffer, 1024-strlen(filterstring), "(icmp and icmp[icmptype] != %d) ", icmp_send_type);
        }
    break;

    case  ARP:
        arp_send_type= o.issetARPOpCode() ? o.getARPOpCode() : DEFAULT_ARP_OP;
        switch(arp_send_type){
            case OP_ARP_REQUEST:
                arp_recv_type=OP_ARP_REPLY;
            break;
            case OP_ARP_REPLY:                 /* If we are sending replies we probably want to see */
                arp_recv_type=OP_ARP_REQUEST;  /* the requests that are being put into the network  */
            break;
            case OP_RARP_REQUEST:
                arp_recv_type=OP_RARP_REPLY;
            break;
            case OP_RARP_REPLY:
                arp_recv_type=OP_RARP_REQUEST;
            break;
            case OP_DRARP_REQUEST:
                arp_recv_type=OP_DRARP_REPLY;
            break;
            case OP_DRARP_REPLY:
                arp_recv_type=OP_DRARP_REQUEST;
            break;
            case OP_DRARP_ERROR:
                arp_recv_type=OP_DRARP_REQUEST;
            break;
            case OP_INARP_REQUEST:
                arp_recv_type=OP_INARP_REPLY;
            break;
            case OP_INARP_REPLY:
                arp_recv_type=OP_INARP_REQUEST;
            break;
            default:
                skip_arp_matching=true;
            break;
        }
        if(!skip_arp_matching){
            /* If we are doing DRARP we also want to receive DRARP errors */
            if(arp_send_type==OP_DRARP_REQUEST || arp_send_type==OP_DRARP_REPLY)
                Snprintf(buffer, 1024-strlen(filterstring),  "arp and arp[6]==0x00 and (arp[7]==0x%02X or arp[7]==0x%02X)", (u8)arp_recv_type, (u8)OP_DRARP_ERROR);
            else
                Snprintf(buffer, 1024-strlen(filterstring),  "arp and arp[6]==0x00 and arp[7]==0x%02X", (u8)arp_recv_type);
        }else{
            /* If we are sending things like ATMARP's ARP_NAK, we just skip the type we send and receive all others */
            Snprintf(buffer, 1024-strlen(filterstring),  "arp and arp[6]==0x00 and arp[7]!=0x%02X", (u8)arp_send_type);
        }
    break;
  }

  /* We also want to get all ICMP error messages */
  if(o.getMode()!=ARP){
    buffer=filterstring+strlen(filterstring);
    Snprintf(buffer, 1024-strlen(filterstring), "or (icmp and (icmp[icmptype] = %d or icmp[icmptype] = %d or icmp[icmptype] = %d or icmp[icmptype] = %d or icmp[icmptype] = %d)) )" ,
                                 ICMP_UNREACH, ICMP_SOURCEQUENCH, ICMP_REDIRECT, ICMP_TIMXCEED, ICMP_PARAMPROB);
  }
  nping_print(DBG_1, "BPF-filter: %s", filterstring);
  return filterstring;
} /* End of getBPFFilterString() */



/** Helper to check whether a received ICMP-in-IPv4 packet is related to a probe
  * we might have sent. Returns non-NULL target pointer if found. Otherwise
  * returns NULL. */
static NpingTarget *is_response_icmp(const unsigned char *packet, unsigned int packetlen) {
    const void *data;
    unsigned int datalen;
    struct abstract_ip_hdr packethdr;
    NpingTarget *trg;

    /* Parse the outermost IP header (for its source address). */
    datalen = packetlen;
    data = ip_get_data(packet, &datalen, &packethdr);
    if (data == NULL)
        return NULL;

    trg = o.targets.findTarget(&packethdr.src);
    if (trg != NULL) {
        if (packethdr.proto == IPPROTO_ICMP) {
            struct icmp_hdr *icmp;
            struct icmp_msg_echo *echo;

            if (datalen < 4)
                return NULL;
            icmp = (struct icmp_hdr *) data;
            /* In case of echo reply, make sure the ICMP ID is the same as we
               are sending. */
            if (icmp->icmp_type == ICMP_ECHOREPLY) {
                u16 expected_id;

                if (o.issetICMPIdentifier())
                    expected_id = o.getICMPIdentifier();
                else
                    expected_id = trg->getICMPIdentifier();

                if (datalen < 8)
                    return NULL;
                echo = (struct icmp_msg_echo *) ((char *) icmp + 4);
                if (ntohs(echo->icmp_id) != expected_id)
                    return NULL;
            }
        }
        return trg;
    }

    /* If that didn't work, check if this is ICMP with an encapsulated IP
       header. */
    if (packethdr.proto == IPPROTO_ICMP) {
        struct ip *ip;
        unsigned int iplen;
        struct sockaddr_storage ss;
        struct sockaddr_in *sin = (struct sockaddr_in *) &ss;

        if (datalen < 8)
            return NULL;
        ip = (struct ip *) ((char *) data + 8);
        iplen = datalen - 8;
        /* Make sure there is enough header to have a dest address. */
        if (iplen < 20)
            return NULL;
        if (ip->ip_v != 4)
            return NULL;
        sin->sin_family = AF_INET;
        sin->sin_addr = ip->ip_dst;
        trg = o.targets.findTarget(&ss);

        return trg;
    }

    return NULL;
}


/** This function handles nsock events related to raw packet modes
  * TCP, UDP, ICMP and ARP (TCP_CONNEC and UDP_UNPRIV are handled by their
  * own even handlers).
  * Basically the handler receives nsock events and takes the appropriate
  * action based on event type.  This is basically what it does for each event:
  *
  * TIMERS: start() schedules probe transmissions through timers.
  * That's how we manage to send probes at a given rate. When the alarm goes
  * off, nsock generates a timer event so, in this function, we take the
  * supplied "mydata" pointer, convert it to a sendpkt_t pointer and, from
  * the info stored there, we send the packet though a raw socket.
  *
  * PCAP READS: start() also schedules pcap read operations so,
  * whenever pcap has capture a packet, nsock generates a pcap read event so
  * we just read the capture data, update the statistics and print the packet
  * to stdout.
  * */
void ProbeMode::probe_nping_event_handler(nsock_pool nsp, nsock_event nse, void *mydata) {

 nsock_iod nsi = nse_iod(nse);
 enum nse_status status = nse_status(nse);
 enum nse_type type = nse_type(nse);
 sendpkt_t *mypacket = (sendpkt_t *)mydata;
 u8 pktinfobuffer[512+1];
 char *hex=NULL;
 char final_output[65535];
 nsock_event_id ev_id;
 struct timeval *t = (struct timeval *)nsock_gettimeofday();
 const unsigned char *packet=NULL;
 const unsigned char *link=NULL;
 size_t linklen=0;
 size_t packetlen=0;
 u16 *ethtype=NULL;
 u8 buffer[512+1];
 size_t link_offset=0;
 static struct timeval pcaptime;
 static struct timeval prevtime;
 NpingTarget *trg=NULL;
 u16 *prt=NULL;
 u8 proto=0;
 bool ip=false;
 memset(final_output, 0, sizeof(final_output));

 nping_print(DBG_4, "nping_event_handler(): Received callback of type %s with status %s",
                  nse_type2str(type), nse_status2str(status));

 if (status == NSE_STATUS_SUCCESS ) {

   switch(type) {

       /* This is actually for our raw packet probe transmissions */
       case NSE_TYPE_TIMER:
            if( mypacket!=NULL){

                /* Send the packet */
                send_packet(mypacket->target, mypacket->rawfd, mypacket->pkt, mypacket->pktLen);
                o.setLastPacketSentTime(*t);

                /* Print packet contents */
                if( o.sendEth() )
                    link_offset=14;

                if( mypacket->type==PKT_TYPE_ARP_RAW )
                    getPacketStrInfo("ARP",mypacket->pkt+14, mypacket->pktLen-14, pktinfobuffer, 512);
                else if ( o.ipv6UsingSocket() ){
                    size_t sslen;
                    struct sockaddr_storage ss_src;
                    struct sockaddr_storage ss_dst;
                    mypacket->target->getSourceSockAddr(&ss_src, &sslen);
                    mypacket->target->getTargetSockAddr(&ss_dst, &sslen);
                    getPacketStrInfo("IPv6_NO_HEADER", mypacket->pkt, mypacket->pktLen, pktinfobuffer, 512, &ss_src, &ss_dst );
                }
                else
                    getPacketStrInfo("IP", mypacket->pkt+link_offset, mypacket->pktLen-link_offset, pktinfobuffer, 512);

                o.stats.addSentPacket(mypacket->pktLen);
                if( o.getMode()==TCP || o.getMode()==UDP){
                    mypacket->target->setProbeSentTCP(0, mypacket->dstport);
                }else if (o.getMode()==ICMP){
                    mypacket->target->setProbeSentICMP(0,0);
                }
                if( o.showSentPackets() ){
                    nping_print(VB_0,"SENT (%.4fs) %s", o.stats.elapsedRuntime(t), pktinfobuffer );
                    if( o.getVerbosity() >= VB_3 )
                        luis_hdump((char*)mypacket->pkt, mypacket->pktLen);
                }
            }
       break;



       case NSE_TYPE_PCAP_READ:

            /* Read a packet */
            nse_readpcap(nse, &link, &linklen, &packet, &packetlen, NULL, &pcaptime);

            /* If we are on a Ethernet network, extract the next packet protocol
             * from the Ethernet frame. */
            if( nsock_iod_linktype(nsi) == DLT_EN10MB ){
                ethtype=(u16*)(link+12);
                *ethtype=ntohs(*ethtype);
                switch(*ethtype){
                    case ETHTYPE_IPV4:
                    case ETHTYPE_IPV6:
                        ip=true;
                    break;
                    case ETHTYPE_ARP:
                    case ETHTYPE_RARP:
                        ip=false;
                    break;
                    default:
                        nping_warning(QT_1, "RCVD (%.4fs) Unsupported protocol (Ethernet type %02X)", o.stats.elapsedRuntime(t), *ethtype);
                        print_hexdump(VB_3, packet, packetlen);
                        return;
                    break;
                }
            /* If link layer is not Ethernet, check if the first bits of the
             * packets are 4 (IPv4) or 6 (IPv6). This is not exact science but
             * it should be OK for the moment since we should never get non
             * IP packets (the BPF filter prevents that) */
            }else{
                IPv4Header iphdr;
                if( iphdr.storeRecvData(packet, packetlen)!=OP_SUCCESS )
                    nping_warning(QT_1, "RCVD (%.4fs) Bogus packet received.", o.stats.elapsedRuntime(t));
                if( iphdr.getVersion()==4 || iphdr.getVersion()==6){
                    ip=true;
                }else{
                    nping_warning(QT_1, "RCVD (%.4fs) Unsupported protocol.", o.stats.elapsedRuntime(t));
                    print_hexdump(VB_3, packet, packetlen);
                    return;
                }
            }

            /* Packet is IP */
            if(ip){
                getPacketStrInfo("IP",(const u8*)packet, packetlen, buffer, 512);
                proto = getProtoFromIPPacket((u8*)packet, packetlen);
                if (proto == IPPROTO_UDP || proto == IPPROTO_TCP){
                    /* for UDP/TCP we print out and update the global total straight away
                    since we know that pcap only found packets from connections that we
                    opened */
                    snprintf(final_output, sizeof(final_output), "RCVD (%.4fs) %s\n", o.stats.elapsedRuntime(t), buffer);
                    if( o.getVerbosity() >= VB_3 ){
                        hex=hexdump(packet, packetlen);
                        strncat(final_output, hex, sizeof(final_output)-1);
                        free(hex);
                    }
                    prevtime=pcaptime;

                    /* Statistics */
                    o.stats.addRecvPacket(packetlen);

                    /* Then we check for a target and a port and do the individual statistics */
                    trg=o.targets.findTarget( getSrcSockAddrFromIPPacket((u8*)packet, packetlen) );

                    if(trg != NULL){
                        prt=getSrcPortFromIPPacket((u8*)packet, packetlen);
                        if( prt!=NULL )
                            trg->setProbeRecvTCP(*prt, 0);
                    }
                }else if (proto==IPPROTO_ICMP || proto==IPPROTO_ICMPV6){
                    /* we look for a target based on first src addr and second the dest addr of
                    the packet header which is returned in the ICMP packet */
                    trg = is_response_icmp(packet, packetlen);

                    /* In the case of ICMP we only do any printing and statistics if we
                    found a target - otherwise it could be a packet that is nothing
                    to do with us */
                    if(trg!=NULL){
                        snprintf(final_output, sizeof(final_output), "RCVD (%.4fs) %s\n", o.stats.elapsedRuntime(t), buffer);
                        if( o.getVerbosity() >= VB_3 ){
                            hex=hexdump(packet, packetlen);
                            strncat(final_output, hex, sizeof(final_output)-1);
                            free(hex);
                        }
                        prevtime=pcaptime;
                        o.stats.addRecvPacket(packetlen);
                        trg->setProbeRecvICMP(0, 0);
                    }
                }

            /* Packet is ARP */
            }else{
                getPacketStrInfo("ARP",(const u8*)packet, packetlen, buffer, 512);
                nping_print(VB_0, "RCVD (%.4fs) %s", o.stats.elapsedRuntime(t), buffer );
                o.stats.addRecvPacket(packetlen);
                print_hexdump(VB_3 | NO_NEWLINE, packet, packetlen);
                /* TODO: find target and call setProbeRecvARP() */
            }

            if( o.getRole() == ROLE_CLIENT ){
                int delay=(int)MIN(o.getDelay()*0.33, 333);
                ev_id=nsock_timer_create(nsp, probe_delayed_output_handler, delay, NULL);
                o.setDelayedRcvd(final_output, ev_id);
            }
            else
                nping_print(VB_0|NO_NEWLINE, "%s", final_output);
        break;

       /* In theory we should never get these kind of events in this handler
        * because no code schedules them */
       case NSE_TYPE_CONNECT:
       case NSE_TYPE_CONNECT_SSL:
       case NSE_TYPE_READ:
       case NSE_TYPE_WRITE:
            nping_fatal(QT_3, "Bug in nping_event_handler(). Received %s event.", nse_type2str(type));
       break;

       default:
         nping_fatal(QT_3, "nping_event_handler(): Bogus event type.");
       break;

   } /* switch(type) */


 } else if (status == NSE_STATUS_EOF) {
    nping_print(DBG_4, "nping_event_handler(): Unexpected behaviour: Got EOF. Please report this bug.\n");
 } else if (status == NSE_STATUS_ERROR) {
     nping_warning(QT_2, "nping_event_handler(): %s failed: %s", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_TIMEOUT) {
    nping_print(DBG_4,"nping_event_handler(): %s timeout: %s\n", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_CANCELLED) {
    nping_warning(QT_2, "nping_event_handler(): %s canceled: %s", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_KILL) {
    nping_warning(QT_2, "nping_event_handler(): %s killed: %s", nse_type2str(type), strerror(socket_errno()));
 } else{
    nping_warning(QT_2, "nping_event_handler(): Unknown status code %d\n", status);
 }
 return;

} /* End of nping_event_handler() */


/** Prints the supplied string when the nsock timer event goes off. This is used
  * by the echo client to delay output of received packets for a bit, so we
  * receive the echoed packet and print it (CAPT) before the RCVD one. */
void ProbeMode::probe_delayed_output_handler(nsock_pool nsp, nsock_event nse, void *mydata){
  char *str=NULL;
  if((str=o.getDelayedRcvd(NULL))!=NULL){
    printf("%s", str);
    free(str);
  }
  return;
} /* End of probe_delayed_output_handler() */


/* DEFAULT_MAX__DESCRIPTORS. is a hardcoded value for the maximum number of
 * opened descriptors in the current system. Nping tries to determine that
 * limit at run time, but sometimes it can't and the limit defaults to
 * DEFAULT_MAX_DESCRIPTORS. */
#ifndef MACOSX
    #define DEFAULT_MAX_DESCRIPTORS 1024
#else
    #define DEFAULT_MAX_DESCRIPTORS 256
#endif

/* When requesting a large number of descriptors from the system (TCP-connect
 * mode and UDP unprivileged mode), this is the number of descriptors that need
 * to be reserved for things like stdin, stdout, echo mode sockets, data files,
 * etc. */
#define RESERVED_DESCRIPTORS 8

/* Default timeout for UDP socket nsock_read() operations */
#define DEFAULT_UDP_READ_TIMEOUT_MS  1000 

/** This function handles nsock events related to TCP_CONNECT mode
  * Basically the handler receives nsock events and takes the appropriate
  * action based on event type.  This is basically what it does for each event:
  *
  * TIMERS: normalProbeMode() schedules TCP connections through timers, that's
  * how we manage to start the TCP handshakes at a given rate. When the alarm
  * goes off, nsock generates a timer event so, in this function, we take the
  * supplied "mydata" pointer, convert it to a sendpkt_t pointer and, from
  * the info stored there, we schedule a nsock_connect_tcp() event. This means
  * that nsock will initiate a TCP handshake and return. Whenever the handshake
  * is completed, nsock will generate a CONNECT event to indicate it so we
  * know the other peer was alive and willing to TCP-handshake with us.
  *
  * CONNECTS: These events are scheduled by the code that handles timer events.
  * As described above, nsock generates a connect event when handshakes have
  * completed. When we get a connect event we just tell the user the handshake
  * was successful and update the stats.
  * */
/* This is the callback function for the nsock events produced in TCP-Connect
 * mode. */
void ProbeMode::probe_tcpconnect_event_handler(nsock_pool nsp, nsock_event nse, void *mydata) {

 nsock_iod nsi;                   /**< Current nsock IO descriptor.          */
 enum nse_status status;          /**< Current nsock event status.           */
 enum nse_type type;              /**< Current nsock event type.             */
 sendpkt_t *mypacket=NULL;        /**< Info about the current probe.         */
 struct timeval *t=NULL;          /**< Current time obtained through nsock.  */
 struct sockaddr_storage to;      /**< Stores destination address for Tx.    */
 struct sockaddr_in *to4=NULL;    /**<   |_ Sockaddr for IPv4.               */
 struct sockaddr_in6 *to6=NULL;   /**<   |_ Sockaddr for IPv6.               */
 struct sockaddr_storage peer;    /**< Stores source address for Rx.         */
 struct sockaddr_in *peer4=NULL;  /**<   |_ Sockaddr for IPv4.               */
 struct sockaddr_in6 *peer6=NULL; /**<   |_ Sockaddr for IPv6.               */
 int family=0;                    /**< Hill hold Rx address family.          */
 char ipstring[128];              /**< To print IP Addresses.                */
 u16 peerport=0;                  /**< To hold peer's port number.           */
 size_t sslen=0;                  /**< To store length of sockaddr structs.  */
 static nsock_iod *fds=NULL;      /**< IODs for multiple parallel connections*/
 static int max_iods=0;           /**< Number of IODS in "fds"               */
 static u32 packetno=0;           /**< Packets sent from this handler.       */
 NpingTarget *trg=NULL;           /**< Target we look up in NpingTargets::   */

 /* Initializations */
 nsi = nse_iod(nse);
 status = nse_status(nse);
 type = nse_type(nse);
 mypacket = (sendpkt_t *)mydata;
 t = (struct timeval *)nsock_gettimeofday();
 to6=(struct sockaddr_in6 *)&to;
 to4=(struct sockaddr_in *)&to;
 peer4=(struct sockaddr_in *)&peer;
 peer6=(struct sockaddr_in6 *)&peer;
 memset(&to, 0, sizeof(struct sockaddr_storage));
 memset(&peer, 0, sizeof(struct sockaddr_storage));

  /* Try to determine the max number of opened descriptors. If the limit is
   * less than than we need, try to increase it. */
  if(fds==NULL){
    max_iods=get_max_open_descriptors()-RESERVED_DESCRIPTORS;
    if( o.getTotalProbes() > max_iods ){
        max_iods=set_max_open_descriptors( o.getTotalProbes() )-RESERVED_DESCRIPTORS;
    }
    /* If we couldn't determine the limit, just use a predefined value */
    if(max_iods<=0)
        max_iods=DEFAULT_MAX_DESCRIPTORS-RESERVED_DESCRIPTORS;
    /* Allocate space for nsock_iods */
    if( (fds=(nsock_iod *)calloc(max_iods, sizeof(nsock_iod)))==NULL ){
        /* If we can't allocate for that many descriptors, reduce our requirements */
        max_iods=DEFAULT_MAX_DESCRIPTORS-RESERVED_DESCRIPTORS;
        if( (fds=(nsock_iod *)calloc(max_iods, sizeof(nsock_iod)))==NULL ){
            nping_fatal(QT_3, "ProbeMode::probe_tcpconnect_event_handler(): Not enough memory");
        }
    }
    nping_print(DBG_7, "%d descriptors needed, %d available", o.getTotalProbes(), max_iods);
  }

 nping_print(DBG_4, "tcpconnect_event_handler(): Received callback of type %s with status %s", nse_type2str(type), nse_status2str(status));

 if (status == NSE_STATUS_SUCCESS ) {

  switch(type) {

    /* TCP Handshake was completed successfully */
    case NSE_TYPE_CONNECT:
        if( mypacket==NULL )
            nping_fatal(QT_3, "tcpconnect_event_handler(): NULL value supplied.");
        /* Determine which target are we dealing with */
        nsock_iod_get_communication_info(nsi, NULL, &family, NULL,
                                         (struct sockaddr*)&peer,
                                         sizeof(struct sockaddr_storage) );
        if(family==AF_INET6){
            inet_ntop(AF_INET6, &peer6->sin6_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer6->sin6_port);
        }else{
            inet_ntop(AF_INET, &peer4->sin_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer4->sin_port);
        }

        /* We cannot trust "mydata" pointer because it's contents may have
         * been overwritten by the time we get the CONNECT event, so we have
         * to look up the target by its IP address. */
        trg=o.targets.findTarget( &peer );
        if(trg!=NULL){
            if ( trg->getSuppliedHostName() )
                nping_print(VB_0,"RCVD (%.4fs) Handshake with %s:%d (%s:%d) completed",
                         o.stats.elapsedRuntime(t), trg->getSuppliedHostName(), peerport, ipstring, peerport );
            else
                nping_print(VB_0,"RCVD (%.4fs) Handshake with %s:%d completed", o.stats.elapsedRuntime(t), ipstring, peerport );
            trg->setProbeRecvTCP( peerport , 0);
        }else{
            nping_print(VB_0,"RCVD (%.4fs) Handshake with %s:%d completed", o.stats.elapsedRuntime(t), ipstring, peerport );
        }
        o.stats.addRecvPacket(40); /* Estimation Dst>We 1 TCP SYN|ACK */
    break;


    /* We need to start an scheduled TCP Handshake. Theoretically in this
     * case we can trust the supplied "mydata" structure because all our timers
     * have the same exact time and Nsock should do FIFO with list of timer
     * events.  Additionally, even if that failed, more than MAX_PKT timer
     * events would have to overlap to "corrupt" "mydata". Even if that's
     * the case, it is only a problem when dealing with multiple targets host
     * and/or multiple target ports. */
    case NSE_TYPE_TIMER:
        if( mypacket==NULL )
            nping_fatal(QT_3, "tcpconnect_event_handler():2: NULL value supplied.");

        /* Fill the appropriate sockaddr for the connect() call */
        if( o.getIPVersion() == IP_VERSION_6 ){
            to6->sin6_addr=mypacket->target->getIPv6Address();
            to6->sin6_family = AF_INET6;
            to6->sin6_port  = htons( mypacket->dstport );
            sslen=sizeof(struct sockaddr_in6);
        }else{
            to4->sin_addr=mypacket->target->getIPv4Address();
            to4->sin_family = AF_INET;
            to4->sin_port  = htons( mypacket->dstport );
            sslen=sizeof(struct sockaddr_in);
        }

        /* We need to keep many IODs open in parallel but we don't allocate
         * millions, just as many as the OS let us (max number of open files).
         * If we run out of them, we just start overwriting the oldest one.
         * If we don't have a response by that time we probably aren't gonna
         * get any, so it shouldn't be a big problem. */
        if( packetno>(u32)max_iods ){
            nsock_iod_delete(fds[packetno%max_iods], NSOCK_PENDING_SILENT);
        }
        /* Create new IOD for connects */
        if ((fds[packetno%max_iods] = nsock_iod_new(nsp, NULL)) == NULL)
            nping_fatal(QT_3, "tcpconnect_event_handler(): Failed to create new nsock_iod.\n");

        /* Set socket source address. This allows setting things like custom source port */
        struct sockaddr_storage ss;
        nsock_iod_set_localaddr(fds[packetno%max_iods], o.getSourceSockAddr(&ss), sizeof(sockaddr_storage));
        /*Set socket options for REUSEADDR*/
        //setsockopt(nsock_iod_get_sd(fds[packetno%max_iods]),SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));

        nsock_connect_tcp(nsp, fds[packetno%max_iods], tcpconnect_event_handler, 100000, mypacket, (struct sockaddr *)&to, sslen, mypacket->dstport);
        if( o.showSentPackets() ){
            if ( mypacket->target->getSuppliedHostName() )
                nping_print(VB_0,"SENT (%.4fs) Starting TCP Handshake > %s:%d (%s:%d)", o.stats.elapsedRuntime(NULL), mypacket->target->getSuppliedHostName(), mypacket->dstport ,mypacket->target->getTargetIPstr(), mypacket->dstport);
            else
                nping_print(VB_0,"SENT (%.4fs) Starting TCP Handshake > %s:%d", o.stats.elapsedRuntime(NULL), mypacket->target->getTargetIPstr(), mypacket->dstport);
        }
        packetno++;
        o.stats.addSentPacket(80); /* Estimation Src>Dst 1 TCP SYN && TCP ACK */
        mypacket->target->setProbeSentTCP(0, mypacket->dstport);
    break;

    case NSE_TYPE_WRITE:
    case NSE_TYPE_READ:
    case NSE_TYPE_PCAP_READ:
    case NSE_TYPE_CONNECT_SSL:
        nping_warning(QT_2,"tcpconnect_event_handler(): Unexpected behaviour, %s event received . Please report this bug.", nse_type2str(type));
    break;

    default:
        nping_fatal(QT_3, "tcpconnect_event_handler(): Bogus event type (%d). Please report this bug.", type);
    break;

  } /* switch(type) */


 } else if (status == NSE_STATUS_EOF) {
        nping_print(DBG_4, "tcpconnect_event_handler(): Unexpected behaviour: Got EOF. Please report this bug.\n");
 } else if (status == NSE_STATUS_ERROR) {
   /** In my tests with Nping and Wireshark, I've seen that we get NSE_STATUS_ERROR
    * whenever we start a TCP handshake but our peer sends a TCP RST packet back
    * denying the connection. So in this case, we inform the user (as opposed
    * to saying nothing, that's what we do when we don't get responses, e.g:
    * when trying to connect to filtered ports). This is not 100% accurate
    * because there may be other reasons why ge get NSE_STATUS_ERROR so that's
    * why we say "Possible TCP RST received". */
    if ( type == NSE_TYPE_CONNECT ){
        nsock_iod_get_communication_info(nsi, NULL, &family, NULL, (struct sockaddr*)&peer, sizeof(struct sockaddr_storage) );
        if(family==AF_INET6){
            inet_ntop(AF_INET6, &peer6->sin6_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer6->sin6_port);
        }else{
            inet_ntop(AF_INET, &peer4->sin_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer4->sin_port);
        }
        nping_print(VB_0,"RCVD (%.4fs) Possible TCP RST received from %s:%d --> %s", o.stats.elapsedRuntime(t),ipstring, peerport, strerror(nse_errorcode(nse)) );
     }
     else
        nping_warning(QT_2,"ERR: (%.4fs) %s to %s:%d failed: %s", o.stats.elapsedRuntime(t), nse_type2str(type), ipstring, peerport, strerror(socket_errno()));
 } else if (status == NSE_STATUS_TIMEOUT) {
    nping_print(DBG_4, "tcpconnect_event_handler(): %s timeout: %s\n", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_CANCELLED) {
    nping_print(DBG_4, "tcpconnect_event_handler(): %s canceled: %s", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_KILL) {
    nping_print(DBG_4, "tcpconnect_event_handler(): %s killed: %s", nse_type2str(type), strerror(socket_errno()));
 } else{
    nping_warning(QT_2, "tcpconnect_event_handler(): Unknown status code %d. Please report this bug.", status);
 }
 return;

} /* End of tcpconnect_event_handler() */





/** This function handles nsock events related to UDP_UNPRIV mode.
  * Basically the handler receives nsock events and takes the appropriate
  * action based on event type.  This is basically what it does for each event:
  *
  * TIMERS: normalProbeMode() schedules UDP packet transmissions through timers,
  * that's how we manage to send the packets at a given rate. When the alarm
  * goes off, nsock generates a timer event so, in this function, we take the
  * supplied "mydata" pointer, convert it to a sendpkt_t pointer and, from
  * the info stored there, we schedule a nsock_connect_udp() event. This means
  * that nsock will perform the necessary system calls to obtain a UDP socket
  * suitable to transmit information to our target host. We also schedule
  * a write operation, since the connect_udp() doesn't do anything useful
  * really and what we want to do is to actually send a TCP packet.
  *
  *
  * CONNECTS: These events generated by nsock for consistency with the
  * behavior in TCP connects. They are pretty useless. They merely indicate
  * that nsock successfully obtained a UDP socket ready to allow sending
  * packets to the appropriate target. We basically don't do anything when
  * that event is received, just print a message if we are un debugging mode.
  *
  * WRITES: When we get event WRITE it means that nsock actually managed to
  * get our data sent to the target. In this case, we inform the user that
  * the packet has been sent, and we schedule a READ operation, to see
  * if our peer actually returns any data.
  *
  * READS: When we get this event it means that the other end actually sent
  * some data back to us. What we do is read that data, tell the user that
  * we received some bytes and update statistics.
  *
  * */
void ProbeMode::probe_udpunpriv_event_handler(nsock_pool nsp, nsock_event nse, void *mydata) {

 nsock_iod nsi;                   /**< Current nsock IO descriptor.          */
 enum nse_status status;          /**< Current nsock event status.           */
 enum nse_type type;              /**< Current nsock event type.             */
 sendpkt_t *mypacket=NULL;        /**< Info about the current probe.         */
 struct timeval *t=NULL;          /**< Current time obtained through nsock.  */
 struct sockaddr_storage to;      /**< Stores destination address for Tx.    */
 struct sockaddr_in *to4=NULL;    /**<   |_ Sockaddr for IPv4.               */
 struct sockaddr_in6 *to6=NULL;   /**<   |_ Sockaddr for IPv6.               */
 struct sockaddr_storage peer;    /**< Stores source address for Rx.         */
 struct sockaddr_in *peer4=NULL;  /**<   |_ Sockaddr for IPv4.               */
 struct sockaddr_in6 *peer6=NULL; /**<   |_ Sockaddr for IPv6.               */
 int family=0;                    /**< Hill hold Rx address family.          */
 char ipstring[128];              /**< To print IP Addresses.                */
 u16 peerport=0;                  /**< To hold peer's port number.           */
 size_t sslen=0;                  /**< To store length of sockaddr structs.  */
 static nsock_iod *fds=NULL;      /**< IODs for multiple parallel connections*/
 static int max_iods=0;           /**< Number of IODS in "fds"               */
 static u32 packetno=0;           /**< Packets sent from this handler.       */
 int readbytes=0;                 /**< Bytes read in total.                  */
 char *readbuff=NULL;             /**< Hill hold read data.                  */
 static size_t sentbytes=0;       /**< Payload bytes sent in each UDP packet */
 NpingTarget *trg=NULL;           /**< Target we look up in NpingTargets::   */

 /* Initializations */
 nsi = nse_iod(nse);
 status = nse_status(nse);
 type = nse_type(nse);
 mypacket = (sendpkt_t *)mydata;
 t = (struct timeval *)nsock_gettimeofday();
 to6=(struct sockaddr_in6 *)&to;
 to4=(struct sockaddr_in *)&to;
 peer4=(struct sockaddr_in *)&peer;
 peer6=(struct sockaddr_in6 *)&peer;
 memset(&to, 0, sizeof(struct sockaddr_storage));
 memset(&peer, 0, sizeof(struct sockaddr_storage));

  /* Try to determine the max number of opened descriptors. If the limit is
   * less than than we need, try to increase it. */
  if(fds==NULL){
    max_iods=get_max_open_descriptors()-RESERVED_DESCRIPTORS;
    if( o.getTotalProbes() > max_iods ){
        max_iods=set_max_open_descriptors( o.getTotalProbes() )-RESERVED_DESCRIPTORS;
    }
    /* If we couldn't determine the limit, just use a predefined value */
    if(max_iods<=0)
        max_iods=DEFAULT_MAX_DESCRIPTORS-RESERVED_DESCRIPTORS;
    /* Allocate space for nsock_iods */
    if( (fds=(nsock_iod *)calloc(max_iods, sizeof(nsock_iod)))==NULL ){
        /* If we can't allocate for that many descriptors, reduce our requirements */
        max_iods=DEFAULT_MAX_DESCRIPTORS-RESERVED_DESCRIPTORS;
        if( (fds=(nsock_iod *)calloc(max_iods, sizeof(nsock_iod)))==NULL ){
            nping_fatal(QT_3, "ProbeMode:probe_udpunpriv_event_handler(): Not enough memory");
        }
    }
    nping_print(DBG_7, "%d descriptors needed, %d available", o.getTotalProbes(), max_iods);
  }

 nping_print(DBG_4, "udpunpriv_event_handler(): Received callback of type %s with status %s", nse_type2str(type), nse_status2str(status));

 if (status == NSE_STATUS_SUCCESS ) {

  switch(type) {


    /* This is a bit stupid but, for consistency, Nsock creates an event of
     * type NSE_TYPE_CONNECT after a call to nsock_connect_udp() is made.
     * Basically this just means that nsock successfully obtained a UDP socket
     * ready to allow sending packets to the appropriate target. */
    case NSE_TYPE_CONNECT:
            nping_print(DBG_3,"Nsock UDP \"connection\" completed successfully.");
    break;



    /* We need to start an scheduled UDP packet transmission. */
    case NSE_TYPE_TIMER:
        if( mypacket==NULL )
            nping_fatal(QT_3, "udpunpriv_event_handler():: NULL value supplied.");

        /* Fill the appropriate sockaddr for the connect() call */
        if( o.getIPVersion() == IP_VERSION_6 ){
            to6->sin6_addr=mypacket->target->getIPv6Address();
            to6->sin6_family = AF_INET6;
            to6->sin6_port  = htons( mypacket->dstport );
            sslen=sizeof(struct sockaddr_in6);
        }else{
            to4->sin_addr=mypacket->target->getIPv4Address();
            to4->sin_family = AF_INET;
            to4->sin_port  = htons( mypacket->dstport );
            sslen=sizeof(struct sockaddr_in);
        }

        /* We need to keep many IODs open in parallel but we don't allocate
         * millions, just as many as the OS let us (max number of open files).
         * If we run out of them, we just start overwriting the oldest one.
         * If we don't have a response by that time we probably aren't gonna
         * get any, so it shouldn't be a big problem. */
        if( packetno>(u32)max_iods ){
            nsock_iod_delete(fds[packetno%max_iods], NSOCK_PENDING_SILENT);
        }
        /* Create new IOD for connects */
        if ((fds[packetno%max_iods] = nsock_iod_new(nsp, NULL)) == NULL)
            nping_fatal(QT_3, "Failed to create new nsock_iod.  QUITTING.\n");

        /* Set socket source address. This allows setting things like custom source port */
        struct sockaddr_storage ss;
        nsock_iod_set_localaddr(fds[packetno%max_iods], o.getSourceSockAddr(&ss), sizeof(sockaddr_storage));


        /* I dunno if it's safe to schedule an nsock_write before we
         * receive a NSE_TYPE_CONNECT event. The call to nsock_connect_udp()
         * calls inheritable_socket() before returning which should mean
         * an actual socket() call has been made before we nsock_write().
         * However, if the way nsock behaves changes in the future it may
         * break this so we may need to place nsock_write() in
         * "case NSE_TYPE_CONNECT:". We could do it right now but it may
         * be a bit complicated due to the "packetno" index.
         */
        nsock_connect_udp(nsp, fds[packetno%max_iods], udpunpriv_event_handler, mypacket, (struct sockaddr *)&to, sslen, mypacket->dstport);
        nsock_write(nsp, fds[packetno%max_iods], udpunpriv_event_handler,100000, mypacket, (const char*)mypacket->pkt, mypacket->pktLen);
        sentbytes=mypacket->pktLen;
        packetno++;
    break;




    /* We get this event as a result of the nsock_write() call performed by
     * the code in charge of dealing with the timer event. When we get this
     * even it means that nsock successfully wrote data to the UDP socket so
     * here we basically just print that we did send some data and we schedule
     * a read operation.
     */
    case NSE_TYPE_WRITE:
        /* Determine which target are we dealing with */
        nsock_iod_get_communication_info(nsi, NULL, &family, NULL, (struct sockaddr*)&peer, sizeof(struct sockaddr_storage) );
        if(family==AF_INET6){
            inet_ntop(AF_INET6, &peer6->sin6_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer6->sin6_port);
        }else{
            inet_ntop(AF_INET, &peer4->sin_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer4->sin_port);
        }

        /* We cannot trust "mydata" pointer because it's contents may have
         * been overwritten by the time we get the WRITE event, (this is
         * unlikely but it may happen when sending probes at a very high rate).
         * As a consequence, we have to look up the target by its IP address. */
        trg=o.targets.findTarget( &peer );
        if(trg!=NULL){
            if ( trg->getSuppliedHostName() )
                nping_print(VB_0,"SENT (%.4fs) UDP packet with %lu bytes to %s:%d (%s:%d)", o.stats.elapsedRuntime(NULL),  (unsigned long int)sentbytes, trg->getSuppliedHostName(), peerport, ipstring, peerport );
            else
                nping_print(VB_0,"SENT (%.4fs) UDP packet with %lu bytes to %s:%d", o.stats.elapsedRuntime(NULL),  (unsigned long int)sentbytes, ipstring, peerport );
            trg->setProbeSentUDP( 0, peerport);
        }else{
            nping_print(VB_0,"SENT (%.4fs) UDP packet with %lu bytes to %s:%d", o.stats.elapsedRuntime(t), (unsigned long int)sentbytes, ipstring, peerport );
        }
        o.stats.addSentPacket(sentbytes); /* Here we don't count the headers, just payload bytes */

        /* If user did not disable packet capture, schedule a read operation */
        if( !o.disablePacketCapture() )
            nsock_read(nsp, nsi, udpunpriv_event_handler, DEFAULT_UDP_READ_TIMEOUT_MS, mypacket);
    break;



    /* We get this event when we've written some data to a UDP socket and
     * the other end has sent some data back. In this case we read the data and
     * inform the user of how many bytes we got.
     */
    case NSE_TYPE_READ:
        /* Do an actual read() of the recv data */
        readbuff=nse_readbuf(nse, &readbytes);
        if(readbuff==NULL){
            nping_fatal(QT_3, "Error: nse_readbuff failed to read in the from the probe");
        }
        /* Determine which target are we dealing with */
        nsock_iod_get_communication_info(nsi, NULL, &family, NULL, (struct sockaddr*)&peer, sizeof(struct sockaddr_storage) );
        if(family==AF_INET6){
            inet_ntop(AF_INET6, &peer6->sin6_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer6->sin6_port);
        }else{
            inet_ntop(AF_INET, &peer4->sin_addr, ipstring, sizeof(ipstring));
            peerport=ntohs(peer4->sin_port);
        }

        /* Lookup our peer's NpingTarget entry */
        trg=o.targets.findTarget( &peer );
        if(trg!=NULL){
            if ( trg->getSuppliedHostName() )
                nping_print(VB_0,"RCVD (%.4fs) UDP packet with %d bytes from %s:%d (%s:%d)", o.stats.elapsedRuntime(NULL),  readbytes, trg->getSuppliedHostName(), peerport, ipstring, peerport );
            else
                nping_print(VB_0,"RCVD (%.4fs) UDP packet with %d bytes from %s:%d", o.stats.elapsedRuntime(NULL),  readbytes, ipstring, peerport );
            trg->setProbeRecvUDP(peerport, 0);
        }else{
            nping_print(VB_0,"RCVD (%.4fs) UDP packet with %d bytes from %s:%d", o.stats.elapsedRuntime(t), readbytes, ipstring, peerport );
        }
        o.stats.addRecvPacket(readbytes);
    break;


    case NSE_TYPE_PCAP_READ:
    case NSE_TYPE_CONNECT_SSL:
        nping_warning(QT_2,"udpunpriv_event_handler(): Unexpected behavior, %s event received . Please report this bug.", nse_type2str(type));
    break;

    default:
        nping_fatal(QT_3, "udpunpriv_event_handler(): Bogus event type (%d). Please report this bug.", type);
    break;

  } /* switch(type) */


 } else if (status == NSE_STATUS_EOF) {
    nping_print(DBG_4, "udpunpriv_event_handler(): Unexpected behaviour: Got EOF. Please report this bug.\n");
 } else if (status == NSE_STATUS_ERROR) {
    nsock_iod_get_communication_info(nsi, NULL, &family, NULL, (struct sockaddr*)&peer, sizeof(struct sockaddr_storage) );
    if(family==AF_INET6){
        inet_ntop(AF_INET6, &peer6->sin6_addr, ipstring, sizeof(ipstring));
        peerport=ntohs(peer6->sin6_port);
    }else{
        inet_ntop(AF_INET, &peer4->sin_addr, ipstring, sizeof(ipstring));
        peerport=ntohs(peer4->sin_port);
    }
    nping_warning(QT_2,"ERR: (%.4fs) %s to %s:%d failed: %s", o.stats.elapsedRuntime(t), nse_type2str(type), ipstring, peerport, strerror(socket_errno()));
 } else if (status == NSE_STATUS_TIMEOUT) {
       nping_print(DBG_4, "udpunpriv_event_handler(): %s timeout: %s\n", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_CANCELLED) {
       nping_print(DBG_4, "udpunpriv_event_handler(): %s canceled: %s", nse_type2str(type), strerror(socket_errno()));
 } else if (status == NSE_STATUS_KILL) {
       nping_print(DBG_4, "udpunpriv_event_handler(): %s killed: %s", nse_type2str(type), strerror(socket_errno()));
 }
 else{
       nping_warning(QT_2, "udpunpriv_event_handler(): Unknown status code %d. Please report this bug.", status);
 }
 return;

} /* End of udpunpriv_event_handler() */



/* This handler is a wrapper for the ProbeMode::probe_nping_event_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void nping_event_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ProbeMode::probe_nping_event_handler(nsp, nse, arg);
  return;
} /* End of nping_event_handler() */


/* This handler is a wrapper for the ProbeMode::probe_tcpconnect_event_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void tcpconnect_event_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ProbeMode::probe_tcpconnect_event_handler(nsp, nse, arg);
  return;
} /* End of tcpconnect_event_handler() */


/* This handler is a wrapper for the ProbeMode::probe_udpunpriv_event_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void udpunpriv_event_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ProbeMode::probe_udpunpriv_event_handler(nsp, nse, arg);
  return;
} /* End of udpunpriv_event_handler() */



/* This handler is a wrapper for the ProbeMode::probe_delayed_output_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void delayed_output_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  ProbeMode::probe_delayed_output_handler(nsp, nse, arg);
  return;
} /* End of udpunpriv_event_handler() */
