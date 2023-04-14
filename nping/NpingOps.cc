
/***************************************************************************
 * NpingOps.cc -- The NpingOps class contains global options, mostly based *
 * on user-provided command-line settings.                                 *
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

#ifdef WIN32
#include "winfix.h"
#endif

#include "nping.h"
#include "nbase.h"
#include "NpingOps.h"
#include "utils.h"
#include "utils_net.h"
#include "ArgParser.h"
#include "output.h"
#include "common.h"


/******************************************************************************
 *  Constructors and destructors                                              *
 ******************************************************************************/

/* Constructor */
NpingOps::NpingOps() {

    /* Probe modes */
    mode=0;
    mode_set=false;

    traceroute=false;
    traceroute_set=false;

    /* Output */
    vb=DEFAULT_VERBOSITY;
    vb_set=false;

    dbg=DEFAULT_DEBUGGING;
    dbg_set=false;

    show_sent_pkts=true;
    show_sent_pkts_set=false;

    /* Operation and Performance */
    pcount=0;
    pcount_set=false;

    sendpref=0;
    sendpref_set=false;

    send_eth=false;
    send_eth_set=false;

    delay=0;
    delay_set=false;

    memset(device, 0, MAX_DEV_LEN);
    device_set=false;

    spoofsource=false;
    spoofsource_set=false;

    bpf_filter_spec=NULL;
    bpf_filter_spec_set=false;

    current_round=0;

    have_pcap=true;

    disable_packet_capture=false;
    disable_packet_capture_set=false;

    /* Privileges */
/* If user did not specify --privileged or --unprivileged explicitly, try to
 * determine if has root privileges. */
#if defined WIN32 || defined __amigaos__
    /* TODO: Check this because although nmap does exactly the same, it has a this->have_pcap that may affect to this */
    isr00t=true;
#else
  if (getenv("NMAP_PRIVILEGED") || getenv("NPING_PRIVILEGED"))
    isr00t=true;
  else if (getenv("NMAP_UNPRIVILEGED") || getenv("NPING_UNPRIVILEGED"))
    isr00t=false;
  else
    isr00t = !(geteuid());
#endif

    /* Payloads */
    payload_type=PL_NONE;
    payload_type_set=false;

    payload_buff=NULL;
    payload_buff_set=false;

    payload_len=0;
    payload_len_set=false;

    /* Roles */
    role=0;
    role_set=false;

    /* IP */
    ttl=0;
    ttl_set=false;

    tos=0;
    tos_set=false;

    identification=0;
    identification_set=false;

    mf=false;
    mf_set=false;

    df=false;
    df_set=false;

    mtu=0;
    mtu_set=false;

    badsum_ip=false;
    badsum_ip_set=false;

    ipversion=0;
    ipversion_set=false;

    memset(&ipv4_src_address, 0, sizeof(struct in_addr));
    ipv4_src_address_set=false;

    ip_options=NULL;
    ip_options_set=false;

    /* IPv6 */
    ipv6_tclass=0;
    ipv6_tclass_set=false;

    ipv6_flowlabel=0;
    ipv6_flowlabel_set=false;

    memset(&ipv6_src_address, 0, sizeof(struct in6_addr));
    ipv6_src_address_set=false;

    /* TCP / UDP */
    target_ports=NULL;
    tportcount=0;
    target_ports_set=false;

    source_port=0;
    source_port_set=false;

    tcpseq=0;
    tcpseq_set=false;

    memset(tcpflags, 0, 8);
    tcpflags_set=false;

    tcpack=0;
    tcpack_set=false;

    tcpwin=0;
    tcpwin_set=false;

    badsum=false;
    badsum_set=false;

    /* ICMP */
    icmp_type=0;
    icmp_type_set=false;

    icmp_code=0;
    icmp_code_set=false;

    badsum_icmp=false;
    badsum_icmp_set=false;

    icmp_redir_addr.s_addr=0;
    icmp_redir_addr_set=false;

    icmp_paramprob_pnt=0;
    icmp_paramprob_pnt_set=false;

    icmp_routeadv_ltime=0;
    icmp_routeadv_ltime_set=false;

    icmp_id=0;
    icmp_id_set=false;

    icmp_seq=0;
    icmp_seq_set=false;

    icmp_orig_time=0;
    icmp_orig_time_set=false;

    icmp_recv_time=0;
    icmp_recv_time_set=false;

    icmp_trans_time=0;
    icmp_trans_time_set=false;

    memset( icmp_advert_entry_addr, 0, sizeof(u32)*MAX_ICMP_ADVERT_ENTRIES );
    memset( icmp_advert_entry_pref, 0, sizeof(u32)*MAX_ICMP_ADVERT_ENTRIES );
    icmp_advert_entry_count=0;
    icmp_advert_entry_set=false;

    /* Ethernet */
    memset(src_mac, 0, 6);
    src_mac_set=false;

    memset(dst_mac, 0, 6);
    dst_mac_set=false;

    eth_type=0;
    eth_type_set=false;

    arp_htype=0;
    arp_htype_set=false;

    /* ARP/RARP */
    arp_ptype=0;
    arp_ptype_set=false;

    arp_hlen=0;
    arp_hlen_set=false;

    arp_plen=0;
    arp_plen_set=false;

    arp_opcode=0;
    arp_opcode_set=false;

    memset(arp_sha, 0, 6);
    arp_sha_set=false;

    memset(arp_tha, 0, 6);
    arp_tha_set=false;

    arp_spa.s_addr=0;
    arp_spa_set=false;

    arp_tpa.s_addr=0;
    arp_tpa_set=false;

    /* Echo mode */
    echo_port=DEFAULT_ECHO_PORT;
    echo_port_set=false;

    do_crypto=true;

    echo_payload=false;

    echo_server_once=false;
    echo_server_once_set=false;

    memset(echo_passphrase, 0, sizeof(echo_passphrase));
    echo_passphrase_set=false;

    memset(&last_sent_pkt_time, 0, sizeof(struct timeval));

    delayed_rcvd_str=NULL;
    delayed_rcvd_str_set=false;

} /* End of NpingOps() */


/* Destructor */
NpingOps::~NpingOps() {
 if (payload_buff!=NULL)
    free(payload_buff);
 if ( ip_options!=NULL )
    free(ip_options);
 if ( target_ports!=NULL )
    free(target_ports);
 if (delayed_rcvd_str_set)
   free(delayed_rcvd_str);
 return;
} /* End of ~NpingOps() */


/******************************************************************************
 *  Nping probe modes                                                         *
 ******************************************************************************/

/** Sets attribute "mode". Mode must be one of: TCP_CONNECT TCP, UDP, ICMP,
 *  ARP
 *  @return OP_SUCCESS on success.
 *  @return OP_FAILURE in case of error. */
int NpingOps::setMode(int md) {
  if ( md!=TCP_CONNECT && md!=TCP && md!=UDP && md!=UDP_UNPRIV && md!=ICMP && md!=ARP )
    return OP_FAILURE;
  else{
    this->mode=md;
    this->mode_set=true;
  }
  return OP_SUCCESS;
} /* End of setMode() */


/** Returns value of attribute "mode". The value returned is supposed to be
 *  one of : TCP_CONNECT, TCP, UDP, UDP_UNPRIV, ICMP, ARP */
int NpingOps::getMode() {
  return mode;
} /* End of getMode() */


/* Returns true if option has been set */
bool NpingOps::issetMode(){
  return this->mode_set;
} /* End of isset() */


/** Takes a probe mode and returns an ASCII string with the name of the mode.
 *  @warning Returned pointer is a static buffer that subsequent calls
 *            will overwrite.
 *  @return Pointer to the appropriate string on success and pointer to a
 *          string containing "Unknown probe" in case of failure.
 * */
char * NpingOps::mode2Ascii(int md) {
  static char buff[24];

  switch( md ){
    case TCP_CONNECT:
        sprintf(buff, "TCP-Connect");
    break;

    case TCP:
        sprintf(buff, "TCP");
    break;

    case UDP:
        sprintf(buff, "UDP");
    break;

    case UDP_UNPRIV:
        sprintf(buff, "UDP-Unprivileged");
    break;

    case ICMP:
        sprintf(buff, "ICMP");
    break;

    case ARP:
        sprintf(buff, "ARP");
    break;

    default:
        sprintf(buff, "Unknown mode");
    break;
 }
 return buff;
} /* End of mode2Ascii() */


/** Returns value of attribute "traceroute" */
bool NpingOps::getTraceroute() {
  return traceroute;
} /* End of getTraceroute() */


/** Sets attribute traceroute to "true".
 *  @return previous value of the attribute. */
bool NpingOps::enableTraceroute() {
  bool prev = traceroute;
  this->traceroute=true;
  this->traceroute_set=true;
  return prev;
} /* End of enableTraceroute() */


/** Sets attribute traceroute to "false".
 *  @return previous value of the attribute. */
bool NpingOps::disableTraceroute() {
  bool prev = traceroute;
  this->traceroute=false;
  this->traceroute_set=true;
  return prev;
} /* End of disableTraceroute() */


/* Returns true if option has been set */
bool NpingOps::issetTraceroute(){
  return this->traceroute_set;
} /* End of issetTraceroute() */


/******************************************************************************
 * Output                                                                     *
 ******************************************************************************/

/** Sets verbosity level. Supplied level must be an integer between -4 and
 *  4. Check man pages for details.
 *
 *  The thing here is that what the argument parser gets from the user is
 *  number in the range [-4, 4]. However, in NpingOps we don't store negative
 *  verbosity values, we just convert the supplied level into our internal
 *  levels (QT_4, QT_3, ... , VB_0, VB_1, ..., VB_4)
 *  So the rest of the code in Nping should check for these defines, rather
 *  than checking for numbers. Check nping.h for more information on how to
 *  handle verbosity levels.
 *
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setVerbosity(int level){
   if( level < -4 || level > 4 ){
        nping_fatal(QT_3,"setVerbosity(): Invalid verbosity level supplied\n");
        return OP_FAILURE;
   }else{
        switch(level){
            case -4:  vb=QT_4;  break;
            case -3:  vb=QT_3;  break;
            case -2:  vb=QT_2;  break;
            case -1:  vb=QT_1;  break;
            case  0:  vb=VB_0;  break;
            case  1:  vb=VB_1;  break;
            case  2:  vb=VB_2;  break;
            case  3:  vb=VB_3;  break;
            case  4:  vb=VB_4;  break;
            default:
                nping_fatal(QT_3,"setVerbosity():2: Invalid verbosity level supplied\n");
            break;
        }
    }
    this->vb_set=true;
    return OP_SUCCESS;
} /* End of setVerbosity() */


/** Returns value of attribute vb (current verbosity level) */
int NpingOps::getVerbosity(){
  return vb;
} /* End of getVerbosity() */



/* Returns true if option has been set */
bool NpingOps::issetVerbosity(){
  return this->vb_set;
} /* End of issetVerbosity() */


/** Increments verbosity level by one. (When it reaches VB_4 it stops
  * getting incremented)
  * @return previous verbosity level */
int NpingOps::increaseVerbosity(){
  this->vb_set=true;
  if (vb < VB_4){
    vb++;
    return vb-1;
  }else{
    return vb;
  }
} /* End of increaseVerbosity() */


/** Decreases verbosity level by one. (When it reaches QT_4 it stops
  * getting incremented)
  * @return previous verbosity level */
int NpingOps::decreaseVerbosity(){
  this->vb_set=true;
  if (vb > QT_4){
    vb--;
    return vb+1;
  }else{
    return vb;
  }
} /* End of decreaseVerbosity() */


/** Sets debugging level. Supplied level must be an integer between DBG_0 and
 *  DBG_9. Check file nping.h for details
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setDebugging(int level){
  if( level < 0 || level > 9){
    nping_fatal(QT_3,"setDebugging(): Invalid debugging level supplied\n");
    return OP_FAILURE;
  }else{
    this->dbg= DBG_0  + level;
  }
  this->dbg_set=true;
  return OP_SUCCESS;
} /* End of setDebugging() */


/** Returns value of attribute dbg (current debugging level) */
int NpingOps::getDebugging(){
  return dbg;
} /* End of getDebugging() */


/** Increments debugging level by one. (When it reaches DBG_9 it stops
  * getting incremented)
  *   * @return previous verbosity level */
int NpingOps::increaseDebugging(){
  this->dbg_set=true;
  if (dbg < DBG_9){
    dbg++;
    return dbg-1;
  }else{
    return dbg;
  }
} /* End of increaseDebugging() */


/* Returns true if option has been set */
bool NpingOps::issetDebugging(){
    return this->dbg_set;
} /* End of issetDebugging() */


/** Sets ShowSentPackets.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setShowSentPackets(bool val){
  this->show_sent_pkts=val;
  this->show_sent_pkts_set=true;
  return OP_SUCCESS;
} /* End of setShowSentPackets() */


/** Returns value of attribute show_sent_pkts */
bool NpingOps::showSentPackets(){
  return this->show_sent_pkts;
} /* End of showSentPackets() */


/* Returns true if option has been set */
bool NpingOps::issetShowSentPackets(){
  return this->show_sent_pkts_set;
} /* End of issetShowSentPackets() */



/******************************************************************************
 *  Operation and Performance                                                 *
 ******************************************************************************/

/** Sets packet count (number of packets that should be sent to each target)
 *  Supplied parameter must be a non-negative integer.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setPacketCount(u32 val){
  /* If zero is supplied, use the highest possible value */
  if( val==0 )
    this->pcount=0xFFFFFFFF;
  else
    pcount=val;
  this->pcount_set=true;
  return OP_SUCCESS;
} /* End of setPacketCount() */


/** Returns value of attribute pcount (number of packets that should be sent
 *  to each target)  */
u32 NpingOps::getPacketCount(){
  return this->pcount;
} /* End of getPacketCount() */


/* Returns true if option has been set */
bool NpingOps::issetPacketCount(){
  return this->pcount_set;
} /* End of issetPacketCount() */


/** Sets attribute sendpref which defines user's preference for packet
 *  sending. Supplied parameter must be an integer with one of these values:
 *  PACKET_SEND_NOPREF, PACKET_SEND_ETH_WEAK, PACKET_SEND_ETH_STRONG,
 *  PACKET_SEND_ETH, PACKET_SEND_IP_WEAK, PACKET_SEND_IP_STRONG, PACKET_SEND_IP
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setSendPreference(int v){
   if( v!=PACKET_SEND_NOPREF && v!=PACKET_SEND_ETH_WEAK &&
       v!=PACKET_SEND_ETH_STRONG && v!=PACKET_SEND_ETH &&
       v!=PACKET_SEND_IP_WEAK && v!=PACKET_SEND_IP_STRONG &&
       v!=PACKET_SEND_IP ){
        nping_fatal(QT_3,"setSendPreference(): Invalid value supplied\n");
        return OP_FAILURE;
    }else{
        sendpref=v;
    }
    this->sendpref_set=true;
    return OP_SUCCESS;
} /* End of setSendPreference() */


/** Returns value of attribute sendpref */
int NpingOps::getSendPreference(){
  return this->sendpref;
} /* End of getSendPreference() */


/* Returns true if option has been set */
bool NpingOps::issetSendPreference(){
  return this->sendpref_set;
} /* End of issetSendPreference() */


/* Returns true if send preference is Ethernet */
bool NpingOps::sendPreferenceEthernet(){
  if ( this->getSendPreference()==PACKET_SEND_ETH_WEAK )
    return true;
  else if (this->getSendPreference()==PACKET_SEND_ETH_STRONG)
    return true;
  else if (this->getSendPreference()==PACKET_SEND_ETH )
    return true;
  else
    return false;
} /* End of sendPreferenceEthernet() */


/* Returns true if send preference is Ethernet */
bool NpingOps::sendPreferenceIP(){
  if ( this->getSendPreference()==PACKET_SEND_IP_WEAK )
    return true;
  else if (this->getSendPreference()==PACKET_SEND_IP_STRONG)
    return true;
  else if (this->getSendPreference()==PACKET_SEND_IP )
    return true;
  else
    return false;
} /* End of sendPreferenceIP() */


/** Sets SendEth.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setSendEth(bool val){
  this->send_eth=val;
  this->send_eth_set=true;
  return OP_SUCCESS;
} /* End of setSendEth() */


/** Returns value of attribute send_eth */
bool NpingOps::sendEth(){
  return this->send_eth;
} /* End of getSendEth() */


/* Returns true if option has been set */
bool NpingOps::issetSendEth(){
  return this->send_eth_set;
} /* End of issetSendEth() */


/** Sets inter-probe delay. Supplied parameter is assumed to be in milliseconds
 *  and must be a long integer greater than zero.
 *  @warning timeout is assumed to be in milliseconds. Use tval2msecs() from
 *           nbase to obtain a proper value.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setDelay(long t){
  if( t < 0 )
    nping_fatal(QT_3,"setDelay(): Invalid time supplied\n");
  this->delay=t;
  this->delay_set=true;
  return OP_SUCCESS;
} /* End of setDelay() */


/** Returns value of attribute delay */
long NpingOps::getDelay(){
  return delay;
} /* End of getDelay() */


/* Returns true if option has been set */
bool NpingOps::issetDelay(){
  return this->delay_set;
} /* End of issetDelay() */


/** Sets network device. Supplied parameter must be a valid network interface
 *  name.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setDevice(char *n){
  if( n==NULL ){
    nping_fatal(QT_3,"setDevice(): Invalid value supplied\n");
  }else{
    Strncpy(this->device, n, MAX_DEV_LEN-1);
  }
  this->device_set=true;
  return OP_SUCCESS;
} /* End of setDevice() */


char *NpingOps::getDevice(){
  return this->device;
} /* End of getDevice() */


/* Returns true if option has been set */
bool NpingOps::issetDevice(){
  return this->device_set;
} /* End of issetDevice() */


/** Returns true if user requested explicitly that he wants IP source
 *  spoofing */
bool NpingOps::spoofSource(){
  return this->spoofsource;
} /* End of spoofSource() */


bool NpingOps::getSpoofSource(){
  return this->spoofsource;
} /* End of getSpoofSource() */


int NpingOps::setSpoofSource(){
  this->spoofsource=true;
  this->spoofsource_set=true;
  return OP_SUCCESS;
} /* End of spoofSource() */


/* Returns true if option has been set */
bool NpingOps::issetSpoofSource(){
  return this->spoofsource_set;
} /* End of issetSpoofSource() */


/** Sets BPFFilterSpec.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setBPFFilterSpec(char *val){
  this->bpf_filter_spec=val;
  this->bpf_filter_spec_set=true;
  return OP_SUCCESS;
} /* End of setBPFFilterSpec() */


/** Returns value of attribute bpf_filter_spec */
char *NpingOps::getBPFFilterSpec(){
  return this->bpf_filter_spec;
} /* End of getBPFFilterSpec() */


/* Returns true if option has been set */
bool NpingOps::issetBPFFilterSpec(){
  return this->bpf_filter_spec_set;
} /* End of issetBPFFilterSpec() */


/** Sets CurrentRound.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setCurrentRound(int val){
  this->current_round=val;
  return OP_SUCCESS;
} /* End of setCurrentRound() */


/** Returns value of attribute current_round */
int NpingOps::getCurrentRound(){
  return this->current_round;
} /* End of getCurrentRound() */


bool NpingOps::havePcap(){
  return this->have_pcap;
} /* End of havePcap() */


int NpingOps::setHavePcap(bool val){
  this->have_pcap=val;
  return OP_SUCCESS;
} /* End of setHavePcap() */


/** Sets DisablePacketCapture.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setDisablePacketCapture(bool val){
  this->disable_packet_capture=val;
  this->disable_packet_capture_set=true;
  return OP_SUCCESS;
} /* End of setDisablePacketCapture() */


/** Returns value of attribute disable_packet_capture */
bool NpingOps::disablePacketCapture(){
  return this->disable_packet_capture;
} /* End of disablePacketCapture() */


/* Returns true if option has been set */
bool NpingOps::issetDisablePacketCapture(){
  return this->disable_packet_capture_set;
} /* End of issetDisablePacketCapture() */

/** Sets the IP version that will be used in all packets. Supplied parameter
 *  must be either IP_VERSION_4 or IP_VERSION_&.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setIPVersion(u8 val){
  if( val!=IP_VERSION_4 && val!=IP_VERSION_6 ){
    nping_fatal(QT_3,"setIPVersion(): Invalid value supplied\n");
    return OP_FAILURE;
  }else{
    this-> ipversion=val;
  }
  this->ipversion_set=true;
  return OP_SUCCESS;
} /* End of setIPVersion() */


/** Returns value of attribute ipversion. */
int NpingOps::getIPVersion(){
  return ipversion;
} /* End of getIPVersion() */


/* Returns true if option has been set */
bool NpingOps::issetIPVersion(){
  return this->ipversion_set;
} /* End of issetIPversion() */


/* Returns true if we are using IPv4 */
bool NpingOps::ipv4(){
  if( this->getIPVersion() == IP_VERSION_4 )
    return true;
  else
    return false;
} /* End of ipv4() */


/* Returns true if we are using IPv6 */
bool NpingOps::ipv6(){
  if( this->getIPVersion() == IP_VERSION_6 )
    return true;
  else
    return false;
} /* End of ipv6() */


/* Returns true if we are sending IPv6 packets at raw TCP level (using a
 * useless and boring IPv6 socket that doesn't let us include our own IPv6
 * header)*/
bool NpingOps::ipv6UsingSocket(){
  if( this->getIPVersion() == IP_VERSION_6 && this->sendEth()==false)
    return true;
  else
    return false;
} /* End of ipv6UsingSocket() */


/* Returns AF_INET or AF_INET6, depending on current configuration */
int NpingOps::af(){
  if( this->getIPVersion() == IP_VERSION_6 )
    return AF_INET6;
  else
    return AF_INET;
} /* End of af() */


/******************************************************************************
 *  User types and Privileges                                                 *
 ******************************************************************************/

/** Sets value of attribute isr00t.
 *  @returns previous isr00t value */
int NpingOps::setIsRoot(int v) {
  int prev=this->isr00t;
  this->isr00t = (v==0) ? 0 : 1;
  return prev;
} /* End of setIsRoot() */


/** Sets attribute isr00t to value 1.
 *  @returns previous isr00t value */
int NpingOps::setIsRoot() {
  int prev=this->isr00t;
  this->isr00t=1;
 return prev;
} /* End of setIsRoot() */


/* Returns the state of attribute isr00t */
bool NpingOps::isRoot() {
  return (this->isr00t);
} /* End of isRoot() */


/******************************************************************************
 *  Payloads                                                                  *
 ******************************************************************************/

/** Sets payload type. Supplied parameter must be one of: PL_RAND, PL_HEX or
 *  PL_FILE;
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setPayloadType(int t){
  if( t!=PL_RAND && t!=PL_HEX && t!=PL_FILE && t!=PL_STRING){
    nping_fatal(QT_3,"setPayloadType(): Invalid value supplied\n");
    return OP_FAILURE;
  }else{
    payload_type=t;
  }
  this->payload_type_set=true;
  return OP_SUCCESS;
} /* End of setPayloadType() */


/** Returns value of attribute payload_type */
int NpingOps::getPayloadType(){
  return payload_type;
} /* End of getPayloadType() */


/* Returns true if option has been set */
bool NpingOps::issetPayloadType(){
  return this->payload_type_set;
} /* End of issetPayloadType() */


/** Sets payload buffer pointer. Supplied pointer must be a free()able
 *  non-NULL pointer; Supplied length must be a positive integer.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setPayloadBuffer(u8 *p, int len){
  if( p==NULL || len < 0 ){
    nping_fatal(QT_3,"setPayloadBuffer(): Invalid value supplied\n");
    return OP_FAILURE;
  }else{
    this->payload_buff=p;
    this->payload_len=len;
  }
  this->payload_buff_set=true;
  this->payload_len_set=true;
  return OP_SUCCESS;
} /* End of setPayloadBuffer() */


/** Returns value of attribute payload_type */
u8 *NpingOps::getPayloadBuffer(){
  return this->payload_buff;
} /* End of getPayloadBuffer() */


/* Returns true if option has been set */
bool NpingOps::issetPayloadBuffer(){
  return this->payload_buff_set;
} /* End of issetPayloadBuffer() */


/** Returns value of attribute payload_len */
int NpingOps::getPayloadLen(){
  return this->payload_len;
} /* End of getPayloadLen() */


/* Returns true if option has been set */
bool NpingOps::issetPayloadLen(){
  return this->payload_len_set;
} /* End of issetPayloadLen() */


/******************************************************************************
 *  Roles (normal, client, server... )                                        *
 ******************************************************************************/

/** Sets nping's role. Supplied argument must be one of: ROLE_NORMAL,
 *  ROLE_CLIENT or ROLE_SERVER.
 *  @return previous value of attribute "role" or OP_FAILURE in case of error.
 *  */
int NpingOps::setRole(int r){
  int prev = this->role;
  if (r!=ROLE_NORMAL && r!=ROLE_CLIENT && r!=ROLE_SERVER){
    nping_warning(QT_2,"setRoleClient(): Invalid role supplied");
    return OP_FAILURE;
  }
  else
    this->role=r;
  this->role_set=true;
  return prev;
} /* End of setRole() */


/** Sets nping's role to ROLE_CLIENT.
 *  @return previous value of attribute "role".  */
int NpingOps::setRoleClient(){
  int prev = this->role;
  this->role=ROLE_CLIENT;
  this->role_set=true;
  return prev;
} /* End of setRoleClient() */


/** Sets nping's role to ROLE_SERVER.
 *  @return previous value of attribute "role". */
int NpingOps::setRoleServer(){
  int prev = this->role;
  this->role=ROLE_SERVER;
  this->role_set=true;
  return prev;
} /* End of setRoleServer() */


/** Sets nping's role to ROLE_NORMAL.
 *  @return previous value of attribute "role". */
int NpingOps::setRoleNormal(){
  int prev = this->role;
  this->role=ROLE_NORMAL;
  this->role_set=true;
  return prev;
} /* End of setRoleNormal() */

/* Returns nping role. */
int NpingOps::getRole(){
  return this->role;
} /* End of getRole() */


/* Returns true if option has been set */
bool NpingOps::issetRole(){
  return this->role_set;
} /* End of issetRole() */



/******************************************************************************
 * Internet Protocol  Version 4                                               *
 ******************************************************************************/

/** Sets IPv4 TTL / IPv6 hop limit. Supplied parameter must be an integer
 *  between 0 and 255 (included).
 *  @return OP_SUCCESS                                                       */
int NpingOps::setTTL(u8 t){
  this->ttl=t;
  this->ttl_set=true;
  return OP_SUCCESS;
} /* End of setTTL() */


/** Sets IPv4 TTL / IPv6 hop limit. This a wrapper for setTTL(). It is provided
 *  for consistency with IPv6 option setters.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setHopLimit(u8 t){
  return setTTL(t);
} /* End of setHopLimit() */


/** Returns value of attribute ttl */
u8 NpingOps::getTTL(){
  return ttl;
} /* End of getTTL() */


/** Returns value of attribute ttl */
u8 NpingOps::getHopLimit(){
  return getTTL();
} /* End of getHopLimit() */


/* Returns true if option has been set */
bool NpingOps::issetTTL(){
  return this->ttl_set;
} /* End of issetTTL() */


/* Returns true if option has been set */
bool NpingOps::issetHopLimit(){
  return issetTTL();
} /* End of issetHopLimit() */


/** Sets IP TOS. Supplied parameter must be 0<=n<=255
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setTOS(u8 val){
  this->tos=val;
  this->tos_set=true;
  return OP_SUCCESS;
} /* End of setTOS() */


/** Returns value of attribute TOS */
u8 NpingOps::getTOS(){
  return this->tos;
} /* End of getTOS() */


/* Returns true if option has been set */
bool NpingOps::issetTOS(){
  return this->tos_set;
} /* End of isset() */


/** Sets IP Identification. Supplied parameter must be 0<=n<=255
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setIdentification(u16 val){
  this->identification=val;
  this->identification_set=true;
  return OP_SUCCESS;
} /* End of setIdentification() */


/** Returns value of attribute Identification */
u16 NpingOps::getIdentification(){
  return this->identification;
} /* End of getIdentification() */


/* Returns true if option has been set */
bool NpingOps::issetIdentification(){
  return this->identification_set;
} /* End of issetIdentification() */


int NpingOps::setMF(){
  this->mf = true;
  this->mf_set=true;
  return OP_SUCCESS;
} /* End of setMF() */


/* Get MF flag */
bool NpingOps::getMF(){
  return this->mf;
} /* End of getMF() */


/** Set DF flag */
int NpingOps::setDF(){
  this->df = true;
  this->df_set=true;
  return OP_SUCCESS;
} /* End of setDF() */


/** Get DF flag */
bool NpingOps::getDF(){
  return this->df;
} /* End of getDF() */


/** Set Reserved / Evil flag */
int NpingOps::setRF(){
  this->rf = true;
  this->rf_set = true;
  return OP_SUCCESS;
} /* End of setRF() */


/** Get Reserved / Evil flag */
bool NpingOps::getRF(){
  return this->rf;
} /* End of getRF() */


/* Returns true if option has been set */
bool NpingOps::issetMF(){
  return this->mf_set;
} /* End of isset() */


/* Returns true if option has been set */
bool NpingOps::issetDF(){
  return this->df_set;
} /* End of isset() */


/* Returns true if option has been set */
bool NpingOps::issetRF(){
  return this->rf_set;
} /* End of isset() */


/** Sets Maximum Transmission Unit length. Supplied parameter must be a positive
 *  integer and must be a multiple of 8.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setMTU(u32 t){
  if(t==0 || (t%8)!=0){
    nping_fatal(QT_3,"setMTU(): Invalid mtu supplied\n");
  }else{
    this->mtu=t;
    this->mtu_set=true;
  }
  return OP_SUCCESS;
} /* End of setMTU() */


/** Returns value of attribute mtu */
u32 NpingOps::getMTU(){
  return this->mtu;
} /* End of getMTU() */


/* Returns true if option has been set */
bool NpingOps::issetMTU(){
  return this->mtu_set;
} /* End of issetMTU() */


/** Sets attribute badsum_ip to "true". (Generate invalid checksums in IP
 *  packets)
 *  @return previous value of the attribute. */
bool NpingOps::enableBadsumIP() {
  bool prev = this->badsum_ip;
  this->badsum_ip=true;
  this->badsum_ip_set=true;
  return prev;
} /* End of enableBadsumIP() */


/** Sets attribute badsum_ip to "false". (Do NOT Generate invalid checksums
 *  in IP packets)
 *  @return previous value of the attribute. */
bool NpingOps::disableBadsumIP() {
   bool prev = badsum_ip;
   badsum_ip=false;
   this->badsum_ip_set=true;
   return prev;
} /* End of disableBadsumIP() */


/** Returns value of attribute badsum_ip */
bool NpingOps::getBadsumIP() {
   return this->badsum_ip;
} /* End of getBadsumIP() */


/* Returns true if option has been set */
bool NpingOps::issetBadsumIP(){
  return this->badsum_ip_set;
} /* End of issetBadsumIP() */


/** @warning Supplied parameter must be in NETWORK byte order */
int NpingOps::setIPv4SourceAddress(struct in_addr i){
  this->ipv4_src_address=i;
  this->ipv4_src_address_set=true;
  return OP_SUCCESS;
} /* End of setIPv4SourceAddress() */


struct in_addr NpingOps::getIPv4SourceAddress(){
  return ipv4_src_address;
} /* End of getIPv4SourceAddress() */


/* Returns true if option has been set */
bool NpingOps::issetIPv4SourceAddress(){
  return this->ipv4_src_address_set;
} /* End of issetIPv4SourceAddress() */


/** @warning  This method makes a copy of the supplied buffer. That copy will
 *  be free()ed by the NpingOps destructor.                                  */
int NpingOps::setIPOptions(char *txt){
  if (txt==NULL)
    nping_fatal(QT_3,"setIPOptions(): NULL pointer supplied\n");
  this->ip_options=strdup(txt) ;
  this->ip_options_set=true;
  return OP_SUCCESS;
} /* End of setIPOptions() */


char *NpingOps::getIPOptions(){
  return this->ip_options;
} /* End of getIPOptions() */


bool NpingOps::issetIPOptions(){
  return this->ip_options_set;
} /* End of issetIPOptions() */


/******************************************************************************
 * Internet Protocol  Version 6                                               *
 ******************************************************************************/
/** Sets TrafficClass.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setTrafficClass(u8 val){
  this->ipv6_tclass=val;
  this->ipv6_tclass_set=true;
  return OP_SUCCESS;
} /* End of setTrafficClass() */


/** Returns value of attribute ipv6_tclass */
u8 NpingOps::getTrafficClass(){
  return this->ipv6_tclass;
} /* End of getTrafficClass() */


/* Returns true if option has been set */
bool NpingOps::issetTrafficClass(){
  return this->ipv6_tclass_set;
} /* End of issetTrafficClass() */


/** Sets FlowLabel.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setFlowLabel(u32 val){
  this->ipv6_flowlabel=val;
  this->ipv6_flowlabel_set=true;
  return OP_SUCCESS;
} /* End of setFlowLabel() */


/** Returns value of attribute ipv6_flowlabel */
u32 NpingOps::getFlowLabel(){
  return this->ipv6_flowlabel;
} /* End of getFlowLabel() */


/* Returns true if option has been set */
bool NpingOps::issetFlowLabel(){
  return this->ipv6_flowlabel_set;
} /* End of issetFlowLabel() */



int NpingOps::setIPv6SourceAddress(u8 *val){
  if(val==NULL)
    nping_fatal(QT_3,"setIPv6SourceAddress(): NULL pointer supplied\n");
  memcpy(this->ipv6_src_address.s6_addr, val, 16);
  this->ipv6_src_address_set=true;
  return OP_SUCCESS;
} /* End of setIPv6SourceAddress() */


int NpingOps::setIPv6SourceAddress(struct in6_addr val){
  this->ipv6_src_address = val;
  this->ipv6_src_address_set=true;
  return OP_SUCCESS;
} /* End of setIPv6SourceAddress() */


struct in6_addr NpingOps::getIPv6SourceAddress(){
  return ipv6_src_address;
} /* End of getIPv6SourceAddress() */


/* Returns true if option has been set */
bool NpingOps::issetIPv6SourceAddress(){
  return this->ipv6_src_address_set;
} /* End of issetIPv6SourceAddress() */


/* Returns a pointer to a sockaddr_storage structure that contains the
 * source IP address. This function takes into account this->getIPVersion()
 * an returns an IPv4 sockaddr_in or an IPv6 sockaddr_in6 struct.  */
struct sockaddr_storage *NpingOps::getSourceSockAddr(){
  static struct sockaddr_storage ss;
  return getSourceSockAddr(&ss);
} /* End of getSourceSockAddr() */


/* Returns a pointer to the supplied sockaddr_storage structure that now
 * contains the source IP address. This function takes into account
 * this->getIPVersion() an returns an IPv4 sockaddr_in or an IPv6
 * sockaddr_in6 struct.  */
struct sockaddr_storage *NpingOps::getSourceSockAddr(struct sockaddr_storage *ss){
  struct sockaddr_in *s4 = (struct sockaddr_in*)ss;
  struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ss;
  memset(ss, 0, sizeof(struct sockaddr_storage));
  if( this->getIPVersion() == IP_VERSION_4){
    if(this->spoofSource())
        s4->sin_addr=getIPv4SourceAddress();
    else
        s4->sin_addr.s_addr=INADDR_ANY;
    s4->sin_family=AF_INET;
    if(this->issetSourcePort())
        s4->sin_port=htons(this->getSourcePort());
    else
        s4->sin_port=0;
  }
  else if (this->getIPVersion() == IP_VERSION_6){
    if(this->spoofSource())
        s6->sin6_addr=this->getIPv6SourceAddress();
    else
        s6->sin6_addr=in6addr_any;
    s6->sin6_addr=this->getIPv6SourceAddress();
    s6->sin6_family=AF_INET6;
    if(this->issetSourcePort())
        s6->sin6_port=htons(this->getSourcePort());
    else
        s6->sin6_port=0;
  }else{
    nping_fatal(QT_3, "NpingOps::getSourceSockAddr(): IP version unset.");
  }
  return ss;
} /* End of getSourceSockAddr() */



/******************************************************************************
 * Transmission Control Protocol and User Datagram Protocol                   *
 ******************************************************************************/

/** @warning Returned ports are in HOST byte order */
u16 *NpingOps::getTargetPorts( int *len ){
  if( this->tportcount <= 0)
    return NULL;
  if(len!=NULL)
    *len=this->tportcount;
  return this->target_ports;
} /* End of getTargetPorts() */


/** @warning ports in the supplied array must be in HOST byte order */
int NpingOps::setTargetPorts( u16 *pnt, int n ){
  if(this->tportcount>65536 || this->tportcount<0)
    nping_fatal(QT_3, "setTargetPorts():: Invalid number of ports supplied.");
  this->target_ports=pnt;
  this->tportcount=n;
  this->target_ports_set=true;
  return OP_SUCCESS;
} /* End of setTargetPorts() */


/* Returns true if option has been set */
bool NpingOps::issetTargetPorts(){
  return this->target_ports_set;
} /* End of issetTargetPorts() */

/*Returns true if the scan type can use the -p option*/
bool NpingOps::scan_mode_uses_target_ports(int mode){
    return (mode==TCP_CONNECT || mode==TCP || mode == UDP || mode == UDP_UNPRIV);
} /*End of scan_mode_uses_target_ports*/

/** Sets TCP/UPD source port. Supplied parameter must be an integer >=0 &&
 * <=65535
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setSourcePort(u16 val){
  this->source_port=val;
  this->source_port_set=true;
  return OP_SUCCESS;
} /* End of setSourcePort() */


/** Returns value of attribute source_port */
u16 NpingOps::getSourcePort(){
  return this->source_port;
} /* End of getSourcePort() */


/* Returns true if option has been set */
bool NpingOps::issetSourcePort(){
  return this->source_port_set;
} /* End of issetSourcePort() */


/** Sets TCP Seq number. Supplied parameter must be a positive integer between
 *  0 and 2^32 -1
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setTCPSequence(u32 val){
  this->tcpseq=val;
  this->tcpseq_set=true;
  return OP_SUCCESS;
} /* End of setTCPSequence() */


/** Returns value of attribute tcpseq */
u32 NpingOps::getTCPSequence(){
  return this->tcpseq;
} /* End of getTCPSequence() */


/** Returns true if option has been set */
bool NpingOps::issetTCPSequence(){
  return this->tcpseq_set;
} /* End of issetTCPSequence() */


/** Sets TCP Ack. Supplied parameter must be a positive integer between 0 and
 *  2^32 -1
 *  @return OP_SUCCESS                                                       */
int NpingOps::setTCPAck(u32 val){
  this->tcpack=val;
  this->tcpack_set=true;
  return OP_SUCCESS;
} /* End of setTCPAck() */


/** Returns value of attribute tcpack */
u32 NpingOps::getTCPAck(){
  return this->tcpack;
} /* End of getTCPAck() */


/** Returns true if option has been set */
bool NpingOps::issetTCPAck(){
  return this->tcpack_set;
} /* End of issetTCPAck() */


int NpingOps::setFlagTCP(int flag){
  if (flag < FLAG_CWR || flag > FLAG_FIN)
    nping_fatal(QT_3,"setFlagTCP(): Invalid flag supplied\n");
  else
    this->tcpflags[flag]=1;
  this->tcpflags_set=true;
  return OP_SUCCESS;
} /* End of setFlagTCP() */


int NpingOps::setAllFlagsTCP(){
  for(int i=FLAG_CWR; i<=FLAG_FIN; i++)
    this->tcpflags[i]=1;
  this->tcpflags_set=true;
  return OP_SUCCESS;
} /* End of setFlagTCP() */


int NpingOps::unsetAllFlagsTCP(){
  for(int i=FLAG_CWR; i<=FLAG_FIN; i++)
    this->tcpflags[i]=0;
  this->tcpflags_set=true;
  return OP_SUCCESS;
} /* End of setFlagTCP() */


int NpingOps::getFlagTCP(int flag){
  if (flag < FLAG_CWR || flag > FLAG_FIN)
    nping_fatal(QT_3,"setFlagTCP(): Invalid flag supplied\n");
  return this->tcpflags[flag];
} /* End of getFlagTCP() */


u8 NpingOps::getTCPFlags(){
 u8 octet=0x00;
  if(this->getFlagTCP(FLAG_CWR))
    octet |= TH_CWR;
  if(this->getFlagTCP(FLAG_ECN))
    octet |= TH_ECN;
  if(this->getFlagTCP(FLAG_URG))
    octet |= TH_URG;
  if(this->getFlagTCP(FLAG_ACK))
    octet |= TH_ACK;
  if(this->getFlagTCP(FLAG_PSH))
    octet |= TH_PSH;
  if(this->getFlagTCP(FLAG_RST))
    octet |= TH_RST;
  if(this->getFlagTCP(FLAG_SYN))
    octet |= TH_SYN;
  if(this->getFlagTCP(FLAG_FIN))
    octet |= TH_FIN;
 return octet;
} /* End of getTCPFlags() */


/* Returns true if option has been set */
bool NpingOps::issetTCPFlags(){
  return this->tcpflags_set;
} /* End of isset() */


/** Sets TCP Window. Supplied parameter must be a positive integer between 0 and
 *  2^32 -1
 *  @return OP_SUCCESS                                                       */
int NpingOps::setTCPWindow(u16 val){
  this->tcpwin=val;
  this->tcpwin_set=true;
  return OP_SUCCESS;
} /* End of setTCPWindow() */


/** Returns value of attribute tcpwin */
u16 NpingOps::getTCPWindow(){
  return this->tcpwin;
} /* End of getTCPWindow() */


/** Returns true if option has been set */
bool NpingOps::issetTCPWindow(){
  return this->tcpwin_set;
} /* End of issetTCPWindow() */


/** Sets attribute badsum to "true". (Generate invalid checksums in UDP / TCP
 *  packets)
 *  @return previous value of the attribute. */
bool NpingOps::enableBadsum() {
  bool prev = this->badsum;
  this->badsum=true;
  this->badsum_set=true;
  return prev;
} /* End of enableBadsumTCP() */


/** Sets attribute traceroute to "false". (Do NOT Generate invalid checksums
 *  in UDP / TCP packets)
 *  @return previous value of the attribute. */
bool NpingOps::disableBadsum() {
  bool prev = this->badsum;
  this->badsum=false;
  this->badsum_set=true;
  return prev;
} /* End of disableBadsum() */


/** Returns value of attribute badsum */
bool NpingOps::getBadsum() {
  return this->badsum;
} /* End of getBadsum() */


/* Returns true if option has been set */
bool NpingOps::issetBadsum(){
  return this->badsum_set;
} /* End of issetBadsum() */



/******************************************************************************
 *  Internet Control Message Protocol                                         *
 ******************************************************************************/
/** Sets ICMPType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPType(u8 val){
  this->icmp_type=val;
  this->icmp_type_set=true;
  return OP_SUCCESS;
} /* End of setICMPType() */


/** Returns value of attribute icmp_type */
u8 NpingOps::getICMPType(){
  return this->icmp_type;
} /* End of getICMPType() */


/* Returns true if option has been set */
bool NpingOps::issetICMPType(){
  return this->icmp_type_set;
} /* End of issetICMPType() */


/** Sets ICMPCode.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPCode(u8 val){
  this->icmp_code=val;
  this->icmp_code_set=true;
  return OP_SUCCESS;
} /* End of setICMPCode() */


/** Returns value of attribute icmp_code */
u8 NpingOps::getICMPCode(){
  return this->icmp_code;
} /* End of getICMPCode() */


/* Returns true if option has been set */
bool NpingOps::issetICMPCode(){
  return this->icmp_code_set;
} /* End of issetICMPCode() */


/** Sets attribute badsum_icmp to "true". (Generate invalid checksums in ICMP
 *  packets)
 *  @return previous value of the attribute. */
bool NpingOps::enableBadsumICMP() {
  bool prev = this->badsum_icmp;
  this->badsum_icmp=true;
  this->badsum_icmp_set=true;
  return prev;
} /* End of enableBadsumICMPTCP() */


/** Sets attribute traceroute to "false". (Do NOT Generate invalid checksums
 *  in UDP / TCP packets)
 *  @return previous value of the attribute. */
bool NpingOps::disableBadsumICMP() {
  bool prev = this->badsum_icmp;
  this->badsum_icmp=false;
  this->badsum_icmp_set=true;
  return prev;
} /* End of disableBadsumICMP() */


/** Returns value of attribute badsum_icmp */
bool NpingOps::getBadsumICMP() {
  return this->badsum_icmp;
} /* End of getBadsumICMP() */


/* Returns true if option has been set */
bool NpingOps::issetBadsumICMP(){
  return this->badsum_icmp_set;
} /* End of issetBadsumICMP() */


/** Sets ICMPRedirectAddress.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPRedirectAddress(struct in_addr val){
  this->icmp_redir_addr=val;
  this->icmp_redir_addr_set=true;
  return OP_SUCCESS;
} /* End of setICMPRedirectAddress() */


/** Returns value of attribute icmp_redir_addr */
struct in_addr NpingOps::getICMPRedirectAddress(){
  return this->icmp_redir_addr;
} /* End of getICMPRedirectAddress() */


/* Returns true if option has been set */
bool NpingOps::issetICMPRedirectAddress(){
  return this->icmp_redir_addr_set;
} /* End of issetICMPRedirectAddress() */


/** Sets ICMPParamProblemPointer.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPParamProblemPointer(u8 val){
  this->icmp_paramprob_pnt=val;
  this->icmp_paramprob_pnt_set=true;
  return OP_SUCCESS;
} /* End of setICMPParamProblemPointer() */


/** Returns value of attribute icmp_paramprob_pnt */
u8 NpingOps::getICMPParamProblemPointer(){
  return this->icmp_paramprob_pnt;
} /* End of getICMPParamProblemPointer() */


/* Returns true if option has been set */
bool NpingOps::issetICMPParamProblemPointer(){
  return this->icmp_paramprob_pnt_set;
} /* End of issetICMPParamProblemPointer() */


/** Sets ICMPRouterAdvLifetime.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPRouterAdvLifetime(u16 val){
  this->icmp_routeadv_ltime=val;
  this->icmp_routeadv_ltime_set=true;
  return OP_SUCCESS;
} /* End of setICMPRouterAdvLifetime() */


/** Returns value of attribute icmp_routeadv_ltime */
u16 NpingOps::getICMPRouterAdvLifetime(){
  return this->icmp_routeadv_ltime;
} /* End of getICMPRouterAdvLifetime() */


/* Returns true if option has been set */
bool NpingOps::issetICMPRouterAdvLifetime(){
  return this->icmp_routeadv_ltime_set;
} /* End of issetICMPRouterAdvLifetime() */


/** Sets ICMPIdentifier.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPIdentifier(u16 val){
  this->icmp_id=val;
  this->icmp_id_set=true;
  return OP_SUCCESS;
} /* End of setICMPIdentifier() */

/** Returns value of attribute icmp_id */
u16 NpingOps::getICMPIdentifier(){
  return this->icmp_id;
} /* End of getICMPIdentifier() */


/* Returns true if option has been set */
bool NpingOps::issetICMPIdentifier(){
  return this->icmp_id_set;
} /* End of issetICMPIdentifier() */


/** Sets ICMPSequence.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPSequence(u16 val){
  this->icmp_seq=val;
  this->icmp_seq_set=true;
  return OP_SUCCESS;
} /* End of setICMPSequence() */


/** Returns value of attribute icmp_seq */
u16 NpingOps::getICMPSequence(){
  return this->icmp_seq;
} /* End of getICMPSequence() */


/* Returns true if option has been set */
bool NpingOps::issetICMPSequence(){
  return this->icmp_seq_set;
} /* End of issetICMPSequence() */


/** Sets ICMPOriginateTimestamp.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPOriginateTimestamp(u32 val){
  this->icmp_orig_time=val;
  this->icmp_orig_time_set=true;
  return OP_SUCCESS;
} /* End of setICMPOriginateTimestamp() */


/** Returns value of attribute icmp_orig_time */
u32 NpingOps::getICMPOriginateTimestamp(){
  return this->icmp_orig_time;
} /* End of getICMPOriginateTimestamp() */


/* Returns true if option has been set */
bool NpingOps::issetICMPOriginateTimestamp(){
  return this->icmp_orig_time_set;
} /* End of issetICMPOriginateTimestamp() */


/** Sets ICMPReceiveTimestamp.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPReceiveTimestamp(u32 val){
  this->icmp_recv_time=val;
  this->icmp_recv_time_set=true;
  return OP_SUCCESS;
} /* End of setICMPReceiveTimestamp() */


/** Returns value of attribute icmp_recv_time */
u32 NpingOps::getICMPReceiveTimestamp(){
  return this->icmp_recv_time;
} /* End of getICMPReceiveTimestamp() */


/* Returns true if option has been set */
bool NpingOps::issetICMPReceiveTimestamp(){
  return this->icmp_recv_time_set;
} /* End of issetICMPReceiveTimestamp() */


/** Sets ICMPTransmitTimestamp.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setICMPTransmitTimestamp(u32 val){
  this->icmp_trans_time=val;
  this->icmp_trans_time_set=true;
  return OP_SUCCESS;
} /* End of setICMPTransmitTimestamp() */


/** Returns value of attribute icmp_trans_time */
u32 NpingOps::getICMPTransmitTimestamp(){
  return this->icmp_trans_time;
} /* End of getICMPTransmitTimestamp() */


/* Returns true if option has been set */
bool NpingOps::issetICMPTransmitTimestamp(){
  return this->icmp_trans_time_set;
} /* End of issetICMPTransmitTimestamp() */


int NpingOps::addICMPAdvertEntry(struct in_addr addr, u32 pref ){
  if( this->icmp_advert_entry_count > MAX_ICMP_ADVERT_ENTRIES )
    return OP_FAILURE;
  this->icmp_advert_entry_addr[this->icmp_advert_entry_count] = addr;
  this->icmp_advert_entry_pref[this->icmp_advert_entry_count] = pref;
  this->icmp_advert_entry_count++;
  this->icmp_advert_entry_set=true;
  return OP_SUCCESS;
} /* End of addICMPAdvertEntry() */


/** @param num means that the caller wants to obtain the num-th entry.
 *  Count starts in 0 so the supplied value must be
 *  0 <= num < getICMPAdvertEntryCount() */
int NpingOps::getICMPAdvertEntry(int num, struct in_addr *addr, u32 *pref){
  if( num<0 || num>=icmp_advert_entry_count )
    nping_fatal(QT_3,"getICMPAdvertEntry(): Supplied index is out of bounds.\n");
  if( addr==NULL || pref==NULL)
    nping_fatal(QT_3,"getICMPAdvertEntry(): NULL pointer supplied\n");
  *addr =  this->icmp_advert_entry_addr[num];
  *pref =  this->icmp_advert_entry_pref[num];
  return OP_SUCCESS;
} /* End of getICMPAdvertEntry() */


int NpingOps::getICMPAdvertEntryCount(){
  return this->icmp_advert_entry_count;
} /* End of getICMPAdvertEntryCount()*/

bool NpingOps::issetICMPAdvertEntry(){
  return this->icmp_advert_entry_set;
} /* End of issetICMPAdvertEntry()*/



/******************************************************************************
 *  Ethernet                                                                  *
 ******************************************************************************/
/** Sets SourceMAC.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setSourceMAC(u8 * val){
  memcpy(this->src_mac, val, 6);
  this->src_mac_set=true;
  return OP_SUCCESS;
} /* End of setSourceMAC() */


/** Returns value of attribute src_mac */
u8 * NpingOps::getSourceMAC(){
  return this->src_mac;
} /* End of getSourceMAC() */


/* Returns true if option has been set */
bool NpingOps::issetSourceMAC(){
  return this->src_mac_set;
} /* End of issetSourceMAC() */


/** Sets DestMAC.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setDestMAC(u8 * val){
  memcpy(this->dst_mac, val, 6);
  this->dst_mac_set=true;
  return OP_SUCCESS;
} /* End of setDestMAC() */


/** Returns value of attribute dst_mac */
u8 * NpingOps::getDestMAC(){
  return this->dst_mac;
} /* End of getDestMAC() */


/* Returns true if option has been set */
bool NpingOps::issetDestMAC(){
  return this->dst_mac_set;
} /* End of issetDestMAC() */

/** Sets EtherType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setEtherType(u16 val){
  this->eth_type=val;
  this->eth_type_set=true;
  return OP_SUCCESS;
} /* End of setEtherType() */


/** Returns value of attribute eth_type */
u16 NpingOps::getEtherType(){
  return this->eth_type;
} /* End of getEtherType() */


/* Returns true if option has been set */
bool NpingOps::issetEtherType(){
  return this->eth_type_set;
} /* End of issetEtherType() */



/******************************************************************************
 *  Address Resolution Protocol / Reverse Address Resolution Protocol         *
 ******************************************************************************/
/** Sets ARPHardwareType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPHardwareType(u16 val){
  this->arp_htype=val;
  this->arp_htype_set=true;
  return OP_SUCCESS;
} /* End of setARPHardwareType() */


/** Returns value of attribute arp_htype */
u16 NpingOps::getARPHardwareType(){
  return this->arp_htype;
} /* End of getARPHardwareType() */


/* Returns true if option has been set */
bool NpingOps::issetARPHardwareType(){
  return this->arp_htype_set;
} /* End of issetARPHardwareType() */


/** Sets ARPProtocolType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPProtocolType(u16 val){
  this->arp_ptype=val;
  this->arp_ptype_set=true;
  return OP_SUCCESS;
} /* End of setARPProtocolType() */


/** Returns value of attribute arp_ptype */
u16 NpingOps::getARPProtocolType(){
  return this->arp_ptype;
} /* End of getARPProtocolType() */


/* Returns true if option has been set */
bool NpingOps::issetARPProtocolType(){
  return this->arp_ptype_set;
} /* End of issetARPProtocolType() */


/** Sets ARPHwAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPHwAddrLen(u8 val){
  this->arp_hlen=val;
  this->arp_hlen_set=true;
  return OP_SUCCESS;
} /* End of setARPHwAddrLen() */


/** Returns value of attribute arp_hlen */
u8 NpingOps::getARPHwAddrLen(){
  return this->arp_hlen;
} /* End of getARPHwAddrLen() */


/* Returns true if option has been set */
bool NpingOps::issetARPHwAddrLen(){
  return this->arp_hlen_set;
} /* End of issetARPHwAddrLen() */


/** Sets ARPProtoAddrLen.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPProtoAddrLen(u8 val){
  this->arp_plen=val;
  this->arp_plen_set=true;
  return OP_SUCCESS;
} /* End of setARPProtoAddrLen() */


/** Returns value of attribute arp_plen */
u8 NpingOps::getARPProtoAddrLen(){
  return this->arp_plen;
} /* End of getARPProtoAddrLen() */


/* Returns true if option has been set */
bool NpingOps::issetARPProtoAddrLen(){
  return this->arp_plen_set;
} /* End of issetARPProtoAddrLen() */


/** Sets ARPOpCode.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPOpCode(u16 val){
  this->arp_opcode=val;
  this->arp_opcode_set=true;
  return OP_SUCCESS;
} /* End of setARPOpCode() */


/** Returns value of attribute arp_opcode */
u16 NpingOps::getARPOpCode(){
  return this->arp_opcode;
} /* End of getARPOpCode() */


/* Returns true if option has been set */
bool NpingOps::issetARPOpCode(){
  return this->arp_opcode_set;
} /* End of issetARPOpCode() */


/** Sets ARPSenderHwAddr.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPSenderHwAddr(u8 * val){
  memcpy(this->arp_sha, val, 6); /* MAC Address (6 bytes) */
  this->arp_sha_set=true;
  return OP_SUCCESS;
} /* End of setARPSenderHwAddr() */


/** Returns value of attribute arp_sha */
u8 * NpingOps::getARPSenderHwAddr(){
  return this->arp_sha;
} /* End of getARPSenderHwAddr() */


/* Returns true if option has been set */
bool NpingOps::issetARPSenderHwAddr(){
  return this->arp_sha_set;
} /* End of issetARPSenderHwAddr() */


/** Sets ARPTargetHwAddr.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPTargetHwAddr(u8 * val){
  memcpy(this->arp_tha, val, 6); /* MAC Address (6 bytes) */
  this->arp_tha_set=true;
  return OP_SUCCESS;
} /* End of setARPTargetHwAddr() */


/** Returns value of attribute arp_tha */
u8 * NpingOps::getARPTargetHwAddr(){
  return this->arp_tha;
} /* End of getARPTargetHwAddr() */


/* Returns true if option has been set */
bool NpingOps::issetARPTargetHwAddr(){
  return this->arp_tha_set;
} /* End of issetARPTargetHwAddr() */


/** Sets ARPSenderProtoAddr.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPSenderProtoAddr(struct in_addr val){
  this->arp_spa=val;
  this->arp_spa_set=true;
  return OP_SUCCESS;
} /* End of setARPSenderProtoAddr() */


/** Returns value of attribute arp_spa */
struct in_addr NpingOps::getARPSenderProtoAddr(){
  return this->arp_spa;
} /* End of getARPSenderProtoAddr() */


/* Returns true if option has been set */
bool NpingOps::issetARPSenderProtoAddr(){
  return this->arp_spa_set;
} /* End of issetARPSenderProtoAddr() */


/** Sets ARPTargetProtoAddr.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setARPTargetProtoAddr(struct in_addr val){
  this->arp_tpa=val;
  this->arp_tpa_set=true;
  return OP_SUCCESS;
} /* End of setARPTargetProtoAddr() */


/** Returns value of attribute arp_tpa */
struct in_addr NpingOps::getARPTargetProtoAddr(){
  return this->arp_tpa;
} /* End of getARPTargetProtoAddr() */


/* Returns true if option has been set */
bool NpingOps::issetARPTargetProtoAddr(){
  return this->arp_tpa_set;
} /* End of issetARPTargetProtoAddr() */


/** Sets EchoPort.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int NpingOps::setEchoPort(u16 val){
  this->echo_port=val;
  this->echo_port_set=true;
  return OP_SUCCESS;
} /* End of setEchoPort() */


/** Returns value of attribute echo_port */
u16 NpingOps::getEchoPort(){
  return this->echo_port;
} /* End of getEchoPort() */


/* Returns true if option has been set */
bool NpingOps::issetEchoPort(){
  return this->echo_port_set;
} /* End of issetEchoPort() */


int NpingOps::setEchoPassphrase(const char *str){
  strncpy(this->echo_passphrase, str, sizeof(echo_passphrase)-1);
  this->echo_passphrase_set=true;
  return OP_SUCCESS;
} /* End of setEchoPassphrase() */


char *NpingOps::getEchoPassphrase(){
  return this->echo_passphrase;
} /* End of getEchoPassphrase() */


bool NpingOps::issetEchoPassphrase(){
  return this->echo_passphrase_set;
} /* End of issetEchoPassphrase() */

/** Sets value of this->echo_server_once. When true, the echo server
  * will exit after attending one client. */
int NpingOps::setOnce(bool val){
  this->echo_server_once=val;
  this->echo_server_once_set=true;
  return OP_SUCCESS;
} /* End of once() */


/** Returns value of attribute echo_port */
bool NpingOps::once(){
  return this->echo_server_once;
} /* End of once() */


/******************************************************************************
 *  Option Validation                                                         *
 ******************************************************************************/

void NpingOps::validateOptions() {

/** DETERMINE ROOT PRIVILEGES ************************************************/
const char *privreq = "root privileges";
#ifdef WIN32
    //if (!this->have_pcap)
          privreq = "Npcap, but it seems to be missing.\n\
Npcap is available from https://npcap.com. The Npcap driver service must\n\
be started by an administrator before Npcap can be used. Running nping.exe\n\
will open a UAC dialog where you can start the service if you have\n\
administrator privileges.";
#endif

if (this->havePcap()==false){
    #ifdef WIN32
        nping_fatal(QT_3, "Nping requires %s", privreq);
    #else
        nping_fatal(QT_3, "Nping requires libpcap to be installed on your system.");
    #endif
}


/** ROLE SELECTION ***********************************************************/
  /* Ensure that at least one role is selected */
  if ( !this->issetRole() ) {
      this->setRoleNormal();
  }

/** TARGET SPECIFICATION *****************************************************/
  /* Check if user entered at least one target spec */
  if( this->getRole() == ROLE_NORMAL ){
    if ( this->targets.getTargetSpecCount() <= 0 )
        nping_fatal(QT_3,"WARNING: No targets were specified, so 0 hosts pinged.");
  }else if( this->getRole() == ROLE_CLIENT ){
    if ( this->targets.getTargetSpecCount() <= 0 )
        nping_fatal(QT_3,"No echo server was specified.");
  }

/** IP VERSION ***************************************************************/
  /* Default to IP version 4 */
  if( !this->issetIPVersion() )
    this->setIPVersion( IP_VERSION_4 );


/** PROBE MODE SELECTION *****************************************************/
  /* Ensure that one probe mode is selected */
  if( !this->issetMode() ){
      if ( this->isRoot() ){
        if( !this->ipv6() )
            this->setMode(ICMP);
        else
            this->setMode(TCP);
      }
      else
        this->setMode(TCP_CONNECT);
  }

/** PACKET COUNT / ROUNDS ****************************************************/
  if( !this->issetPacketCount() ){
      /* If --traceroute is set, the packet count is higher */
      if(this->issetTraceroute() )
          this->setPacketCount( TRACEROUTE_PACKET_COUNT );
      else
          this->setPacketCount( DEFAULT_PACKET_COUNT );
  }


  if( !this->issetDelay() )
    this->setDelay( DEFAULT_DELAY );

/** UDP UNPRIVILEGED MODE? ***************************************************/
  /* If user is NOT root and specified UDP mode, check if he did not specify
   * any option that requires privileges. In that case, we enter
   * UDP-Unprivileged mode, where users can send UDP packets and read responses
   * trough a normal UDP socket.  */
  if( !this->isRoot() && this->getMode()==UDP && canRunUDPWithoutPrivileges() )
    this->setMode( UDP_UNPRIV );

/** CHECK PRIVILEGES FOR CURRENT ROLE ****************************************/
  if( !this->isRoot() && (this->getRole()==ROLE_SERVER || this->getRole()==ROLE_CLIENT) )
    nping_fatal(QT_3,"Echo mode requires %s.", privreq);

/** CHECK PRIVILEGES FOR CURRENT MODE ****************************************/
  if( !this->isRoot() && this->getMode()!=UDP_UNPRIV && this->getMode()!=TCP_CONNECT )
    nping_fatal(QT_3,"Mode %s requires %s.", this->mode2Ascii( this->getMode() ), privreq);


/** DEFAULT HEADER PARAMETERS *************************************************/
  this->setDefaultHeaderValues();

/** ARP MODE RELATED PARAMETERS *********************************************/
  if(this->getMode()==ARP && this->ipv6()) {
    nping_fatal(QT_3, "Sorry, ARP does not support IPv6 and Nping does not yet support NDP.");
  }

/** TCP CONNECT RELATED PARAMETERS *********************************************/
  if(this->getMode()==TCP_CONNECT) {
      if(this->issetPayloadBuffer())
        nping_print(VB_0, "Warning: Payload supplied in TCP Connect mode. Payload will be ignored.");
  }

/** SOURCE IP, SOURCE MAC and NETWORK DEVICE *********************************/
/* If we are in a mode where we need to craft IP packets, then we need to
 * obtain a network interface name and a source IP address. There are three
 * different possibilities:
 *  1. User did NOT specify both network interface and source IP address.
 *  2. User did specify a network interface but not a source IP address.
 *  3. User did actually supply a source IP but not a network interface name
 *
 * I know the following code is ugly but the thing is that we want to determine
 * interface and source IP without user intervention, so we try in many ways
 * until either we succeed or we run out of possibilities and fatal().
 */
if( this->getMode()!=TCP_CONNECT && this->getMode()!=UDP_UNPRIV && this->getRole()!=ROLE_SERVER){

    char devbuff[32];
    char *dev;
    struct sockaddr_storage ss, ifaddr;
    struct sockaddr_in *s4=(struct sockaddr_in *)&ifaddr;
    struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ifaddr;
    size_t ss_len;
    char hostname[128];
    memset(&ss, 0, sizeof(struct sockaddr_storage));
    memset(&ifaddr, 0, sizeof(struct sockaddr_storage));


   /* CASE 1: User did not specify a device so we have to select one. */
    if( !this->issetDevice() ){
        if( this->ipv4() ){
            /* Ugly hack. Get the first resolvable target and determine net interface. Let's
             * hope user did not specify something that mixes localhost with
             * other targets, like "nping localhost google.com playboy.com" */
             for(int z=0; z<this->targets.getTargetSpecCount(); z++){
                if( this->targets.getNextTargetAddressAndName(&ss, &ss_len, hostname, sizeof(hostname)) == OP_SUCCESS )
                    break;
                else if( z>=(this->targets.getTargetSpecCount()-1) )
                    nping_fatal(QT_3,"Cannot find a valid target. Please make sure the specified hosts are either IP addresses in standard notation or hostnames that can be resolved with DNS");
             }
             this->targets.rewind();

             /* Try to obtain a device name from the target IP */
             if ( getNetworkInterfaceName( &ss , devbuff) != OP_SUCCESS ) {
                /* If that didn't work, ask libpcap */
                if ( (dev = this->select_network_iface()) == NULL)
                    nping_fatal(QT_3, "Cannot obtain device for packet capture");
                else
                    this->setDevice( dev );
                /* Libpcap gave us a device name, try to obtain it's IP */
                if ( devname2ipaddr_alt(this->getDevice(), &ifaddr) != 0 ){
                    if( this->isRoot() )
                        nping_fatal(QT_3,"Cannot figure out what source address to use for device %s, does it even exist?", this->getDevice());
                    else
                        nping_fatal(QT_3,"Cannot figure out what source address to use for device %s, are you root?", this->getDevice());
                }
                else{
                    if( s4->sin_family==AF_INET )
                        this->setIPv4SourceAddress(s4->sin_addr);
                    else if ( s6->sin6_family==AF_INET6 )
                        this->setIPv6SourceAddress(s6->sin6_addr.s6_addr);
                }
            }else{
                this->setDevice(devbuff);
            }
        }else{ /* In IPv6 we just select one in libpcap and hope is the right one */
            char *selected_iface=this->select_network_iface();
            if(selected_iface==NULL)
                nping_fatal(QT_3, "Error trying to find a suitable network interface ");
            else
                this->setDevice( selected_iface );
        }
    } /* CASE 2: User did actually supply a device name */
    else{
        nping_print(DBG_2, "Using network interface \"%s\"", this->getDevice() );
    }

/* The echo server needs to find out a network interface*/
}else if (this->getRole()==ROLE_SERVER && this->issetDevice()==false){
  char *selected_iface=this->select_network_iface();
  if(selected_iface==NULL)
    nping_fatal(QT_3, "Error trying to find a suitable network interface ");
  else
    this->setDevice( selected_iface );
  nping_print(DBG_2, "Using network interface \"%s\"", this->getDevice() );
}

/** RAW IP AND RAW ETHERNET TRANSMISSION MODES *******************************/
/* Determine if we need to send at raw ip level or at raw ethernet level */
if(this->getRole()!=ROLE_SERVER){
 if (!this->issetSendPreference()) {


    /* CASE 1: ARP requested. We have to do raw ethernet transmission */
    if(this->getMode()==ARP ){
        this->setSendEth(true);
        this->setSendPreference( PACKET_SEND_ETH_STRONG );
    }

    /* CASE 2: If we are dealing with IPv6 we have two options: send at raw
     * eth level or sent at raw transport layer level. So here, we check if the
     * user has specified some IPv6 header specific options. If he has, we then
     * have to use raw ethernet (since we cannot include our own IPv6 header in
     * raw IPv6 sockets). If he hasn't, the best way is to send at raw TCP/UDP
     * level so we disable sendEth() */
    else if (this->ipv6() ){

        /* CASE 2.A: If user did not specify custom IPv6 header or Ethernet
         * field values go for raw transport layer level transmission */
        if( this->canDoIPv6ThroughSocket() ){
            this->setSendEth(false);
            this->setSendPreference( PACKET_SEND_IP_STRONG );
        }
        /* CASE 2.B: User wants to set some IPv6 or Ethernet values. So here we
         * check if enough parameters were supplied. */
        else if (this->canDoIPv6Ethernet() ){
            this->setSendEth(true);
            this->setSendPreference( PACKET_SEND_ETH_STRONG );
        }else{
            nping_fatal(QT_3, "If you want to control some of the fields"
                         " in the IPv6 header you also have to supply source and"
                         " destination MAC address. However, you can always"
                         " choose to let the kernel create the IPv6  header"
                         " choosing not to pass --source-IP, --traffic-class"
                         " or --flow options. That should simplify things a bit");
        }
    }
    /* CASE 3: We are dealing with regular, IPv4-based modes. In this case
     * we just select transmission mode based on current OS. For Windows
     * we choose raw eth level because MS has disable raw sockets support.
     * For the rest of systems, we chose raw IP because it's easier for us
     * as we don't have to deal with all the source MAC and next-hop MAC address
     * determination process. */
    else{
         #ifdef WIN32
            this->setSendPreference( PACKET_SEND_ETH_STRONG );
            this->setSendEth(true);
         #else
            this->setSendPreference( PACKET_SEND_IP_WEAK );
            this->setSendEth(false);
         #endif
    }

 /* User did actually supplied his own sending preference. Let's check if we
  * can actually send probes the way he wants. */
 }else{

    if( this->getMode()==ARP && !this->sendPreferenceEthernet() ){
        this->setSendEth(true);
        nping_warning(QT_2, "Warning: ARP mode requires raw ethernet frame transmission. Specified preference will be ignored.");
    }
    else if( this->ipv6() ){

        /* CASE 1: User requested ethernet explicitly and supplied all
         * necessary options. */
        if( this->sendPreferenceEthernet() && this->canDoIPv6Ethernet() ){
            this->setSendEth(true);

        /* CASE 2: User requested Ethernet but did not really supplied all
         * the information we need */
        }else if( this->sendPreferenceEthernet() && !this->canDoIPv6Ethernet() ){
            nping_fatal(QT_3, "You requested raw ethernet level transmission and IPv6."
                    " In this case, you need to supply source MAC address,"
                    " destination MAC address and IPv6 source address.");

        /* CASE 3: User requested raw IP transmission and did not request
         * any special IPv6 header options. */
        }else if( this->sendPreferenceIP() && this->canDoIPv6ThroughSocket() ){
            this->setSendEth(false);

        /* CASE 4: User requested raw IP transmission but also wanted to
         * set custom IPv6 header field values. */
        }else if (this->sendPreferenceIP() && !this->canDoIPv6ThroughSocket()){
            nping_fatal(QT_3, "You requested raw IP transmission mode for IPv6."
                         " Nping does not currently allow IPv6 header manipulation"
                         " when sending packets at raw IP level due to the limitations"
                         " on raw IPv6 sockets, imposed by RFC 2292. Please"
                         " use raw Ethernet transmission (option --send-eth)");


        }
    }
    else if( this->sendPreferenceEthernet() ){
            this->setSendEth(true);
    }else{
        this->setSendEth(false);
    }
 }
 if( this->getMode()==TCP_CONNECT || this->getMode()==UDP_UNPRIV )
    nping_print(DBG_2,"Nping will send packets in unprivileged mode using regular system calls");
 else
    nping_print(DBG_2,"Nping will send packets at %s",  this->sendEth() ? "raw ethernet level" : "raw IP level" );
}

/** ECHO MODE ************************************************************/

  if(this->getRole()==ROLE_CLIENT){

    /* Make sure the nping echo client does not generate packets with tcp
     * src port or tcp dst port 9929 (or --echo-port N, if that is set),
     * because 1) the echo server does not capture those packets and 2) to
     * avoid messing with the established side-channel tcp connection. */
    if(this->getMode()==TCP){
        for(int i=0; i<tportcount; i++){
            if( this->target_ports[i]==this->getEchoPort())
                nping_fatal(QT_3, "Packets can't be sent to the same port that is used to connect to the echo server (%d)", this->getEchoPort());
            else if(this->getSourcePort()==this->getEchoPort())
                nping_fatal(QT_3, "Packets can't be sent from the same port that is used to connect to the echo server (%d)", this->getEchoPort());
        }
    }

    /* Check the echo client only produces TCP/UDP/ICMP packets */
    switch( this->getMode() ){
        case TCP:
        case UDP:
        case ICMP:
        break;

        default:
            nping_fatal(QT_3, "The echo client can't be run with protocols other than TCP, UDP or ICMP.");
        break;
    }
  }
  #ifndef HAVE_OPENSSL
  if(this->getRole()==ROLE_CLIENT || this->getRole()==ROLE_SERVER ){
    if( this->doCrypto()==true  ){
        nping_fatal(QT_3, "Nping was compiled without OpenSSL so authentications need to be transmitted as cleartext. If you wish to continue, please specify --no-crypto.");
    }
  }
  #endif

/** FRAGMENTATION ************************************************************/
#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (this->issetMTU()) {
    error("Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.");
  }
#endif

/** MISCELLANEOUS ************************************************************/
if( this->issetSourcePort() && this->getMode()==TCP_CONNECT && this->getPacketCount()>1 )
    error("Warning: Setting a source port in TCP-Connect mode with %d rounds may not work after the first round. You may want to do just one round (use --count 1).", this->getPacketCount() );
} /* End of validateOptions() */


/** Returns true if requested mode is a simple TCP connect probe mode */
bool NpingOps::canRunUDPWithoutPrivileges(){
  if( this->issetBadsumIP() ||
    this->issetTTL() ||
    this->issetHopLimit() ||
    this->issetTOS() ||
    this->issetIdentification() ||
    this->issetMF() ||
    this->issetDF() ||
    this->issetRF() ||
    this->issetIPv4SourceAddress() ||
    this->issetIPv6SourceAddress() ||
    this->issetIPOptions() ||
    this->issetMTU() ||
    this->issetSpoofSource() ||
    this->issetSourceMAC() ||
    this->issetDestMAC() ||
    this->issetEtherType() ||
    this->issetTraceroute() ||
    this->issetBPFFilterSpec()
  )
    return false;
  else
    return true;
} /* End canRunUDPWithoutPrivileges() */


/** Returns true if user did not request any special ethernet or ipv6 header
  * options */
bool NpingOps::canDoIPv6ThroughSocket(){
  if( this->issetEtherType() ||
    this->issetDestMAC() ||
    this->issetSourceMAC() ||
    this->issetHopLimit() ||
    this->issetTrafficClass() ||
    this->issetFlowLabel() ||
    this->issetIPv6SourceAddress()
  )
    return false;
  else
    return true;
} /* End canDoIPv6ThroughSocket() */


/** Returns true if user supplied all necessary options to allow IPv6 at raw
  * Ethernet level */
bool NpingOps::canDoIPv6Ethernet(){
  if( this->issetDestMAC() &&  this->issetSourceMAC() && this->issetIPv6SourceAddress() )
    return true;
  else
    return false;
} /* End canDoIPv6Ethernet() */


/******************************************************************************
 *  Miscellaneous                                                             *
 ******************************************************************************/

void NpingOps::displayNpingDoneMsg(){

  if( this->getRole()==ROLE_SERVER ){
      nping_print(QT_1, "Nping done: %lu %s served in %.2f seconds",
               (unsigned long)this->stats.getEchoClientsServed(),
               (this->stats.getEchoClientsServed() == 1)? "client" : "clients",
               this->stats.elapsedRuntime()
              );
  }else{
      nping_print(QT_1, "Nping done: %lu %s pinged in %.2f seconds",
               this->targets.getTargetsFetched(),
               (this->targets.getTargetsFetched() == 1)? "IP address" : "IP addresses",
               this->stats.elapsedRuntime()
              );
  }
} /* End of displayNpingDoneMessage() */


/** @warning This method calls targets.rewind() */
void NpingOps::displayStatistics(){
  char auxbuff[256];
  memset(auxbuff, 0, 256);
  NpingTarget *target=NULL;
  this->targets.rewind();

  nping_print(VB_0," "); /* Print newline */

    /* Per-target statistics */
    if( this->targets.getTargetsFetched() > 1){
        while( (target=this->targets.getNextTarget()) != NULL )
            target->printStats();
    }else{
        target=this->targets.getNextTarget();
        if( target!= NULL)
            target->printRTTs();
    }

#ifdef WIN32
      /* Sent/Recv/Echoed Packets */
      if(this->getRole()==ROLE_CLIENT){
          nping_print(QT_1|NO_NEWLINE, "Raw packets sent: %I64u ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getSentBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %I64u ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Lost: %I64u ", this->stats.getLostPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
          nping_print(QT_1|NO_NEWLINE,"| Echoed: %I64u ", this->stats.getEchoedPackets() );
          nping_print(QT_1,"(%s) ", format_bytecount(this->stats.getEchoedBytes(), auxbuff, 256));
      }else if(this->getRole()==ROLE_SERVER){
          nping_print(QT_1|NO_NEWLINE, "Raw packets captured: %I64u ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Echoed: %I64u ", this->stats.getEchoedPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getEchoedBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Not Matched: %I64u ", this->stats.getUnmatchedPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes()-this->stats.getEchoedBytes(), auxbuff, 256));
          nping_print(QT_1,"(%.2lf%%)", this->stats.getUnmatchedPacketPercentage100() );
      }else if(this->getMode()==TCP_CONNECT){
          nping_print(QT_1|NO_NEWLINE, "TCP connection attempts: %I64u ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Successful connections: %I64u ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Failed: %I64u ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
      } else if (this->getMode()==UDP_UNPRIV){
          nping_print(QT_1|NO_NEWLINE, "UDP packets sent: %I64u ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %I64u ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Lost: %I64u ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
      } else{
          nping_print(QT_1|NO_NEWLINE, "Raw packets sent: %I64u ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getSentBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %I64u ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Lost: %I64u ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
     }
#else
      /* Sent/Recv/Echoed Packets */
      if(this->getRole()==ROLE_CLIENT){
          nping_print(QT_1|NO_NEWLINE, "Raw packets sent: %llu ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getSentBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %llu ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Lost: %llu ", this->stats.getLostPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
          nping_print(QT_1|NO_NEWLINE,"| Echoed: %llu ", this->stats.getEchoedPackets() );
          nping_print(QT_1,"(%s) ", format_bytecount(this->stats.getEchoedBytes(), auxbuff, 256));
      }else if(this->getRole()==ROLE_SERVER){
          nping_print(QT_1|NO_NEWLINE, "Raw packets captured: %llu ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Echoed: %llu ", this->stats.getEchoedPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getEchoedBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Not Matched: %llu ", this->stats.getUnmatchedPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes()-this->stats.getEchoedBytes(), auxbuff, 256));
          nping_print(QT_1,"(%.2lf%%)", this->stats.getUnmatchedPacketPercentage100() );
      }else if(this->getMode()==TCP_CONNECT){
          nping_print(QT_1|NO_NEWLINE, "TCP connection attempts: %llu ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Successful connections: %llu ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Failed: %llu ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
      } else if (this->getMode()==UDP_UNPRIV){
          nping_print(QT_1|NO_NEWLINE, "UDP packets sent: %llu ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %llu ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"| Lost: %llu ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
      } else{
          nping_print(QT_1|NO_NEWLINE, "Raw packets sent: %llu ", this->stats.getSentPackets() );
          nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->stats.getSentBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Rcvd: %llu ", this->stats.getRecvPackets() );
          nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->stats.getRecvBytes(), auxbuff, 256));
          nping_print(QT_1|NO_NEWLINE,"| Lost: %llu ", this->stats.getLostPackets() );
          nping_print(QT_1,"(%.2lf%%)", this->stats.getLostPacketPercentage100() );
     }
#endif

      /* Transmission times & rates */
      nping_print(VB_1|NO_NEWLINE,"Tx time: %.5lfs ", this->stats.elapsedTx() );
      nping_print(VB_1|NO_NEWLINE,"| Tx bytes/s: %.2lf ", this->stats.getOverallTxByteRate() );
      nping_print(VB_1,"| Tx pkts/s: %.2lf", this->stats.getOverallTxPacketRate() );
      nping_print(VB_1|NO_NEWLINE,"Rx time: %.5lfs ", this->stats.elapsedRx() );
      nping_print(VB_1|NO_NEWLINE,"| Rx bytes/s: %.2lf ", this->stats.getOverallRxByteRate() );
      nping_print(VB_1,"| Rx pkts/s: %.2lf", this->stats.getOverallRxPacketRate() );

} /* End of displayStatistics() */


/* Close open files, free allocated memory, etc. */
int NpingOps::cleanup(){
  this->targets.freeTargets();
  return OP_SUCCESS;
} /* End of cleanup() */


char *NpingOps::select_network_iface(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *pcap_ifaces=NULL;

    /* Vars for the current interface in the loop */
    pcap_if_t *curr=NULL;             /* Current pcap pcap_if_t element   */
    bool current_has_address=false;   /* Does it have an addr of any type? */
    bool current_has_ipv6=false;      /* Does it have an IPv6 address?     */
    bool current_has_ipv4=false;      /* Does it have an IPv4 address?     */
    bool current_is_loopback=false;   /* Is it a loopback interface?       */
    bool select_current=false;        /* Is current better than candidate? */
    struct sockaddr_in6 devaddr6;     /* We store iface's IPv6 address     */
    struct sockaddr_in devaddr4;      /* And also its IPv4 address         */

    /* Vars for our candidate interface */
    pcap_if_t *candidate=NULL;
    bool candidate_has_address=false;
    bool candidate_has_ipv6=false;
    bool candidate_has_ipv4=false;
    bool candidate_is_loopback=false;
    //struct sockaddr_in6 candidate_addr6;
    //struct sockaddr_in candidate_addr4;

    /* Ask libpcap for a list of network interfaces */
    if( pcap_findalldevs(&pcap_ifaces, errbuf) != 0 )
        nping_fatal(QT_3, "Cannot obtain device for packet capture --> %s. You may want to specify one explicitly using option -e", errbuf);

    /* Iterate over the interface list and select the best one */
    for(curr=pcap_ifaces; curr!=NULL; curr=curr->next){
        current_has_address=false;   candidate_has_ipv6=false;
        candidate_is_loopback=false; candidate_has_ipv4=false;
        select_current=false;

        if( curr->flags==PCAP_IF_LOOPBACK)
            current_is_loopback=true;

        /* Loop through the list of addresses */
        for(pcap_addr_t *curraddr=curr->addresses; curraddr!=NULL; curraddr=curraddr->next){
            current_has_address=true;
            if( curraddr->addr->sa_family==AF_INET){
                current_has_ipv4=true;
                memcpy( &devaddr4, curraddr->addr, sizeof(struct sockaddr_in));
            } else if( curraddr->addr->sa_family==AF_INET6){
                current_has_ipv6=true;
                memcpy( &devaddr6, curraddr->addr, sizeof(struct sockaddr_in6));
            }
         }

        /* If we still have no candidate, take the first one we find */
        if( candidate==NULL){
            select_current=true;
        }
        /* If we already have a candidate, check if the one we are
         * processing right now is better than the one we've already got */
        else{
            /* If our candidate does not have an IPv6 address but this one does,
             * select the new one. */
            if( candidate_has_ipv6==false && current_has_ipv6==true ){
                select_current=true;
            }
            /* If our candidate does not even have an IPv4 address but this
             * one does, select the new one. */
            else if( candidate_has_ipv4==false && candidate_has_ipv6==false && current_has_ipv4){
                select_current=true;
            }
            /* If our candidate is a loopback iface, select the new one */
            else if( candidate_is_loopback && !current_is_loopback){

                /* Select the new one only if it has an IPv6 address
                 * and the old one didn't. If our old loopback iface
                 * has an IPv6 address and this one does not, we
                 * prefer to keep the loopback one, even though the
                 * other is not loopback */
                if(current_has_ipv6==true){
                    select_current=true;
                }
                /* We also prefer IPv4 capable interfaces than  */
                else if(candidate_has_ipv6==false && current_has_ipv4==true){
                    select_current=true;
                }
            }
            /* If both are loopback, select the best one. */
            else if( candidate->flags==PCAP_IF_LOOPBACK && curr->flags==PCAP_IF_LOOPBACK){
                if( candidate_has_ipv6==false && current_has_ipv6 )
                    select_current=true;
            }
        }

        /* Did we determine that we should discard our old candidate? */
        if( select_current ){
            candidate=curr;
            candidate_has_address=current_has_address;
            candidate_has_ipv4=current_has_ipv4;
            candidate_has_ipv6=current_has_ipv6;
            candidate_is_loopback=current_is_loopback;
        }

        /* Let's see if we have the interface of our dreams... */
        if( candidate_has_address && candidate_has_ipv6 && candidate_has_ipv4 && candidate_is_loopback==false){
            break;
        }

    }
    if(candidate==NULL)
        return NULL;
    else
       return candidate->name;
} /* End of select_network_iface() */


int NpingOps::setDefaultHeaderValues(){
  if(this->ipv6()){ /* IPv6 */
    if(!this->issetTrafficClass())
        this->ipv6_tclass=DEFAULT_IPv6_TRAFFIC_CLASS;
    if(!this->issetFlowLabel())
        this->ipv6_flowlabel=(get_random_u32() % 1048575);
    if(!this->issetHopLimit() && !this->issetTraceroute())
        this->ttl=DEFAULT_IPv6_TTL;
  }else{ /* IPv4 */
    if(!this->issetTOS())
        this->tos=DEFAULT_IP_TOS;
    if(!this->issetIdentification())
        this->identification=get_random_u16();
    if(!this->issetTTL() && !this->issetTraceroute())
        this->ttl=DEFAULT_IP_TTL;

  }
  switch( this->getMode() ){
    case TCP:
        if(!this->issetTargetPorts()){
            u16 *list = (u16 *)safe_zalloc( sizeof(u16) );
            list[0]=DEFAULT_TCP_TARGET_PORT;
            this->setTargetPorts(list, 1);
        }
        if(!this->issetSourcePort()){
            /* Generate any source port higher than 1024 */
            if(this->getRole()!=ROLE_CLIENT){
                this->source_port=(1024 + ( get_random_u16()%(65535-1024) ));
            }else{
                /* For the echo client, avoid choosing the port used for the echo side channel */
                while( (this->source_port=(1024 + ( get_random_u16()%(65535-1024) )))==this->echo_port );
            }
        }
        if(!this->issetTCPSequence())
            this->tcpseq=get_random_u32();
        if(!this->issetTCPAck()){
            if(this->getFlagTCP(FLAG_ACK))
                this->tcpack=get_random_u32();
            else
                this->tcpack=0;
        }
        if(!this->issetTCPFlags())
            this->setFlagTCP(FLAG_SYN);
        if(!this->issetTCPWindow())
            this->tcpwin=DEFAULT_TCP_WINDOW_SIZE;
        /* @todo ADD urgent pointer handling here when it gets implemented */
    break;

    case UDP:
        if(!this->issetTargetPorts()){
            u16 *list = (u16 *)safe_zalloc( sizeof(u16) );
            list[0]=DEFAULT_UDP_TARGET_PORT;
            this->setTargetPorts(list, 1);
        }
        if(!this->issetSourcePort())
            this->source_port=DEFAULT_UDP_SOURCE_PORT;
    break;

    case ICMP:
        if(this->ipv6()){
            if(!this->issetICMPType()) /* Default to ICMP Echo */
                this->icmp_type=DEFAULT_ICMPv6_TYPE;
            if(!this->issetICMPCode())
                this->icmp_code=DEFAULT_ICMPv6_CODE;
        }else{
            if(!this->issetICMPType()) /* Default to ICMP Echo */
                this->icmp_type=DEFAULT_ICMP_TYPE;
            if(!this->issetICMPCode())
                this->icmp_code=DEFAULT_ICMP_CODE;
        }
    break;

    case ARP:
        if(!this->issetARPOpCode())
            this->arp_opcode=DEFAULT_ARP_OP;
    break;

    case UDP_UNPRIV:
        if(!this->issetTargetPorts()){
            u16 *list = (u16 *)safe_zalloc( sizeof(u16) );
            list[0]=DEFAULT_UDP_TARGET_PORT;
            this->setTargetPorts(list, 1);
        }
        if(!this->issetSourcePort())
            this->source_port=DEFAULT_UDP_SOURCE_PORT;
    break;

    case TCP_CONNECT:
        if( !this->issetTargetPorts() ) {
            u16 *list = (u16 *)safe_zalloc( sizeof(u16) );
            list[0]=DEFAULT_TCP_TARGET_PORT;
            this->setTargetPorts(list, 1);
        }

    default:
        return OP_FAILURE;
    break;
  }

  return OP_SUCCESS;
} /* End of setDefaultHeaderValues() */


int NpingOps::setLastPacketSentTime(struct timeval t){
  this->last_sent_pkt_time=t;
  return OP_SUCCESS;
} /* End of setLastPacketSentTime() */


struct timeval NpingOps::getLastPacketSentTime(){
  return this->last_sent_pkt_time;
} /* End of getLastPacketSentTime() */


/** Sets the RCVD output to be delayed. The supplied string is strdup()ed, so
  * the caller may safely free() it or modify after calling this function.
  * The "id" parameter is the nsock timer event scheduled for the output of
  * the RCVD string (usually scheduled by ProbeMode). It is provided to allow
  * other objects (like EchoClient) to cancel the event if they take care of
  * printing the RCVD string before the timer goes off.*/
int NpingOps::setDelayedRcvd(const char *str, nsock_event_id id){
  if(str==NULL)
    return OP_FAILURE;
  this->delayed_rcvd_str=strdup(str);
  this->delayed_rcvd_event=id;
  this->delayed_rcvd_str_set=true;
  return OP_SUCCESS;
} /* End of setDelayedRcvd() */


/** Returns a pointer to a delayed RCVD output string. It returns non-NULL 
  * strings only once per prior setDelayedRcvd() call. This is, when a string
  * has been set through a setDelayRcdv() call, the first time getDelayRcvd()
  * is called, it returns that string. Subsequent calls will return NULL until
  * another string is set, using setDelayRcdv() again.
  * The "id" parameter will be filled with the timer event that was supposed
  * to print the message. If getDelayedRcvd() is called by the timer handler
  * itself, then NULL can be passed safely since the event id is not needed.
  * If the caller is some other method that wants to print the RCVD string
  * before the timer goes off, it may use the event ID to cancel the scheduled
  * event since it's no longer necessary.
  * @warning returned string is the strdup()ed version of the string passed
  * in the call to setDelayedRcvd(), so the caller MUST free the returned
  * pointer when it's done using it.  */
char *NpingOps::getDelayedRcvd(nsock_event_id *id){
  if(delayed_rcvd_str_set==false){
    return NULL;
  }else{
    this->delayed_rcvd_str_set=false;
    char *old=this->delayed_rcvd_str;
    this->delayed_rcvd_str=NULL;
    if(id!=NULL)
        *id=this->delayed_rcvd_event;
    return old;
  }
} /* End of getDelayedRcvd() */


bool NpingOps::doCrypto(){
  return this->do_crypto;
}

int NpingOps::doCrypto(bool value){
  this->do_crypto=value;
  return OP_SUCCESS;
}

/* Returns true if the echo server is allowed to include payloads in NEP_ECHO
 * messages. */
bool NpingOps::echoPayload(){
  return this->echo_payload;
}

/* Enables or disables payload echo for the echo server. Pass true to enable
 * or false to disable. */
int NpingOps::echoPayload(bool value){
  this->echo_payload=value;
  this->echo_payload_set=true;
  return OP_SUCCESS;
}


/** Returns the total number of probes to be sent (this takes into account
  * the number of rounds, ports, and targets. It returns a positive integer
  * on success and n<=0 in case of error. */
int NpingOps::getTotalProbes(){
  int total_ports=0;
  this->getTargetPorts(&total_ports);
  u64 tmp = (u64) this->getPacketCount() * total_ports;
  if (tmp > INT_MAX) {
    return -1;
  }
  tmp *= this->targets.Targets.size();
  if (tmp > INT_MAX) {
    return -1;
  }
  return (int) tmp;
}


/******************************************************************************
 *  Code templates.                                                           *
 ******************************************************************************/

/*

Attributes for NpingOps:

        TYPE ATTRNAME;
        bool ATTRNAME_set;

Prototypes for NpingOps:

    int setMETHNAME(TYPE val);
    TYPE getMETHNAME();
    bool issetMETHNAME();

Initialization for NpingOps::NpingOps()

    ATTRNAME=0;
    ATTRNAME_set=false;
*/

/** Sets METHNAME. Supplied parameter must be XXXXXXXX
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
/*int NpingOps::setMETHNAME(TYPE val){
   if( 0 ){
        nping_fatal(QT_3,"setMETHNAME(): Invalid value supplied\n");
        return OP_FAILURE;
    }else{
        ATTRNAME=val;
        ATTRNAME_set=true;
    }
    return OP_SUCCESS;
} *//* End of setMETHNAME() */



/** Returns value of attribute ATTRNAME */
/*TYPE NpingOps::getMETHNAME(){
  return this->ATTRNAME;
} *//* End of getMETHNAME() */


/* Returns true if option has been set */
/*bool NpingOps::issetMETHNAME(){
  return this->ATTRNAME_set;
} *//* End of issetMETHNAME() */
