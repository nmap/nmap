
/***************************************************************************
 * FPEngine.cc -- Routines used for IPv6 OS detection via TCP/IP           *
 * fingerprinting.  * For more information on how this works in Nmap, see  *
 * https://nmap.org/osdetect/                                               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
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
 * including the terms and conditions of this license text as well.        *
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
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "FPEngine.h"
#include "Target.h"
#include "FingerPrintResults.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "osscan.h"
#include "linear.h"
#include "FPModel.h"
extern NmapOps o;
#ifdef WIN32
/* from libdnet's intf-win32.c */
extern "C" int g_has_npcap_loopback;
#endif

#include <math.h>


/******************************************************************************
 * Globals.                                                                   *
 ******************************************************************************/

/* This is the global network controller. FPHost classes use it to request
 * network resources and schedule packet transmissions. */
FPNetworkControl global_netctl;


/******************************************************************************
 * Implementation of class FPNetworkControl.                                  *
 ******************************************************************************/
FPNetworkControl::FPNetworkControl() {
  memset(&this->nsp, 0, sizeof(nsock_pool));
  memset(&this->pcap_nsi, 0, sizeof(pcap_nsi));
  memset(&this->pcap_ev_id, 0, sizeof(nsock_event_id));
  this->nsock_init = false;
  this->rawsd = -1;
  this->probes_sent = 0;
  this->responses_recv = 0;
  this->probes_timedout = 0;
  this->cc_cwnd = 0;
  this->cc_ssthresh = 0;
}


FPNetworkControl::~FPNetworkControl() {
  if (this->nsock_init) {
    nsock_event_cancel(this->nsp, this->pcap_ev_id, 0);
    nsock_pool_delete(this->nsp);
    this->nsock_init = false;
  }
}


/* (Re)-Initialize object's state (default parameter setup and nsock
 * initialization). */
void FPNetworkControl::init(const char *ifname, devtype iftype) {

  /* Init congestion control parameters */
  this->cc_init();

   /* If there was a previous nsock pool, delete it */
  if (this->pcap_nsi) {
    nsock_iod_delete(this->pcap_nsi, NSOCK_PENDING_SILENT);
  }
  if (this->nsock_init) {
    nsock_event_cancel(this->nsp, this->pcap_ev_id, 0);
    nsock_pool_delete(this->nsp);
  }

  /* Create a new nsock pool */
  if ((this->nsp = nsock_pool_new(NULL)) == NULL)
    fatal("Unable to obtain an Nsock pool");

  nsock_set_log_function(nmap_nsock_stderr_logger);
  nmap_adjust_loglevel(o.packetTrace());

  nsock_pool_set_device(nsp, o.device);

  if (o.proxy_chain)
    nsock_pool_set_proxychain(this->nsp, o.proxy_chain);

  /* Allow broadcast addresses */
  nsock_pool_set_broadcast(this->nsp, 1);

  /* Allocate an NSI for packet capture */
  this->pcap_nsi = nsock_iod_new(this->nsp, NULL);
  this->first_pcap_scheduled = false;

  /* Flag it as already initialized so we free this nsp next time */
  this->nsock_init = true;

  /* Obtain raw socket or check that we can obtain an eth descriptor. */
  if ((o.sendpref & PACKET_SEND_ETH) && (iftype == devt_ethernet
#ifdef WIN32
        || (g_has_npcap_loopback && iftype == devt_loopback)
#endif
        ) && ifname != NULL) {
    /* We don't need to store the eth handler because FPProbes come with a
     * suitable one (FPProbes::getEthernet()), we just attempt to obtain one
     * to see if it fails. */
    if (eth_open_cached(ifname) == NULL)
      fatal("dnet: failed to open device %s", ifname);
    this->rawsd = -1;
  } else {
#ifdef WIN32
    win32_fatal_raw_sockets(ifname);
#endif
    if (this->rawsd >= 0)
      close(this->rawsd);
    rawsd = nmap_raw_socket();
    if (rawsd < 0)
      pfatal("Couldn't obtain raw socket in %s", __func__);
  }

  /* De-register existing callers */
  while (this->callers.size() > 0) {
    this->callers.pop_back();
  }
  return;
}


/* This function initializes the controller's congestion control parameters.
 * The network controller uses TCP's Slow Start and Congestion Avoidance
 * algorithms from RFC 5681 (slightly modified for convenience).
 *
 * As the OS detection process does not open full TCP connections, we can't just
 * use ACKs (or the lack of ACKs) to increase or decrease the congestion window
 * so we use probe responses. Every time we get a response to an OS detection
 * probe, we treat it as if it was a TCP ACK in TCP's congestion control.
 *
 * Note that the initial Congestion Window is set to the number of timed
 * probes that we send to each target. This is necessary since we need to
 * know for sure that we can send that many packets in order to transmit them.
 * Otherwise, we could fail to deliver the probes 100ms apart. */
int FPNetworkControl::cc_init() {
  this->probes_sent = 0;
  this->responses_recv = 0;
  this->probes_timedout = 0;
  this->cc_cwnd = OSSCAN_INITIAL_CWND;
  this->cc_ssthresh = OSSCAN_INITIAL_SSTHRESH;
  return OP_SUCCESS;
}


/* This method is used to indicate that we have scheduled the transmission of
 * one or more packets. This is used in congestion control to determine the
 * number of outstanding probes (number of probes sent but not answered yet)
 * and therefore, the effective transmission window. @param pkts indicates the
 * number of packets that were scheduled. Returns OP_SUCCESS on success and
 * OP_FAILURE in case of error. */
int FPNetworkControl::cc_update_sent(int pkts = 1) {
  if (pkts <= 0)
    return OP_FAILURE;
  this->probes_sent+=pkts;
  return OP_SUCCESS;
}


/* This method is used to indicate that a drop has occurred. In TCP, drops are
 * detected by the absence of an ACK. However, we can't use that, since it is
 * very likely that our targets do not respond to some of our OS detection
 * probes intentionally. For this reason, we consider that a drop has occurred
 * when we receive a response for a probe that has already suffered one
 * retransmission (first transmission got dropped in transit, some later
 * transmission made it to the host and it responded). So when we detect a drop
 * we do the same as TCP, adjust the congestion window and the slow start
 * threshold. */
int FPNetworkControl::cc_report_drop() {
/* FROM RFC 5681

   When a TCP sender detects segment loss using the retransmission timer
   and the given segment has not yet been resent by way of the
   retransmission timer, the value of ssthresh MUST be set to no more
   than the value given in equation (4):

      ssthresh = max (FlightSize / 2, 2*SMSS)            (4)

   where, as discussed above, FlightSize is the amount of outstanding
   data in the network.

   On the other hand, when a TCP sender detects segment loss using the
   retransmission timer and the given segment has already been
   retransmitted by way of the retransmission timer at least once, the
   value of ssthresh is held constant.
 */
  int probes_outstanding = this->probes_sent - this->responses_recv - this->probes_timedout;
  this->cc_ssthresh = MAX(probes_outstanding, OSSCAN_INITIAL_CWND);
  this->cc_cwnd = OSSCAN_INITIAL_CWND;
  return OP_SUCCESS;
}


/* This method is used to indicate that a response to a previous probe was
 * received. For us this is like getting and ACK in TCP congestion control, so
 * we update the congestion window (increase by one packet if we are in slow
 * start or increase it by a small percentage of a packet if we are in
 * congestion avoidance). */
int FPNetworkControl::cc_update_received() {
  this->responses_recv++;
  /* If we are in Slow Start, increment congestion window by one packet.
   * (Note that we treat probe responses the same way TCP CC treats ACKs). */
  if (this->cc_cwnd < this->cc_ssthresh) {
    this->cc_cwnd += 1;
  /* Otherwise we are in Congestion Avoidance and CWND is incremented slowly,
   * approximately one packet per RTT */
  } else {
    this->cc_cwnd = this->cc_cwnd + 1/this->cc_cwnd;
  }
  if (o.debugging > 3) {
    log_write(LOG_PLAIN, "[FPNetworkControl] Congestion Control Parameters: cwnd=%f ssthresh=%f sent=%d recv=%d tout=%d outstanding=%d\n",
           this->cc_cwnd, this->cc_ssthresh,  this->probes_sent, this->responses_recv, this->probes_timedout,
           this->probes_sent - this->responses_recv - this->probes_timedout);
  }
  return OP_SUCCESS;
}


/* This method is public and can be called by FPHosts to inform the controller
 * that a probe has experienced a final timeout. In other words, that no
 * response was received for the probe after doing the necessary retransmissions
 * and waiting for the RTO. This is used to decrease the number of outstanding
 * probes. Otherwise, if no host responded to the probes, the effective
 * transmission window could reach zero and prevent new probes from being sent,
 * clogging the engine. */
int FPNetworkControl::cc_report_final_timeout() {
  this->probes_timedout++;
  return OP_SUCCESS;
}


/* This method is used by FPHosts to request permission to transmit a number of
 * probes. Permission is granted if the current congestion window allows the
 * transmission of new probes. It returns true if permission is granted and
 * false if it is denied. */
bool FPNetworkControl::request_slots(size_t num_packets) {
  int probes_outstanding = this->probes_sent - this->responses_recv - this->probes_timedout;
  if (o.debugging > 3)
    log_write(LOG_PLAIN, "[FPNetworkControl] Slot request for %u packets. ProbesOutstanding=%d cwnd=%f ssthresh=%f\n",
              (unsigned int)num_packets, probes_outstanding, this->cc_cwnd, this->cc_ssthresh);
  /* If we still have room for more outstanding probes, let the caller
   * schedule transmissions. */
  if ((probes_outstanding + num_packets) <= this->cc_cwnd) {
    this->cc_update_sent(num_packets);
    return true;
  }
  return false;
}


/* This method lets FPHosts register themselves in the network controller so
 * the controller can call them back every time a packet they are interested
 * in is captured.*/
int FPNetworkControl::register_caller(FPHost *newcaller) {
  this->callers.push_back(newcaller);
  return OP_SUCCESS;
}


/* This method lets FPHosts unregister themselves in the network controller so
 * the controller does not call them back again. This is called by hosts that
 * have already finished their OS detection. */
int FPNetworkControl::unregister_caller(FPHost *oldcaller) {
  for (size_t i = 0; i < this->callers.size(); i++) {
    if (this->callers[i] == oldcaller) {
      this->callers.erase(this->callers.begin() + i);
      return OP_SUCCESS;
    }
  }
  return OP_FAILURE;
}


/* This method gets the controller ready for packet capture. Basically it
 * obtains a pcap descriptor from nsock and sets an appropriate BPF filter. */
int FPNetworkControl::setup_sniffer(const char *iface, const char *bpf_filter) {
  char pcapdev[128];
  int rc;

#ifdef WIN32
  /* Nmap normally uses device names obtained through dnet for interfaces, but
     Pcap has its own naming system.  So the conversion is done here */
  if (!DnetName2PcapName(iface, pcapdev, sizeof(pcapdev))) {
    /* Oh crap -- couldn't find the corresponding dev apparently.  Let's just go
       with what we have then ... */
    Strncpy(pcapdev, iface, sizeof(pcapdev));
  }
#else
  Strncpy(pcapdev, iface, sizeof(pcapdev));
#endif

  /* Obtain a pcap descriptor */
  rc = nsock_pcap_open(this->nsp, this->pcap_nsi, pcapdev, 8192, 0, bpf_filter);
  if (rc)
    fatal("Error opening capture device %s\n", pcapdev);

  /* Store the pcap NSI inside the pool so we can retrieve it inside a callback */
  nsock_pool_set_udata(this->nsp, (void *)&(this->pcap_nsi));

  return OP_SUCCESS;
}


/* This method makes the controller process pending events (like packet
 * transmissions or packet captures). */
void FPNetworkControl::handle_events() {
  nmap_adjust_loglevel(o.packetTrace());
  nsock_loop(nsp, 50);
}


/* This method lets FPHosts to schedule the transmission of an OS detection
 * probe. It takes an FPProbe pointer and the amount of milliseconds the
 * controller should wait before injecting the probe into the wire. */
int FPNetworkControl::scheduleProbe(FPProbe *pkt, int in_msecs_time) {
  nsock_timer_create(this->nsp, probe_transmission_handler_wrapper, in_msecs_time, (void*)pkt);
  return OP_SUCCESS;
}


/* This is the handler for packet transmission. It is called by nsock whenever a timer expires,
 * which means that a new packet needs to be transmitted. Note that this method is not
 * called directly by Nsock but by the wrapper function probe_transmission_handler_wrapper().
 * The reason for that is because C++ does not allow to use class methods as callback
 * functions, so this is a small hack to make that happen. */
void FPNetworkControl::probe_transmission_handler(nsock_pool nsp, nsock_event nse, void *arg) {
  assert(nsock_pool_get_udata(nsp) != NULL);
  nsock_iod nsi_pcap = *((nsock_iod *)nsock_pool_get_udata(nsp));
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  FPProbe *myprobe = (FPProbe *)arg;
  u8 *buf;
  size_t len;

  if (status == NSE_STATUS_SUCCESS) {
    switch(type) {
    /* Timer events mean that we need to send a packet.  */
    case NSE_TYPE_TIMER:

      /* The first time a packet is sent, we schedule a pcap event. After that
       * we don't have to worry since the response reception handler schedules
       * a new capture event for each captured packet. */
      if (!this->first_pcap_scheduled) {
        this->pcap_ev_id = nsock_pcap_read_packet(nsp, nsi_pcap, response_reception_handler_wrapper, -1, NULL);
        this->first_pcap_scheduled = true;
      }

      buf = myprobe->getPacketBuffer(&len);
      /* Send the packet*/
      assert(myprobe->host != NULL);
      if (send_ip_packet(this->rawsd, myprobe->getEthernet(), myprobe->host->getTargetAddress(), buf, len) == -1) {
        myprobe->setFailed();
        this->cc_report_final_timeout();
        myprobe->host->fail_one_probe();
        gh_perror("Unable to send packet in %s", __func__);
      }
      myprobe->setTimeSent();
      free(buf);
      break;

    default:
      fatal("Unexpected Nsock event in probe_transmission_handler()");
      break;
    } /* switch(type) */
  } else if (status == NSE_STATUS_EOF) {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): EOF\n");
  } else if (status == NSE_STATUS_ERROR || status == NSE_STATUS_PROXYERROR) {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): %s failed: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_TIMEOUT) {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): %s timeout: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_CANCELLED) {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): %s canceled: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_KILL) {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): %s killed: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else {
    if (o.debugging)
      log_write(LOG_PLAIN, "probe_transmission_handler(): Unknown status code %d\n", status);
  }
  return;
}


/* This is the handler for packet capture. It is called by nsock whenever libpcap
 * captures a packet from the network interface. This method basically captures
 * the packet, extracts its source IP address and tries to find an FPHost that
 * is targeting such address. If it does, it passes the packet to that FPHost
 * via callback() so the FPHost can determine if the packet is actually the
 * response to a FPProbe that it sent before. Note that this method is not
 * called directly by Nsock but by the wrapper function
 * response_reception_handler_wrapper(). See doc in probe_transmission_handler()
 * for details. */
void FPNetworkControl::response_reception_handler(nsock_pool nsp, nsock_event nse, void *arg) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  const u8 *rcvd_pkt = NULL;                    /* Points to the captured packet */
  size_t rcvd_pkt_len = 0;                      /* Length of the captured packet */
  struct timeval pcaptime;                    /* Time the packet was captured  */
  struct sockaddr_storage sent_ss;
  struct sockaddr_storage rcvd_ss;
  struct sockaddr_in *rcvd_ss4 = (struct sockaddr_in *)&rcvd_ss;
  struct sockaddr_in6 *rcvd_ss6 = (struct sockaddr_in6 *)&rcvd_ss;
  memset(&rcvd_ss, 0, sizeof(struct sockaddr_storage));
  IPv4Header ip4;
  IPv6Header ip6;
  int res = -1;

  struct timeval tv;
  gettimeofday(&tv, NULL);

  if (status == NSE_STATUS_SUCCESS) {
    switch(type) {

      case NSE_TYPE_PCAP_READ:

        /* Schedule a new pcap read operation */
        this->pcap_ev_id = nsock_pcap_read_packet(nsp, nsi, response_reception_handler_wrapper, -1, NULL);

        /* Get captured packet */
        nse_readpcap(nse, NULL, NULL, &rcvd_pkt, &rcvd_pkt_len, NULL, &pcaptime);

        /* Extract the packet's source address */
        ip4.storeRecvData(rcvd_pkt, rcvd_pkt_len);
        if (ip4.validate() != OP_FAILURE && ip4.getVersion() == 4) {
          ip4.getSourceAddress(&(rcvd_ss4->sin_addr));
          rcvd_ss4->sin_family = AF_INET;
        } else {
          ip6.storeRecvData(rcvd_pkt, rcvd_pkt_len);
          if (ip6.validate() != OP_FAILURE && ip6.getVersion() == 6) {
            ip6.getSourceAddress(&(rcvd_ss6->sin6_addr));
            rcvd_ss6->sin6_family = AF_INET6;
          } else {
            /* If we get here it means that the received packet is not
             * IPv4 or IPv6 so we just discard it returning. */
            return;
          }
        }

        /* Check if we have a caller that expects packets from this sender */
        for (size_t i = 0; i < this->callers.size(); i++) {

          /* Obtain the target address */
          sent_ss = *this->callers[i]->getTargetAddress();

          /* Check that the received packet is of the same address family */
          if (sent_ss.ss_family != rcvd_ss.ss_family)
            continue;

          /* Check that the captured packet's source address matches the
           * target address. If it matches, pass the received packet
           * to the appropriate FPHost object through callback().  */
          if (sockaddr_storage_equal(&rcvd_ss, &sent_ss)) {
            if ((res = this->callers[i]->callback(rcvd_pkt, rcvd_pkt_len, &tv)) >= 0) {

               /* If callback() returns >=0 it means that the packet we've just
                * passed was successfully matched with a previous probe. Now
                * update the count of received packets (so we can determine how
                * many outstanding packets are out there). Note that we only do
                * that if callback() returned >0 because 0 is a special case: a
                * reply to a retransmitted timed probe that was already replied
                * to in the past. We don't want to count replies to the same probe
                * more than once, so that's why we only update when res > 0. */
                if (res > 0)
                  this->cc_update_received();

               /* When the callback returns more than 1 it means that the packet
                * was sent more than once before being answered. This means that
                * we experienced congestion (first transmission got dropped), so
                * we update our CC parameters to deal with the congestion. */
                if (res > 1) {
                  this->cc_report_drop();
                }
            }
            return;
          }
        }
      break;

      default:
       fatal("Unexpected Nsock event in response_reception_handler()");
      break;

    } /* switch(type) */

  } else if (status == NSE_STATUS_EOF) {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): EOF\n");
  } else if (status == NSE_STATUS_ERROR || status == NSE_STATUS_PROXYERROR) {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): %s failed: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_TIMEOUT) {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): %s timeout: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_CANCELLED) {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): %s canceled: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_KILL) {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): %s killed: %s\n", nse_type2str(type), strerror(socket_errno()));
  } else {
    if (o.debugging)
      log_write(LOG_PLAIN, "response_reception_handler(): Unknown status code %d\n", status);
  }
  return;
}


/******************************************************************************
 * Implementation of class FPEngine.                                          *
 ******************************************************************************/
FPEngine::FPEngine() {
  this->osgroup_size = OSSCAN_GROUP_SIZE;
}


FPEngine::~FPEngine() {

}


/* Returns a suitable BPF filter for the OS detection. If less than 20 targets
 * are passed, the filter contains an explicit list of target addresses. It
 * looks similar to this:
 *
 * dst host fe80::250:56ff:fec0:1 and (src host fe80::20c:29ff:feb0:2316 or src host fe80::20c:29ff:fe9f:5bc2)
 *
 * When more than 20 targets are passed, a generic filter based on the source
 * address is used. The returned filter looks something like:
 *
 * dst host fe80::250:56ff:fec0:1
 */
const char *FPEngine::bpf_filter(std::vector<Target *> &Targets) {
  static char pcap_filter[2048];
  /* 20 IPv6 addresses is max (46 byte addy + 14 (" or src host ")) * 20 == 1200 */
  char dst_hosts[1220];
  int filterlen = 0;
  int len = 0;
  unsigned int targetno;
  memset(pcap_filter, 0, sizeof(pcap_filter));

  /* If we have 20 or less targets, build a list of addresses so we can set
   * an explicit BPF filter */
  if (Targets.size() <= 20) {
    for (targetno = 0; targetno < Targets.size(); targetno++) {
      len = Snprintf(dst_hosts + filterlen,
                     sizeof(dst_hosts) - filterlen,
                     "%ssrc host %s", (targetno == 0)? "" : " or ",
                     Targets[targetno]->targetipstr());

      if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
        fatal("ran out of space in dst_hosts");
      filterlen += len;
    }
    if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
      fatal("ran out of space in dst_hosts");

    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and (%s)",
                   Targets[0]->sourceipstr(), dst_hosts);
  } else {
    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s", Targets[0]->sourceipstr());
  }

  if (len < 0 || len >= (int) sizeof(pcap_filter))
    fatal("ran out of space in pcap filter");

  return pcap_filter;
}


/******************************************************************************
 * Implementation of class FPEngine6.                                         *
 ******************************************************************************/
FPEngine6::FPEngine6() {

}


FPEngine6::~FPEngine6() {

}

/* Not all operating systems allow setting the flow label in outgoing packets;
   notably all Unixes other than Linux when using raw sockets. This function
   finds out whether the flow labels we set are likely really being sent.
   Otherwise, the operating system is probably filling in 0. Compare to the
   logic in send_ipv6_packet_eth_or_sd. */
static bool can_set_flow_label(const struct eth_nfo *eth) {
  if (eth != NULL)
    return true;
#if HAVE_IPV6_IPPROTO_RAW
  return true;
#else
  return false;
#endif
}

void FPHost6::fill_FPR(FingerPrintResultsIPv6 *FPR) {
  unsigned int i;

  FPR->begin_time = this->begin_time;

  for (i = 0; i < sizeof(this->fp_responses) / sizeof(this->fp_responses[0]); i++) {
    const FPResponse *resp;

    resp = this->fp_responses[i];
    if (resp != NULL) {
      FPR->fp_responses[i] = new FPResponse(resp->probe_id, resp->buf, resp->len,
        resp->senttime, resp->rcvdtime);
    }
  }

  /* Were we actually able to set the flow label? */
  FPR->flow_label = 0;
  for (i = 0; i < sizeof(this->fp_probes) / sizeof(this->fp_probes[0]); i++) {
    const FPProbe& probe = fp_probes[0];
    if (probe.is_set()) {
      if (can_set_flow_label(probe.getEthernet()))
        FPR->flow_label = OSDETECT_FLOW_LABEL;
      break;
    }
  }

  /* Did we fail to send some probe? */
  FPR->incomplete = this->incomplete_fp;
}

static const IPv6Header *find_ipv6(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_IPv6)
    pe = pe->getNextElement();

  return (IPv6Header *) pe;
}

static const TCPHeader *find_tcp(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_TCP)
    pe = pe->getNextElement();

  return (TCPHeader *) pe;
}

static const ICMPv6Header *find_icmpv6(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_ICMPv6)
    pe = pe->getNextElement();

  return (ICMPv6Header *) pe;
}

static double vectorize_plen(const PacketElement *pe) {
  const IPv6Header *ipv6;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  else
    return ipv6->getPayloadLength();
}

static double vectorize_tc(const PacketElement *pe) {
  const IPv6Header *ipv6;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  else
    return ipv6->getTrafficClass();
}

/* For reference, the dev@nmap.org email thread which contains the explanations for the
 * design decisions of this vectorization method:
 * http://seclists.org/nmap-dev/2015/q1/218
 */
static int vectorize_hlim(const PacketElement *pe, int target_distance, enum dist_calc_method method) {
  const IPv6Header *ipv6;
  int hlim;
  int er_lim;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  hlim = ipv6->getHopLimit();

  if (method != DIST_METHOD_NONE) {
      if (method == DIST_METHOD_TRACEROUTE || method == DIST_METHOD_ICMP) {
        if (target_distance > 0)
          hlim += target_distance - 1;
      }
      er_lim = 5;
  } else
    er_lim = 20;

  if (32 - er_lim <= hlim && hlim <= 32+ 5 )
    hlim = 32;
  else if (64 - er_lim <= hlim && hlim <= 64+ 5 )
    hlim = 64;
  else if (128 - er_lim <= hlim && hlim <= 128+ 5 )
    hlim = 128;
  else if (255 - er_lim <= hlim && hlim <= 255+ 5 )
    hlim = 255;
  else
    hlim = -1;

  return hlim;
}

static double vectorize_isr(std::map<std::string, FPPacket>& resps) {
  const char * const SEQ_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6"};
  u32 seqs[NELEMS(SEQ_PROBE_NAMES)];
  struct timeval times[NELEMS(SEQ_PROBE_NAMES)];
  unsigned int i, j;
  double sum, t;

  j = 0;
  for (i = 0; i < NELEMS(SEQ_PROBE_NAMES); i++) {
    const char *probe_name;
    const FPPacket *fp;
    const TCPHeader *tcp;
    std::map<std::string, FPPacket>::iterator it;

    probe_name = SEQ_PROBE_NAMES[i];
    it = resps.find(probe_name);
    if (it == resps.end())
      continue;

    fp = &it->second;
    tcp = find_tcp(fp->getPacket());
    if (tcp == NULL)
      continue;

    seqs[j] = tcp->getSeq();
    times[j] = fp->getTime();
    j++;
  }

  if (j < 2)
    return -1;

  sum = 0.0;
  for (i = 0; i < j - 1; i++)
    sum += seqs[i + 1] - seqs[i];
  t = TIMEVAL_FSEC_SUBTRACT(times[j - 1], times[0]);

  return sum / t;
}

static int vectorize_icmpv6_type(const PacketElement *pe) {
  const ICMPv6Header *icmpv6;

  icmpv6 = find_icmpv6(pe);
  if (icmpv6 == NULL)
    return -1;

  return icmpv6->getType();
}

static int vectorize_icmpv6_code(const PacketElement *pe) {
  const ICMPv6Header *icmpv6;

  icmpv6 = find_icmpv6(pe);
  if (icmpv6 == NULL)
    return -1;

  return icmpv6->getCode();
}

static struct feature_node *vectorize(const FingerPrintResultsIPv6 *FPR) {
  const char * const IPV6_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6", "IE1", "IE2", "NS", "U1", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"};
  const char * const TCP_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"};
  const char * const ICMPV6_PROBE_NAMES[] = {"IE1", "IE2", "NS"};

  unsigned int nr_feature, i, idx;
  struct feature_node *features;
  std::map<std::string, FPPacket> resps;

  for (i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    PacketElement *pe;

    if (FPR->fp_responses[i] == NULL)
      continue;
    pe = PacketParser::split(FPR->fp_responses[i]->buf, FPR->fp_responses[i]->len);
    assert(pe != NULL);
    resps[FPR->fp_responses[i]->probe_id].setPacket(pe);
    resps[FPR->fp_responses[i]->probe_id].setTime(&FPR->fp_responses[i]->senttime);
  }

  nr_feature = get_nr_feature(&FPModel);
  features = new feature_node[nr_feature + 1];
  for (i = 0; i < nr_feature; i++) {
    features[i].index = i + 1;
    features[i].value = -1;
  }
  features[i].index = -1;

  idx = 0;
  for (i = 0; i < NELEMS(IPV6_PROBE_NAMES); i++) {
    const char *probe_name;

    probe_name = IPV6_PROBE_NAMES[i];
    features[idx++].value = vectorize_plen(resps[probe_name].getPacket());
    features[idx++].value = vectorize_tc(resps[probe_name].getPacket());
    features[idx++].value = vectorize_hlim(resps[probe_name].getPacket(), FPR->distance, FPR->distance_calculation_method);
  }
  /* TCP features */
  features[idx++].value = vectorize_isr(resps);
  for (i = 0; i < NELEMS(TCP_PROBE_NAMES); i++) {
    const char *probe_name;
    const TCPHeader *tcp;
    u16 flags;
    u16 mask;
    unsigned int j;
    int mss;
    int sackok;
    int wscale;

    probe_name = TCP_PROBE_NAMES[i];

    mss = -1;
    sackok = -1;
    wscale = -1;

    tcp = find_tcp(resps[probe_name].getPacket());
    if (tcp == NULL) {
      /* 49 TCP features. */
      idx += 49;
      continue;
    }
    features[idx++].value = tcp->getWindow();
    flags = tcp->getFlags16();
    for (mask = 0x001; mask <= 0x800; mask <<= 1)
      features[idx++].value = (flags & mask) != 0;

    for (j = 0; j < 16; j++) {
      nping_tcp_opt_t opt;
      opt = tcp->getOption(j);
      if (opt.value == NULL)
        break;
      features[idx++].value = opt.type;
      /* opt.len includes the two (type, len) bytes. */
      if (opt.type == TCPOPT_MSS && opt.len == 4 && mss == -1)
        mss = ntohs(*(u16 *) opt.value);
      else if (opt.type == TCPOPT_SACKOK && opt.len == 2 && sackok == -1)
        sackok = 1;
      else if (opt.type == TCPOPT_WSCALE && opt.len == 3 && wscale == -1)
        wscale = *(u8 *) opt.value;
    }
    for (; j < 16; j++)
      idx++;

    for (j = 0; j < 16; j++) {
      nping_tcp_opt_t opt;
      opt = tcp->getOption(j);
      if (opt.value == NULL)
        break;
      features[idx++].value = opt.len;
    }
    for (; j < 16; j++)
      idx++;

    features[idx++].value = mss;
    features[idx++].value = sackok;
    features[idx++].value = wscale;
    if (mss != 0 && mss != -1)
      features[idx++].value = (float)tcp->getWindow() / mss;
    else
      features[idx++].value = -1;
  }
  /* ICMPv6 features */
  for (i = 0; i < NELEMS(ICMPV6_PROBE_NAMES); i++) {
    const char *probe_name;

    probe_name = ICMPV6_PROBE_NAMES[i];
    features[idx++].value = vectorize_icmpv6_type(resps[probe_name].getPacket());
    features[idx++].value = vectorize_icmpv6_code(resps[probe_name].getPacket());
  }

  assert(idx == nr_feature);

  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "v = {");
    for (i = 0; i < nr_feature; i++)
      log_write(LOG_PLAIN, "%.16g, ", features[i].value);
    log_write(LOG_PLAIN, "};\n");
  }

  return features;
}

static void apply_scale(struct feature_node *features, unsigned int num_features,
  const double (*scale)[2]) {
  unsigned int i;

  for (i = 0; i < num_features; i++) {
    double val = features[i].value;
    if (val < 0)
      continue;
    val = (val + scale[i][0]) * scale[i][1];
    features[i].value = val;
  }
}

/* (label, prob) pairs for purpose of sorting. */
struct label_prob {
  int label;
  double prob;
};

int label_prob_cmp(const void *a, const void *b) {
  const struct label_prob *la, *lb;

  la = (struct label_prob *) a;
  lb = (struct label_prob *) b;

  /* Sort descending. */
  if (la->prob > lb->prob)
    return -1;
  else if (la->prob < lb->prob)
    return 1;
  else
    return 0;
}

/* Return a measure of how much the given feature vector differs from the other
   members of the class given by label.

   This can be thought of as the distance from the given feature vector to the
   mean of the class in multidimensional space, after scaling. Each dimension is
   further scaled by the inverse of the sample variance of that feature. This is
   an approximation of the Mahalanobis distance
   (https://en.wikipedia.org/wiki/Mahalanobis_distance), which normally uses a
   full covariance matrix of the features. If we take the features to be
   pairwise independent (which they are not), then the covariance matrix is just
   the diagonal matrix containing per-feature variances, leading to the same
   calculation as is done below. Using only the per-feature variances rather
   than covariance matrices is to save space; it requires only n entries per
   class rather than n^2, where n is the length of a feature vector.

   It happens often that a feature's variance is undefined (because there is
   only one example in the class) or zero (because there are two identical
   values for that feature). Both these cases are mapped to zero by train.py,
   and we handle them the same way: by using a small default variance. This will
   tend to make small differences count a lot (because we probably want this
   fingerprint in order to expand the class), while still allowing near-perfect
   matches to match. */
static double novelty_of(const struct feature_node *features, int label) {
  const double *means, *variances;
  int i, nr_feature;
  double sum;

  nr_feature = get_nr_feature(&FPModel);
  assert(0 <= label);
  assert(label < nr_feature);

  means = FPmean[label];
  variances = FPvariance[label];

  sum = 0.0;
  for (i = 0; i < nr_feature; i++) {
    double d, v;

    assert(i + 1 == features[i].index);
    d = features[i].value - means[i];
    v = variances[i];
    if (v == 0.0) {
      /* No variance? It means that samples were identical. Substitute a default
         variance. This will tend to make novelty large in these cases, which
         will hopefully encourage for submissions for this class. */
      v = 0.01;
    }
    sum += d * d / v;
  }

  return sqrt(sum);
}

static void classify(FingerPrintResultsIPv6 *FPR) {
  int nr_class, i;
  struct feature_node *features;
  double *values;
  struct label_prob *labels;

  nr_class = get_nr_class(&FPModel);

  features = vectorize(FPR);
  values = new double[nr_class];
  labels = new struct label_prob[nr_class];

  apply_scale(features, get_nr_feature(&FPModel), FPscale);

  predict_values(&FPModel, features, values);
  for (i = 0; i < nr_class; i++) {
    labels[i].label = i;
    labels[i].prob = 1.0 / (1.0 + exp(-values[i]));
  }
  qsort(labels, nr_class, sizeof(labels[0]), label_prob_cmp);
  for (i = 0; i < nr_class && i < MAX_FP_RESULTS; i++) {
    FPR->matches[i] = &o.os_labels_ipv6[labels[i].label];
    FPR->accuracy[i] = labels[i].prob;
    FPR->num_matches = i + 1;
    if (labels[i].prob >= 0.90 * labels[0].prob)
      FPR->num_perfect_matches = i + 1;
    if (o.debugging > 2) {
      printf("%7.4f %7.4f %3u %s\n", FPR->accuracy[i] * 100,
        novelty_of(features, labels[i].label), labels[i].label, FPR->matches[i]->OS_name);
    }
  }
  if (FPR->num_perfect_matches == 0) {
    FPR->overall_results = OSSCAN_NOMATCHES;
  } else if (FPR->num_perfect_matches == 1) {
    double novelty;

    novelty = novelty_of(features, labels[0].label);
    if (o.debugging > 1)
      log_write(LOG_PLAIN, "Novelty of closest match is %.3f.\n", novelty);

    if (novelty < FP_NOVELTY_THRESHOLD) {
      FPR->overall_results = OSSCAN_SUCCESS;
    } else {
      if (o.debugging > 0) {
        log_write(LOG_PLAIN, "Novelty of closest match is %.3f > %.3f; ignoring.\n",
          novelty, FP_NOVELTY_THRESHOLD);
      }
      FPR->overall_results = OSSCAN_NOMATCHES;
      FPR->num_perfect_matches = 0;
    }
  } else {
    FPR->overall_results = OSSCAN_NOMATCHES;
    FPR->num_perfect_matches = 0;
  }

  delete[] features;
  delete[] values;
  delete[] labels;
}


/* This method is the core of the FPEngine class. It takes a list of IPv6
 * targets that need to be fingerprinted. The method handles the whole
 * fingerprinting process, sending probes, collecting responses, analyzing
 * results and matching fingerprints. If everything goes well, the internal
 * state of the supplied target objects will be modified to reflect the results
 * of the */
int FPEngine6::os_scan(std::vector<Target *> &Targets) {
  bool osscan_done = false;
  const char *bpf_filter = NULL;
  std::vector<FPHost6 *> curr_hosts;  /* Hosts currently doing OS detection      */
  std::vector<FPHost6 *> done_hosts;  /* Hosts for which we already did OSdetect */
  std::vector<FPHost6 *> left_hosts;  /* Hosts we have not yet started with      */
  struct timeval begin_time;

  if (o.debugging)
    log_write(LOG_PLAIN, "Starting IPv6 OS Scan...\n");

  /* Initialize variables, timers, etc. */
  gettimeofday(&begin_time, NULL);
  global_netctl.init(Targets[0]->deviceName(), Targets[0]->ifType());
  for (size_t i = 0; i < Targets.size(); i++) {
    if (o.debugging > 3) {
      log_write(LOG_PLAIN, "[FPEngine] Allocating FPHost6 for %s %s\n",
        Targets[i]->targetipstr(), Targets[i]->sourceipstr());
    }
    FPHost6 *newhost = new FPHost6(Targets[i], &global_netctl);
    newhost->begin_time = begin_time;
    fphosts.push_back(newhost);
  }

  /* Build the BPF filter */
  bpf_filter = this->bpf_filter(Targets);
  if (o.debugging)
    log_write(LOG_PLAIN, "[FPEngine] Interface=%s BPF:%s\n", Targets[0]->deviceName(), bpf_filter);

  /* Set up the sniffer */
  global_netctl.setup_sniffer(Targets[0]->deviceName(), bpf_filter);

  /* Divide the targets into two groups, the ones we are going to start
   * processing, and the ones we leave for later. */
  for (size_t i = 0; i < Targets.size() && i < this->osgroup_size; i++) {
    curr_hosts.push_back(fphosts[i]);
  }
  for (size_t i = curr_hosts.size(); i < Targets.size(); i++) {
    left_hosts.push_back(fphosts[i]);
  }

  /* Do the OS detection rounds */
  while (!osscan_done) {
    osscan_done = true; /* It will remain true only when all hosts are .done() */
    if (o.debugging > 3) {
      log_write(LOG_PLAIN, "[FPEngine] CurrHosts=%d, LeftHosts=%d, DoneHosts=%d\n",
        (int) curr_hosts.size(), (int) left_hosts.size(), (int) done_hosts.size());
    }

    /* Go through the list of hosts and ask them to schedule their probes */
    for (unsigned int i = 0; i < curr_hosts.size(); i++) {

      /* If the host is not done yet, call schedule() to let it schedule
       * new probes, retransmissions, etc. */
      if (!curr_hosts[i]->done()) {
        osscan_done = false;
        curr_hosts[i]->schedule();
        if (o.debugging > 3)
          log_write(LOG_PLAIN, "[FPEngine] CurrHost #%u not done\n", i);

      /* If the host is done, take it out of the curr_hosts group and add it
       * to the done_hosts group. If we still have hosts left in the left_hosts
       * group, take the first one and insert it into curr_hosts. This way we
       * always have a full working group of hosts (unless we ran out of hosts,
       * of course). */
      } else {
        if (o.debugging > 3)
          log_write(LOG_PLAIN, "[FPEngine] CurrHost #%u done\n", i);
        if (o.debugging > 3)
          log_write(LOG_PLAIN, "[FPEngine] Moving done host %u to the done_hosts list\n", i);
        done_hosts.push_back(curr_hosts[i]);
        curr_hosts.erase(curr_hosts.begin() + i);

        /* If we still have hosts left, add one to the current group */
        if (left_hosts.size() > 0) {
          if (o.debugging > 3)
            log_write(LOG_PLAIN, "[FPEngine] Inserting one new hosts in the curr_hosts list.\n");
          curr_hosts.push_back(left_hosts[0]);
          left_hosts.erase(left_hosts.begin());
          osscan_done = false;
        }

        i--; /* Decrement i so we don't miss the host that is now in the
              * position of the host we've just removed from the list */
      }
    }

    /* Handle scheduled events */
    global_netctl.handle_events();

  }

  /* Once we've finished with all fphosts, check which ones were correctly
   * fingerprinted, and update the Target objects. */
  for (size_t i = 0; i < this->fphosts.size(); i++) {
    fphosts[i]->finish();

    fphosts[i]->fill_FPR((FingerPrintResultsIPv6 *) Targets[i]->FPR);
    classify((FingerPrintResultsIPv6 *) Targets[i]->FPR);
  }

  /* Cleanup and return */
  while (this->fphosts.size() > 0) {
    FPHost6 *tmp = fphosts.back();
    delete tmp;
    fphosts.pop_back();
  }

  if (o.debugging)
    log_write(LOG_PLAIN, "IPv6 OS Scan completed.\n");
  return OP_SUCCESS;
}


/******************************************************************************
 * Implementation of class FPHost.                                            *
 ******************************************************************************/
FPHost::FPHost() {
  this->__reset();
}


FPHost::~FPHost() {

}


void FPHost::__reset() {
  this->total_probes = 0;
  this->timed_probes = 0;
  this->probes_sent = 0;
  this->probes_answered = 0;
  this->probes_unanswered = 0;
  this->incomplete_fp = false;
  this->detection_done = false;
  this->timedprobes_sent = false;
  this->target_host = NULL;
  this->netctl = NULL;
  this->netctl_registered = false;
  this->tcpSeqBase = 0;
  this->open_port_tcp = -1;
  this->closed_port_tcp = -1;
  this->closed_port_udp = -1;
  this->tcp_port_base = -1;
  this->udp_port_base = -1;
  /* Retransmission time-out parameters.
   *
   * From RFC 2988:
   * Until a round-trip time (RTT) measurement has been made for a segment
   * sent between the sender and receiver, the sender SHOULD set
   * RTO <- 3 seconds */
  this->rto = OSSCAN_INITIAL_RTO;
  this->rttvar = -1;
  this->srtt = -1;

  this->begin_time.tv_sec = 0;
  this->begin_time.tv_usec = 0;
}


/* Returns the IP address of the target associated with the FPHost in
 * struct sockaddr_storage format. */
const struct sockaddr_storage *FPHost::getTargetAddress() {
  return this->target_host->TargetSockAddr();
}

/* Marks one probe as unanswerable, making the fingerprint incomplete and
 * ineligible for submission */
void FPHost::fail_one_probe() {
  this->probes_unanswered++;
  this->incomplete_fp = true;
}

/* Accesses the Target object associated with the FPHost to extract the port
 * numbers to be used in OS detection. In particular it extracts:
 *
 * - An open TCP port.
 * - A closed TCP port.
 * - A closed UDP port.
 *
 * When not enough information is found in the Target, the necessary port
 * numbers are generated randomly. */
int FPHost::choose_osscan_ports() {
  Port *tport = NULL;
  Port port;
  /* Choose an open TCP port: First, check if the host already has a
   * FingerPrintResults object that defines an open port. */
  if (this->target_host->FPR != NULL && this->target_host->FPR->osscan_opentcpport > 0) {
    this->open_port_tcp = this->target_host->FPR->osscan_opentcpport;

  /* Otherwise, get the first open port that we've found open */
  } else if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_TCP, PORT_OPEN))) {
    this->open_port_tcp = tport->portno;
    /* If it is zero, let's try another one if there is one */
    if (tport->portno == 0) {
      if ((tport = this->target_host->ports.nextPort(tport, &port, IPPROTO_TCP, PORT_OPEN)))
       this->open_port_tcp = tport->portno;
    }
    this->target_host->FPR->osscan_opentcpport = this->open_port_tcp;
  } else {
    /* If we don't have an open port, set it to -1 so we don't send probes that
     * target TCP open ports */
    this->open_port_tcp = -1;
  }

  /* Choose a closed TCP port. */
  if (this->target_host->FPR != NULL && this->target_host->FPR->osscan_closedtcpport > 0) {
     this->closed_port_tcp = this->target_host->FPR->osscan_closedtcpport;
  } else if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_TCP, PORT_CLOSED))) {
    this->closed_port_tcp = tport->portno;
    /* If it is zero, let's try another one if there is one */
    if (tport->portno == 0)
      if ((tport = this->target_host->ports.nextPort(tport, &port, IPPROTO_TCP, PORT_CLOSED)))
        this->closed_port_tcp = tport->portno;
    this->target_host->FPR->osscan_closedtcpport = this->closed_port_tcp;
  } else if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_TCP, PORT_UNFILTERED))) {
    /* Well, we will settle for unfiltered */
    this->closed_port_tcp = tport->portno;
    /* But again we'd prefer not to have zero */
    if (tport->portno == 0)
      if ((tport = this->target_host->ports.nextPort(tport, &port, IPPROTO_TCP, PORT_UNFILTERED)))
        this->closed_port_tcp = tport->portno;
  } else {
    /* If we don't have a closed port, set it to -1 so we don't send probes that
     * target TCP closed ports. */
    this->closed_port_tcp = -1;
  }

  /* Closed UDP port */
  if (this->target_host->FPR != NULL && this->target_host->FPR->osscan_closedudpport > 0) {
    this->closed_port_udp = this->target_host->FPR->osscan_closedudpport;
  } else if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_UDP, PORT_CLOSED))) {
    this->closed_port_udp = tport->portno;
    /* Not zero, if possible */
    if (tport->portno == 0)
      if ((tport = this->target_host->ports.nextPort(tport, &port, IPPROTO_UDP, PORT_CLOSED)))
        this->closed_port_udp = tport->portno;
    this->target_host->FPR->osscan_closedudpport = this->closed_port_udp;
  } else if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_UDP, PORT_UNFILTERED))) {
    /* Well, we will settle for unfiltered */
    this->closed_port_udp = tport->portno;
    /* But not zero, please */
    if (tport->portno == 0)
      if ((tport = this->target_host->ports.nextPort(NULL, &port, IPPROTO_UDP, PORT_UNFILTERED)))
        this->closed_port_udp = tport->portno;
  } else {
    /* Pick one at random.  Shrug. */
    this->closed_port_udp = (get_random_uint() % 14781) + 30000;
  }

  this->tcpSeqBase = get_random_u32();
  this->tcp_port_base = o.magic_port_set ? o.magic_port : o.magic_port + get_random_u8();
  this->udp_port_base = o.magic_port_set ? o.magic_port : o.magic_port + get_random_u8();
  this->icmp_seq_counter = 0;

  return OP_SUCCESS;
}


/* This method is called whenever we receive a response to a probe. It
 * recomputes the host's retransmission timer based on the new RTT measure.
 * @param measured_rtt_usecs is the new RTT observation in MICROseconds.
 * @param retransmission indicates whether the observed RTT correspond to
 * a packet that was transmitted more than once or not. It is used to
 * avoid using RTT samples obtained from retransmissions (Karn's algorithm) */
int FPHost::update_RTO(int measured_rtt_usecs, bool retransmission) {
/* RFC 2988: TCP MUST use Karn's algorithm [KP87] for taking RTT samples.  That
 * is, RTT samples MUST NOT be made using segments that were
 * retransmitted (and thus for which it is ambiguous whether the reply
 * was for the first instance of the packet or a later instance).*/
  if (retransmission == true)
    return OP_SUCCESS;

/* RFC 2988: When the first RTT measurement R is made, the host MUST set
 *
 *  SRTT <- R
 *  RTTVAR <- R/2
 *  RTO <- SRTT + max (G, K*RTTVAR)
 *
 * where K = 4, and G is the clock granularity.. */
  if (this->srtt == -1 && this->rttvar == -1) {
      this->srtt = measured_rtt_usecs;
      this->rttvar = measured_rtt_usecs/2;
      this->rto = this->srtt + MAX(500000, 4*this->rttvar); /* Assume a granularity of 1/2 sec */
  } else {

 /* RFC 2988: When a subsequent RTT measurement R' is made, a host MUST set
  *
  *  RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
  *  SRTT <- (1 - alpha) * SRTT + alpha * R'
  *
  * The above SHOULD be computed using alpha = 1/8 and beta = 1/4.
  * After the computation, a host MUST update
  *
  *  RTO <- SRTT + max (G, K*RTTVAR)
  */
    this->rttvar = ((1.0 - 0.25) * this->rttvar) + (0.25 * ABS(this->srtt - measured_rtt_usecs));
    this->srtt = ((1.0 - 0.125) * this->srtt) + (0.125 * measured_rtt_usecs);
    this->rto = this->srtt + MAX(500000, 4*this->rttvar);
  }

/* RFC 2988: Whenever RTO is computed, if it is less than 1 second then the RTO
 * SHOULD be rounded up to 1 second.
 * [NOTE: In Nmap we find this excessive, so we set a minimum of 100ms
 * (100,000 usecs). It may seem aggressive but waiting too long can cause
 * the engine to fail to detect drops until many probes later on extremely
 * low-latency networks (such as localhost scans).  */
  if (this->rto < (MIN_RTT_TIMEOUT*1000))
    this->rto = (MIN_RTT_TIMEOUT*1000);
   return this->rto;
}


/******************************************************************************
 * Implementation of class FPHost6.                                           *
 ******************************************************************************/

FPHost6::FPHost6(Target *tgt, FPNetworkControl *fpnc) {
  this->init(tgt, fpnc);
  return;
}


FPHost6::~FPHost6() {
  this->reset();
}


void FPHost6::reset() {
  this->__reset();
  for (unsigned int i = 0; i < NUM_FP_PROBES_IPv6; i++) {
      this->fp_probes[i].reset();
      if (this->fp_responses[i]) {
          delete this->fp_responses[i];
          this->fp_responses[i] = NULL;
      }
  }
}


void FPHost6::init(Target *tgt, FPNetworkControl *fpnc) {
  this->target_host = tgt;
  this->netctl = fpnc;
  this->total_probes = 0;
  this->timed_probes = 0;

  /* Set state in the supplied Target */
  if (this->target_host->FPR == NULL)
    this->target_host->FPR = new FingerPrintResultsIPv6;
  this->target_host->osscanSetFlag(OS_PERF);

  /* Choose TCP/UDP ports for the probes. */
  this->choose_osscan_ports();

  /* Build the list of OS detection probes */
  this->build_probe_list();

  for (unsigned int i = 0; i < NUM_FP_PROBES_IPv6; i++)
    this->fp_responses[i] = NULL;

  for (unsigned int i = 0; i < NUM_FP_TIMEDPROBES_IPv6; i++)
    this->aux_resp[i] = NULL;
}

/* Get the hop limit encapsulated in an ICMPv6 error reply. Return -1 if it
 * can't be found. */
static int get_encapsulated_hoplimit(const PacketElement *pe) {
  /* Check that it's IPv6. */
  if (pe == NULL || pe->protocol_id() != HEADER_TYPE_IPv6)
    return -1;
  /* Find the ICMPv6 payload. */
  pe = pe->getNextElement();
  for (; pe != NULL; pe = pe->getNextElement()) {
    if (pe->protocol_id() == HEADER_TYPE_ICMPv6)
      break;
  }
  if (pe == NULL)
    return -1;
  /* Check that encapsulated is IPv6. */
  pe = pe->getNextElement();
  if (pe == NULL || pe->protocol_id() != HEADER_TYPE_IPv6)
    return -1;

  return ((IPv6Header *) pe)->getHopLimit();
}

void FPHost6::finish() {
  /* These probes are likely to get an ICMPv6 error (allowing us to calculate
     distance. */
  const char * const DISTANCE_PROBE_NAMES[] = { "IE2", "U1" };
  int distance = -1;
  int hoplimit_distance = -1;
  enum dist_calc_method distance_calculation_method = DIST_METHOD_NONE;
  unsigned int i;

  /* Calculate distance based on hop limit difference. */
  for (i = 0; i < NELEMS(DISTANCE_PROBE_NAMES); i++) {
    const FPProbe *probe;
    const FPResponse *resp;
    const PacketElement *probe_pe;
    PacketElement *resp_pe;
    int sent_ttl, rcvd_ttl;
    const char *probe_name;

    probe_name = DISTANCE_PROBE_NAMES[i];
    probe = this->getProbe(probe_name);
    resp = this->getResponse(probe_name);
    if (probe == NULL || resp == NULL)
      continue;
    probe_pe = probe->getPacket();
    if (probe_pe->protocol_id() != HEADER_TYPE_IPv6)
      continue;
    sent_ttl = ((IPv6Header *) probe_pe)->getHopLimit();

    resp_pe = PacketParser::split(resp->buf, resp->len);
    assert(resp_pe != NULL);
    rcvd_ttl = get_encapsulated_hoplimit(resp_pe);
    if (rcvd_ttl != -1) {
      if (o.debugging > 1) {
        log_write(LOG_PLAIN, "Hop limit distance from %s probe: %d - %d + 1 == %d\n",
          probe_name, sent_ttl, rcvd_ttl, sent_ttl - rcvd_ttl + 1);
      }
      /* Set only if not already set. */
      if (hoplimit_distance == -1)
        hoplimit_distance = sent_ttl - rcvd_ttl + 1;

      /* Special case: for the U1 probe, mark that we found the port closed. */
      if (this->target_host->FPR->osscan_closedudpport == -1 && strcmp(probe_name, "U1") == 0) {
        const PacketElement *udp;
        u16 portno;

        udp = probe_pe->getNextElement();
        assert(udp != NULL);
        assert(udp->protocol_id() == HEADER_TYPE_UDP);
        portno = ((UDPHeader *) udp)->getDestinationPort();
        this->target_host->FPR->osscan_closedudpport = portno;
      }
    }
    PacketParser::freePacketChain(resp_pe);
  }

  if (islocalhost(this->target_host->TargetSockAddr())) {
    /* scanning localhost */
    distance = 0;
    distance_calculation_method = DIST_METHOD_LOCALHOST;
  } else if (this->target_host->directlyConnected()) {
    /* on the same network segment */
    distance = 1;
    distance_calculation_method = DIST_METHOD_DIRECT;
  } else if (hoplimit_distance != -1) {
    distance = hoplimit_distance;
    distance_calculation_method = DIST_METHOD_ICMP;
  }

  this->target_host->distance = this->target_host->FPR->distance = distance;
  this->target_host->distance_calculation_method =
    this->target_host->FPR->distance_calculation_method =
    distance_calculation_method;
}

struct tcp_desc {
  const char *id;
  u16 win;
  u8 flags;
  u16 dstport;
  u16 urgptr;
  const char *opts;
  unsigned int optslen;
};

static u8 get_hoplimit() {
  if (o.ttl != -1)
    return o.ttl;
  else
    return (get_random_uint() % 23) + 37;
}

static IPv6Header *make_tcp(const struct sockaddr_in6 *src,
  const struct sockaddr_in6 *dst,
  u32 fl, u16 win, u32 seq, u32 ack, u8 flags, u16 srcport, u16 dstport,
  u16 urgptr, const char *opts, unsigned int optslen) {
  IPv6Header *ip6;
  TCPHeader *tcp;

  /* Allocate an instance of the protocol headers */
  ip6 = new IPv6Header();
  tcp = new TCPHeader();

  ip6->setSourceAddress(src->sin6_addr);
  ip6->setDestinationAddress(dst->sin6_addr);

  ip6->setFlowLabel(fl);
  ip6->setHopLimit(get_hoplimit());
  ip6->setNextHeader("TCP");
  ip6->setNextElement(tcp);

  tcp->setWindow(win);
  tcp->setSeq(seq);
  tcp->setAck(ack);
  tcp->setFlags(flags);
  tcp->setSourcePort(srcport);
  tcp->setDestinationPort(dstport);
  tcp->setUrgPointer(urgptr);
  tcp->setOptions((u8 *) opts, optslen);

  ip6->setPayloadLength(tcp->getLen());
  tcp->setSum();

  return ip6;
}

/* This method generates the list of OS detection probes to be sent to the
 * target. It also sets up the list of responses. It is defined private
 * because it is called by the constructor when the class is instantiated. */
int FPHost6::build_probe_list() {
#define OPEN 1
#define CLSD 0
  /* TCP Options:
   *  S1-S6: six sequencing probes.
   *  TECN:  ECN probe.
   *  T2-T7: other non-sequencing probes.
   *
   * option 0: WScale (10), Nop, MSS (1460), Timestamp, SackP
   * option 1: MSS (1400), WScale (0), SackP, T(0xFFFFFFFF,0x0), EOL
   * option 2: T(0xFFFFFFFF, 0x0), Nop, Nop, WScale (5), Nop, MSS (640)
   * option 3: SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
   * option 4: MSS (536), SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
   * option 5: MSS (265), SackP, T(0xFFFFFFFF,0x0)
   * option 6: WScale (10), Nop, MSS (1460), SackP, Nop, Nop
   * option 7-11: WScale (10), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
   * option 12: WScale (15), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP */
  const struct tcp_desc TCP_DESCS[] = {
    { "S1",     1, 0x02, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "S2",    63, 0x02, OPEN,     0,
      "\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00", 20 },
    { "S3",     4, 0x02, OPEN,     0,
      "\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80", 20 },
    { "S4",     4, 0x02, OPEN,     0,
      "\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 16 },
    { "S5",    16, 0x02, OPEN,     0,
      "\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 20 },
    { "S6",   512, 0x02, OPEN,     0,
      "\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00", 16 },
    { "TECN",   3, 0xc2, OPEN, 63477,
      "\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01", 12 },
    { "T2",   128, 0x00, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T3",   256, 0x2b, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T4",  1024, 0x10, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T5", 31337, 0x02, CLSD,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T6", 32768, 0x10, CLSD,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T7", 65535, 0x29, CLSD,     0,
      "\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
  };

  sockaddr_storage ss;
  size_t slen = 0;
  sockaddr_in6 *ss6 = (sockaddr_in6 *)&ss;
  IPv6Header *ip6;
  ICMPv6Header *icmp6;
  UDPHeader *udp;
  DestOptsHeader *dstopts;
  RoutingHeader *routing;
  HopByHopHeader *hopbyhop1, *hopbyhop2;
  RawData *payload;
  unsigned int i;
  char payloadbuf[300];

  assert(this->target_host != NULL);

  /* Set timed TCP probes */
  for (i = 0; i < NUM_FP_PROBES_IPv6_TCP && i < NUM_FP_TIMEDPROBES_IPv6; i++) {
    /* If the probe is targeted to a TCP port and we don't have
     * any port number for that particular state, skip the probe. */
    if (TCP_DESCS[i].dstport == OPEN && this->open_port_tcp < 0)
      continue;
    if (TCP_DESCS[i].dstport == CLSD && this->closed_port_tcp < 0)
      continue;

    ip6 = make_tcp((struct sockaddr_in6 *) this->target_host->SourceSockAddr(),
      (struct sockaddr_in6 *) this->target_host->TargetSockAddr(),
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, this->tcpSeqBase + i, get_random_u32(),
      TCP_DESCS[i].flags, this->tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? this->open_port_tcp : this->closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen);

    /* Store the probe in the list so we can send it later */
    this->fp_probes[this->total_probes].host = this;
    this->fp_probes[this->total_probes].setPacket(ip6);
    this->fp_probes[this->total_probes].setProbeID(TCP_DESCS[i].id);
    this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
    /* Mark as a timed probe. */
    this->fp_probes[this->total_probes].setTimed();
    this->timed_probes++;
    this->total_probes++;
  }


  /* Set ICMPv6 probes */

  memset(payloadbuf, 0, 120);

  /* ICMP Probe #1: Echo Request with hop-by-hop options */
  /* This one immediately follows the timed seq TCP probes, to allow testing for
     shared flow label sequence. */
  ip6 = new IPv6Header();
  icmp6 = new ICMPv6Header();
  hopbyhop1 = new HopByHopHeader();
  payload = new RawData();
  this->target_host->SourceSockAddr(&ss, &slen);
  ip6->setSourceAddress(ss6->sin6_addr);
  this->target_host->TargetSockAddr(&ss, &slen);
  ip6->setDestinationAddress(ss6->sin6_addr);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(get_hoplimit());
  ip6->setNextHeader((u8) HEADER_TYPE_IPv6_HOPOPT);
  ip6->setNextElement(hopbyhop1);
  hopbyhop1->setNextHeader(HEADER_TYPE_ICMPv6);
  hopbyhop1->setNextElement(icmp6);
  icmp6->setNextElement(payload);
  payload->store((u8 *) payloadbuf, 120);
  icmp6->setType(ICMPv6_ECHO);
  icmp6->setCode(9); // But is supposed to be 0.
  icmp6->setIdentifier(0xabcd);
  icmp6->setSequence(this->icmp_seq_counter++);
  icmp6->setTargetAddress(ss6->sin6_addr); // Should still contain target's addr
  ip6->setPayloadLength();
  icmp6->setSum();
  this->fp_probes[this->total_probes].host = this;
  this->fp_probes[this->total_probes].setPacket(ip6);
  this->fp_probes[this->total_probes].setProbeID("IE1");
  this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
  this->total_probes++;

  /* ICMP Probe #2: Echo Request with badly ordered extension headers */
  ip6 = new IPv6Header();
  hopbyhop1 = new HopByHopHeader();
  dstopts = new DestOptsHeader();
  routing = new RoutingHeader();
  hopbyhop2 = new HopByHopHeader();
  icmp6 = new ICMPv6Header();
  payload = new RawData();
  this->target_host->SourceSockAddr(&ss, &slen);
  ip6->setSourceAddress(ss6->sin6_addr);
  this->target_host->TargetSockAddr(&ss, &slen);
  ip6->setDestinationAddress(ss6->sin6_addr);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(get_hoplimit());
  ip6->setNextHeader((u8) HEADER_TYPE_IPv6_HOPOPT);
  ip6->setNextElement(hopbyhop1);
  hopbyhop1->setNextHeader(HEADER_TYPE_IPv6_OPTS);
  hopbyhop1->setNextElement(dstopts);
  dstopts->setNextHeader(HEADER_TYPE_IPv6_ROUTE);
  dstopts->setNextElement(routing);
  routing->setNextHeader(HEADER_TYPE_IPv6_HOPOPT);
  routing->setNextElement(hopbyhop2);
  hopbyhop2->setNextHeader(HEADER_TYPE_ICMPv6);
  hopbyhop2->setNextElement(icmp6);
  icmp6->setType(ICMPv6_ECHO);
  icmp6->setCode(0);
  icmp6->setIdentifier(0xabcd);
  icmp6->setSequence(this->icmp_seq_counter++);
  icmp6->setTargetAddress(ss6->sin6_addr); // Should still contain target's addr
  ip6->setPayloadLength();
  icmp6->setSum();
  this->fp_probes[this->total_probes].host = this;
  this->fp_probes[this->total_probes].setPacket(ip6);
  this->fp_probes[this->total_probes].setProbeID("IE2");
  this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
  this->total_probes++;

  /* ICMP Probe #3: Neighbor Solicitation. (only sent to on-link targets) */
  if (this->target_host->directlyConnected()) {
    ip6 = new IPv6Header();
    icmp6 = new ICMPv6Header();
    this->target_host->SourceSockAddr(&ss, &slen);
    ip6->setSourceAddress(ss6->sin6_addr);
    this->target_host->TargetSockAddr(&ss, &slen);
    ip6->setDestinationAddress(ss6->sin6_addr);
    ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
    /* RFC 2461 section 7.1.1: "A node MUST silently discard any received
       Neighbor Solicitation messages that do not satisfy all of the following
       validity checks: - The IP Hop Limit field has a value of 255 ... */
    ip6->setHopLimit(255);
    ip6->setNextHeader("ICMPv6");
    ip6->setNextElement(icmp6);
    icmp6->setType(ICMPv6_NGHBRSOLICIT);
    icmp6->setCode(0);
    icmp6->setTargetAddress(ss6->sin6_addr); // Should still contain target's addr
    icmp6->setSum();
    ip6->setPayloadLength();
    this->fp_probes[this->total_probes].host = this;
    this->fp_probes[this->total_probes].setPacket(ip6);
    this->fp_probes[this->total_probes].setProbeID("NS");
    this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
    this->total_probes++;
  }

  /* Set UDP probes */

  memset(payloadbuf, 0x43, 300);

  ip6 = new IPv6Header();
  udp = new UDPHeader();
  payload = new RawData();
  this->target_host->SourceSockAddr(&ss, &slen);
  ip6->setSourceAddress(ss6->sin6_addr);
  this->target_host->TargetSockAddr(&ss, &slen);
  ip6->setDestinationAddress(ss6->sin6_addr);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(get_hoplimit());
  ip6->setNextHeader("UDP");
  ip6->setNextElement(udp);
  udp->setSourcePort(this->udp_port_base);
  udp->setDestinationPort(this->closed_port_udp);
  payload->store((u8 *) payloadbuf, 300);
  udp->setNextElement(payload);
  udp->setTotalLength();
  udp->setSum();
  ip6->setPayloadLength(udp->getLen());
  this->fp_probes[this->total_probes].host = this;
  this->fp_probes[this->total_probes].setPacket(ip6);
  this->fp_probes[this->total_probes].setProbeID("U1");
  this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
  this->total_probes++;

  /* Set TECN probe */
  if ((TCP_DESCS[i].dstport == OPEN && this->open_port_tcp >= 0)
      || (TCP_DESCS[i].dstport == CLSD && this->closed_port_tcp >= 0)) {
    ip6 = make_tcp((struct sockaddr_in6 *) this->target_host->SourceSockAddr(),
      (struct sockaddr_in6 *) this->target_host->TargetSockAddr(),
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, this->tcpSeqBase + i, 0,
      TCP_DESCS[i].flags, tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? this->open_port_tcp : this->closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen);

    /* Store the probe in the list so we can send it later */
    this->fp_probes[this->total_probes].host = this;
    this->fp_probes[this->total_probes].setPacket(ip6);
    this->fp_probes[this->total_probes].setProbeID(TCP_DESCS[i].id);
    this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
    this->total_probes++;
  }
  i++;

  /* Set untimed TCP probes */
  for (; i < NUM_FP_PROBES_IPv6_TCP; i++) {
    /* If the probe is targeted to a TCP port and we don't have
     * any port number for that particular state, skip the probe. */
    if (TCP_DESCS[i].dstport == OPEN && this->open_port_tcp < 0)
      continue;
    if (TCP_DESCS[i].dstport == CLSD && this->closed_port_tcp < 0)
      continue;

    ip6 = make_tcp((struct sockaddr_in6 *) this->target_host->SourceSockAddr(),
      (struct sockaddr_in6 *) this->target_host->TargetSockAddr(),
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, this->tcpSeqBase + i, get_random_u32(),
      TCP_DESCS[i].flags, tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? this->open_port_tcp : this->closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen);

    /* Store the probe in the list so we can send it later */
    this->fp_probes[this->total_probes].host = this;
    this->fp_probes[this->total_probes].setPacket(ip6);
    this->fp_probes[this->total_probes].setProbeID(TCP_DESCS[i].id);
    this->fp_probes[this->total_probes].setEthernet(this->target_host->SrcMACAddress(), this->target_host->NextHopMACAddress(), this->target_host->deviceName());
    this->total_probes++;
  }

  return OP_SUCCESS;
}

/* Indicates whether the OS detection process has finished for this host.
 * Note that when "true" is returned the caller cannot assume that the host
 * has been accurately fingerprinted, only that the OS detection process
 * was carried out. In other words, when true is returned it means that the
 * fingerprinting engine sent all OS detection probes, performed the necessary
 * retransmission and attempted to capture the target's replies. In order to
 * check if the detection was successful (if we actually know what OS the target
 * is running), the status() method should be used. */
bool FPHost6::done() {
  if (this->probes_sent == this->total_probes) {
    if (this->probes_answered + this->probes_unanswered == this->total_probes)
      return true;
  }
  return false;
}


/* Asks the host to schedule the transmission of probes (if they need to do so).
 * This method is called repeatedly by the FPEngine to make the host request
 * the probe transmissions that it needs. From the hosts point of view, it
 * determines if new transmissions need to be scheduled based on the number
 * of probes sent, the number of answers received, etc. Also, in order to
 * transmit a packet, the network controller must approve it (hosts may not
 * be able to send packets any time they want due to congestion control
 * restrictions). */
int FPHost6::schedule() {
  struct timeval now;
  unsigned int timed_probes_answered = 0;
  unsigned int timed_probes_timedout = 0;

  /* The first time we are asked to schedule a packet, register ourselves in
   * the network controller so it can call us back when packets that match our
   * target are captured. */
  if (this->netctl_registered == false && this->netctl != NULL) {
    this->netctl->register_caller(this);
    this->netctl_registered = true;
  }

  /* Make sure we have things to do, otherwise, just return. */
  if (this->detection_done || (this->probes_answered + this->probes_unanswered == this->total_probes)) {
    /* Update our internal state to indicate we have finished */
    if (!this->detection_done)
      this->set_done_and_wrap_up();
    return OP_SUCCESS;
  }

  /* If we have not yet sent the timed probes (and we have timed probes to send)
   * request permission from the network controller and schedule the transmission
   * for all of them, 100ms apart from each other. We don't want all the hosts
   * to schedule their transmission for the same exact time so we add a random
   * offset (between 0 and 100ms) to the first transmission. All subsequent
   * ones are sent 100ms apart from the first. Note that if we did not find
   * and open port, then we just don't send the timed probes. */
  if (this->timed_probes > 0 && this->timedprobes_sent == false) {
    if (o.debugging > 3)
      log_write(LOG_PLAIN, "[%s] %u Tx slots requested\n", this->target_host->targetipstr(), this->timed_probes);
    if (this->netctl->request_slots(this->timed_probes) == true) {
      if (o.debugging > 3)
        log_write(LOG_PLAIN, "[%s] Slots granted!\n", this->target_host->targetipstr());
      this->timedprobes_sent = true;
      int whentostart = get_random_u16()%100;
      for (size_t i = 0; i < this->timed_probes; i++) {
        this->netctl->scheduleProbe(&(this->fp_probes[i]), whentostart + i*100);
        this->probes_sent++;
      }
      return OP_SUCCESS;
    }
    if (o.debugging > 3)
      log_write(LOG_PLAIN, "[%s] Slots denied.\n", this->target_host->targetipstr());
    return OP_FAILURE;
  } else if (this->timed_probes > 0 && this->timedprobes_sent && this->fp_probes[this->timed_probes - 1].getTimeSent().tv_sec == 0) {
      /* If the sent time for the last timed probe has not been set, it means
       * that we haven't sent all the timed probes yet, so we don't schedule
       * any other probes, we just wait until our schedule() gets called again.
       * We do this because we don't want to mess with the target's stack
       * in the middle of our timed probes. Otherwise, we can screw up the
       * TCP sequence generation tests, etc. We also get here when timed probes
       * suffer a retransmission. In that case, we also stop sending packets
       * to our target until we have sent all of them. */
      if (o.debugging > 3)
        log_write(LOG_PLAIN, "[%s] Waiting for all timed probes to be sent...\n", this->target_host->targetipstr());
      return OP_FAILURE;
  } else {
    /* If we get here it means that either we have sent all the timed probes or
     * we don't even have to send them (because no open port was found).
     * At this point if we have other probes to transmit, schedule the next one.
     * Also, check for timedout probes so we can retransmit one of them. */
    if (o.debugging > 3 && this->timed_probes > 0 && this->probes_sent == this->timed_probes)
      log_write(LOG_PLAIN, "[%s] All timed probes have been sent.\n", this->target_host->targetipstr());

    if (this->probes_sent < this->total_probes) {
      if (this->netctl->request_slots(1) == true) {
        if (o.debugging > 3)
          log_write(LOG_PLAIN, "[%s] Scheduling probe %s\n", this->target_host->targetipstr(), this->fp_probes[this->probes_sent].getProbeID());
        this->netctl->scheduleProbe(&(this->fp_probes[this->probes_sent]), 0);
        this->probes_sent++;
      } else {
        if (o.debugging > 3)
          log_write(LOG_PLAIN, "[%s] Can't schedule probe %s\n", this->target_host->targetipstr(), this->fp_probes[this->probes_sent].getProbeID());
      }
    }

    /**************************************************************************
     *                         PROBE TIMEOUT HANDLING                         *
     **************************************************************************/
    if (o.debugging > 3)
      log_write(LOG_PLAIN, "[%s] Checking for regular probe timeouts...\n", this->target_host->targetipstr());

    /* Determine if some regular probe (not timed probes) has timedout. In that
     * case, choose some outstanding probe to retransmit. */
    gettimeofday(&now, NULL);
    for (unsigned int i = this->timed_probes; i < this->probes_sent; i++) {

      /* Skip probes that have already been answered */
      if (this->fp_responses[i]) {
        continue;
      }

      /* Skip probes that we have scheduled but have not been yet transmitted */
      if (this->fp_probes[i].getTimeSent().tv_sec == 0)
        continue;

      /* Skip probes for which we didn't get a response after all
       * retransmissions. */
      if (this->fp_probes[i].probeFailed()) {
        continue;
      }

      /* Check if the probe timedout */
      if (TIMEVAL_SUBTRACT(now, this->fp_probes[i].getTimeSent()) >= this->rto) {

        /* If we have reached the maximum number of retransmissions, mark the
         * probe as failed. Otherwise, schedule its transmission. */
        if (this->fp_probes[i].getRetransmissions() >= o.maxOSTries()) {
          if (o.debugging > 3) {
            log_write(LOG_PLAIN, "[%s] Probe #%d (%s) failed after %d retransmissions.\n",
              this->target_host->targetipstr(), i, this->fp_probes[i].getProbeID(),
              this->fp_probes[i].getRetransmissions());
          }
          this->fp_probes[i].setFailed();
          /* Let the network controller know that we don't expect a response
           * for the probe anymore so the number of outstanding probes is
           * reduced and the effective window is incremented. */
          this->netctl->cc_report_final_timeout();
          /* Also, increase our unanswered counter so we can later decide
           * if the process has finished. */
          this->probes_unanswered++;
          continue;
        /* Otherwise, retransmit the packet.*/
        } else {
          /* Note that we do not request permission to re-transmit (we don't
           * call request_slots(). In TCP one can retransmit timedout
           * probes even when CWND is zero, as CWND only applies for new packets. */
          if (o.debugging > 3) {
            log_write(LOG_PLAIN, "[%s] Retransmitting probe #%d (%s) (retransmitted %d times already).\n",
              this->target_host->targetipstr(), i, this->fp_probes[i].getProbeID(),
              this->fp_probes[i].getRetransmissions());
          }
          this->fp_probes[i].incrementRetransmissions();
          this->netctl->scheduleProbe(&(this->fp_probes[i]), 0);
          break;
        }
      }
    }

    /* Now let's check the state of the timed probes. We iterate over the list
     * of timed probes to count how many have been answered and how many have
     * timed out. If answered + timeout == total_timed_probes, it's time to
     * retransmit them. */

    /* Make sure we are actually sending timed probes. */
    if (this->timed_probes <= 0)
      return OP_SUCCESS;

    bool timed_failed = false;
    if (o.debugging > 3)
      log_write(LOG_PLAIN, "[%s] Checking for timed probe timeouts...\n", this->target_host->targetipstr());
    for (unsigned int i = 0; i < this->timed_probes; i++) {
      assert(this->fp_probes[i].isTimed());

      /* Skip probes that have already been answered, but count how many of
       * them are there. */
      if (this->fp_responses[i]) {
        timed_probes_answered++;
        continue;
      }

      /* If there is some timed probe for which we have already scheduled its
       * retransmission but it hasn't been sent yet, break the loop. We don't
       * have to worry about retransmitting these probes yet.*/
      if (this->fp_probes[i].getTimeSent().tv_sec == 0)
        return OP_SUCCESS;

      /* If we got a total timeout for any of the timed probes, we shouldn't
       * attempt more retransmissions. We set a flag to indicate that but we
       * still stay in the loop because we want to mark as "failed" any other
       * probes we have not yet checked. */
      if (this->fp_probes[i].probeFailed()) {
        timed_failed = true;
        continue;
      }

      /* Now check if the timed probe has timed out. If it suffered a total
       * time out (max retransmissions done and still no answer) then mark
       * it as such. Otherwise, count it so we can retransmit the whole
       * group of timed probes later if appropriate. */
      if (TIMEVAL_SUBTRACT(now, this->fp_probes[i].getTimeSent()) >= this->rto) {
        if (o.debugging > 3) {
          log_write(LOG_PLAIN, "[%s] timed probe %d (%s) timedout\n",
            this->target_host->targetipstr(), i, this->fp_probes[i].getProbeID());
        }
        if (this->fp_probes[i].getRetransmissions() >= o.maxOSTries()) {
          if (o.debugging > 3)
            log_write(LOG_PLAIN, "[%s] Timed probe #%d (%s) failed after %d retransmissions.\n", this->target_host->targetipstr(), i, this->fp_probes[i].getProbeID(), this->fp_probes[i].getRetransmissions());
          this->fp_probes[i].setFailed();
          /* Let the network controller know that we don't expect a response
           * for the probe anymore so the number of outstanding probes is
           * reduced and the effective window is incremented. */
          this->netctl->cc_report_final_timeout();
          /* Also, increase our unanswered counter so we can later decide
           * if the process has finished. */
          this->probes_unanswered++;
        } else {
          if (o.debugging > 3)
            log_write(LOG_PLAIN, "[%s] Timed probe #%d (%s) has timed out (%d retransmissions done).\n", this->target_host->targetipstr(), i, this->fp_probes[i].getProbeID(), this->fp_probes[i].getRetransmissions());
          timed_probes_timedout++;
        }
      }
    }

    if (o.debugging > 3)
      log_write(LOG_PLAIN, "[%s] Timed_probes=%d, answered=%u, timedout=%u\n",  this->target_host->targetipstr(), this->timed_probes, timed_probes_answered, timed_probes_timedout);

    /* If the probe that has timed out is a "timed probe" it means that
     * we need to retransmit all timed probes, not only this one. For
     * that, we wait until all timed probes have either timed out or
     * been responded. When that happens, we do the following:
     * 1) Store the responses we have received the last time we sent
     *    the timed probes in an aux array (this->aux_resp).
     * 2) Clear the responses to the timed probes from the main
     *    response array (this->fp_responses).
     * 3) Schedule the retransmission of all timed probes, 100ms apart. */
    if (this->timed_probes > 0 && timed_failed == false && timed_probes_timedout > 0 && (timed_probes_answered + timed_probes_timedout == this->timed_probes)) {

      /* Count the number of responses we have now and the number
       * of responses we stored in the aux buffer last time. */
      unsigned int responses_stored = 0;
      unsigned int responses_now = 0;
      for (unsigned int j = 0; j < this->timed_probes; j++) {
        if (this->aux_resp[j] != NULL)
          responses_stored++;
        if (this->fp_responses[j] != NULL)
          responses_now++;
      }

      /* If now we have more responses than before, copy our current
       * set of responses to the aux array. Otherwise, just
       * delete the current set of responses. */
      for (unsigned int k = 0; k < this->timed_probes; k++) {
        if (responses_now > responses_stored) {
          /* Free previous allocations */
          if (this->aux_resp[k] != NULL) {
            delete this->aux_resp[k];
          }
          /* Move the current response to the aux array */
          this->aux_resp[k] = this->fp_responses[k];
          this->fp_responses[k] = NULL;
        } else {
          delete this->fp_responses[k];
          this->fp_responses[k] = NULL;
        }
      }

      /* Update answer count because now we expect new answers to the timed probes. */
      assert(((int)this->probes_answered - (int)timed_probes_answered) >= 0);
      this->probes_answered-= timed_probes_answered;
      if (o.debugging > 3)
        log_write(LOG_PLAIN, "[%s] Adjusting answer count: before=%d, after=%d\n", this->target_host->targetipstr(), this->probes_answered + timed_probes_answered, this->probes_answered);


      /* Finally do the actual retransmission. Like the first time,
       * we schedule them 100ms apart, starting at same random point
       * between right now and 99ms. */
      int whentostart = get_random_u16()%100;
      for (size_t l = 0; l < this->timed_probes; l++) {
        this->fp_probes[l].incrementRetransmissions();
        this->netctl->scheduleProbe(&(this->fp_probes[l]), whentostart + l*100);
      }
      if (o.debugging > 3 && this->timed_probes > 0)
        log_write(LOG_PLAIN, "[%s] Retransmitting timed probes (rcvd_before=%u, rcvd_now=%u times=%d).\n", this->target_host->targetipstr(), responses_stored, responses_now, this->fp_probes[0].getRetransmissions());

      /* Reset our local counters. */
      timed_probes_answered = 0;
      timed_probes_timedout = 0;
    }
  }
  return OP_FAILURE;
}


/* This method is called when we detect that the OS detection process for this
 * host is completed. It basically updates the host's internal state to
 * indicate that the processed finished and unregisters the host from the
 * network controller so we don't get any more callbacks. Here we also handle
 * the special case of the retransmitted "timed probes". When we have to
 * retransmit such probes, we usually have two sets of responses: the ones we
 * got for the last retransmission, and the ones we got in the best try before
 * that. So what we have to do is to decide which set is the best and discard
 * the other one.*/
int FPHost6::set_done_and_wrap_up() {
  assert(this->probes_answered + this->probes_unanswered == this->total_probes);

  /* Inform the network controller that we do not wish to continue
   * receiving callbacks (it could happen if the system had some other
   * connections established with the target) */
  this->netctl->unregister_caller(this);

  /* Set up an internal flag to indicate we have finished */
  this->detection_done = true;

  /* Check the state of the timed probe retransmissions. In particular if we
   * retransmitted timed probes, we should have two sets of responses,
   * the ones we got last time we retransmitted, and the best set of responses
   * we got out of all previous retransmissions but the last one. So now, we
   * determine which set is the best and discard the other one. Btw, none of
   * these loops run if timed_probes == 0, so it's safe in all cases. */

  /* First count the number of responses in each set.  */
  unsigned int stored = 0;
  unsigned int current = 0;
  for (unsigned int i = 0; i < this->timed_probes; i++) {
    if (this->aux_resp[i] != NULL)
      stored++;
    if (this->fp_responses[i] != NULL)
      current++;
  }
  /* If we got more responses in a previous try, use them and get rid of
   * the current ones. */
  if (stored > current) {
    for (unsigned int i = 0; i < this->timed_probes; i++) {
        if (this->fp_responses[i] != NULL)
          delete this->fp_responses[i];
        this->fp_responses[i] = this->aux_resp[i];
        this->aux_resp[i] = NULL;
    }
  /* Otherwise, get rid of the stored responses, use the current set */
  } else {
    for (unsigned int i = 0; i < this->timed_probes; i++) {
      if (this->aux_resp[i] != NULL) {
        delete this->aux_resp[i];
        this->aux_resp[i] = NULL;
      }
    }
  }

  return OP_SUCCESS;
}


/* This function is called by the network controller every time a packet of
 * interest is captured. A "packet of interest" is a packet whose source
 * address matches the IP address of the target associated with the FPHost
 * instance. Inside the method, the received packet is processed in order to
 * determine if it corresponds to a response to a previous FPProbe sent to
 * that target. If the packet is a proper response, it will be stored for
 * later processing, as it is part of the target's stack fingerprint. Returns
 * a positive integer when the supplied packet could be successfully matched with
 * a previously sent probe. The returned value indicates how many times the
 * probe was sent before getting a reply: a return value of 1 means that we
 * got a normal reply, value two means that we had to retransmit the packet
 * once to get the reply, and so on. A return value of zero is a special case
 * that indicates that the supplied packet is a response to a timed probed
 * for which we already had received a reply in the past. This is necessary
 * because we need to indicate the network controller that this is not a normal
 * response to a retransmitted probe, and so, it should not be used to alter
 * congestion control parameters. A negative return value indicates that the
 * supplied packet is not a response to any probe sent by this host. */
int FPHost6::callback(const u8 *pkt, size_t pkt_len, const struct timeval *tv) {
  PacketElement *rcvd = NULL;
  /* Dummy packet to ensure destruction of rcvd. */
  FPPacket dummy;
  bool match_found = false;
  int times_tx = 0;

  /* Make sure we still expect callbacks */
  if (this->detection_done)
    return -1;

  if (o.debugging > 3)
    log_write(LOG_PLAIN, "[%s] Captured %lu bytes\n", this->target_host->targetipstr(), (unsigned long)pkt_len);

  /* Convert the ugly raw buffer into a nice chain of PacketElement objects, so
   * it's easier to parse the captured packet */
  if ((rcvd = PacketParser::split(pkt, pkt_len, false)) == NULL)
    return -2;
  dummy.setPacket(rcvd);

  /* Iterate over the list of sent probes and determine if the captured
   * packet is a response to one of them. */
  for (unsigned int i = 0; i < this->probes_sent; i++) {
      /* Skip probes for which we already got a response */
      if (this->fp_responses[i])
          continue;

      /* See if the received packet is a response to a probe */
      if (this->fp_probes[i].isResponse(rcvd)) {
          struct timeval now, time_sent;

          gettimeofday(&now, NULL);
          this->fp_responses[i] = new FPResponse(this->fp_probes[i].getProbeID(),
            pkt, pkt_len, fp_probes[i].getTimeSent(), *tv);
          this->fp_probes[i].incrementReplies();
          match_found = true;

          /* If the response that we've received is for a timed probe, we
           * need to do a special handling. We don't want to report that
           * we've received a response after N retransmissions because we
           * may have re-sent the packet even if we got a response in the past.
           * This happens when one of the timed probes times out and we
           * retransmit all of them. We don't want the network controller to
           * think there is congestion, so we only return the number of
           * retransmissions if we didn't get a response before and we did now. */
          if (this->fp_probes[i].isTimed() && this->fp_probes[i].getRetransmissions() > 0 && this->fp_probes[i].getReplies() > 1) {
            times_tx = 0; // Special case.
          } else {
            times_tx = this->fp_probes[i].getRetransmissions()+1;
          }
          this->probes_answered++;
          /* Recompute the Retransmission Timeout based on this new RTT observation. */
          time_sent = this->fp_probes[i].getTimeSent();
          assert(time_sent.tv_sec > 0);
          this->update_RTO(TIMEVAL_SUBTRACT(now, time_sent), this->fp_probes[i].getRetransmissions() != 0);
          break;
      }
  }

  if (match_found) {
    if (o.packetTrace()) {
      log_write(LOG_PLAIN, "RCVD  ");
      rcvd->print(stdout, LOW_DETAIL);
      log_write(LOG_PLAIN, "\n");
    }
    /* Here, check if with this match we completed the OS detection */
    if (this->probes_answered + this->probes_unanswered == this->total_probes) {
      /* Update our internal state to indicate we have finished */
      this->set_done_and_wrap_up();
    }
    /* Return the number of times that the packet was transmitted before
     * getting the reply. */
    return times_tx;
  } else {
    return -3;
  }
}


const FPProbe *FPHost6::getProbe(const char *id) {
  unsigned int i;

  for (i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    if (!this->fp_probes[i].is_set())
      continue;
    if (strcmp(this->fp_probes[i].getProbeID(), id) == 0)
      return &this->fp_probes[i];
  }

  return NULL;
}

const FPResponse *FPHost6::getResponse(const char *id) {
  unsigned int i;

  for (i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    if (this->fp_responses[i] == NULL)
      continue;
    if (strcmp(this->fp_responses[i]->probe_id, id) == 0)
      return this->fp_responses[i];
  }

  return NULL;
}


/******************************************************************************
 * Implementation of class FPPacket.                                          *
 ******************************************************************************/
FPPacket::FPPacket() {
 this->pkt = NULL;
 this->__reset();
}


FPPacket::~FPPacket() {
  this->__reset();
}


/* Resets all internal state, freeing any previously stored packets */
void FPPacket::__reset() {
  this->link_eth = false;
  memset(&(this->eth_hdr), 0, sizeof(struct eth_nfo));

  PacketElement *me = this->pkt, *aux = NULL;
  while (me != NULL) {
    aux = me->getNextElement();
    delete me;
    me = aux;
  }
  this->pkt = NULL;
  memset(&this->pkt_time, 0, sizeof(struct timeval));
}


/* Returns true if the FPPacket has been associated with a packet (through a
 * call to setPacket(). This is equivalent to the following conditional:
 * fppacket.getPacket() != NULL */
bool FPPacket::is_set() const {
  if (this->pkt != NULL)
    return true;
  else
    return false;
}


/* Associates de FPPacket instance with the first protocol header of a networkj
 * packet. Such header may be linked to others through the setNextElement()
 * mechanism. Note that FPPacket does NOT make a copy of the contents of the
 * supplied pointer, it just stores the memory address. Therefore, the caller
 * MUST ensure that the supplied pointer remains valid during the lifetime of
 * the FPPacket instance.
 *
 * After calling this function, the FPPacket takes ownership of pkt and will
 * delete pkt in its destructor. */
int FPPacket::setPacket(PacketElement *pkt) {
  assert(pkt != NULL);
  this->pkt = pkt;
  return OP_SUCCESS;
}


/* Returns a newly allocated byte array with packet contents. The caller is
 * responsible for freeing the buffer. */
u8 *FPPacket::getPacketBuffer(size_t *pkt_len) const {
  u8 *pkt_buff;

  pkt_buff = (u8 *)safe_malloc(this->pkt->getLen());
  this->pkt->dumpToBinaryBuffer(pkt_buff, this->pkt->getLen());

  *pkt_len = (size_t)this->pkt->getLen();

  return pkt_buff;
}


/* Returns a pointer to first header of the packet associated with the FPPacket
 * instance. Note that this method will return NULL unless a previous call to
 * setPacket() has been made. */
const PacketElement *FPPacket::getPacket() const {
  return this->pkt;
}


/* Returns the length of the packet associated with the FPPacket instance. Note
 * that this method will return zero unless an actual packet was associated
 * with the FPPacket object through a call to setPacket(). */
size_t FPPacket::getLength() const {
  if (this->pkt != NULL)
    return this->pkt->getLen();
  else
    return 0;
}


/* This method associates some link layer information with the packet. If
 * sending at the ethernet level is not required, just call it passing NULL
 * values, like this: instance.setEthernet(NULL, NULL, NULL);
 * Otherwise, pass the source address, the next hop address and the name of
 * the network interface the packet should be injected through. */
int FPPacket::setEthernet(const u8 *src_mac, const u8 *dst_mac, const char *devname) {
  if (src_mac == NULL || dst_mac == NULL) {
   memset(&(this->eth_hdr), 0, sizeof(struct eth_nfo));
   this->link_eth = false;
   return OP_FAILURE;
  }
  memcpy(this->eth_hdr.srcmac, src_mac, 6);
  memcpy(this->eth_hdr.dstmac, dst_mac, 6);
  this->link_eth = true;
  if (devname != NULL) {
    strncpy(this->eth_hdr.devname, devname, sizeof(this->eth_hdr.devname)-1);
    if ((this->eth_hdr.ethsd = eth_open_cached(devname)) == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, devname);
  } else {
    this->eth_hdr.devname[0] = '\0';
    this->eth_hdr.ethsd = NULL;
  }
  return OP_SUCCESS;
}


/* Returns an eth_nfo structure that contains the necessary parameters to
 * allow the transmission of the packet at the Ethernet level. Note that
 * such structure is only returned if a previous call to setEthernet() has
 * been made. If it hasn't, this means that the packet should be sent at
 * the IP layer, and only NULL will be returned. */
const struct eth_nfo *FPPacket::getEthernet() const {
  if (this->link_eth == true)
    return &(this->eth_hdr);
  else
    return NULL;
}


/* Sets the internal time holder to the current time. */
int FPPacket::setTime(const struct timeval *tv) {
  if (tv != NULL) {
    this->pkt_time = *tv;
    return 0;
  } else {
    return gettimeofday(&this->pkt_time, NULL);
  }
}


/* Returns the value of the internal time holder */
struct timeval FPPacket::getTime() const {
  return this->pkt_time;
}


/* Sets the internal time holder to zero. */
int FPPacket::resetTime() {
  memset(&this->pkt_time, 0, sizeof(struct timeval));
  return OP_SUCCESS;
}



/******************************************************************************
 * Implementation of class FPProbe.                                           *
 ******************************************************************************/
FPProbe::FPProbe() {
  this->probe_id = NULL;
  this->host = NULL;
  this->reset();
}


FPProbe::~FPProbe() {
  if (this->probe_id != NULL)
    free(this->probe_id);
}


void FPProbe::reset() {
  this->probe_no = 0;
  this->retransmissions = 0;
  this->times_replied = 0;
  this->failed = false;
  this->timed = false;
  if (this->probe_id != NULL)
    free(this->probe_id);
  this->probe_id = NULL;

  /* Also call FPPacket::__reset() to free any existing packet information */
  this->__reset();
}


/* Returns true if the supplied packet is a response to this FPProbe. This
 * method handles IPv4, IPv6, ICMPv4, ICMPv6, TCP and UDP. Basically it uses
 * PacketParser::is_response(). Check there for a list of matched packets and
 * some usage examples.*/
bool FPProbe::isResponse(PacketElement *rcvd) {
  /* If we don't have a record of even sending this probe, no packet can be a
     response. */
  if (this->pkt_time.tv_sec == 0 && this->pkt_time.tv_usec == 0)
    return false;

  bool is_response = PacketParser::is_response(this->pkt, rcvd);
  if (o.debugging > 2 && is_response)
    printf("Received response to probe %s\n", this->getProbeID());

  return is_response;
}


/* Store this probe's textual identifier. Note that this method makes a copy
 * of the supplied string, so you can safely change its contents without
 * affecting the object's state. */
int FPProbe::setProbeID(const char *id) {
  this->probe_id = strdup(id);
  return OP_SUCCESS;
}


/* Returns a pointer to probe's textual identifier. */
const char *FPProbe::getProbeID() const {
  return this->probe_id;
}


/* Returns the number of times the probe has been scheduled for retransmission. */
int FPProbe::getRetransmissions() const {
  return this->retransmissions;
}


/* Increment the number of times the probe has been scheduled for retransmission
 * by one unit. It returns the current value of the retransmission counter. */
int FPProbe::incrementRetransmissions() {
  this->retransmissions++;
  return this->retransmissions;
}


/* Returns the number of times the probe has been replied. This applies for
 * timed probes, which may be retransmitted even if we got a reply (because
 * another timed probe timeout and we had to retransmit all of them to keep
 * the timing accurate). */
int FPProbe::getReplies() const {
  return this->times_replied;
}


/* Increment the number of times the probe has been replied. It returns the
 * current value of the reply counter. */
int FPProbe::incrementReplies() {
  this->times_replied++;
  return this->times_replied;
}


/* Sets the time at which the probe was sent */
int FPProbe::setTimeSent() {
  return this->setTime();
}


/* Returns the time at which te packet was sent */
struct timeval FPProbe::getTimeSent() const {
  return this->getTime();
}


/* Sets the time at which the probe was sent to zero. */
int FPProbe::resetTimeSent() {
  return this->resetTime();
}

/* Returns true if this FPProbe did not receive any response after all
 * necessary retransmissions. When it returns true, callers should not
 * attempt to change the state of the FPProbe. */
bool FPProbe::probeFailed() const {
  return this->failed;
}


/* This method should be called when the probe has been retransmitted as many
 * times as we could and it still timed out without a response. Once this
 * method is called, the state is irreversible (unless a call to FPProbe::reset()
 * is made, in which case all internal state disappears) */
int FPProbe::setFailed() {
  this->failed = true;
  return OP_SUCCESS;
}


/* Returns true if the probe is one of the "timed probes". */
bool FPProbe::isTimed() const {
  return this->timed;
}


/* Marks the probe as "timed". This is used to indicate that this probe has
 * specific timing requirements (it must be sent exactly 100ms after the
 * previous probe)., */
int FPProbe::setTimed() {
  this->timed = true;
  return OP_SUCCESS;
}


/******************************************************************************
 * Implementation of class FPResponse.                                        *
 ******************************************************************************/
FPResponse::FPResponse(const char *probe_id, const u8 *buf, size_t len,
  struct timeval senttime, struct timeval rcvdtime) {
  this->probe_id = string_pool_insert(probe_id);
  this->buf = (u8 *) safe_malloc(len);
  memcpy(this->buf, buf, len);
  this->len = len;
  this->senttime = senttime;
  this->rcvdtime = rcvdtime;
}


FPResponse::~FPResponse() {
  free(buf);
}


/******************************************************************************
 * Nsock handler wrappers.                                                    *
 ******************************************************************************/

/* This handler is a wrapper for the FPNetworkControl::probe_transmission_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void probe_transmission_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg) {
  global_netctl.probe_transmission_handler(nsp, nse, arg);
  return;
}


/* This handler is a wrapper for the FPNetworkControl:response_reception_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void response_reception_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg) {
  global_netctl.response_reception_handler(nsp, nse, arg);
  return;
}
