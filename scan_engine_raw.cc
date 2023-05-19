
/***************************************************************************
 * scan_engine_raw.cc -- includes helper functions for scan_engine.cc that *
 * are related to port scanning using raw (IP, Ethernet) packets.          *
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

/* $Id$ */

#include "nmap_error.h"
#include "NmapOps.h"
#include "Target.h"
#include "payload.h"
#include "scan_engine.h"
#include "scan_engine_raw.h"
#include "struct_ip.h"
#include "tcpip.h"
#include "utils.h"
#include <string>

#ifndef IPPROTO_SCTP
#include "libnetutil/netutil.h"
#endif

extern NmapOps o;

u16 UltraProbe::sport() const {
  switch (mypspec.proto) {
    case IPPROTO_TCP:
      return probes.IP.pd.tcp.sport;
    case IPPROTO_UDP:
      return probes.IP.pd.udp.sport;
    case IPPROTO_SCTP:
      return probes.IP.pd.sctp.sport;
    default:
      return 0;
  }
  /* not reached */
}

u16 UltraProbe::dport() const {
  switch (mypspec.proto) {
    case IPPROTO_TCP:
      return mypspec.pd.tcp.dport;
    case IPPROTO_UDP:
      return mypspec.pd.udp.dport;
    case IPPROTO_SCTP:
      return mypspec.pd.sctp.dport;
    default:
      /* dport() can get called for other protos if we
       * get ICMP responses during IP proto scans. */
      return 0;
  }
  /* not reached */
}

bool UltraProbe::check_proto_port(u8 proto, u16 sport_or_icmpid, u16 dport) const {
  if (proto != mypspec.proto)
    return false;
  switch (proto) {
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
      return sport_or_icmpid == probes.IP.pd.icmp.ident;
      break;
    case IPPROTO_TCP:
      return sport_or_icmpid == probes.IP.pd.tcp.sport &&
        dport == mypspec.pd.tcp.dport;
      break;
    case IPPROTO_UDP:
      return sport_or_icmpid == probes.IP.pd.udp.sport &&
        dport == mypspec.pd.udp.dport;
      break;
    case IPPROTO_SCTP:
      return sport_or_icmpid == probes.IP.pd.sctp.sport &&
        dport == mypspec.pd.sctp.dport;
      break;
    default:
      break;
  }
    return false;
}

/* Pass an arp packet, including ethernet header. Must be 42bytes */

void UltraProbe::setARP(const u8 *arppkt, u32 arplen) {
  type = UP_ARP;
  mypspec.type = PS_ARP;
  return;
}

void UltraProbe::setND(const u8 *ndpkt, u32 ndlen) {
  type = UP_ND;
  mypspec.type = PS_ND;
  return;
}

/* Sets this UltraProbe as type UP_IP and creates & initializes the
    internal IPProbe.  The relevant probespec is necessary for setIP
    because pspec.type is ambiguous with just the ippacket (e.g. a
    tcp packet could be PS_PROTO or PS_TCP). */
void UltraProbe::setIP(const u8 *ippacket, u32 len, const probespec *pspec) {
  const struct ip *ip = (const struct ip *) ippacket;
  const struct tcp_hdr *tcp = NULL;
  const struct udp_hdr *udp = NULL;
  const struct sctp_hdr *sctp = NULL;
  const struct ppkt *icmp = NULL;
  const void *data;
  u8 hdr;

  type = UP_IP;
  if (ip->ip_v == 4) {
    data = ipv4_get_data(ip, &len);
    assert(data != NULL);
    assert(len + ip->ip_hl * 4 == (u32) ntohs(ip->ip_len));
    probes.IP.ipid = ntohs(ip->ip_id);
    hdr = ip->ip_p;
  } else if (ip->ip_v == 6) {
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *) ippacket;
    data = ipv6_get_data_any(ip6, &len, &hdr);
    assert(data != NULL);
    assert(len == (u32) ntohs(ip6->ip6_plen));
    probes.IP.ipid = ntohl(ip6->ip6_flow & IP6_FLOWLABEL_MASK);
    hdr = ip6->ip6_nxt;
  } else {
    fatal("Bogus packet passed to %s -- only IP packets allowed", __func__);
  }

  if (hdr == IPPROTO_TCP) {
    assert(len >= sizeof(struct tcp_hdr));
    tcp = (const struct tcp_hdr *) data;
    probes.IP.pd.tcp.sport = ntohs(tcp->th_sport);
    probes.IP.pd.tcp.seq = ntohl(tcp->th_seq);
  } else if (hdr == IPPROTO_UDP) {
    assert(len >= sizeof(struct udp_hdr));
    udp = (const struct udp_hdr *) data;
    probes.IP.pd.udp.sport = ntohs(udp->uh_sport);
  } else if (hdr == IPPROTO_SCTP) {
    assert(len >= sizeof(struct sctp_hdr));
    sctp = (const struct sctp_hdr *) data;
    probes.IP.pd.sctp.sport = ntohs(sctp->sh_sport);
    probes.IP.pd.sctp.vtag = ntohl(sctp->sh_vtag);
  } else if ((ip->ip_v == 4 && hdr == IPPROTO_ICMP) || (ip->ip_v == 6 && hdr == IPPROTO_ICMPV6)) {
    assert(len >= sizeof(struct ppkt));
    icmp = (const struct ppkt *) data;
    probes.IP.pd.icmp.ident = ntohs(icmp->id);
  }

  mypspec = *pspec;
  return;
}

u16 UltraProbe::icmpid() const {
  assert(mypspec.proto == IPPROTO_ICMP || mypspec.proto == IPPROTO_ICMPV6);
  return probes.IP.pd.icmp.ident;
}

u32 UltraProbe::tcpseq() const {
  if (mypspec.proto == IPPROTO_TCP)
    return probes.IP.pd.tcp.seq;
  else
    fatal("Bogus seq number request to %s -- type is %s", __func__,
          pspectype2ascii(mypspec.type));

  return 0; // Unreached
}

u32 UltraProbe::sctpvtag() const {
  assert(mypspec.proto == IPPROTO_SCTP);
  return probes.IP.pd.sctp.vtag;
}

/* The try number can be encoded into a TCP SEQ or ACK
   field. This returns a 32-bit number which encodes this value along
   with a simple checksum. Decoding is done by seq32_decode. */
static u32 seq32_encode(UltraScanInfo *USI, tryno_t trynum) {
  u32 seq;
  u8 nfo;

  /* tryno is 8 bits */
  nfo = trynum.opaque;
  /* Mirror the data to ensure it is reconstructed correctly. */
  seq = (nfo << 16) + nfo;
  /* Obfuscate it a little */
  seq = seq ^ USI->seqmask;

  return seq;
}

/* Undoes seq32_encode. This extracts a try number and a port number from a
   32-bit value. Returns true if the checksum is correct, false otherwise. */
static bool seq32_decode(const UltraScanInfo *USI, u32 seq,
                         tryno_t *trynum) {
  if (trynum)
    trynum->opaque = 0;

  /* Undo the mask xor. */
  seq = seq ^ USI->seqmask;
  /* Check that both sides are the same. */
  if ((seq >> 16) != (seq & 0xFFFF))
    return false;

  if (trynum)
    trynum->opaque = seq & 0xFF;

  return true;
}

/* The try number can be encoded in the source port number. This returns a new
   port number that contains a try number encoded into the given port number.
   Decoding is done by sport_decode. */
static u16 sport_encode(u16 base_portno, tryno_t trynum) {
  return base_portno + trynum.opaque;
}

/* We don't actually decode the port number, since we already compare the
 * destination port number of the response with the source port of the probe.
 */
#if 0
/* Undoes sport_encode. This extracts a try number and ping sequence number from
   a port number given a "base" port number (the one given to
   sport_encode). Returns true if the decoded values seem reasonable, false
   otherwise. */
static bool sport_decode(u16 base_portno, u16 portno,
                         tryno_t *trynum) {
  unsigned int t;

  t = portno - base_portno;
  if (t > 0xff) {
    return false;
  } else {
    if (trynum)
      trynum->opaque = t;
  }

  return true;
}
#endif



static bool icmp_probe_match(const UltraScanInfo *USI, const UltraProbe *probe,
                             const struct ppkt *ping,
                             const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst,
                             u8 proto,
                             u32 ipid) {
  /* Check if it is ICMP or ICMPV6. */
  if (!probe->check_proto_port(proto, ntohs(ping->id), 0))
    return false;

  /* Don't match a timestamp request with an echo reply, for example. */
  if (proto == IPPROTO_ICMP &&
      ((ping->type == 0 && probe->pspec()->pd.icmp.type != 8) ||
       (ping->type == 14 && probe->pspec()->pd.icmp.type != 13) ||
       (ping->type == 18 && probe->pspec()->pd.icmp.type != 17)))
    return false;
  if (proto == IPPROTO_ICMPV6 &&
      (ping->type == 129 && probe->pspec()->pd.icmpv6.type != 128))
    return false;

  /* Sometimes we get false results when scanning localhost with
     -p- because we scan localhost with src port = dst port and
     see our outgoing packet and think it is a response. */
  if (probe->dport() == probe->sport() &&
      sockaddr_storage_cmp(src, dst) == 0 &&
      probe->ipid() == ipid)
    return false; /* We saw the packet we ourselves sent */

  return true;
}

static bool tcp_probe_match(const UltraScanInfo *USI, const UltraProbe *probe,
                            const struct tcp_hdr *tcp,
                            const struct sockaddr_storage *src, const struct sockaddr_storage *dst,
                            u32 ipid) {
  const struct probespec_tcpdata *probedata;
  tryno_t tryno = {0};
  bool goodseq;

  // If magic port is *not* set, then tryno is in the source port, and we
  // already checked that it matches.
  if (o.magic_port_set) {
    /* We are looking to recover the tryno of the probe, which are
       encoded in the ACK field for probes with the ACK flag set and in the SEQ
       field for all other probes. According to RFC 793, section 3.9, under
       "SEGMENT ARRIVES", it's supposed to work like this: If our probe had ACK
       set, our ACK number is reflected in the response's SEQ field. If our
       probe had SYN or FIN set (and not ACK), then our SEQ is one less than the
       returned ACK value because SYN and FIN consume a sequence number (section
       3.3). Otherwise, our SEQ is the returned ACK.

       However, nmap-os-db shows that these assumptions can't be relied on, so
       we try all three possibilities for each probe. */
    goodseq = seq32_decode(USI, ntohl(tcp->th_ack) - 1, &tryno)
              || seq32_decode(USI, ntohl(tcp->th_ack), &tryno)
              || seq32_decode(USI, ntohl(tcp->th_seq), &tryno);
    if (!goodseq) {
      /* Connection info matches, but there was a nonsensical tryno. */
      if (o.debugging)
        log_write(LOG_PLAIN, "Bad Sequence number from host %s.\n", inet_ntop_ez(src, sizeof(*src)));
      return false;
    }

    /* Make sure that tryno matches the values in the probe. */
    if (!probe->check_tryno(tryno.opaque))
      return false;

  }

  /* Make sure we are matching up the right kind of probe, otherwise just the
     ports, address, and tryno can be ambiguous, between a SYN and an
     ACK probe during a -PS80 -PA80 scan for example. A SYN/ACK can only be
     matched to a SYN probe. */
  probedata = &probe->pspec()->pd.tcp;
  if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)
      && !(probedata->flags & TH_SYN)) {
    return false;
  }

  /* Sometimes we get false results when scanning localhost with -p- because we
     scan localhost with src port = dst port and see our outgoing packet and
     think it is a response. */
  if (probe->dport() == probe->sport()
      && sockaddr_storage_cmp(src, dst) == 0
      && probe->ipid() == ipid)
    return false;

  return true;
}

/* Tries to get one *good* (finishes a probe) pcap response to a host discovery
   (ping) probe by the (absolute) time given in stime.  Even if stime is now,
   try an ultra-quick pcap read just in case.  Returns true if a "good" result
   was found, false if it timed out instead. */
int get_ping_pcap_result(UltraScanInfo *USI, struct timeval *stime) {
  bool goodone = false;
  bool timedout = false;
  bool adjust_timing = true;
  struct timeval rcvdtime;
  struct link_header linkhdr;
  const struct ip *ip_tmp;
  unsigned int bytes;
  const struct ppkt *ping;
  long to_usec;
  HostScanStats *hss = NULL;
  std::list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  int newstate = HOST_UNKNOWN;
  unsigned int probenum;
  unsigned int listsz;
  reason_t current_reason = ER_NORESPONSE;

  const void *data = NULL;
  unsigned int datalen;
  struct abstract_ip_hdr hdr;

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000)
      to_usec = 2000;
    ip_tmp = (struct ip *) readip_pcap(USI->pd, &bytes, to_usec, &rcvdtime,
                                       &linkhdr, true);
    gettimeofday(&USI->now, NULL);
    if (!ip_tmp) {
      if (TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
        timedout = true;
        break;
      } else {
        continue;
      }
    }

    if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
      /* While packets are still being received, I'll be generous and give
      an extra 1/5 sec.  But we have to draw the line somewhere */
      timedout = true;
    }

    /* OK, we got a packet.  Most packet validity tests are taken care
     * of in readip_pcap, so this is simple
     */

    datalen = bytes;
    data = ip_get_data(ip_tmp, &datalen, &hdr);
    if (data == NULL)
      continue;
    // If it's not sent to us, we don't care.
    if (sockaddr_storage_cmp(USI->SourceSockAddr(), &hdr.dst) != 0)
      continue;

    /* First check if it is ICMP, TCP, or UDP */
    if (hdr.proto == IPPROTO_ICMP || hdr.proto == IPPROTO_ICMPV6) {
      /* if it is our response */
      ping = (struct ppkt *) data;
      if (bytes < 8U) {
        if (!ip_tmp->ip_off)
          error("Supposed ping packet is only %d bytes long!", bytes);
        continue;
      }

      current_reason = icmp_to_reason(hdr.proto, ping->type, ping->code);

      /* Echo reply, Timestamp reply, or Address Mask Reply. RFCs 792 and 950. */
      /* ICMPv6 Echo reply */
      if (USI->ptech.rawicmpscan
          && ((hdr.proto == IPPROTO_ICMP && (ping->type == 0 || ping->type == 14 || ping->type == 18))
              || (hdr.proto == IPPROTO_ICMPV6 && ping->type == 129))) {
        hss = USI->findHost(&hdr.src);
        if (!hss)
          continue; // Not from a host that interests us
        setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
        probeI = hss->probes_outstanding.end();
        listsz = hss->num_probes_outstanding();

        /* A check for weird_responses is needed here. This is not currently
           possible because we don't have a good way to look up the original
           target of an ICMP probe based on the response. (massping encoded an
           array index in the ICMP sequence, which won't work here.) Once we've
           found the host that sent the probe that elicited the response, the
           test for weird_responses is
              if (sending_host->v4host().s_addr != ip->ip_src.s_addr)
                hss->target->weird_responses++;
           (That is, the target that sent the probe is not the same one that
           sent the response.)
         */

        goodone = false;

        /* Find the probe that provoked this response. */
        for (probenum = 0; probenum < listsz && !goodone; probenum++) {
          probeI--;
          probe = *probeI;

          if (!icmp_probe_match(USI, probe, ping, &hdr.src, &hdr.dst, hdr.proto, hdr.ipid))
            continue;

          goodone = true;
          newstate = HOST_UP;

          if (o.debugging)
            log_write(LOG_STDOUT, "We got a ping packet back from %s: id = %d seq = %d checksum = %d\n", inet_ntop_ez(&hdr.src, sizeof(hdr.src)), ping->id, ping->seq, ping->checksum);
        }
      }
      // For ICMP, the reply of TCP/UDP/ICMP packets can be Destination unreachable, source quench, or time exceeded
      /* For ICMPv6, the reply of TCP/UDP/ICMPV6 packets can be Destination Unreachable,
       * Packet Too Big, Time Exceeded and Parameter Problem.*/
      else if ((hdr.proto == IPPROTO_ICMP && (ping->type == 3 || ping->type
                                              == 4 || ping->type == 11))
               || (hdr.proto == IPPROTO_ICMPV6 && (ping->type == 1 || ping->type == 2
                   || ping->type == 3 || ping->type == 4))) {
        const void *encaps_data;
        unsigned int encaps_len;
        struct abstract_ip_hdr encaps_hdr;

        if (datalen < 8)
          continue;

        encaps_len = datalen - 8;
        encaps_data = ip_get_data((char *) data + 8, &encaps_len, &encaps_hdr);
        if (encaps_data == NULL ||
            /* UDP hdr, or TCP hdr up to seq #, or SCTP hdr up to vtag */
            ((USI->tcp_scan || USI->udp_scan || USI->sctp_scan) && encaps_len < 8)
            /* prot scan has no headers coming back, so we don't reserve the
               8 extra bytes */
           ) {
          if (o.debugging)
            error("Received short ICMP or ICMPv6 packet (%u bytes)", datalen);
          continue;
        }

        /* Bail out early if possible. */
        if (!USI->ptech.rawprotoscan) {
          if (encaps_hdr.proto == IPPROTO_ICMP && !USI->ptech.rawicmpscan)
            continue;
          if (encaps_hdr.proto == IPPROTO_ICMPV6 && !USI->ptech.rawicmpscan)
            continue;
          if (encaps_hdr.proto == IPPROTO_TCP && !USI->ptech.rawtcpscan)
            continue;
          if (encaps_hdr.proto == IPPROTO_UDP && !USI->ptech.rawudpscan)
            continue;
          if (encaps_hdr.proto == IPPROTO_SCTP && !USI->ptech.rawsctpscan)
            continue;
        }
        // If it didn't come from us, we don't care.
        if (sockaddr_storage_cmp(USI->SourceSockAddr(), &encaps_hdr.src) != 0)
          continue;

        hss = USI->findHost(&encaps_hdr.dst);
        if (!hss)
          continue; // Not referring to a host that interests us
        setTargetMACIfAvailable(hss->target, &linkhdr, &encaps_hdr.dst, 0);
        probeI = hss->probes_outstanding.end();
        listsz = hss->num_probes_outstanding();

        /* Find the probe that provoked this response. */
        for (probenum = 0; probenum < listsz; probenum++) {
          probeI--;
          probe = *probeI;

          if (probe->protocol() != encaps_hdr.proto)
            continue;

          if ((encaps_hdr.proto == IPPROTO_ICMP || encaps_hdr.proto == IPPROTO_ICMPV6)
              && USI->ptech.rawicmpscan) {
            /* The response was based on a ping packet we sent */
            if (probe->icmpid() != ntohs(((struct icmp *) encaps_data)->icmp_id))
              continue;
          } else if (encaps_hdr.proto == IPPROTO_TCP && USI->ptech.rawtcpscan) {
            const struct tcp_hdr *tcp = (struct tcp_hdr *) encaps_data;
            if (probe->dport() != ntohs(tcp->th_dport) ||
                probe->sport() != ntohs(tcp->th_sport) ||
                probe->tcpseq() != ntohl(tcp->th_seq))
              continue;
          } else if (encaps_hdr.proto == IPPROTO_UDP && USI->ptech.rawudpscan) {
            const struct udp_hdr *udp = (struct udp_hdr *) encaps_data;
            if (probe->dport() != ntohs(udp->uh_dport) ||
                probe->sport() != ntohs(udp->uh_sport))
              continue;
          } else if (encaps_hdr.proto == IPPROTO_SCTP && USI->ptech.rawsctpscan) {
            const struct sctp_hdr *sctp = (struct sctp_hdr *) encaps_data;
            if (probe->dport() != ntohs(sctp->sh_dport) ||
                probe->sport() != ntohs(sctp->sh_sport) ||
                probe->sctpvtag() != ntohl(sctp->sh_vtag))
              continue;
          } else if (USI->ptech.rawprotoscan) {
            /* Success; we already know that the address and protocol match. */
          } else {
            assert(0);
          }

          /* If we made it this far, we found it. We don't yet know if it's
             going to change a host state (goodone) or not. */
          break;
        }
        /* Did we fail to find a probe? */
        if (probenum >= listsz)
          continue;

        /* Destination unreachable. */
        if ((hdr.proto == IPPROTO_ICMP && ping->type == 3)
            || (hdr.proto == IPPROTO_ICMPV6 && ping->type == 1)) {
          // If it's Port or Proto unreachable and the address matches, it's up.
          if (((hdr.proto == IPPROTO_ICMP && (ping->code == 2 || ping->code == 3))
                || (hdr.proto == IPPROTO_ICMPV6 && ping->code == 4))
                && sockaddr_storage_cmp(hss->target->TargetSockAddr(), &hdr.src) == 0) {
            /* The ICMP or ICMPv6 error came directly from the target, so it's up. */
            goodone = true;
            newstate = HOST_UP;
            if (o.debugging) {
              log_write(LOG_STDOUT, "Got port/proto unreachable for %s\n", hss->target->targetipstr());
            }
          }
          else {
            /* For other codes, see RFC 1122:
             * A Destination Unreachable message that is received with code
             * 0 (Net), 1 (Host), or 5 (Bad Source Route) may result from a
             * routing transient and MUST therefore be interpreted as only
             * a hint, not proof, that the specified destination is unreachable
             */
            // Still, it's a response so we should destroy the matching probe.
            goodone = true;
            newstate = HOST_UNKNOWN;
            adjust_timing = false;
            if (o.debugging) {
              log_write(LOG_STDOUT, "Got destination unreachable for %s\n", hss->target->targetipstr());
            }
          }
        } else if ((hdr.proto == IPPROTO_ICMP && ping->type == 11)
                   || (hdr.proto == IPPROTO_ICMPV6 && ping->type == 3)) {
          if (o.debugging)
            log_write(LOG_STDOUT, "Got Time Exceeded for %s\n", hss->target->targetipstr());
          goodone = 1;
          newstate = HOST_DOWN;
          /* I don't want anything to do with timing this. */
          adjust_timing = false;
        } else if (hdr.proto == IPPROTO_ICMP) {
          if (ping->type == 4) {
            if (o.debugging)
              log_write(LOG_STDOUT, "Got ICMP source quench\n");
            usleep(50000);
          } else {
            if (o.debugging) {
              log_write(LOG_STDOUT, "Got ICMP message type %d code %d\n",
                  ping->type, ping->code);
            }
          }
        } else if (hdr.proto == IPPROTO_ICMPV6) {
          if (ping->type == 4) {
            if (o.debugging)
              log_write(LOG_STDOUT, "Got ICMPv6 Parameter Problem\n");
          } else {
            if (o.debugging)
              log_write(LOG_STDOUT, "Got ICMPv6 message type %d code %d\n",
                  ping->type, ping->code);
          }
        }
      }
    } else if (hdr.proto == IPPROTO_TCP && USI->ptech.rawtcpscan) {
      const struct tcp_hdr *tcp = (struct tcp_hdr *) data;
      /* Check that the packet has useful flags. */
      if (o.discovery_ignore_rst
        && (tcp->th_flags & TH_RST))
          continue;
      else if (!(tcp->th_flags & TH_RST)
        && ((tcp->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)))
          continue;

      /* Now ensure this host is even in the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      u16 sport = ntohs(tcp->th_sport);
      u16 dport = ntohs(tcp->th_dport);

      goodone = false;

      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
            continue;
        if (!tcp_probe_match(USI, probe, tcp, &hdr.src, &hdr.dst, hdr.ipid))
          continue;

        goodone = true;
        newstate = HOST_UP;

        /* Fill out the reason. */
        if (o.pingtype & PINGTYPE_TCP_USE_SYN) {
          if (tcp->th_flags & TH_RST) {
            current_reason = ER_RESETPEER;
          } else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            current_reason = ER_SYNACK;
          }
        } else if (o.pingtype & PINGTYPE_TCP_USE_ACK) {
          if (tcp->th_flags & TH_RST)
            current_reason = ER_RESETPEER;
        }

        if (o.debugging)
          log_write(LOG_STDOUT, "We got a TCP ping packet back from %s port %hu (trynum = %d)\n", inet_ntop_ez(&hdr.src, sizeof(hdr.src)), sport, probe->get_tryno());
      }
    } else if (hdr.proto == IPPROTO_UDP && USI->ptech.rawudpscan) {
      const struct udp_hdr *udp = (struct udp_hdr *) data;
      /* Search for this host on the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us

      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      u16 sport = ntohs(udp->uh_sport);
      u16 dport = ntohs(udp->uh_dport);

      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
          continue;

        /* Sometimes we get false results when scanning localhost with
           -p- because we scan localhost with src port = dst port and
           see our outgoing packet and think it is a response. */
        if (probe->dport() == probe->sport() &&
            sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
            probe->ipid() == hdr.ipid)
          continue; /* We saw the packet we ourselves sent */

        goodone = true;
        newstate = HOST_UP;
        current_reason = ER_UDPRESPONSE;

        if (o.debugging)
          log_write(LOG_STDOUT, "In response to UDP-ping, we got UDP packet back from %s port %hu (trynum = %d)\n", inet_ntop_ez(&hdr.src, sizeof(hdr.src)), sport, probe->get_tryno());
      }
    } else if (hdr.proto == IPPROTO_SCTP && USI->ptech.rawsctpscan) {
      const struct sctp_hdr *sctp = (struct sctp_hdr *) data;
      const struct dnet_sctp_chunkhdr *chunk =
        (struct dnet_sctp_chunkhdr *) ((u8 *) sctp + 12);
      /* Search for this host on the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      u16 sport = ntohs(sctp->sh_sport);
      u16 dport = ntohs(sctp->sh_dport);

      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
          continue;

        /* Sometimes we get false results when scanning localhost with
           -p- because we scan localhost with src port = dst port and
           see our outgoing packet and think it is a response. */
        if (probe->dport() == probe->sport() &&
            sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
            probe->ipid() == hdr.ipid)
          continue; /* We saw the packet we ourselves sent */

        goodone = true;
        newstate = HOST_UP;
        if (chunk->sch_type == SCTP_INIT_ACK) {
          current_reason = ER_INITACK;
        } else if (chunk->sch_type == SCTP_ABORT) {
          current_reason = ER_ABORT;
        } else {
          current_reason = ER_UNKNOWN;
          if (o.debugging)
            log_write(LOG_STDOUT, "Received scan response with unexpected SCTP chunks: n/a");
        }
      }
    } else if (!USI->ptech.rawprotoscan) {
      if (o.debugging > 2)
        error("Received packet with protocol %d; ignoring.", hdr.proto);
    }

    /* Check for a protocol reply */
    if (!goodone && USI->ptech.rawprotoscan) {
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue;
      setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (probe->protocol() == hdr.proto) {
          /* if this is our probe we sent to localhost, then it doesn't count! */
          if (sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
              probe->ipid() == hdr.ipid)
            break;

          newstate = HOST_UP;
          current_reason = ER_PROTORESPONSE;
          goodone = true;
        }
      }
    }
  } while (!goodone && !timedout);

  if (goodone && newstate != HOST_UNKNOWN) {
    if (probe->isPing())
      ultrascan_ping_update(USI, hss, probeI, &USI->now, adjust_timing);
    else {
      ultrascan_host_probe_update(USI, hss, probeI, newstate, &rcvdtime, adjust_timing);
      /* If the host is up, we can forget our other probes. */
      if (newstate == HOST_UP)
        hss->destroyAllOutstandingProbes();
      if (newstate == HOST_UP && data)
        setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
      hss->target->reason.reason_id = current_reason;
      hss->target->reason.ttl = hdr.ttl;
      if (sockaddr_storage_cmp(&hdr.src, hss->target->TargetSockAddr()) != 0) {
        hss->target->reason.set_ip_addr(&hdr.src);
      }
    }
  }

  return goodone;
}

/* Initiate libpcap or some other sniffer as appropriate to be able to catch
   responses */
void begin_sniffer(UltraScanInfo *USI, std::vector<Target *> &Targets) {
  std::string pcap_filter = "";
  /* 20 IPv6 addresses is max (45 byte addy + 14 (" or src host ")) * 20 == 1180 */
  std::string dst_hosts = "";
  unsigned int len = 0;
  unsigned int targetno;
  bool doIndividual = Targets.size() <= 20; // Don't bother IP limits if scanning huge # of hosts

  if (doIndividual) {
    for (targetno = 0; targetno < Targets.size(); targetno++) {
      dst_hosts += (targetno == 0) ? "" : " or ";
      dst_hosts += "src host ";
      dst_hosts += Targets[targetno]->targetipstr();
    }
  }

  if ((USI->pd = my_pcap_open_live(Targets[0]->deviceName(), 256,  (o.spoofsource) ? 1 : 0, pcap_selectable_fd_valid() ? 200 : 2)) == NULL)
    fatal("%s", PCAP_OPEN_ERRMSG);

  int datalink = pcap_datalink(USI->pd);
  if (datalink < 0) {
    error("Warning: unable to determine data link for interface %s", Targets[0]->deviceName());
  }
  if (USI->ping_scan_arp) {
    assert(datalink == DLT_EN10MB);
    /* Some OSs including Windows 7 and Solaris 10 have been seen to send their
       ARP replies to the broadcast address, not to the (unicast) address that
       the request came from, therefore listening for ARP packets directed to
       us is not enough. Look inside the ARP reply at the target address field
       instead. The filter string will look like
         arp and arp[18:4] = 0xAABBCCDD and arp[22:2] = 0xEEFF */
    char macstring[2 * ETH_ADDR_LEN + 1];
    const u8 *mac = Targets[0]->SrcMACAddress();
    assert(mac);
    len = Snprintf(macstring, sizeof(macstring), "%02X%02X%02X%02X%02X%02X",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (len != sizeof(macstring) - 1)
      fatal("macstring length is %d, should be %u", len, (unsigned)(sizeof(macstring) - 1));
    /* First four bytes of MAC. */
    pcap_filter = "arp and arp[18:4] = 0x";
    pcap_filter.append(macstring, 0, 4 * 2);
    /* Last two bytes. */
    pcap_filter += " and arp[22:2] = 0x";
    pcap_filter.append(macstring, 4 * 2, 2 * 2);
    //its not arp, so lets check if for a protocol scan.
  } else if (USI->ping_scan_nd) {
    /* Libpcap: IPv6 upper-layer protocol is not supported by proto[x] */
    /* Grab the ICMPv6 type using ip6[X:Y] syntax. This works only if there are no
       extension headers (top-level nh is IPPROTO_ICMPV6). */
    const u8 *srcmac = Targets[0]->SrcMACAddress();
    assert(srcmac);
    char filterstr[256];
    Snprintf(filterstr, 256, "icmp6 and ip6[6:1] = %u and ip6[40:1] = %u",
             IPPROTO_ICMPV6, ICMPV6_NEIGHBOR_ADVERTISEMENT);
    pcap_filter.append(filterstr);
  } else if (USI->prot_scan || (USI->ping_scan && USI->ptech.rawprotoscan)) {
    pcap_filter = "dst host ";
    pcap_filter += inet_ntop_ez(USI->SourceSockAddr(), sizeof(struct sockaddr_storage));
    if (doIndividual) {
      pcap_filter += " and (icmp or icmp6 or (";
      pcap_filter += dst_hosts;
      pcap_filter += "))";
    }
  } else if (USI->tcp_scan || USI->udp_scan || USI->sctp_scan || USI->ping_scan) {
    bool first = false;
    pcap_filter = "dst host ";
    pcap_filter += inet_ntop_ez(USI->SourceSockAddr(), sizeof(struct sockaddr_storage));
    pcap_filter += " and (icmp or icmp6";
    if (doIndividual) {
      pcap_filter += " or (";
      first = true;
    }
    if (USI->tcp_scan || (USI->ping_scan && USI->ptech.rawtcpscan)) {
      if (!first) {
        pcap_filter += " or ";
      }
      else if (doIndividual) {
        pcap_filter += "(";
      }
      pcap_filter += "tcp";
      first = false;
    }
    if (USI->udp_scan || (USI->ping_scan && USI->ptech.rawudpscan)) {
      if (!first) {
        pcap_filter += " or ";
      }
      else if (doIndividual) {
        pcap_filter += "(";
      }
      pcap_filter += "udp";
      first = false;
    }
    if (USI->sctp_scan || (USI->ping_scan && USI->ptech.rawsctpscan)) {
      if (!first) {
        pcap_filter += " or ";
      }
      else if (doIndividual) {
        pcap_filter += "(";
      }
      pcap_filter += "sctp";
      first = false;
    }
    if (doIndividual) {
      if (!first) {
        pcap_filter += ") and (";
      }
      pcap_filter += dst_hosts;
      if (!first) {
        pcap_filter += ")";
      }
      pcap_filter += ")";
    }
    pcap_filter += ")";
  } else {
    assert(0);
  }
  if (o.debugging)
    log_write(LOG_PLAIN, "Packet capture filter (device %s): %s\n", Targets[0]->deviceFullName(), pcap_filter.c_str());
  set_pcap_filter(Targets[0]->deviceFullName(), USI->pd, pcap_filter.c_str());
  /* pcap_setnonblock(USI->pd, 1, NULL); */
  return;
}

/* The probe sent is returned. */
UltraProbe *sendArpScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                             tryno_t tryno) {
  int rc;
  UltraProbe *probe = new UltraProbe();

  /* 3 cheers for libdnet header files */
  u8 frame[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

  eth_pack_hdr(frame, ETH_ADDR_BROADCAST, *hss->target->SrcMACAddress(),
               ETH_TYPE_ARP);
  arp_pack_hdr_ethip(frame + ETH_HDR_LEN, ARP_OP_REQUEST,
                     *hss->target->SrcMACAddress(), *hss->target->v4sourceip(),
                     "\x00\x00\x00\x00\x00\x00",  *hss->target->v4hostip());
// RFC 826 says that the ar$tha field need not be set to anything in particular (i.e. its value doesn't matter)
// We use 00:00:00:00:00:00 since that is what IP stacks in currently popular operating systems use

  gettimeofday(&USI->now, NULL);
  probe->sent = USI->now;
  hss->probeSent(sizeof(frame));
  if ((rc = eth_send(USI->ethsd, frame, sizeof(frame))) != sizeof(frame)) {
    int err = socket_errno();
    error("WARNING: eth_send of ARP packet returned %i rather than expected %d (errno=%i: %s)", rc, (int) sizeof(frame), err, strerror(err));
  }
  PacketTrace::traceArp(PacketTrace::SENT, (u8 *) frame + ETH_HDR_LEN, sizeof(frame) - ETH_HDR_LEN, &USI->now);
  probe->tryno = tryno;
  /* First build the probe */
  probe->setARP(frame, sizeof(frame));

  /* Now that the probe has been sent, add it to the Queue for this host */
  hss->probes_outstanding.push_back(probe);
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  gettimeofday(&USI->now, NULL);
  return probe;
}

UltraProbe *sendNDScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                            tryno_t tryno) {
  UltraProbe *probe = new UltraProbe();
  struct eth_nfo eth;
  struct eth_nfo *ethptr = NULL;
  u8 *packet = NULL;
  u32 packetlen = 0;
  struct in6_addr ns_dst_ip6;
  ns_dst_ip6 = *hss->target->v6hostip();

  if (USI->ethsd) {
    unsigned char ns_dst_mac[6] = {0x33, 0x33, 0xff};
    ns_dst_mac[3] = ns_dst_ip6.s6_addr[13];
    ns_dst_mac[4] = ns_dst_ip6.s6_addr[14];
    ns_dst_mac[5] = ns_dst_ip6.s6_addr[15];

    memcpy(eth.srcmac, hss->target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, ns_dst_mac, 6);
    eth.ethsd = USI->ethsd;
    eth.devname[0] = '\0';
    ethptr = &eth;
  }

  unsigned char multicast_prefix[13] = {0};
  multicast_prefix[0] = 0xff;
  multicast_prefix[1] = 0x02;
  multicast_prefix[11] = 0x1;
  multicast_prefix[12] = 0xff;
  memcpy(&ns_dst_ip6, multicast_prefix, sizeof(multicast_prefix));

  const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) USI->SourceSockAddr();

  struct icmpv6_msg_nd ns_msg;
  ns_msg.icmpv6_flags = htons(0);
  memcpy(&ns_msg.icmpv6_target, hss->target->v6hostip(), IP6_ADDR_LEN);
  ns_msg.icmpv6_option_type = 1;
  ns_msg.icmpv6_option_length = 1;
  memcpy(&ns_msg.icmpv6_mac, hss->target->SrcMACAddress(), ETH_ADDR_LEN);

  packet = build_icmpv6_raw(&sin6->sin6_addr, &ns_dst_ip6,
                            0, 0, o.ttl, 0, 0, ICMPV6_NEIGHBOR_SOLICITATION,
                            0, (char *)&ns_msg, sizeof(ns_msg),
                            &packetlen);
  probe->sent = USI->now;
  hss->probeSent(packetlen);
  send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);

  probe->tryno = tryno;
  /* First build the probe */
  probe->setND(packet, packetlen);

  free(packet);

  /* Now that the probe has been sent, add it to the Queue for this host */
  hss->probes_outstanding.push_back(probe);
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  gettimeofday(&USI->now, NULL);
  return probe;
}

/* Build an appropriate protocol scan (-sO) probe for the given source and
   destination addresses and protocol. src and dst must be of the same address
   family. Returns NULL on error. */
static u8 *build_protoscan_packet(const struct sockaddr_storage *src,
                                  const struct sockaddr_storage *dst, u8 proto, u16 sport, u32 *packetlen) {
  u16 icmp_ident, ipid;
  u8 *packet;

  packet = NULL;
  *packetlen = 0;

  ipid = get_random_u16();
  /* Some hosts do not respond to ICMP requests if the identifier is 0. */
  icmp_ident = (get_random_u16() % 0xffff) + 1;

  assert(src->ss_family == dst->ss_family);

  if (src->ss_family == AF_INET) {
    const struct sockaddr_in *src_in, *dst_in;

    src_in = (struct sockaddr_in *) src;
    dst_in = (struct sockaddr_in *) dst;

    switch (proto) {
    case IPPROTO_TCP:
      packet = build_tcp_raw(&src_in->sin_addr, &dst_in->sin_addr,
                             o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                             sport, DEFAULT_TCP_PROBE_PORT, get_random_u32(), get_random_u32(), 0, TH_ACK, 0, 0, NULL, 0,
                             o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_ICMP:
      packet = build_icmp_raw(&src_in->sin_addr, &dst_in->sin_addr,
                              o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                              0, icmp_ident, 8, 0,
                              o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_IGMP:
      packet = build_igmp_raw(&src_in->sin_addr, &dst_in->sin_addr,
                              o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                              0x11, 0,
                              o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_UDP:
      packet = build_udp_raw(&src_in->sin_addr, &dst_in->sin_addr,
                             o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                             sport, DEFAULT_UDP_PROBE_PORT,
                             o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_SCTP: {
      struct sctp_chunkhdr_init chunk;

      sctp_pack_chunkhdr_init(&chunk, SCTP_INIT, 0, sizeof(chunk),
                              get_random_u32() /*itag*/, 32768, 10, 2048, get_random_u32() /*itsn*/);
      packet = build_sctp_raw(&src_in->sin_addr, &dst_in->sin_addr,
                              o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                              sport, DEFAULT_SCTP_PROBE_PORT, 0UL, (char*) &chunk, sizeof(chunk),
                              o.extra_payload, o.extra_payload_length, packetlen);
    }
    break;
    default:
      packet = build_ip_raw(&src_in->sin_addr, &dst_in->sin_addr,
                            proto,
                            o.ttl, ipid, IP_TOS_DEFAULT, false, o.ipoptions, o.ipoptionslen,
                            o.extra_payload, o.extra_payload_length, packetlen);
      break;
    }
  } else if (src->ss_family == AF_INET6) {
    const struct sockaddr_in6 *src_in6, *dst_in6;

    src_in6 = (struct sockaddr_in6 *) src;
    dst_in6 = (struct sockaddr_in6 *) dst;

    switch (proto) {
    case IPPROTO_TCP:
      packet = build_tcp_raw_ipv6(&src_in6->sin6_addr, &dst_in6->sin6_addr,
                                  0, ipid, o.ttl,
                                  sport, DEFAULT_TCP_PROBE_PORT, get_random_u32(), get_random_u32(), 0, TH_ACK, 0, 0, NULL, 0,
                                  o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_ICMPV6:
      packet = build_icmpv6_raw(&src_in6->sin6_addr, &dst_in6->sin6_addr,
                                0, ipid, o.ttl,
                                0, icmp_ident, ICMPV6_ECHO, ICMPV6_ECHOREPLY,
                                o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_UDP:
      packet = build_udp_raw_ipv6(&src_in6->sin6_addr, &dst_in6->sin6_addr,
                                  0, ipid, o.ttl,
                                  sport, DEFAULT_UDP_PROBE_PORT,
                                  o.extra_payload, o.extra_payload_length, packetlen);
      break;
    case IPPROTO_SCTP: {
      struct sctp_chunkhdr_init chunk;
      sctp_pack_chunkhdr_init(&chunk, SCTP_INIT, 0, sizeof(chunk),
                              get_random_u32() /*itag*/, 32768, 10, 2048, get_random_u32() /*itsn*/);
      packet = build_sctp_raw_ipv6(&src_in6->sin6_addr, &dst_in6->sin6_addr,
                                   0, ipid, o.ttl,
                                   sport, DEFAULT_SCTP_PROBE_PORT, 0UL, (char*) &chunk, sizeof(chunk),
                                   o.extra_payload, o.extra_payload_length, packetlen);
    }
    break;
    default:
      packet = build_ipv6_raw(&src_in6->sin6_addr, &dst_in6->sin6_addr,
                              0, ipid, proto, o.ttl,
                              o.extra_payload, o.extra_payload_length, packetlen);
      break;
    }
  }

  return packet;
}

/* The probe sent is returned.

   This function also handles the sending of decoys. There is no fine-grained
   control of this; all decoys are sent at once on one call of this function.
   This means that decoys do not honor any scan delay and may violate congestion
   control limits. */
UltraProbe *sendIPScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                            const probespec *pspec, tryno_t tryno) {
  u8 *packet = NULL;
  u32 packetlen = 0;
  UltraProbe *probe = new UltraProbe();
  int decoy = 0;
  u32 seq = 0;
  u32 ack = 0;
  u16 sport;
  u16 ipid = get_random_u16();
  struct eth_nfo eth;
  struct eth_nfo *ethptr = NULL;
  u8 *tcpops = NULL;
  u16 tcpopslen = 0;
  u32 vtag = 0;
  char *chunk = NULL;
  int chunklen = 0;
  /* Some hosts do not respond to ICMP requests if the identifier is 0. */
  u16 icmp_ident = (get_random_u16() % 0xffff) + 1;

  if (USI->ethsd) {
    memcpy(eth.srcmac, hss->target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, hss->target->NextHopMACAddress(), 6);
    eth.ethsd = USI->ethsd;
    eth.devname[0] = '\0';
    ethptr = &eth;
  }

  if (o.magic_port_set)
    sport = o.magic_port;
  else
    sport = sport_encode(USI->base_port, tryno);

  probe->tryno = tryno;
  /* First build the probe */
  if (pspec->type == PS_TCP) {
    assert(USI->scantype != CONNECT_SCAN);

    /* Normally we encode the tryno in the SEQ field, because that
       comes back (possibly incremented) in the ACK field of responses. But if
       our probe has the ACK flag set, the response reflects our own ACK number
       instead. */
    if (pspec->pd.tcp.flags & TH_ACK)
      ack = seq32_encode(USI, tryno);
    else
      seq = seq32_encode(USI, tryno);

    if (pspec->pd.tcp.flags & TH_SYN) {
      tcpops = (u8 *) TCP_SYN_PROBE_OPTIONS;
      tcpopslen = TCP_SYN_PROBE_OPTIONS_LEN;
    }

    if (hss->target->af() == AF_INET) {
      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        packet = build_tcp_raw(&((struct sockaddr_in *)&o.decoys[decoy])->sin_addr, hss->target->v4hostip(),
                               o.ttl, ipid, IP_TOS_DEFAULT, false,
                               o.ipoptions, o.ipoptionslen,
                               sport, pspec->pd.tcp.dport,
                               seq, ack, 0, pspec->pd.tcp.flags, 0, 0,
                               tcpops, tcpopslen,
                               o.extra_payload, o.extra_payload_length,
                               &packetlen);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    } else if (hss->target->af() == AF_INET6) {
      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        packet = build_tcp_raw_ipv6(&((struct sockaddr_in6 *)&o.decoys[decoy])->sin6_addr, hss->target->v6hostip(),
                                  0, 0, o.ttl, sport, pspec->pd.tcp.dport,
                                  seq, ack, 0, pspec->pd.tcp.flags, 0, 0,
                                  tcpops, tcpopslen,
                                  o.extra_payload, o.extra_payload_length,
                                  &packetlen);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    }
  } else if (pspec->type == PS_UDP) {
    const u8 *payload;
    int payload_length;
    u8 numpayloads = udp_payload_count(pspec->pd.udp.dport);
    // Even if no payloads, we can send with null payload
    numpayloads = MAX(numpayloads, 1);

    for (u8 i=0; i < numpayloads; i++) {
      payload = get_udp_payload(pspec->pd.udp.dport, &payload_length, i);

      if (hss->target->af() == AF_INET) {
        for (decoy = 0; decoy < o.numdecoys; decoy++) {
          packet = build_udp_raw(&((struct sockaddr_in *)&o.decoys[decoy])->sin_addr, hss->target->v4hostip(),
                                 o.ttl, ipid, IP_TOS_DEFAULT, false,
                                 o.ipoptions, o.ipoptionslen,
                                 sport, pspec->pd.udp.dport,
                                 (char *) payload, payload_length,
                                 &packetlen);
          if (decoy == o.decoyturn) {
            probe->setIP(packet, packetlen, pspec);
            probe->sent = USI->now;
          }
          hss->probeSent(packetlen);
          send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
          free(packet);
        }
      } else if (hss->target->af() == AF_INET6) {
        for (decoy = 0; decoy < o.numdecoys; decoy++) {
          packet = build_udp_raw_ipv6(&((struct sockaddr_in6 *)&o.decoys[decoy])->sin6_addr, hss->target->v6hostip(),
                                    0, 0, o.ttl, sport, pspec->pd.tcp.dport,
                                    (char *) payload, payload_length,
                                    &packetlen);
          if (decoy == o.decoyturn) {
            probe->setIP(packet, packetlen, pspec);
            probe->sent = USI->now;
          }
          hss->probeSent(packetlen);
          send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
          free(packet);
        }
      }
    }
  } else if (pspec->type == PS_SCTP) {
    switch (pspec->pd.sctp.chunktype) {
    case SCTP_INIT:
      chunklen = sizeof(struct sctp_chunkhdr_init);
      chunk = (char*)safe_malloc(chunklen);
      sctp_pack_chunkhdr_init(chunk, SCTP_INIT, 0, chunklen,
                              get_random_u32()/*itag*/,
                              32768, 10, 2048,
                              get_random_u32()/*itsn*/);
      vtag = 0;
      break;
    case SCTP_COOKIE_ECHO:
      chunklen = sizeof(struct sctp_chunkhdr_cookie_echo) + 4;
      chunk = (char*)safe_malloc(chunklen);
      *((u32*)((char*)chunk + sizeof(struct sctp_chunkhdr_cookie_echo))) =
        get_random_u32();
      sctp_pack_chunkhdr_cookie_echo(chunk, SCTP_COOKIE_ECHO, 0, chunklen);
      vtag = get_random_u32();
      break;
    default:
      assert(0);
    }
    if (hss->target->af() == AF_INET) {
      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        packet = build_sctp_raw(&((struct sockaddr_in *)&o.decoys[decoy])->sin_addr, hss->target->v4hostip(),
                                o.ttl, ipid, IP_TOS_DEFAULT, false,
                                o.ipoptions, o.ipoptionslen,
                                sport, pspec->pd.sctp.dport,
                                vtag, chunk, chunklen,
                                o.extra_payload, o.extra_payload_length,
                                &packetlen);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    } else if (hss->target->af() == AF_INET6) {
      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        packet = build_sctp_raw_ipv6(&((struct sockaddr_in6 *)&o.decoys[decoy])->sin6_addr, hss->target->v6hostip(),
                                   0, 0, o.ttl, sport, pspec->pd.sctp.dport,
                                   vtag, chunk, chunklen,
                                   o.extra_payload, o.extra_payload_length,
                                   &packetlen);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    }
    free(chunk);
  } else if (pspec->type == PS_PROTO) {
    if (hss->target->af() == AF_INET) {
      struct sockaddr_storage ss;
      struct sockaddr_in *sin;

      sin = (struct sockaddr_in *) &ss;
      sin->sin_family = AF_INET;

      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        sin->sin_addr = ((struct sockaddr_in *)&o.decoys[decoy])->sin_addr;
        packet = build_protoscan_packet(&ss, hss->target->TargetSockAddr(),
                                        pspec->proto, sport, &packetlen);
        assert(packet != NULL);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    } else if (hss->target->af() == AF_INET6) {
      struct sockaddr_storage ss;
      struct sockaddr_in6 *sin6;

      sin6 = (struct sockaddr_in6 *) &ss;
      sin6->sin6_family = AF_INET6;

      for (decoy = 0; decoy < o.numdecoys; decoy++) {
        sin6->sin6_addr = ((struct sockaddr_in6 *)&o.decoys[decoy])->sin6_addr;
        packet = build_protoscan_packet(&ss, hss->target->TargetSockAddr(),
                                      pspec->proto, sport, &packetlen);
        assert(packet != NULL);
        if (decoy == o.decoyturn) {
          probe->setIP(packet, packetlen, pspec);
          probe->sent = USI->now;
        }
        hss->probeSent(packetlen);
        send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
        free(packet);
      }
    }
  } else if (pspec->type == PS_ICMP) {
    for (decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_icmp_raw(&((struct sockaddr_in *)&o.decoys[decoy])->sin_addr, hss->target->v4hostip(),
                              o.ttl, ipid, IP_TOS_DEFAULT, false,
                              o.ipoptions, o.ipoptionslen,
                              0, icmp_ident, pspec->pd.icmp.type, pspec->pd.icmp.code,
                              o.extra_payload, o.extra_payload_length,
                              &packetlen);
      if (decoy == o.decoyturn) {
        probe->setIP(packet, packetlen, pspec);
        probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
      free(packet);
    }
  } else if (pspec->type == PS_ICMPV6) {
    for (decoy =0; decoy < o.numdecoys; decoy++) {
      packet = build_icmpv6_raw(&((struct sockaddr_in6 *)&o.decoys[decoy])->sin6_addr, hss->target->v6hostip(),
                              0, 0, o.ttl, 0, icmp_ident, pspec->pd.icmpv6.type,
                              pspec->pd.icmpv6.code, o.extra_payload,
                              o.extra_payload_length,
                              &packetlen);
      if (decoy == o.decoyturn) {
        probe->setIP(packet, packetlen, pspec);
        probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, hss->target->TargetSockAddr(), packet, packetlen);
      free(packet);
    }
  } else assert(0);

  /* Now that the probe has been sent, add it to the Queue for this host */
  hss->probes_outstanding.push_back(probe);
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  gettimeofday(&USI->now, NULL);
  return probe;
}

/* Tries to get one *good* (finishes a probe) ARP response with pcap
   by the (absolute) time given in stime.  Even if stime is now, try
   an ultra-quick pcap read just in case.  Returns true if a "good"
   result was found, false if it timed out instead. */
bool get_arp_result(UltraScanInfo *USI, struct timeval *stime) {
  long to_usec;
  int rc;
  u8 rcvdmac[6];
  struct in_addr rcvdIP;
  struct timeval rcvdtime, fudgedsenttime;
  bool timedout = false;
  struct sockaddr_in sin;
  HostScanStats *hss = NULL;
  std::list<UltraProbe *>::iterator probeI;
  int gotone = 0;

  gettimeofday(&USI->now, NULL);

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000)
      to_usec = 2000;
    rc = read_arp_reply_pcap(USI->pd, rcvdmac, &rcvdIP, to_usec, &rcvdtime, PacketTrace::traceArp);
    gettimeofday(&USI->now, NULL);
    if (rc == -1)
      fatal("Received -1 response from read_arp_reply_pcap");
    if (rc == 0) {
      if (TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
        timedout = true;
        break;
      } else {
        continue;
      }
    }
    if (rc == 1) {
      if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
        /* While packets are still being received, I'll be generous
           and give an extra 1/5 sec.  But we have to draw the line
           somewhere.  Hopefully this response will be a keeper so it
           won't matter.  */
        timedout = true;
      }

      /* Yay, I got one.  Find whether I asked for it */
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = rcvdIP.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss)
        continue;
      /* Add found HW address for target */
      hss->target->setMACAddress(rcvdmac);
      hss->target->reason.reason_id = ER_ARPRESPONSE;

      if (hss->probes_outstanding.empty()) {
        /* It's up because we got a response, but doesn't count as a response
         * within this timeout window. Go around again. */
        hss->target->flags = HOST_UP;
        continue;
      }
      probeI = hss->probes_outstanding.end();
      do {
        /* Delay in libpcap could mean we sent another probe *after* this
         * response was received. Search back for the last probe before rcvdtime. */
        probeI--;
        /* If the response came just a hair (<25ms) after the probe was sent, it's
         * probably a response to an earlier probe instead. Keep looking. */
        TIMEVAL_MSEC_ADD(fudgedsenttime, (*probeI)->sent, INITIAL_ARP_RTT_TIMEOUT / 8);
      } while (TIMEVAL_AFTER(fudgedsenttime, rcvdtime) && probeI != hss->probes_outstanding.begin());
      ultrascan_host_probe_update(USI, hss, probeI, HOST_UP, &rcvdtime);
      /* Now that we know the host is up, we can forget our other probes. */
      hss->destroyAllOutstandingProbes();
      gotone = 1;
      //      printf("Marked host %s as up!", hss->target->NameIP());
      break;
    }
  } while (!timedout);

  return gotone;
}

bool get_ns_result(UltraScanInfo *USI, struct timeval *stime) {
  long to_usec;
  int rc;
  u8 rcvdmac[6];
  struct sockaddr_in6 rcvdIP;
  struct timeval rcvdtime, fudgedsenttime;
  bool timedout = false;
  bool has_mac = false;
  struct sockaddr_in6 sin6;
  HostScanStats *hss = NULL;
  std::list<UltraProbe *>::iterator probeI;
  int gotone = 0;

  gettimeofday(&USI->now, NULL);

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000)
      to_usec = 2000;
    rc = read_ns_reply_pcap(USI->pd, rcvdmac, &rcvdIP, to_usec, &rcvdtime, &has_mac, PacketTrace::traceND);
    gettimeofday(&USI->now, NULL);
    if (rc == -1)
      fatal("Received -1 response from read_arp_reply_pcap");
    if (rc == 0) {
      if (TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
        timedout = true;
        break;
      } else {
        continue;
      }
    }
    if (rc == 1) {
      if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
        /* While packets are still being received, I'll be generous
           and give an extra 1/5 sec.  But we have to draw the line
           somewhere.  Hopefully this response will be a keeper so it
           won't matter.  */
        timedout = true;
      }

      /* Yay, I got one.  Find whether I asked for it */
      /* Search for this host on the incomplete list */
      memset(&sin6, 0, sizeof(sin6));
      sin6.sin6_addr = rcvdIP.sin6_addr;
      sin6.sin6_family = AF_INET6;
      hss = USI->findHost((struct sockaddr_storage *) &sin6);
      if (!hss)
        continue;
      /* Add found HW address for target */
      /* A Neighbor Advertisement packet may not include the Target link-layer address. */
      if (has_mac)
        hss->target->setMACAddress(rcvdmac);
      hss->target->reason.reason_id = ER_NDRESPONSE;

      if (hss->probes_outstanding.empty()) {
        /* It's up because we got a response, but doesn't count as a response
         * within this timeout window. Go around again. */
        hss->target->flags = HOST_UP;
        continue;
      }
      probeI = hss->probes_outstanding.end();
      do {
        /* Delay in libpcap could mean we sent another probe *after* this
         * response was received. Search back for the last probe before rcvdtime. */
        probeI--;
        /* If the response came just a hair (<25ms) after the probe was sent, it's
         * probably a response to an earlier probe instead. Keep looking. */
        TIMEVAL_MSEC_ADD(fudgedsenttime, (*probeI)->sent, INITIAL_ARP_RTT_TIMEOUT / 8);
      } while (TIMEVAL_AFTER(fudgedsenttime, rcvdtime) && probeI != hss->probes_outstanding.begin());
      ultrascan_host_probe_update(USI, hss, probeI, HOST_UP, &rcvdtime);
      /* Now that we know the host is up, we can forget our other probes. */
      hss->destroyAllOutstandingProbes();
      /* TODO: Set target mac */
      gotone = 1;
      //      printf("Marked host %s as up!", hss->target->NameIP());
      break;
    }
  } while (!timedout);

  return gotone;
}

/* Tries to get one *good* (finishes a probe) pcap response by the
   (absolute) time given in stime.  Even if stime is now, try an
   ultra-quick pcap read just in case.  Returns true if a "good" result
   was found, false if it timed out instead. */
bool get_pcap_result(UltraScanInfo *USI, struct timeval *stime) {
  bool goodone = false;
  bool timedout = false;
  bool adjust_timing = true;
  bool from_target = true;
  struct timeval rcvdtime;
  struct link_header linkhdr;
  unsigned int bytes;
  long to_usec;
  HostScanStats *hss = NULL;
  std::list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  int newstate = PORT_UNKNOWN;
  unsigned int probenum;
  unsigned int listsz;
  /* Static so that we can detect an ICMP response now, then add it later when
     the icmp probe is made */
  static bool protoscanicmphack = false;
  static struct sockaddr_storage protoscanicmphackaddy;
  reason_t current_reason = ER_NORESPONSE;
  struct sockaddr_storage reason_sip = { AF_UNSPEC };

  const void *data = NULL;
  unsigned int datalen;
  struct abstract_ip_hdr hdr;

  gettimeofday(&USI->now, NULL);

  do {
    const struct ip *ip_tmp;

    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000)
      to_usec = 2000;
    ip_tmp = (struct ip *) readip_pcap(USI->pd, &bytes, to_usec, &rcvdtime, &linkhdr, true);
    gettimeofday(&USI->now, NULL);
    if (!ip_tmp && TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
      timedout = true;
      break;
    } else if (!ip_tmp)
      continue;

    if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
      /* While packets are still being received, I'll be generous and give
      an extra 1/5 sec.  But we have to draw the line somewhere */
      timedout = true;
    }

    datalen = bytes;
    data = ip_get_data(ip_tmp, &datalen, &hdr);
    if (data == NULL)
      continue;
    /* Ensure the connection info matches. */
    if (sockaddr_storage_cmp(USI->SourceSockAddr(), &hdr.dst) != 0)
      continue;

    if (USI->prot_scan) {
      hss = USI->findHost(&hdr.src);
      if (hss) {
        setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
        if (hdr.proto == IPPROTO_ICMP) {
          protoscanicmphack = true;
          protoscanicmphackaddy = hdr.src;
        } else {
          probeI = hss->probes_outstanding.end();
          listsz = hss->num_probes_outstanding();
          goodone = false;
          for (probenum = 0; probenum < listsz && !goodone; probenum++) {
            probeI--;
            probe = *probeI;

            if (probe->protocol() == hdr.proto) {
              /* if this is our probe we sent to localhost, then it doesn't count! */
              if (sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
                  probe->ipid() == hdr.ipid)
                break;

              /* We got a packet from the dst host in the protocol we looked for, and
              it wasn't our probe to ourselves, so it must be open */
              newstate = PORT_OPEN;
              current_reason = ER_PROTORESPONSE;
              goodone = true;
            }
          }
        }
      }
    }

    if (hdr.proto == IPPROTO_TCP && !USI->prot_scan) {
      const struct tcp_hdr *tcp = (struct tcp_hdr *) data;
      /* Now ensure this host is even in the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      u16 sport = ntohs(tcp->th_sport);
      u16 dport = ntohs(tcp->th_dport);

      goodone = false;

      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
            continue;
        if (!tcp_probe_match(USI, probe, tcp, &hdr.src, &hdr.dst, hdr.ipid))
          continue;

        if (!probe->isPing()) {
          /* Now that response has been matched to a probe, I interpret it */
          if (USI->scantype == SYN_SCAN && (tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            /* Yeah!  An open port */
            newstate = PORT_OPEN;
            current_reason = ER_SYNACK;
          } else if (tcp->th_flags & TH_RST) {
            current_reason = ER_RESETPEER;
            if (USI->scantype == WINDOW_SCAN ) {
              newstate = (tcp->th_win) ? PORT_OPEN : PORT_CLOSED;
            } else if (USI->scantype == ACK_SCAN) {
              newstate = PORT_UNFILTERED;
            } else newstate = PORT_CLOSED;
          } else if (USI->scantype == SYN_SCAN && (tcp->th_flags & TH_SYN)) {
            /* A SYN from a TCP Split Handshake - https://nmap.org/misc/split-handshake.pdf - open port */
            newstate = PORT_OPEN;
            current_reason = ER_SYN;
          } else {
            if (o.debugging)
              error("Received scan response with unexpected TCP flags: %d", tcp->th_flags);
            break;
          }
        }

        goodone = true;
      }
    } else if (hdr.proto == IPPROTO_SCTP && !USI->prot_scan) {
      const struct sctp_hdr *sctp = (struct sctp_hdr *) data;
      const struct dnet_sctp_chunkhdr *chunk = (struct dnet_sctp_chunkhdr *) ((u8 *) sctp + 12);

      /* Now ensure this host is even in the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, &hdr.src, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();

      goodone = false;

      u16 sport = ntohs(sctp->sh_sport);
      u16 dport = ntohs(sctp->sh_dport);

      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
          continue;

        /* Sometimes we get false results when scanning localhost with
           -p- because we scan localhost with src port = dst port and
           see our outgoing packet and think it is a response. */
        if (probe->dport() == probe->sport() &&
            sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
            probe->ipid() == hdr.ipid)
          continue; /* We saw the packet we ourselves sent */

        if (!probe->isPing()) {
          /* Now that response has been matched to a probe, I interpret it */
          if (USI->scantype == SCTP_INIT_SCAN) {
            if (chunk->sch_type == SCTP_INIT_ACK) {
              newstate = PORT_OPEN;
              current_reason = ER_INITACK;
            } else if (chunk->sch_type == SCTP_ABORT) {
              newstate = PORT_CLOSED;
              current_reason = ER_ABORT;
            } else {
              if (o.debugging)
                error("Received response with unexpected SCTP chunks: %02x",
                      chunk->sch_type);
              break;
            }
          } else if (USI->scantype == SCTP_COOKIE_ECHO_SCAN) {
            if (chunk->sch_type == SCTP_ABORT) {
              newstate = PORT_CLOSED;
              current_reason = ER_ABORT;
            } else {
              if (o.debugging)
                error("Received response with unexpected SCTP chunks: %02x",
                      chunk->sch_type);
              break;
            }
          }
        }

        goodone = true;
      }
    } else if (hdr.proto == IPPROTO_ICMP) {
      const void *encaps_data;
      unsigned int encaps_len;
      struct abstract_ip_hdr encaps_hdr;
      const struct icmp *icmp = NULL;

      icmp = (struct icmp *) data;

      if (datalen < 8)
        continue;
      if (icmp->icmp_type != 3 && icmp->icmp_type != 11)
        continue;

      encaps_len = datalen - 8;
      encaps_data = ip_get_data((char *) data + 8, &encaps_len, &encaps_hdr);
      if (encaps_data == NULL ||
          /* UDP hdr, or TCP hdr up to seq #, or SCTP hdr up to vtag */
          ((USI->tcp_scan || USI->udp_scan || USI->sctp_scan) && encaps_len < 8)
          /* prot scan has no headers coming back, so we don't reserve the
          8 extra bytes */
         ) {
        if (o.debugging)
          error("Received short ICMP packet (%u bytes)", datalen);
        continue;
      }

      /* Make sure the protocol is right */
      if (USI->tcp_scan && encaps_hdr.proto != IPPROTO_TCP)
        continue;

      if (USI->udp_scan && encaps_hdr.proto != IPPROTO_UDP)
        continue;

      if (USI->sctp_scan && encaps_hdr.proto != IPPROTO_SCTP)
        continue;

      // If it didn't come from us, we don't care.
      if (sockaddr_storage_cmp(USI->SourceSockAddr(), &encaps_hdr.src) != 0)
        continue;

      /* ensure this packet relates to a packet to the host
      we are scanning ... */
      hss = USI->findHost(&encaps_hdr.dst);
      if (!hss)
        continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      from_target = sockaddr_storage_cmp(hss->target->TargetSockAddr(), &hdr.src) == 0;

      goodone = false;
      /* Find the matching probe */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;
        if (probe->protocol() != encaps_hdr.proto)
          continue;

        if (encaps_hdr.proto == IPPROTO_TCP && !USI->prot_scan) {
          const struct tcp_hdr *tcp = (struct tcp_hdr *) encaps_data;
          if (ntohs(tcp->th_sport) != probe->sport() ||
              ntohs(tcp->th_dport) != probe->dport() ||
              ntohl(tcp->th_seq) != probe->tcpseq())
            continue;
        } else if (encaps_hdr.proto == IPPROTO_SCTP && !USI->prot_scan) {
          const struct sctp_hdr *sctp = (struct sctp_hdr *) encaps_data;
          if (ntohs(sctp->sh_sport) != probe->sport() ||
              ntohs(sctp->sh_dport) != probe->dport() ||
              ntohl(sctp->sh_vtag) != probe->sctpvtag())
            continue;
        } else if (encaps_hdr.proto == IPPROTO_UDP && !USI->prot_scan) {
          /* TODO: IPID verification */
          const struct udp_hdr *udp = (struct udp_hdr *) encaps_data;
          if (ntohs(udp->uh_sport) != probe->sport() ||
              ntohs(udp->uh_dport) != probe->dport())
            continue;
        } else if (!USI->prot_scan) {
          assert(0);
        }

        if (icmp->icmp_type == 3) {
          switch (icmp->icmp_code) {
          case 0: /* Network unreachable */
            newstate = PORT_FILTERED;
            break;
          case 1: /* Host Unreachable */
            newstate = PORT_FILTERED;
            break;
          case 2: /* protocol unreachable */
            if (USI->scantype == IPPROT_SCAN && from_target)
              newstate = PORT_CLOSED;
            else
              newstate = PORT_FILTERED;
            break;
          case 3: /* Port unreach */
            if (from_target && USI->scantype == UDP_SCAN)
              newstate = PORT_CLOSED;
            else if (from_target && USI->scantype == IPPROT_SCAN)
              newstate = PORT_OPEN;
            else
              newstate = PORT_FILTERED;
            break;
          case 9: /* dest. net admin prohibited */
          case 10: /* dest host admin prohibited */
          case 13: /* communication admin. prohibited */
            newstate = PORT_FILTERED;
            break;

          default:
            error("Unexpected ICMP type/code 3/%d unreachable packet:\n",
                  icmp->icmp_code);
            nmap_hexdump((unsigned char *)icmp, datalen);
            break;
          }
          current_reason = icmp_to_reason(hdr.proto, icmp->icmp_type, icmp->icmp_code);
          if (newstate == PORT_UNKNOWN)
            break;
          goodone = true;
        }
        else if (icmp->icmp_type == 11) { /* ICMP Time Exceeded */
          newstate = PORT_FILTERED;
          current_reason = icmp_to_reason(hdr.proto, icmp->icmp_type, icmp->icmp_code);
          goodone = true;
        }
      }
    } else if (hdr.proto == IPPROTO_ICMPV6) {
      const void *encaps_data;
      unsigned int encaps_len;
      struct abstract_ip_hdr encaps_hdr;
      const struct icmpv6_hdr *icmpv6;

      icmpv6 = (struct icmpv6_hdr *) data;

      if (datalen < 8)
        continue;
      if (!(icmpv6->icmpv6_type == ICMPV6_UNREACH || icmpv6->icmpv6_type == ICMPV6_PARAMPROBLEM))
        continue;

      encaps_len = datalen - 8;
      encaps_data = ip_get_data_any((char *) data + 8, &encaps_len, &encaps_hdr);
      if (encaps_data == NULL ||
          /* UDP hdr, or TCP hdr up to seq #, or SCTP hdr up to vtag */
          ((USI->tcp_scan || USI->udp_scan || USI->sctp_scan) && encaps_len < 8)
          /* prot scan has no headers coming back, so we don't reserve the
             8 extra bytes */
         ) {
        if (o.debugging)
          error("Received short ICMPv6 packet (%u bytes)", datalen);
        continue;
      }

      /* Make sure the protocol is right */
      if (USI->tcp_scan && encaps_hdr.proto != IPPROTO_TCP)
        continue;

      if (USI->udp_scan && encaps_hdr.proto != IPPROTO_UDP)
        continue;

      if (USI->sctp_scan && encaps_hdr.proto != IPPROTO_SCTP)
        continue;

      // If it didn't come from us, we don't care.
      if (sockaddr_storage_cmp(USI->SourceSockAddr(), &encaps_hdr.src) != 0)
        continue;

      /* ensure this packet relates to a packet to the host
      we are scanning ... */
      hss = USI->findHost(&encaps_hdr.dst);
      if (!hss)
        continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      from_target = sockaddr_storage_cmp(hss->target->TargetSockAddr(), &hdr.src) == 0;

      goodone = false;
      /* Find the matching probe */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;
        if (probe->protocol() != encaps_hdr.proto)
          continue;

        if (encaps_hdr.proto == IPPROTO_TCP && !USI->prot_scan) {
          const struct tcp_hdr *tcp = (struct tcp_hdr *) encaps_data;
          if (ntohs(tcp->th_sport) != probe->sport() ||
              ntohs(tcp->th_dport) != probe->dport() ||
              ntohl(tcp->th_seq) != probe->tcpseq())
            continue;
        } else if (encaps_hdr.proto == IPPROTO_SCTP && !USI->prot_scan) {
          const struct sctp_hdr *sctp = (struct sctp_hdr *) encaps_data;
          if (ntohs(sctp->sh_sport) != probe->sport() ||
              ntohs(sctp->sh_dport) != probe->dport() ||
              ntohl(sctp->sh_vtag) != probe->sctpvtag())
            continue;
        } else if (encaps_hdr.proto == IPPROTO_UDP && !USI->prot_scan) {
          /* TODO: IPID verification */
          const struct udp_hdr *udp = (struct udp_hdr *) encaps_data;
          if (ntohs(udp->uh_sport) != probe->sport() ||
              ntohs(udp->uh_dport) != probe->dport())
            continue;
        } else if (!USI->prot_scan) {
          assert(0);
        }

        if (icmpv6->icmpv6_type == ICMPV6_UNREACH) {
          switch (icmpv6->icmpv6_code) {
          case ICMPV6_UNREACH_NOROUTE:
            current_reason = ER_NOROUTE;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_PROHIB:
            current_reason = ER_ADMINPROHIBITED;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_SCOPE:
            current_reason = ER_BEYONDSCOPE;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_ADDR:
            current_reason = ER_HOSTUNREACH;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_FILTER_PROHIB:
            current_reason = ER_ADMINPROHIBITED;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_REJECT_ROUTE:
            current_reason = ER_REJECTROUTE;
            newstate = PORT_FILTERED;
            break;
          case ICMPV6_UNREACH_PORT:
            current_reason = ER_PORTUNREACH;
            if (from_target && USI->scantype == UDP_SCAN)
              newstate = PORT_CLOSED;
            else if (from_target && USI->scantype == IPPROT_SCAN)
              newstate = PORT_OPEN;
            else
              newstate = PORT_FILTERED;
            break;
          default:
            error("Unexpected ICMPv6 type/code %d/%d unreachable packet:\n",
                  icmpv6->icmpv6_type, icmpv6->icmpv6_code);
            nmap_hexdump((unsigned char *)icmpv6, datalen);
            break;
          }
        } else if (icmpv6->icmpv6_type == ICMPV6_PARAMPROBLEM) {
          switch (icmpv6->icmpv6_code) {
          case ICMPV6_PARAMPROBLEM_FIELD:
            /* "Erroneous header field encountered" means it was understood,
               just invalid. */
            newstate = PORT_OPEN;
            break;
          case ICMPV6_PARAMPROBLEM_NEXTHEADER:
            if (from_target && USI->scantype == IPPROT_SCAN)
              newstate = PORT_CLOSED;
            else
              newstate = PORT_FILTERED;
            break;
          default:
            error("Unexpected ICMPv6 type/code %d/%d unreachable packet:\n",
                  icmpv6->icmpv6_type, icmpv6->icmpv6_code);
            nmap_hexdump((unsigned char *)icmpv6, datalen);
            break;
          }
        } else {
          error("Unexpected ICMPv6 type/code %d/%d unreachable packet:\n",
                icmpv6->icmpv6_type, icmpv6->icmpv6_code);
          nmap_hexdump((unsigned char *)icmpv6, datalen);
          break;
        }
        current_reason = icmp_to_reason(hdr.proto, icmpv6->icmpv6_type, icmpv6->icmpv6_code);
        if (newstate == PORT_UNKNOWN)
          break;
        goodone = true;
      }
    } else if (hdr.proto == IPPROTO_UDP && !USI->prot_scan) {
      const struct udp_hdr *udp = (struct udp_hdr *) data;

      /* Search for this host on the incomplete list */
      hss = USI->findHost(&hdr.src);
      if (!hss)
        continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      u16 sport = ntohs(udp->uh_sport);
      u16 dport = ntohs(udp->uh_dport);

      goodone = false;

      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;
        newstate = PORT_UNKNOWN;

        if (!probe->check_proto_port(hdr.proto, dport, sport))
          continue;

        /* Sometimes we get false results when scanning localhost with
           -p- because we scan localhost with src port = dst port and
           see our outgoing packet and think it is a response. */
        if (probe->dport() == probe->sport() &&
            sockaddr_storage_cmp(&hdr.src, &hdr.dst) == 0 &&
            probe->ipid() == hdr.ipid)
          continue; /* We saw the packet we ourselves sent */

        newstate = PORT_OPEN;
        current_reason = ER_UDPRESPONSE;
        goodone = true;
        /* Store the data response in case service_scan wants it later */
        if (datalen > UDP_HDR_LEN) {
          struct EarlySvcResponse *esr = (EarlySvcResponse *) safe_zalloc(sizeof(struct EarlySvcResponse) + datalen - UDP_HDR_LEN);
          esr->pspec = *(probe->pspec());
          esr->len = datalen - UDP_HDR_LEN;
          memcpy(esr->data, (u8 *)data + UDP_HDR_LEN, esr->len);
          hss->target->earlySvcResponses.push_back(esr);
        }
      }
    } else continue; /* Unexpected protocol */
  } while (!goodone && !timedout);

  if (goodone) {
    if (from_target)
      reason_sip.ss_family = AF_UNSPEC;
    else
      reason_sip = hdr.src;
    if (probe->isPing())
      ultrascan_ping_update(USI, hss, probeI, &rcvdtime, adjust_timing);
    else {
      /* Save these values so we can use them after ultrascan_port_probe_update
         deletes probe. */
      u8 protocol = probe->protocol();
      u16 dport = probe->dport();

      ultrascan_port_probe_update(USI, hss, probeI, newstate, &rcvdtime, adjust_timing);
      if (USI->prot_scan)
        hss->target->ports.setStateReason(protocol, IPPROTO_IP,
                                          current_reason, hdr.ttl, &reason_sip);
      else
        hss->target->ports.setStateReason(dport, protocol,
                                          current_reason, hdr.ttl, &reason_sip);
    }
  }

  /* If protoicmphack is true, we are doing an IP proto scan and
     discovered that ICMP is open.  This has to be done separately
     because an ICMP response ALSO frequently shows that some other
     protocol is closed/filtered.  So we let that other protocol stuff
     go first, then handle it here */
  if (protoscanicmphack) {
    hss = USI->findHost((struct sockaddr_storage *) &protoscanicmphackaddy);
    if (hss) {
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();

      for (probenum = 0; probenum < listsz; probenum++) {
        probeI--;
        probe = *probeI;

        if (probe->protocol() == IPPROTO_ICMP) {
          if (probe->isPing())
            ultrascan_ping_update(USI, hss, probeI, &rcvdtime, adjust_timing);
          else {
            const struct icmp *icmp = (struct icmp *) data;
            ultrascan_port_probe_update(USI, hss, probeI, PORT_OPEN, &rcvdtime, adjust_timing);
            if (sockaddr_storage_cmp(&hdr.src, &protoscanicmphackaddy) == 0)
              reason_sip.ss_family = AF_UNSPEC;
            else
              reason_sip = hdr.src;
            if (!icmp->icmp_code && !icmp->icmp_type)
              hss->target->ports.setStateReason(IPPROTO_ICMP, IPPROTO_IP, ER_ECHOREPLY,
                                                hdr.ttl, &reason_sip);
            else
              hss->target->ports.setStateReason(IPPROTO_ICMP, IPPROTO_IP, icmp_to_reason(hdr.proto, icmp->icmp_type, icmp->icmp_code),
                                                hdr.ttl, &reason_sip);
          }
          if (!goodone)
            goodone = true;
          break;
        }
      }
      protoscanicmphack = false;
    }
  }

  return goodone;
}
