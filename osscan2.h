
#ifndef OSSCAN2_H
#define OSSCAN2_H

#include "nmap.h"
#include "tcpip.h"
#include "global_structures.h"
#include "FingerPrintResults.h"
#include "osscan.h"

/**********************  PROTOTYPES  ***********************************/

int os_scan_2(std::vector<Target *> &Targets);

int send_closedudp_probe_2(struct udpprobeinfo &upi, int sd,
                           struct eth_nfo *eth,  const struct in_addr *victim,
                           int ttl, u16 sport, u16 dport);
int send_icmp_echo_probe(int sd, struct eth_nfo *eth, const struct in_addr *victim,
			 u8 tos, bool df, u8 pcode, unsigned short id, u16 seq, u16 datalen);

int get_initial_ttl_guess(u8 ttl);
int get_ipid_sequence(struct ipid_info *ipid, int islocalhost);

#endif /*OSSCAN2_H*/

