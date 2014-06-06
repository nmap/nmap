/*
 * pcap-septel.c: Packet capture interface for Intel Septel card
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the Intel/Septel
 * card code at the same time as another type of device.
 *
 * Authors: Gilbert HOYEK (gil_hoyek@hotmail.com), Elias M. KHOURY
 * (+961 3 485343);
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap-septel.h,v 1.2 2008-04-04 19:37:45 guy Exp $
 */

pcap_t *septel_create(const char *device, char *ebuf, int *is_ours);
int septel_findalldevs(pcap_if_t **devlistp, char *errbuf);
