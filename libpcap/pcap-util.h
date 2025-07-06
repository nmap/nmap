/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * pcap-util.h - common code for various files
 */

/*
 * We use the "receiver-makes-right" approach to byte order;
 * because time is at a premium when we are writing the file.
 * In other words, the pcap_file_header and pcap_pkthdr,
 * records are written in host byte order.
 * Note that the bytes of packet data are written out in the order in
 * which they were received, so multi-byte fields in packets are not
 * written in host byte order, they're written in whatever order the
 * sending machine put them in.
 *
 * We also use this for fixing up packet data headers from a remote
 * capture, where the server may have a different byte order from the
 * client.
 *
 * ntoh[ls] aren't sufficient because we might need to swap on a big-endian
 * machine (if the file was written in little-end order).
 */
#define	SWAPLONG(y) \
    (((((u_int)(y))&0xff)<<24) | \
     ((((u_int)(y))&0xff00)<<8) | \
     ((((u_int)(y))&0xff0000)>>8) | \
     ((((u_int)(y))>>24)&0xff))
#define	SWAPSHORT(y) \
     ((u_short)(((((u_int)(y))&0xff)<<8) | \
                ((((u_int)(y))&0xff00)>>8)))

extern void pcapint_post_process(int linktype, int swapped,
    struct pcap_pkthdr *hdr, u_char *data);
