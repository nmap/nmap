/***************************************************************************
 * IPv6Header.h -- The IPv6Header Class represents an IPv6 datagram. It    *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
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
/* This code was originally part of the Nping tool.                        */

#ifndef IPV6HEADER_H
#define IPV6HEADER_H 1

#include "NetworkLayerElement.h"

#define IPv6_HEADER_LEN 40

/* Default header values */
#define IPv6_DEFAULT_TCLASS    0
#define IPv6_DEFAULT_FLABEL    0
#define IPv6_DEFAULT_HOPLIM    64
#define IPv6_DEFAULT_NXTHDR    6 /* TCP */

class IPv6Header : public NetworkLayerElement {

    private:

  /*  IPv6 Header Format:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version| Traffic Class |             Flow Label                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Payload Length        |  Next Header  |   Hop Limit   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +--                      Source Address                       --+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +--                    Destination Address                    --+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

        struct nping_ipv6_hdr {
            u8  ip6_start[4];                /* Version, Traffic and Flow   */
            u16 ip6_len;                     /* Payload length              */
            u8  ip6_nh;                      /* Next Header                 */
            u8  ip6_hopl;                    /* Hop Limit                   */
            u8  ip6_src[16];                 /* Source IP Address           */
            u8  ip6_dst[16];                 /* Destination IP Address      */
        }__attribute__((__packed__));

        typedef struct nping_ipv6_hdr nping_ipv6_hdr_t;

        nping_ipv6_hdr_t h;

    public:

        /* Misc */
        IPv6Header();
        ~IPv6Header();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        /* IP version */
        int setVersion();
        int setVersion(u8 val);
        u8 getVersion() const;

        /* Traffic class */
        int setTrafficClass(u8 val);
        u8 getTrafficClass() const;

        /* Flow Label */
        int setFlowLabel(u32 val);
        u32 getFlowLabel() const;

        /* Payload Length */
        int setPayloadLength(u16 val);
        int setPayloadLength();
        u16 getPayloadLength() const;

        /* Next Header */
        int setNextHeader(u8 val);
        int setNextHeader(const char *p);
        u8 getNextHeader() const;

        /* Hop Limit */
        int setHopLimit(u8 val);
        u8 getHopLimit() const;

        /* Source Address */
        int setSourceAddress(u8 *val);
        int setSourceAddress(struct in6_addr val);
        const u8 *getSourceAddress() const;
        struct in6_addr getSourceAddress(struct in6_addr *result) const;

        /* Destination Address*/
        int setDestinationAddress(u8 *val);
        int setDestinationAddress(struct in6_addr val);
        const u8 *getDestinationAddress() const;
        struct in6_addr getDestinationAddress(struct in6_addr *result) const;

        u16 getAddressLength() const;
};

#endif
