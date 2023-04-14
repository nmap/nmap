/***************************************************************************
 * IPv4Header.h -- The IPv4Header Class represents an IPv4 datagram. It    *
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

#ifndef IPV4HEADER_H
#define IPV4HEADER_H 1

#include "NetworkLayerElement.h"

#define IP_RF 0x8000               /* Reserved fragment flag         */
#define IP_DF 0x4000               /* Don't fragment flag            */
#define IP_MF 0x2000               /* More fragments flag            */
#define IP_OFFMASK 0x1fff          /* Mask for fragmenting bits      */
#define IP_HEADER_LEN 20           /* Length of the standard header  */
#define MAX_IP_OPTIONS_LEN 40      /* Max Length for IP Options      */

/* Default header values */
#define IPv4_DEFAULT_TOS      0
#define IPv4_DEFAULT_ID       0
#define IPv4_DEFAULT_TTL      64
#define IPv4_DEFAULT_PROTO    6 /* TCP */

class IPv4Header : public NetworkLayerElement {

    private:
        /*
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        struct nping_ipv4_hdr {
        #if WORDS_BIGENDIAN
            u8 ip_v:4;                     /* Version                        */
            u8 ip_hl:4;                    /* Header length                  */
        #else
            u8 ip_hl:4;                    /* Header length                  */
            u8 ip_v:4;                     /* Version                        */
        #endif
            u8 ip_tos;                     /* Type of service                */
            u16 ip_len;                    /* Total length                   */
            u16 ip_id;                     /* Identification                 */
            u16 ip_off;                    /* Fragment offset field          */
            u8 ip_ttl;                     /* Time to live                   */
            u8 ip_p;                       /* Protocol                       */
            u16 ip_sum;                    /* Checksum                       */
            struct in_addr ip_src;         /* Source IP address              */
            struct in_addr ip_dst;         /* Destination IP address         */
            u8 options[MAX_IP_OPTIONS_LEN];  /* IP Options                   */
        }__attribute__((__packed__));

        typedef struct nping_ipv4_hdr nping_ipv4_hdr_t;

        nping_ipv4_hdr_t h;

        int ipoptlen; /**< Length of IP options */

    public:

        /* Misc */
        IPv4Header();
        ~IPv4Header();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        /* IP version */
        int setVersion();
        u8 getVersion() const;

        /* Header Length */
        int setHeaderLength();
        int setHeaderLength(u8 l);
        u8 getHeaderLength() const;

        /* Type of Service */
        int setTOS(u8 v);
        u8 getTOS() const;

        /* Total length of the datagram */
        int setTotalLength();
        int setTotalLength(u16 l);
        u16 getTotalLength() const;

        /* Identification value */
        int setIdentification();
        int setIdentification(u16 i);
        u16 getIdentification() const;

        /* Fragment Offset */
        int setFragOffset();
        int setFragOffset(u16 f);
        u16 getFragOffset() const;

        /* Flags */
        int setRF();
        int unsetRF();
        bool getRF() const;
        int setDF();
        int unsetDF();
        bool getDF() const;
        int setMF();
        int unsetMF();
        bool getMF() const;

        /* Time to live */
        int setTTL();
        int setTTL(u8 t);
        u8 getTTL() const;

        /* Next protocol */
        int setNextProto(u8 p);
        int setNextProto(const char *p);
        u8 getNextProto() const;
        int setNextHeader(u8 val);
        u8 getNextHeader() const;

        /* Checksum */
        int setSum();
        int setSum(u16 s);
        int setSumRandom();
        u16 getSum() const;

        /* Destination IP */
        int setDestinationAddress(u32 d);
        int setDestinationAddress(struct in_addr d);
        const u8 *getDestinationAddress() const;
        struct in_addr getDestinationAddress(struct in_addr *result) const;


        /* Source IP */
        int setSourceAddress(u32 d);
        int setSourceAddress(struct in_addr d);
        const u8 *getSourceAddress() const;
        struct in_addr getSourceAddress(struct in_addr *result) const;

        u16 getAddressLength() const;

        /* IP Options */
        int setOpts(const char *txt);
        int setOpts(u8 *opts_buff,  u32 opts_len);
        const u8 *getOpts() const;
        const u8 *getOpts(int *len) const;
        int printOptions() const;
        const char *getOptionsString() const;

}; /* End of class IPv4Header */

#endif
