/***************************************************************************
 * ICMPv6Option.h -- The ICMPv6Option Class represents an ICMP version 6   *
 * option. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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

#ifndef __ICMPv6OPTION_H__
#define __ICMPv6OPTION_H__ 1

#include "NetworkLayerElement.h"

/* Packet header diagrams included in this file have been taken from the
 * following IETF RFC documents: RFC 2461, RFC 2894 */

/* The following codes have been defined by IANA. A complete list may be found
 * at http://www.iana.org/assignments/icmpv6-parameters */

/* ICMPv6 Option Types */
#define ICMPv6_OPTION_SRC_LINK_ADDR 1
#define ICMPv6_OPTION_TGT_LINK_ADDR 2
#define ICMPv6_OPTION_PREFIX_INFO   3
#define ICMPv6_OPTION_REDIR_HDR     4
#define ICMPv6_OPTION_MTU           5

/* Nping ICMPv6Options Class internal definitions */
#define ICMPv6_OPTION_COMMON_HEADER_LEN    2
#define ICMPv6_OPTION_MIN_HEADER_LEN       8
#define ICMPv6_OPTION_SRC_LINK_ADDR_LEN    (ICMPv6_OPTION_COMMON_HEADER_LEN+6)
#define ICMPv6_OPTION_TGT_LINK_ADDR_LEN    (ICMPv6_OPTION_COMMON_HEADER_LEN+6)
#define ICMPv6_OPTION_PREFIX_INFO_LEN      (ICMPv6_OPTION_COMMON_HEADER_LEN+30)
#define ICMPv6_OPTION_REDIR_HDR_LEN        (ICMPv6_OPTION_COMMON_HEADER_LEN+6)
#define ICMPv6_OPTION_MTU_LEN              (ICMPv6_OPTION_COMMON_HEADER_LEN+6)
/* This must the MAX() of all values defined above*/
#define ICMPv6_OPTION_MAX_MESSAGE_BODY     (ICMPv6_OPTION_PREFIX_INFO_LEN-ICMPv6_OPTION_COMMON_HEADER_LEN)

#define ICMPv6_OPTION_LINK_ADDRESS_LEN 6

class ICMPv6Option : public NetworkLayerElement {

    private:

        /**********************************************************************/
        /* COMMON ICMPv6 OPTION HEADER                                        */
        /**********************************************************************/

        struct nping_icmpv6_option{
            u8 type;
            u8 length;
            u8 data[ICMPv6_OPTION_MAX_MESSAGE_BODY];
        }__attribute__((__packed__));
        typedef struct nping_icmpv6_option nping_icmpv6_option_t;

        /**********************************************************************/
        /* ICMPv6 OPTION FORMATS                                              */
        /**********************************************************************/
        /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |              ...              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ~                              ...                              ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */


        /* Source/Target Link-layer Address
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |    Length     |    Link-Layer Address ...
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct link_addr_option{
            u8 link_addr[6];
        }__attribute__((__packed__));
        typedef struct link_addr_option link_addr_option_t;


        /* Prefix Information
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                         Valid Lifetime                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                       Preferred Lifetime                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Reserved2                           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +                                                               +
          |                                                               |
          +                            Prefix                             +
          |                                                               |
          +                                                               +
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct prefix_info_option{
            u8 prefix_length;
            u8 flags;
            u32 valid_lifetime;
            u32 preferred_lifetime;
            u32 reserved;
            u8 prefix[16];
        }__attribute__((__packed__));
        typedef struct prefix_info_option prefix_info_option_t;


        /* Redirect Header
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |    Length     |            Reserved           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Reserved                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          ~                       IP header + data                        ~
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct redirect_option{
            u16 reserved_1;
            u32 reserved_2;
            //u8 invoking_pkt[?];
        }__attribute__((__packed__));
        typedef struct redirect_option redirect_option_t;


        /* MTU
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |     Type      |    Length     |           Reserved            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                              MTU                              |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct mtu_option{
            u16 reserved;
            u32 mtu;
        }__attribute__((__packed__));
        typedef struct mtu_option mtu_option_t;


        nping_icmpv6_option_t h;

        link_addr_option_t        *h_la;
        prefix_info_option_t      *h_pi;
        redirect_option_t         *h_r;
        mtu_option_t              *h_mtu;

    public:
        ICMPv6Option();
        ~ICMPv6Option();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;

        int setType(u8 val);
        u8 getType();
        bool validateType(u8 val);

        int setLength(u8 val);
        u8 getLength();

        int setLinkAddress(u8* val);
        u8 *getLinkAddress();

        int setPrefixLength(u8 val);
        u8 getPrefixLength();

        int setFlags(u8 val);
        u8 getFlags();

        int setValidLifetime(u32 val);
        u32 getValidLifetime();

        int setPreferredLifetime(u32 val);
        u32 getPreferredLifetime();

        int setPrefix(u8 *val);
        u8 *getPrefix();

        int setMTU(u32 val);
        u32 getMTU();

        int getHeaderLengthFromType(u8 type);

}; /* End of class ICMPv6Option */

#endif
