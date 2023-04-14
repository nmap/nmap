/***************************************************************************
 * ICMPv6RRBody.cc -- The ICMPv6RRBody Class represents an ICMP version 6  *
 * Router Renumbering message body. It contains methods to set any header  *
 * field. In general, these  methods do error checkings and byte order     *
 * conversions.                                                            *
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

#ifndef ICMPv6RRBODY_H
#define ICMPv6RRBODY_H 1

#include "NetworkLayerElement.h"

/* Packet header diagrams included in this file have been taken from the
 * following IETF RFC documents: RFC 2894 */

/* Nping ICMPv6RRBody Class internal definitions */
#define ICMPv6_RR_MATCH_PREFIX_LEN 24
#define ICMPv6_RR_USE_PREFIX_LEN   32
#define ICMPv6_RR_RESULT_MSG_LEN   24
/* This must the MAX() of all values defined above*/
#define ICMPv6_RR_MAX_LENGTH (ICMPv6_RR_USE_PREFIX_LEN)
#define ICMPv6_RR_MIN_LENGTH (ICMPv6_RR_MATCH_PREFIX_LEN)


class ICMPv6RRBody : public NetworkLayerElement {

    private:

        /**********************************************************************/
        /* COMMON ICMPv6 OPTION HEADER                                        */
        /**********************************************************************/

        struct nping_icmpv6_rr_body{
            u8 data[ICMPv6_RR_MAX_LENGTH];
        }__attribute__((__packed__));
        typedef struct nping_icmpv6_rr_body nping_icmpv6_rr_body_t;

        /**********************************************************************/
        /* ICMPv6 OPTION FORMATS                                              */
        /**********************************************************************/


        /* Match-Prefix Part

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    OpCode     |   OpLength    |    Ordinal    |   MatchLen    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    MinLen     |    MaxLen     |           reserved            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                         MatchPrefix                         -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
        struct rr_match_prefix{
            u8 op_code;
            u8 op_length;
            u8 ordinal;
            u8 match_length;
            u8 min_length;
            u8 max_length;
            u16 reserved;
            u8 match_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_match_prefix rr_match_prefix_t;


        /* Use-Prefix Part
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    UseLen     |    KeepLen    |   FlagMask    |    RAFlags    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                        Valid Lifetime                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                      Preferred Lifetime                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |V|P|                         reserved                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                          UsePrefix                          -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
        struct rr_use_prefix{
            u8 use_len;
            u8 keep_len;
            u8 flag_mask;
            u8 ra_flags;
            u32 valid_lifetime;
            u32 preferred_lifetime;
            u8 flags;
            u8 reserved[3];
            u8 use_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_use_prefix rr_use_prefix_t;


        /* Result Message

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |         reserved          |B|F|    Ordinal    |  MatchedLen   |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                         InterfaceIndex                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                        MatchedPrefix                        -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct rr_result_msg{
            u8 reserved;
            u8 flags;
            u8 ordinal;
            u8 matched_length;
            u32 interface_index;
            u8 matched_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_result_msg rr_result_msg_t;

        nping_icmpv6_rr_body_t h;

        rr_match_prefix_t *h_mp;
        rr_use_prefix_t   *h_up;
        rr_result_msg_t   *h_r;

    public:
        ICMPv6RRBody();
        ~ICMPv6RRBody();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);

}; /* End of class ICMPv6RRBody */

#endif
