/***************************************************************************
 * ARPHeader.h -- The ARPHeader Class represents an ARP packet. It         *
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

#ifndef __ARPHEADER_H__
#define __ARPHEADER_H__ 1

#include "NetworkLayerElement.h"

/* Lengths */
#define ARP_HEADER_LEN 28
#define IPv4_ADDRESS_LEN 4
#define ETH_ADDRESS_LEN  6

/* Hardware Types */
#define HDR_RESERVED      0    /* [RFC5494]                                   */
#define HDR_ETH10MB       1    /* Ethernet (10Mb)                             */
#define HDR_ETH3MB        2    /* Experimental Ethernet (3Mb)                 */
#define HDR_AX25          3    /* Amateur Radio AX.25                         */
#define HDR_PRONET_TR     4    /* Proteon ProNET Token Ring                   */
#define HDR_CHAOS         5    /* Chaos                                       */
#define HDR_IEEE802       6    /* IEEE 802 Networks                           */
#define HDR_ARCNET        7    /* ARCNET [RFC1201]                            */
#define HDR_HYPERCHANNEL  8    /* Hyperchannel                                */
#define HDR_LANSTAR       9    /* Lanstar                                     */
#define HDR_AUTONET       10   /* Autonet Short Address                       */
#define HDR_LOCALTALK     11   /* LocalTalk                                   */
#define HDR_LOCALNET      12   /* LocalNet (IBM PCNet or SYTEK LocalNET)      */
#define HDR_ULTRALINK     13   /* Ultra link                                  */
#define HDR_SMDS          14   /* SMDS                                        */
#define HDR_FRAMERELAY    15   /* Frame Relay                                 */
#define HDR_ATM           16   /* Asynchronous Transmission Mode (ATM)        */
#define HDR_HDLC          17   /* HDLC                                        */
#define HDR_FIBRE         18   /* Fibre Channel [RFC4338]                     */
#define HDR_ATMb          19   /* Asynchronous Transmission Mode (ATM)        */
#define HDR_SERIAL        20   /* Serial Line                                 */
#define HDR_ATMc          21   /* Asynchronous Transmission Mode [RFC2225]    */
#define HDR_MILSTD        22   /* MIL-STD-188-220                             */
#define HDR_METRICOM      23   /* Metricom                                    */
#define HDR_IEEE1394      24   /* IEEE 1394.199                               */
#define HDR_MAPOS         25   /* MAPOS [RFC2176]                             */
#define HDR_TWINAXIAL     26   /* Twinaxial                                   */
#define HDR_EUI64         27   /* EUI-64                                      */
#define HDR_HIPARP        28   /* HIPARP                                      */
#define HDR_ISO7816       29   /* IP and ARP over ISO 7816-3                  */
#define HDR_ARPSEC        30   /* ARPSec                                      */
#define HDR_IPSEC         31   /* IPsec tunnel                                */
#define HDR_INFINIBAND    32   /* InfiniBand (TM)                             */
#define HDR_TIA102        33   /* TIA-102 Project 25 Common Air Interface     */
#define HDR_WIEGAND       34   /* Wiegand Interface                           */
#define HDR_PUREIP        35   /* Pure IP                                     */
#define HDR_HW_EXP1       36   /* HW_EXP1 [RFC5494]                           */
#define HDR_HW_EXP2       37   /* HW_EXP2 [RFC5494]                           */

/* Operation Codes */
#define OP_ARP_REQUEST    1     /* ARP Request                                */
#define OP_ARP_REPLY      2     /* ARP Reply                                  */
#define OP_RARP_REQUEST   3     /* Reverse ARP Request                        */
#define OP_RARP_REPLY     4     /* Reverse ARP Reply                          */
#define OP_DRARP_REQUEST  5     /* DRARP-Request                              */
#define OP_DRARP_REPLY    6     /* DRARP-Reply                                */
#define OP_DRARP_ERROR    7     /* DRARP-Error                                */
#define OP_INARP_REQUEST  8     /* InARP-Request                              */
#define OP_INARP_REPLY    9     /* InARP-Reply                                */
#define OP_ARPNAK         10    /* ARP-NAK                                    */
#define OP_MARS_REQUEST   11    /* MARS-Request                               */
#define OP_MARS_MULTI     12    /* MARS-Multi                                 */
#define OP_MARS_MSERV     13    /* MARS-MServ                                 */
#define OP_MARS_JOIN      14    /* MARS-Join                                  */
#define OP_MARS_LEAVE     15    /* MARS-Leave                                 */
#define OP_MARS_NAK       16    /* MARS-NAK                                   */
#define OP_MARS_UNSERV    17    /* MARS-Unserv                                */
#define OP_MARS_SJOIN     18    /* MARS-SJoin                                 */
#define OP_MARS_SLEAVE    19    /* MARS-SLeave                                */
#define OP_MARS_GL_REQ    20    /* MARS-Grouplist-Request                     */
#define OP_MARS_GL_REP    21    /* MARS-Grouplist-Reply                       */
#define OP_MARS_REDIR_MAP 22    /* MARS-Redirect-Map                          */
#define OP_MAPOS_UNARP    23    /* MAPOS-UNARP [RFC2176]                      */
#define OP_EXP1           24    /* OP_EXP1 [RFC5494]                          */
#define OP_EXP2           25    /* OP_EXP2 [RFC5494]                          */
#define OP_RESERVED       65535 /* Reserved [RFC5494]                         */


/* TODO @todo: getTargetIP() and getSenderIP() should  either
 * return struct in_addr or IPAddress but not u32. */

class ARPHeader : public NetworkLayerElement {

    private:

        struct nping_arp_hdr{

            u16 ar_hrd;       /* Hardware Type.                               */
            u16 ar_pro;       /* Protocol Type.                               */
            u8  ar_hln;       /* Hardware Address Length.                     */
            u8  ar_pln;       /* Protocol Address Length.                     */
            u16 ar_op;        /* Operation Code.                              */
            u8 data[20];
            // Cannot use these because the four-flushing alignment screws up
            // everything. I miss ANSI C.
            //u8  ar_sha[6];    /* Sender Hardware Address.                     */
            //u32 ar_sip;       /* Sender Protocol Address (IPv4 address).      */
            //u8  ar_tha[6];    /* Target Hardware Address.                     */
            //u32 ar_tip;       /* Target Protocol Address (IPv4 address).      */
        }__attribute__((__packed__));

        typedef struct nping_arp_hdr nping_arp_hdr_t;

        nping_arp_hdr_t h;

    public:

        /* Misc */
        ARPHeader();
        ~ARPHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        /* Hardware Type */
        int setHardwareType(u16 t);
        int setHardwareType();
        u16 getHardwareType();

        /* Protocol Type */
        int setProtocolType(u16 t);
        int setProtocolType();
        u16 getProtocolType();

        /* Hardware Address Length */
        int setHwAddrLen(u8 v);
        int setHwAddrLen();
        u8 getHwAddrLen();

        /* Hardware Address Length */
        int setProtoAddrLen(u8 v);
        int setProtoAddrLen();
        u8 getProtoAddrLen();

        /* Operation Code */
        int setOpCode(u16 c);
        u16 getOpCode();

        /* Sender Hardware Address */
        int setSenderMAC(const u8 *m);
        u8 *getSenderMAC();

        /* Sender Protocol address */
        int setSenderIP(struct in_addr i);
        u32 getSenderIP();

        /* Target Hardware Address */
        int setTargetMAC(u8 *m);
        u8 *getTargetMAC();

        /* Target Protocol Address */
        int setTargetIP(struct in_addr i);
        u32 getTargetIP();

}; /* End of class ARPHeader */

#endif /* __ARPHEADER_H__ */

