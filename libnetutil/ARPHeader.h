
/***************************************************************************
 * ARPHeader.h -- The ARPHeader Class represents an ARP packet. It         *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
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
            // Cannot use these because the fucking alignment screws up
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

