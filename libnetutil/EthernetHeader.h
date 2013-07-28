
/***************************************************************************
 * EthernetHeader.h -- The EthernetHeader Class represents an Ethernet     *
 * header and footer. It contains methods to set the different header      *
 * fields. These methods tipically perform the necessary error checks and  *
 * byte order conversions.                                                 *
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

#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H 1

#include "DataLinkLayerElement.h"

/* Ether Types. (From RFC 5342 http://www.rfc-editor.org/rfc/rfc5342.txt)     */
#define ETHTYPE_IPV4       0x0800 /* Internet Protocol Version 4              */
#define ETHTYPE_ARP        0x0806 /* Address Resolution Protocol              */
#define ETHTYPE_FRAMERELAY 0x0808 /* Frame Relay ARP                          */
#define ETHTYPE_PPTP       0x880B /* Point-to-Point Tunneling Protocol        */
#define ETHTYPE_GSMP       0x880C /* General Switch Management Protocol       */
#define ETHTYPE_RARP       0x8035 /* Reverse Address Resolution Protocol      */
#define ETHTYPE_IPV6       0x86DD /* Internet Protocol Version 6              */
#define ETHTYPE_MPLS       0x8847 /* MPLS                                     */
#define ETHTYPE_MPS_UAL    0x8848 /* MPLS with upstream-assigned label        */
#define ETHTYPE_MCAP       0x8861 /* Multicast Channel Allocation Protocol    */
#define ETHTYPE_PPPOE_D    0x8863 /* PPP over Ethernet Discovery Stage        */
#define ETHTYPE_PPOE_S     0x8864 /* PPP over Ethernet Session Stage          */
#define ETHTYPE_CTAG       0x8100 /* Customer VLAN Tag Type                   */
#define ETHTYPE_EPON       0x8808 /* Ethernet Passive Optical Network         */
#define ETHTYPE_PBNAC      0x888E /* Port-based network access control        */
#define ETHTYPE_STAG       0x88A8 /* Service VLAN tag identifier              */
#define ETHTYPE_ETHEXP1    0x88B5 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHEXP2    0x88B6 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHOUI     0x88B7 /* OUI Extended Ethertype                   */
#define ETHTYPE_PREAUTH    0x88C7 /* Pre-Authentication                       */
#define ETHTYPE_LLDP       0x88CC /* Link Layer Discovery Protocol (LLDP)     */
#define ETHTYPE_MACSEC     0x88E5 /* Media Access Control Security            */
#define ETHTYPE_MVRP       0x88F5 /* Multiple VLAN Registration Protocol      */
#define ETHTYPE_MMRP       0x88F6 /* Multiple Multicast Registration Protocol */
#define ETHTYPE_FRRR       0x890D /* Fast Roaming Remote Request              */

#define ETH_HEADER_LEN 14

class EthernetHeader : public DataLinkLayerElement {

    private:

        struct nping_eth_hdr{
            u8 eth_dmac[6];
            u8 eth_smac[6];
            u16 eth_type;
        }__attribute__((__packed__));

        typedef struct nping_eth_hdr nping_eth_hdr_t;

        nping_eth_hdr_t h;

    public:
    
        EthernetHeader();
        ~EthernetHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        int setSrcMAC(const u8 *m);
        const u8 *getSrcMAC() const;

        int setDstMAC(u8 *m);
        const u8 *getDstMAC() const;

        int setEtherType(u16 val);
        const u16 getEtherType() const;

};

#endif
