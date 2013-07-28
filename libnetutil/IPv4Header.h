
/***************************************************************************
 * IPv4Header.h -- The IPv4Header Class represents an IPv4 datagram. It    *
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

#ifndef IPV4HEADER_H
#define IPV4HEADER_H 1

#include "NetworkLayerElement.h"

#define IP_RF 0x8000               /* Reserved fragment flag         */
#define IP_DF 0x4000               /* Dont fragment flag             */
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

        /* Total lenght of the datagram */
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
