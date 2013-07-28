
/***************************************************************************
 * EchoHeader.h -- The EchoHeader Class represents packets of the Nping    *
 * Echo Protocol. It contains the appropriate methods to set/get all       *
 * header fields. In general these methods do error checking and perform   *
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

#ifndef __ECHOHEADER_H__
#define __ECHOHEADER_H__ 1

#include "nping.h"

#define ECHO_CURRENT_PROTO_VER  0x01

/* Lengths */
#define STD_NEP_HEADER_LEN 16      /* Common NEP header length                */
#define MAC_LENGTH 32              /* Length of message authentication codes  */
#define NONCE_LEN 32               /* Length of client/server nonces          */
#define PARTNER_IP_LEN 16          /* Length of Partner IP field              */
#define PACKETSPEC_FIELD_LEN 108   /* Length of the packet specification      */
#define ERROR_MSG_LEN 80           /* Length of NEP_ERROR message strings     */

#define NEP_HANDSHAKE_SERVER_LEN  96
#define NEP_HANDSHAKE_CLIENT_LEN 144
#define NEP_HANDSHAKE_FINAL_LEN  112
#define NEP_PACKETSPEC_LEN 160
#define NEP_READY_LEN 48
#define NEP_ERROR_LEN 128

#define ECHOED_PKT_HEADER_LEN 4    /* Length of {DLT Type, Packet Length}     */
#define MAX_ECHOED_PACKET_LEN 9212 /* Max length for echoed packets           */
#define MAX_DATA_LEN (ECHOED_PKT_HEADER_LEN + MAX_ECHOED_PACKET_LEN + MAC_LENGTH)
#define NEP_ECHO_MIN_LEN 64
#define NEP_ECHO_MAX_LEN ( STD_NEP_HEADER_LEN + MAX_DATA_LEN )
#define MAX_NEP_PACKET_LENGTH  ( STD_NEP_HEADER_LEN + MAX_DATA_LEN )

/* Message types */
#define TYPE_NEP_HANDSHAKE_SERVER   0x01
#define TYPE_NEP_HANDSHAKE_CLIENT   0x02
#define TYPE_NEP_HANDSHAKE_FINAL    0x03
#define TYPE_NEP_PACKET_SPEC        0x04
#define TYPE_NEP_READY              0x05
#define TYPE_NEP_ECHO               0x06
#define TYPE_NEP_ERROR              0x07

/* Field specifiers */
#define PSPEC_IPv4_TOS       0xA0
#define PSPEC_IPv4_ID        0xA1
#define PSPEC_IPv4_FRAGOFF   0xA2
#define PSPEC_IPv4_PROTO     0xA3
#define PSPEC_IPv6_TCLASS    0xB0
#define PSPEC_IPv6_FLOW      0xB1
#define PSPEC_IPv6_NHDR      0xB2
#define PSPEC_TCP_SPORT      0xC0
#define PSPEC_TCP_DPORT      0xC1
#define PSPEC_TCP_SEQ        0xC2
#define PSPEC_TCP_ACK        0xC3
#define PSPEC_TCP_FLAGS      0xC4
#define PSPEC_TCP_WIN        0xC5
#define PSPEC_TCP_URP        0xC6
#define PSPEC_ICMP_TYPE      0xD0
#define PSPEC_ICMP_CODE      0xD1
#define PSPEC_UDP_SPORT      0xE0
#define PSPEC_UDP_DPORT      0xE1
#define PSPEC_UDP_LEN        0xE2
#define PSPEC_PAYLOAD_MAGIC  0xFF

/* Protocol identifiers for NEP_PACKET_SPEC */
#define PSPEC_PROTO_TCP      0x06
#define PSPEC_PROTO_UDP      0x11
#define PSPEC_PROTO_ICMP     0x01

#define DLT_NODATALINKHEADERINCLUDED 0x0000

/* GENERAL FORMAT:
 
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Version     |  Message Type |          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Timestamp                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Reserved                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        .                                                               .
        .                              DATA                             .
        .                                                               .
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        .                                                               .
        .                    Message Authentication Code                .
        .                                                               .
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */


class EchoHeader : public ApplicationLayerElement {

    private:

        /* Common NEP packet header */
        struct nep_hdr{
          u8  echo_ver;           /**< Protocol Version          */
          u8  echo_mtype;         /**< Message Type              */  
          u16 echo_tlen;          /**< Total Length              */
          u32 echo_seq;           /**< Sequence Number           */
          u32 echo_ts;            /**< Timestamp                 */
          u32 echo_res;           /**< Reserved                  */
          u8 data[MAX_DATA_LEN];
        }__attribute__((__packed__));
        typedef struct nep_hdr echohdr_t;

        /* NEP_HANDSHAKE_SERVER data */
        struct nep_hs_serv_data{
            u8 server_nonce[NONCE_LEN];
            u8 reserved[16];
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_hs_serv_data nep_hs_serv_data_t;

        /* NEP_HANDSHAKE_CLIENT data */
        struct nep_hs_clnt_data{
            u8 server_nonce[NONCE_LEN];
            u8 client_nonce[NONCE_LEN];
            u8 partner_ip[PARTNER_IP_LEN];
            u8 ip_version;
            u8 reserved[15];
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_hs_clnt_data nep_hs_clnt_data_t;

        /* NEP_HANDSHAKE_FINAL data */
        struct nep_hs_final_data{
            u8 client_nonce[NONCE_LEN];
            u8 partner_ip[PARTNER_IP_LEN];
            u8 ip_version;
            u8 reserved[15];
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_hs_final_data nep_hs_final_data_t;

        /* NEP_PACKET_SPEC data */
        struct nep_packet_spec_data{
            u8 ip_version;
            u8 protocol;
            u16 packet_count;
            u8 packetspec[PACKETSPEC_FIELD_LEN];
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_packet_spec_data nep_packet_spec_data_t;

        /* NEP_READY data */
        struct nep_ready_data{
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_ready_data nep_ready_data_t;

        /* NEP_ECHO data */
        struct nep_echo_data{
            u16 dlt_type;
            u16 packet_len;
            u8 payload_and_mac[MAX_ECHOED_PACKET_LEN + MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_echo_data nep_echo_data_t;

        /* NEP_ERROR data */
        struct nep_error_data{
            u8 errmsg[ERROR_MSG_LEN];
            u8 mac[MAC_LENGTH];
        }__attribute__((__packed__));
        typedef struct nep_error_data nep_error_data_t;

        /* Attributes */
        echohdr_t h;
        echohdr_t h_tmp;
        nep_hs_serv_data_t *data_hsserv;
        nep_hs_clnt_data_t *data_hsclnt;
        nep_hs_final_data_t *data_hsfinal;
        nep_packet_spec_data_t *data_pspec;
        nep_ready_data_t *data_ready;
        nep_echo_data_t *data_echo;
        u8 *echo_mac;
        int echo_bytes;
        nep_error_data_t *data_error;
        u8 *fs_off;    /**< Current field spec offset     */
        int fs_bytes;  /**< Currend field spec byte count */

    private:
        int getFieldLength(u8 field);

    public:

        EchoHeader();
        ~EchoHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;

        int setVersion(u8 val);
        u8 getVersion();
        
        int setMessageType(u8 val);
        u8 getMessageType();
        
        int setTotalLength(u16 val);
        int setTotalLength();
        u16 getTotalLength();

        int setSequenceNumber(u32 val);
        u32 getSequenceNumber();
        
        int setTimestamp(u32 val);
        int setTimestamp();
        u32 getTimestamp();
        
        int setReserved(u32 val);
        u32 getReserved();

        int setMessageAuthenticationCode(u8 *key, size_t keylen);
        u8 *getMessageAuthenticationCode();
        int verifyMessageAuthenticationCode(u8 *key, size_t keylen);

        int setServerNonce(u8 *nonce);
        u8 *getServerNonce();

        int setClientNonce(u8 *nonce);
        u8 *getClientNonce();

        int setPartnerAddress(struct in_addr val);
        int setPartnerAddress(struct in6_addr val);
        int getPartnerAddress(struct in_addr *dst);
        int getPartnerAddress(struct in6_addr *dst);
        int setIPVersion(u8 ver);
        u8 getIPVersion();

        int setProtocol(u8 proto);
        u8 getProtocol();

        int setPacketCount(u16 c);
        u16 getPacketCount();

        int addFieldSpec(u8 field, u8 *val);
        int addFieldSpec(u8 field, u8 *val, size_t flen);
        int getNextFieldSpec(u8 *field, u8 *dst_buff, size_t *final_len);
        int rewindFieldSpecCounters();

        int setDLT(u16 dlt);
        u16 getDLT();

        int setPacketLength(u16 len);
        u16 getPacketLength();

        int setEchoedPacket(const u8 *pkt, size_t pktlen);
        u8 *getEchoedPacket(u16 *final_len);
        u8 *getEchoedPacket();

        int updateEchoInternals();

        int setErrorMessage(const char *err);
        char *getErrorMessage();

        u8 *getCiphertextBounds(size_t *len);
        u8 *getCiphertextBounds(size_t *final_len, int message_type);
        u8 *encrypt(u8 *key, size_t key_len, u8 *iv);
        u8 *decrypt(u8 *key, size_t key_len, u8 *iv, int message_type);
};

#endif /* __ECHOHEADER_H__ */
