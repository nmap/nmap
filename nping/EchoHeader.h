
/***************************************************************************
 * EchoHeader.h -- The EchoHeader Class represents packets of the Nping    *
 * Echo Protocol. It contains the appropriate methods to set/get all       *
 * header fields. In general these methods do error checking and perform   *
 * byte order conversions.                                                 *
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
        int fs_bytes;  /**< Current field spec byte count */

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
