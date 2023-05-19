/***************************************************************************
 * TCPHeader.h -- The TCPHeader Class represents a TCP packet. It contains *
 * methods to set the different header fields. These methods tipically     *
 * perform the necessary error checks and byte order conversions.          *
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

#ifndef __TCPHEADER_H__
#define __TCPHEADER_H__ 1

#include "TransportLayerElement.h"

/* TCP FLAGS */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PSH   0x08
#define TH_ACK   0x10
#define TH_URG   0x20
#define TH_ECN   0x40
#define TH_CWR   0x80

/* TCP OPTIONS */
#define TCPOPT_EOL         0   /* End of Option List (RFC793)                 */
#define TCPOPT_NOOP        1   /* No-Operation (RFC793)                       */
#define TCPOPT_MSS         2   /* Maximum Segment Size (RFC793)               */
#define TCPOPT_WSCALE      3   /* WSOPT - Window Scale (RFC1323)              */
#define TCPOPT_SACKOK      4   /* SACK Permitted (RFC2018)                    */
#define TCPOPT_SACK        5   /* SACK (RFC2018)                              */
#define TCPOPT_ECHOREQ     6   /* Echo (obsolete) (RFC1072)(RFC6247)          */
#define TCPOPT_ECHOREP     7   /* Echo Reply (obsolete) (RFC1072)(RFC6247)    */
#define TCPOPT_TSTAMP      8   /* TSOPT - Time Stamp Option (RFC1323)         */
#define TCPOPT_POCP        9   /* Partial Order Connection Permitted (obsol.) */
#define TCPOPT_POSP        10  /* Partial Order Service Profile (obsolete)    */
#define TCPOPT_CC          11  /* CC (obsolete) (RFC1644)(RFC6247)            */
#define TCPOPT_CCNEW       12  /* CC.NEW (obsolete) (RFC1644)(RFC6247)        */
#define TCPOPT_CCECHO      13  /* CC.ECHO (obsolete) (RFC1644)(RFC6247)       */
#define TCPOPT_ALTCSUMREQ  14  /* TCP Alternate Checksum Request (obsolete)   */
#define TCPOPT_ALTCSUMDATA 15  /* TCP Alternate Checksum Data (obsolete)      */
#define TCPOPT_MD5         19  /* MD5 Signature Option (obsolete) (RFC2385)   */
#define TCPOPT_SCPS        20  /* SCPS Capabilities                           */
#define TCPOPT_SNACK       21  /* Selective Negative Acknowledgements         */
#define TCPOPT_QSRES       27  /* Quick-Start Response (RFC4782)              */
#define TCPOPT_UTO         28  /* User Timeout Option (RFC5482)               */
#define TCPOPT_AO          29  /* TCP Authentication Option (RFC5925)         */

/* Internal constants */
#define TCP_HEADER_LEN 20
#define MAX_TCP_OPTIONS_LEN 40
#define MAX_TCP_PAYLOAD_LEN 65495 /**< Max len of a TCP packet               */

/* Default header values */
#define TCP_DEFAULT_SPORT 20
#define TCP_DEFAULT_DPORT 80
#define TCP_DEFAULT_SEQ   0
#define TCP_DEFAULT_ACK   0
#define TCP_DEFAULT_FLAGS 0x02
#define TCP_DEFAULT_WIN   8192
#define TCP_DEFAULT_URP   0



/*
+--------+--------+---------+--------...
|  Type  |  Len   |       Value
+--------+--------+---------+--------...
*/
struct nping_tcp_opt {
    u8 type;                           /* Option type code.           */
    u8 len;                            /* Option length.              */
    u8 *value;                         /* Option value                */
}__attribute__((__packed__));
typedef struct nping_tcp_opt nping_tcp_opt_t;


class TCPHeader : public TransportLayerElement {

    private:
        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Offset| Res.  |C|E|U|A|P|R|S|F|            Window             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        struct nping_tcp_hdr {
            u16 th_sport;                      /* Source port                 */
            u16 th_dport;                      /* Destination port            */
            u32 th_seq;                        /* Sequence number             */
            u32 th_ack;                        /* Acknowledgement number      */
            #if WORDS_BIGENDIAN
                u8 th_off:4;                   /* Data offset                 */
                u8 th_x2:4;                    /* Reserved                    */
            #else
                u8 th_x2:4;                    /* Reserved                    */
                u8 th_off:4;                   /* Data offset                 */
            #endif
            u8 th_flags;                       /* Flags                       */
            u16 th_win;                        /* Window size                 */
            u16 th_sum;                        /* Checksum                    */
            u16 th_urp;                        /* Urgent pointer              */

            u8 options[MAX_TCP_OPTIONS_LEN ];  /* Space for TCP Options       */
        }__attribute__((__packed__));

        typedef struct nping_tcp_hdr nping_tcp_hdr_t;

        nping_tcp_hdr_t h;

        int tcpoptlen; /**< Length of TCP options */

        void __tcppacketoptinfo(const u8 *optp, int len, char *result, int bufsize) const;

    public:

        TCPHeader();
        ~TCPHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        int setSourcePort(u16 p);
        u16 getSourcePort() const;

        int setDestinationPort(u16 p);
        u16 getDestinationPort() const;

        int setSeq(u32 p);
        u32 getSeq() const;

        int setAck(u32 p);
        u32 getAck() const;

        int setOffset(u8 o);
        int setOffset();
        u8 getOffset() const;

        int setReserved(u8 r);
        u8 getReserved() const;

        int setFlags(u8 f);
        u8 getFlags() const;
        u16 getFlags16() const;
        bool setCWR();
        bool unsetCWR();
        bool getCWR() const;
        bool setECE();
        bool unsetECE();
        bool getECE() const;
        bool setECN();
        bool unsetECN();
        bool getECN() const;
        bool setURG();
        bool unsetURG();
        bool getURG() const;
        bool setACK();
        bool unsetACK();
        bool getACK() const;
        bool setPSH();
        bool unsetPSH();
        bool getPSH() const;
        bool setRST();
        bool unsetRST();
        bool getRST() const;
        bool setSYN();
        bool unsetSYN();
        bool getSYN() const;
        bool setFIN();
        bool unsetFIN();
        bool getFIN() const;

        int setWindow(u16 p);
        u16 getWindow() const;

        int setUrgPointer(u16 l);
        u16 getUrgPointer() const;

        int setSum(u16 s);
        int setSum(struct in_addr source, struct in_addr destination);
        int setSum();
        int setSumRandom();
        int setSumRandom(struct in_addr source, struct in_addr destination);
        u16 getSum() const;

        int setOptions(const u8 *optsbuff, size_t optslen);
        const u8 *getOptions(size_t *optslen) const;
        nping_tcp_opt_t getOption(unsigned int index) const;
        static const char *optcode2str(u8 optcode);

}; /* End of class TCPHeader */

#endif /* __TCPHEADER_H__ */
