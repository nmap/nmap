
/***************************************************************************
 * TCPHeader.h -- The TCPHeader Class represents a TCP packet. It contains *
 * methods to set the different header fields. These methods tipically     *
 * perform the necessary error checks and byte order conversions.          *
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
