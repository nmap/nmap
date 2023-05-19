
/***************************************************************************
 * EchoClient.h --                                                         *
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
#ifndef __ECHOCLIENT_H__
#define __ECHOCLIENT_H__ 1

#include "nping.h"
#include "NpingTarget.h"
#include "NEPContext.h"
#include "ProbeMode.h"

#define ECHO_CONNECT_TIMEOUT (10*1000) /* 10 Seconds */
#define ECHO_READ_TIMEOUT    (10*1000)
#define ECHO_WRITE_TIMEOUT   (10*1000)

/* Max number of bytes that are supplied as data for the PAYLOAD_MAGIC specifier */
#define NEP_PAYLOADMAGIC_MAX_BYTES 8


class EchoClient  {

    private:

        /* Attributes */
        nsock_pool nsp;               /**< Nsock pool (shared with ProbeMode) */
        nsock_iod nsi;                /**< IOD for the side-channel tcp socket*/
        struct sockaddr_in srvaddr4;  /**< Server's IPv4 address */
        struct sockaddr_in6 srvaddr6; /**< Server's IPv6 address */
        int af;                       /**< Address family (AF_INET or AF_INET6)*/
        NEPContext ctx;
        ProbeMode probe;
        u8 lasthdr[MAX_NEP_PACKET_LENGTH];
        size_t readbytes;

        /* Methods */
        int nep_connect(NpingTarget *target, u16 port);
        int nep_handshake();
        int nep_send_packet_spec();
        int nep_recv_ready();
        int nep_recv_echo(u8 *packet, size_t packetlen);

        int parse_hs_server(u8 *pkt, size_t pktlen);
        int parse_hs_final(u8 *pkt, size_t pktlen);
        int parse_ready(u8 *pkt, size_t pktlen);
        int parse_echo(u8 *pkt, size_t pktlen);
        int parse_error(u8 *pkt, size_t pktlen);

        int generate_hs_client(EchoHeader *h);
        int generate_packet_spec(EchoHeader *h);

    public:

        EchoClient();
        ~EchoClient();
        void reset();
        int start(NpingTarget *target, u16 port);
        int cleanup();
        int nep_echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg);

}; /* End of class EchoClient */


/* Handler wrappers */
void echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg);
void connect_done_handler(nsock_pool nsp, nsock_event nse, void *arg);
void write_done_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg);

#endif /* __ECHOCLIENT_H__ */
