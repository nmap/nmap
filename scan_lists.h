/***************************************************************************
 * scan_lists.h -- Structures and functions for lists of ports to scan and *
 * scan types                                                              *
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

#ifndef SCAN_LISTS_H
#define SCAN_LISTS_H

/* just flags to indicate whether a particular port number should get tcp
 * scanned, udp scanned, or both
 */
#define SCAN_TCP_PORT	(1 << 0)
#define SCAN_UDP_PORT	(1 << 1)
#define SCAN_SCTP_PORT	(1 << 2)
#define SCAN_PROTOCOLS	(1 << 3)

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
        /* The "synprobes" are also used when doing a connect() ping */
        unsigned short *syn_ping_ports;
        unsigned short *ack_ping_ports;
        unsigned short *udp_ping_ports;
        unsigned short *sctp_ping_ports;
        unsigned short *proto_ping_ports;
        int syn_ping_count;
        int ack_ping_count;
        int udp_ping_count;
        int sctp_ping_count;
        int proto_ping_count;
        //the above fields are only used for host discovery
        //the fields below are only used for port scanning
        unsigned short *tcp_ports;
        int tcp_count;
        unsigned short *udp_ports;
        int udp_count;
        unsigned short *sctp_ports;
        int sctp_count;
        unsigned short *prots;
        int prot_count;
};

typedef enum {
  STYPE_UNKNOWN,
  HOST_DISCOVERY,
  ACK_SCAN,
  SYN_SCAN,
  FIN_SCAN,
  XMAS_SCAN,
  UDP_SCAN,
  CONNECT_SCAN,
  NULL_SCAN,
  WINDOW_SCAN,
  SCTP_INIT_SCAN,
  SCTP_COOKIE_ECHO_SCAN,
  MAIMON_SCAN,
  IPPROT_SCAN,
  PING_SCAN,
  PING_SCAN_ARP,
  IDLE_SCAN,
  BOUNCE_SCAN,
  SERVICE_SCAN,
  OS_SCAN,
  SCRIPT_PRE_SCAN,
  SCRIPT_SCAN,
  SCRIPT_POST_SCAN,
  TRACEROUTE,
  PING_SCAN_ND
} stype;

/* port manipulators */
void getpts(const char *expr, struct scan_lists * ports); /* someone stole the name getports()! */
void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count);
void removepts(const char *expr, struct scan_lists * ports);
void free_scan_lists(struct scan_lists *ports);

/* general helper functions */
const char *scantype2str(stype scantype);

#endif /* SCAN_LISTS_H */
