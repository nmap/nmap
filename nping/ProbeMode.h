
/***************************************************************************
 * ProbeMode.h -- Probe Mode is nping's default working mode. Basically,   *
 * it involves sending the packets that the user requested at regular      *
 * intervals and capturing responses from the wire.                        *
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
#ifndef __PROBEMODE_H__
#define __PROBEMODE_H__ 1



#include "nping.h"
#include "nsock.h"
#include "NpingTarget.h"
#include "utils_net.h"
#include "utils.h"

#define PKT_TYPE_TCP_CONNECT  1
#define PKT_TYPE_UDP_NORMAL   2
#define PKT_TYPE_TCP_RAW      3
#define PKT_TYPE_UDP_RAW      4
#define PKT_TYPE_ICMP_RAW     5
#define PKT_TYPE_ARP_RAW      6

/* The sendpkt structure is the data normalProbeMode() function passes to
 * the nsock event handler. It contains the necessary information so a
 * handler can send one probe. */
typedef struct sendpkt{
    int type;
    u8 *pkt;
    int pktLen;
    int rawfd;
    u32 seq;
    NpingTarget *target;
    u16 dstport;
}sendpkt_t;


class ProbeMode  {

    private:

        nsock_pool nsp;        /**< Internal Nsock pool                       */
        bool nsock_init;       /**< True if nsock pool has been initialized   */

    public:

        ProbeMode();
        ~ProbeMode();
        void reset();
        int init_nsock();
        int start();
        int cleanup();
        nsock_pool getNsockPool();

        static int createIPv4(IPv4Header *i, PacketElement *next_element, const char *next_proto, NpingTarget *target);
        static int createIPv6(IPv6Header *i, PacketElement *next_element, const char *next_proto, NpingTarget *target);
        static int doIPv6ThroughSocket(int rawfd);
        static int fillPacket(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd);
        static int fillPacketTCP(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd);
        static int fillPacketUDP(NpingTarget *target, u16 port, u8 *buff, int bufflen, int *filledlen, int rawfd);
        static int fillPacketICMP(NpingTarget *target, u8 *buff, int bufflen, int *filledlen, int rawfd);
        static int fillPacketARP(NpingTarget *target, u8 *buff, int bufflen, int *filledlen, int rawfd);
        static char *getBPFFilterString();
        static void probe_nping_event_handler(nsock_pool nsp, nsock_event nse, void *arg);
        static void probe_delayed_output_handler(nsock_pool nsp, nsock_event nse, void *mydata);
        static void probe_tcpconnect_event_handler(nsock_pool nsp, nsock_event nse, void *arg);
        static void probe_udpunpriv_event_handler(nsock_pool nsp, nsock_event nse, void *arg);

}; /* End of class ProbeMode */


/* Handler wrappers */
void nping_event_handler(nsock_pool nsp, nsock_event nse, void *arg);
void tcpconnect_event_handler(nsock_pool nsp, nsock_event nse, void *arg);
void udpunpriv_event_handler(nsock_pool nsp, nsock_event nse, void *arg);
void delayed_output_handler(nsock_pool nsp, nsock_event nse, void *arg);

#endif /* __PROBEMODE_H__ */
