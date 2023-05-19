/***************************************************************************
 * portreasons.h -- Verbose packet-level information on port states        *
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

/*
 * Written by Eddie Bell <ejlbell@gmail.com> 2007
 * Modified by Colin Rice <dah4k0r@gmail.com> 2011
 */

#ifndef REASON_H
#define REASON_H

#include "nbase.h"

#include <sys/types.h>
#include <map>
class Target;
class PortList;

typedef unsigned short reason_t;

/* Holds various string outputs of a reason  *
 * Stored inside a map which maps enum_codes *
 * to reason_strings				     */
class reason_string {
public:
    //Required for map
    reason_string();
    reason_string(const char * singular, const char * plural);
    const char * singular;
    const char * plural;
};

/* stored inside a Port Object and describes
 * why a port is in a specific state */
typedef struct port_reason {
        reason_t reason_id;
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr sockaddr;
        } ip_addr;
        unsigned short ttl;

        int set_ip_addr(const struct sockaddr_storage *ss);
} state_reason_t;

/* used to calculate state reason summaries.
 * I.E 10 ports filter because of 10 no-responses */
typedef struct port_reason_summary {
        reason_t reason_id;
        unsigned int count;
        struct port_reason_summary *next;
        unsigned short proto;
        unsigned short ports[0xffff+1];
} state_reason_summary_t;


enum reason_codes {
        ER_RESETPEER, ER_CONREFUSED, ER_CONACCEPT,
        ER_SYNACK, ER_SYN, ER_UDPRESPONSE, ER_PROTORESPONSE, ER_ACCES,

        ER_NETUNREACH, ER_HOSTUNREACH, ER_PROTOUNREACH,
        ER_PORTUNREACH, ER_ECHOREPLY,

        ER_DESTUNREACH, ER_SOURCEQUENCH, ER_NETPROHIBITED,
        ER_HOSTPROHIBITED, ER_ADMINPROHIBITED,
        ER_TIMEEXCEEDED, ER_TIMESTAMPREPLY,

        ER_ADDRESSMASKREPLY, ER_NOIPIDCHANGE, ER_IPIDCHANGE,
        ER_ARPRESPONSE, ER_NDRESPONSE, ER_TCPRESPONSE, ER_NORESPONSE,
        ER_INITACK, ER_ABORT,
        ER_LOCALHOST, ER_SCRIPT, ER_UNKNOWN, ER_USER,
        ER_NOROUTE, ER_BEYONDSCOPE, ER_REJECTROUTE, ER_PARAMPROBLEM,
};

/* A map of reason_codes to plural and singular *
 * versions of the error string                 */
class reason_map_type{
private:
    std::map<reason_codes,reason_string > reason_map;
public:
    reason_map_type();
    std::map<reason_codes,reason_string>::const_iterator find(const reason_codes& x) const {
        std::map<reason_codes,reason_string>::const_iterator itr = reason_map.find(x);
        if(itr == reason_map.end())
            return reason_map.find(ER_UNKNOWN);
        return itr;
    };
};

/* Function to translate ICMP code and typ to reason code */
reason_codes icmp_to_reason(u8 proto, int icmp_type, int icmp_code);

/* Passed to reason_str to determine if string should be in
 * plural of singular form */
#define SINGULAR 1
#define PLURAL 2

void state_reason_init(state_reason_t *reason);

/* converts a reason_id to a string. number represents the
 * amount ports in a given state. If there is more then one
 * port the plural is used, otherwise the singular is used. */
const char *reason_str(reason_t reason_id, unsigned int number);

/* Returns a linked list of reasons why ports are in a given state */
state_reason_summary_t *get_state_reason_summary(const PortList *Ports, int state);
/* Frees the linked list from get_state_reason_summary */
void state_reason_summary_dinit(state_reason_summary_t *r);

/* Build an output string based on reason and source ip address.
 * Uses static return value so previous values will be over
 * written by subsequent calls */
const char *port_reason_str(state_reason_t r);
const char *target_reason_str(const Target *t);

#endif

