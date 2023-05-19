/***************************************************************************
 * portreasons.cc -- Verbose packet-level information on port states       *
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

#ifdef WIN32
#include "winfix.h"
#endif
#include "portlist.h"
#include "NmapOps.h"
#include "portreasons.h"
#include "Target.h"

extern NmapOps o;

/* Set the ip_addr union to the AF_INET or AF_INET6 value stored in *ss as
   appropriate. Returns 0 on success or -1 if the address family of *ss is not
   known. */
int port_reason::set_ip_addr(const struct sockaddr_storage *ss) {
  if (ss->ss_family == AF_INET) {
    this->ip_addr.in = *(struct sockaddr_in *) ss;
    return 0;
  } else if (ss->ss_family == AF_INET6) {
    this->ip_addr.in6 = *(struct sockaddr_in6 *) ss;
    return 0;
  } else {
    return -1;
  }
}

/* reason_string initializer */
reason_string::reason_string(){
    this->plural = "unknown";
    this->singular = this->plural;
}
reason_string::reason_string(const char * singular, const char * plural){
    this->plural = plural;
    this->singular = singular;
};

reason_map_type::reason_map_type(){
    reason_map[ER_RESETPEER] = reason_string("reset","resets");
    reason_map[ER_CONREFUSED] = reason_string("conn-refused","conn-refused");
    reason_map[ER_CONACCEPT] = reason_string("syn-ack","syn-acks");

    reason_map[ER_SYNACK] = reason_string("syn-ack","syn-acks");
    reason_map[ER_SYN] = reason_string("split-handshake-syn","split-handshake-syns");
    reason_map[ER_UDPRESPONSE] = reason_string("udp-response","udp-responses");
    reason_map[ER_PROTORESPONSE] = reason_string("proto-response","proto-responses");
    reason_map[ER_ACCES] = reason_string("perm-denied","perm-denieds");


    reason_map[ER_NETUNREACH] = reason_string("net-unreach","net-unreaches");
    reason_map[ER_HOSTUNREACH] = reason_string("host-unreach","host-unreaches");
    reason_map[ER_PROTOUNREACH] = reason_string("proto-unreach","proto-unreaches");

    reason_map[ER_PORTUNREACH] = reason_string("port-unreach","port-unreaches");
    reason_map[ER_ECHOREPLY] = reason_string("echo-reply","echo-replies");


    reason_map[ER_DESTUNREACH] = reason_string("dest-unreach","dest-unreaches");
    reason_map[ER_SOURCEQUENCH] = reason_string("source-quench","source-quenches");
    reason_map[ER_NETPROHIBITED] = reason_string("net-prohibited","net-prohibiteds");

    reason_map[ER_HOSTPROHIBITED] = reason_string("host-prohibited","host-prohibiteds");
    reason_map[ER_ADMINPROHIBITED] = reason_string("admin-prohibited","admin-prohibiteds");

    reason_map[ER_TIMEEXCEEDED] = reason_string("time-exceeded","time-exceededs");
    reason_map[ER_TIMESTAMPREPLY] = reason_string("timestamp-reply","timestamp-replies");

    reason_map[ER_ADDRESSMASKREPLY] = reason_string("addressmask-reply","addressmask-replies");
    reason_map[ER_NOIPIDCHANGE] = reason_string("no-ipid-change","no-ipid-changes");
    reason_map[ER_IPIDCHANGE] = reason_string("ipid-change","ipid-changes");

    reason_map[ER_ARPRESPONSE] = reason_string("arp-response","arp-responses");
    reason_map[ER_NDRESPONSE] = reason_string("nd-response","nd-responses");
    reason_map[ER_TCPRESPONSE] = reason_string("tcp-response","tcp-responses");
    reason_map[ER_NORESPONSE] = reason_string("no-response","no-responses");

    reason_map[ER_INITACK] = reason_string("init-ack","init-acks");
    reason_map[ER_ABORT] = reason_string("abort","aborts");

    reason_map[ER_LOCALHOST] = reason_string("localhost-response","localhost-responses");
    reason_map[ER_SCRIPT] = reason_string("script-set","script-set");
    reason_map[ER_UNKNOWN] = reason_string("unknown-response","unknown-responses");
    reason_map[ER_USER] = reason_string("user-set","user-sets");

    reason_map[ER_NOROUTE] = reason_string("no-route", "no-routes");
    reason_map[ER_BEYONDSCOPE] = reason_string("beyond-scope", "beyond-scopes");
    reason_map[ER_REJECTROUTE] = reason_string("reject-route", "reject-routes");
    reason_map[ER_PARAMPROBLEM] = reason_string("param-problem", "param-problems");
}

/* Map holding plural and singular versions of error codes */
reason_map_type reason_map;

/* Function to Translate ICMP codes and types to *
 * Reason Codes                  */

static reason_codes icmpv4_to_reason(int icmp_type, int icmp_code) {

    switch(icmp_type){

        case ICMP_ECHOREPLY:
            return ER_ECHOREPLY;

        case ICMP_UNREACH:
            switch(icmp_code){
            case ICMP_UNREACH_NET:
                return ER_NETUNREACH;
            case ICMP_UNREACH_HOST:
                return ER_HOSTUNREACH;
            case ICMP_UNREACH_PROTO:
                return ER_PROTOUNREACH;
            case ICMP_UNREACH_PORT:
                return ER_PORTUNREACH;
            case ICMP_UNREACH_NET_PROHIB:
                return ER_NETPROHIBITED;
            case ICMP_UNREACH_HOST_PROHIB:
                return ER_HOSTPROHIBITED;
            case ICMP_UNREACH_FILTER_PROHIB:
                return ER_ADMINPROHIBITED;
            }
            return ER_DESTUNREACH;

        case ICMP_SRCQUENCH:
            return ER_SOURCEQUENCH;

        case ICMP_TIMEXCEED:
            return ER_TIMEEXCEEDED;

        case ICMP_TSTAMPREPLY:
            return ER_TIMESTAMPREPLY;

        case ICMP_MASKREPLY:
            return ER_ADDRESSMASKREPLY;


    }
    return ER_UNKNOWN;
};

static reason_codes icmpv6_to_reason(int icmp_type, int icmp_code) {

    switch(icmp_type){

        case ICMPV6_ECHOREPLY:
            return ER_ECHOREPLY;

        case ICMPV6_UNREACH:
            switch(icmp_code) {
            case ICMPV6_UNREACH_NOROUTE:
                return ER_NOROUTE;
            case ICMPV6_UNREACH_PROHIB:
                return ER_ADMINPROHIBITED;
            case ICMPV6_UNREACH_SCOPE:
                return ER_BEYONDSCOPE;
            case ICMPV6_UNREACH_ADDR:
                return ER_HOSTUNREACH;
            case ICMPV6_UNREACH_PORT:
                return ER_PORTUNREACH;
            case ICMPV6_UNREACH_FILTER_PROHIB:
                return ER_ADMINPROHIBITED;
            case ICMPV6_UNREACH_REJECT_ROUTE:
                return ER_REJECTROUTE;
            }
            return ER_DESTUNREACH;

        case ICMPV6_PARAMPROBLEM:
            return ER_PARAMPROBLEM;

        case ICMPV6_TIMEXCEED:
            return ER_TIMEEXCEEDED;
    }
    return ER_UNKNOWN;
};

reason_codes icmp_to_reason(u8 proto, int icmp_type, int icmp_code) {
        if (proto == IPPROTO_ICMP)
                return icmpv4_to_reason(icmp_type, icmp_code);
        else if (proto == IPPROTO_ICMPV6)
                return icmpv6_to_reason(icmp_type, icmp_code);
        else
                return ER_UNKNOWN;
}

static void state_reason_summary_init(state_reason_summary_t *r) {
        r->reason_id = ER_UNKNOWN;
        r->count = 0;
        r->next = NULL;
}

void state_reason_summary_dinit(state_reason_summary_t *r) {
        state_reason_summary_t *tmp;

        while(r != NULL) {
                tmp = r->next;
                free(r);
                r = tmp;
        }
}

/* Simon Tatham's linked list merge sort
 *
 * Merge sort works really well on linked lists
 * because it does not require the O(N) extra space
 * needed with arrays */
static state_reason_summary_t *reason_sort(state_reason_summary_t *list) {
        state_reason_summary_t *p, *q, *e, *tail;
        int insize = 1, nmerges, psize, qsize, i;

    if (!list)
          return NULL;

    while (1) {
        p = list;
        list = NULL;
        tail = NULL;
        nmerges = 0;

        while (p) {
            nmerges++;
            q = p;
            psize = 0;
            for (i = 0; i < insize; i++) {
                psize++;
                        q = q->next;
                if (!q) break;
            }
            qsize = insize;
            while (psize > 0 || (qsize > 0 && q)) {
              if (psize == 0) {
                        e = q; q = q->next; qsize--;
                     } else if (qsize == 0 || !q) {
                        e = p; p = p->next; psize--;
                     } else if (q->count<p->count) {
                        e = p; p = p->next; psize--;
                     } else {
                       e = q; q = q->next; qsize--;
                     }

                     if (tail) {
                      tail->next = e;
                    } else {
                      list = e;
                    }
                    tail = e;
          }
          p = q;
       }
      if (!tail)
        return NULL;
      tail->next = NULL;
      if (nmerges <= 1)
        return list;
      insize *= 2;
    }
}

/* Builds and aggregates reason state summary messages */
static int update_state_summary(state_reason_summary_t *head, Port *port) {
        state_reason_summary_t *tmp = head;

        if(tmp == NULL)
                return -1;

        while(1) {
                if(tmp->reason_id == port->reason.reason_id && tmp->proto == port->proto) {
                        break;
                }

                if(tmp->next == NULL) {
                  tmp->next = (state_reason_summary_t *)safe_malloc(sizeof(state_reason_summary_t));
                  tmp = tmp->next;
                  state_reason_summary_init(tmp);
                  tmp->reason_id = port->reason.reason_id;
                  tmp->proto = port->proto;
                  break;
                }
                tmp = tmp->next;
        }
        tmp->ports[tmp->count] = port->portno;
        tmp->count++;
        return 0;
}

/* Converts Port objects and their corresponding state_reason structures into
 * state_reason_summary structures using update_state_summary */
static unsigned int get_state_summary(state_reason_summary_t *head, const PortList *Ports, int state) {
        Port *current = NULL;
        Port port;
        state_reason_summary_t *reason;
        unsigned int total = 0;
        unsigned short proto = (o.ipprotscan) ? IPPROTO_IP : TCPANDUDPANDSCTP;

        if(head == NULL)
                return 0;
        reason = head;

        while((current = Ports->nextPort(current, &port, proto, state)) != NULL) {
                if(Ports->isIgnoredState(current->state, NULL)) {
                        total++;
                        update_state_summary(reason, current);
                }
        }
        return total;
}

/* parse and sort reason summary for main print_* functions */
state_reason_summary_t *get_state_reason_summary(const PortList *Ports, int state) {
        state_reason_summary_t *reason_head;

        reason_head = (state_reason_summary_t *)safe_malloc(sizeof(state_reason_summary_t));

        state_reason_summary_init(reason_head);

        if((get_state_summary(reason_head, Ports, state) < 1)) {
                state_reason_summary_dinit(reason_head);
                return NULL;
        }

        if((reason_head = reason_sort(reason_head)) == NULL)
                return NULL;
        return reason_head;
}

/* looks up reason_id's and returns with the plural or singular
 * string representation. If 'number' is equal to 1 then the
 * singular is used, otherwise the plural */
const char *reason_str(reason_t reason_code, unsigned int number) {
    std::map<reason_codes,reason_string>::const_iterator itr = reason_map.find((reason_codes)reason_code);
    const reason_string *temp = &itr->second;
    if (number == SINGULAR){
        return temp->singular;
    }
    return temp->plural;
}

void state_reason_init(state_reason_t *reason) {
        reason->reason_id = ER_UNKNOWN;
        reason->ip_addr.sockaddr.sa_family = AF_UNSPEC;
        reason->ttl = 0;
}

/* converts target into reason message for ping scans. Uses a static
 * buffer so new values overwrite old values */
const char *target_reason_str(const Target *t) {
        static char reason[128];
        memset(reason,'\0', 128);
        Snprintf(reason, 128, "received %s", reason_str(t->reason.reason_id, SINGULAR));
        return reason;
}

/* Build an output string based on reason and source ip address.
 * uses a static return value so previous values will be over
 * written by subsequent calls */
const char *port_reason_str(state_reason_t r) {
        static char reason[128];
        memset(reason,'\0', 128);
        if (r.ip_addr.sockaddr.sa_family == AF_UNSPEC) {
                Snprintf(reason, sizeof(reason), "%s", reason_str(r.reason_id, SINGULAR));
        } else {
                struct sockaddr_storage ss;
                memcpy(&ss, &r.ip_addr, sizeof(r.ip_addr));
                Snprintf(reason, sizeof(reason), "%s from %s", reason_str(r.reason_id, SINGULAR),
                        inet_ntop_ez(&ss, sizeof(ss)));
        }
        return reason;
}
