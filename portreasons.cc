/***************************************************************************
 * portreasons.cc -- Verbose packet-level information on port states       *
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

/*
 * Written by Eddie Bell <ejlbell@gmail.com> 2007
 * Modified by Colin Rice <dah4k0r@gmail.com> 2011
 */

#include "nmap.h"
#include "portlist.h"
#include "NmapOps.h"
#include "portreasons.h"
#include "Target.h"
#include "xml.h"
#ifdef WIN32
#include "winfix.h"
#endif
#include <iostream>

extern NmapOps o;
class PortList;

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
            return ER_UNKNOWN;

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
            return ER_UNKNOWN;

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

static void state_reason_summary_dinit(state_reason_summary_t *r) {
	state_reason_summary_t *tmp;

	while(r != NULL) {
		tmp = r->next;
		free(r);
		r = tmp;
	}
}

/* Counts how different valid state reasons exist */
static int state_summary_size(state_reason_summary_t *head) {
	state_reason_summary_t *current = head;
	int size = 0;

	while(current) {
		if(current->count > 0)
			size++;
		current = current->next;
	}
	return size;
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
static int update_state_summary(state_reason_summary_t *head, reason_t reason_id) {
	state_reason_summary_t *tmp = head;

	if(tmp == NULL)
		return -1;

	while(1) {
		if(tmp->reason_id == reason_id) {
			tmp->count++;
			return 0;
		}

		if(tmp->next == NULL) {
		  tmp->next = (state_reason_summary_t *)safe_malloc(sizeof(state_reason_summary_t));
		  tmp = tmp->next;
		  break;
		}
		tmp = tmp->next;
	}
	state_reason_summary_init(tmp);
	tmp->reason_id = reason_id;
	tmp->count = 1;
	return 0;
}

/* Converts Port objects and their corrosponsing state_reason structures into
 * state_reason_summary structures using update_state_summary */
static unsigned int get_state_summary(state_reason_summary_t *head, PortList *Ports, int state) {
	Port *current = NULL;
        Port port;
	state_reason_summary_t *reason;
	unsigned int total = 0;
	unsigned short proto = (o.ipprotscan) ? IPPROTO_IP : TCPANDUDPANDSCTP;

	if(head == NULL)
		return 0;
	reason = head;

	while((current = Ports->nextPort(current, &port, proto, state)) != NULL) {
		if(Ports->isIgnoredState(current->state)) {
			total++;
			update_state_summary(reason, current->reason.reason_id);
		}
	}
	return total;
}

/* parse and sort reason summary for main print_* functions */
static state_reason_summary_t *print_state_summary_internal(PortList *Ports, int state) {
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
    std::map<reason_codes,reason_string>::iterator itr = reason_map.find((reason_codes)reason_code);
    reason_string temp = (*itr).second;
    if (number == SINGULAR){
        return temp.singular;
    }
    return temp.plural;
}

void state_reason_init(state_reason_t *reason) {
	reason->reason_id = ER_UNKNOWN;
	reason->ip_addr.sockaddr.sa_family = AF_UNSPEC;
	reason->ttl = 0;
}

/* Main external interface to converting, building, sorting and
 * printing plain-text state reason summaries */
void print_state_summary(PortList *Ports, unsigned short type) {
	state_reason_summary_t *reason_head, *currentr;
	bool first_time = true;
	const char *separator = ", ";
	int states;

	if((reason_head = print_state_summary_internal(Ports, 0)) == NULL)
		return;

	if(type == STATE_REASON_EMPTY)
		log_write(LOG_PLAIN, " because of");
	else if(type == STATE_REASON_FULL)
		log_write(LOG_PLAIN, "Reason:");
	else
		assert(0);

	states = state_summary_size(reason_head);
	currentr = reason_head;
	
	while(currentr != NULL) {
		if(states == 1 && (!first_time))
			separator = " and ";
		if(currentr->count > 0) {
			log_write(LOG_PLAIN, "%s%d %s", (first_time) ? " " : separator,
				currentr->count, reason_str(currentr->reason_id, currentr->count));
			first_time = false;

		}
		states--;
		currentr  = currentr->next;
	}
	if(type == STATE_REASON_FULL)
		log_write(LOG_PLAIN, "\n");
	state_reason_summary_dinit(reason_head);
}

void print_xml_state_summary(PortList *Ports, int state) {
	state_reason_summary_t *reason_head, *currentr;

	if((currentr = reason_head = print_state_summary_internal(Ports, state)) == NULL)
		return;

	while(currentr != NULL) {
		if(currentr->count > 0) {
			xml_open_start_tag("extrareasons");
			xml_attribute("reason", "%s", reason_str(currentr->reason_id, currentr->count));
			xml_attribute("count", "%d", currentr->count);
			xml_close_empty_tag();
			xml_newline();
		}
		currentr = currentr->next;
	}
    state_reason_summary_dinit(reason_head);
}

/* converts target into reason message for ping scans. Uses a static
 * buffer so new values overwrite old values */
char *target_reason_str(Target *t) {
	static char reason[128];
	memset(reason,'\0', 128);
	Snprintf(reason, 128, "received %s", reason_str(t->reason.reason_id, SINGULAR));
	return reason;
}

/* Build an output string based on reason and source ip address.
 * uses a static return value so previous values will be over
 * written by subsequent calls */
char *port_reason_str(state_reason_t r) {
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
