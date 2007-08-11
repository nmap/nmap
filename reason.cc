/***************************************************************************
 * reason.cc -- Verbose packet-level information on port states            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as   *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://www.insecure.org/nmap/ to download Nmap.                         *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/*
 * Written by Eddie Bell <ejlbell@gmail.com> 2007
 */

#include <iostream>
#include "nmap.h"
#include "portlist.h"
#include "NmapOps.h"
#include "reason.h"
#include "Target.h"
#ifdef WIN32
#include "winfix.h"
#endif

extern NmapOps o;
class PortList;

/* Possible plural and singular reasons */
char *reason_text[ER_MAX+1]={ 
        "reset", "conn-refused", "syn-ack", "syn-ack",  "udp-response",
        "proto-response","net-unreach", "host-unreach", "proto-unreach",
        "port-unreach", "echo-reply", "unknown", "unknown", "dest-unreach",
        "source-quench", "net-prohibited", "host-prohibited", "unknown", 
        "unknown", "admin-prohibited", "unknown", "time-exceeded", "unknown", "unknown",
        "timestamp-reply", "unknown", "unknown", "unknown", "addressmask-reply",
        "no-ipid-change", "ipid-change", "arp-reponse", "tcp-response",
        "no-response", "localhost-response", "unknown-response"
};

char *reason_pl_text[ER_MAX+1]={ 
        "resets", "conn-refused", "syn-acks", "syn-acks",  "udp-responses",
        "proto-responses","net-unreaches", "host-unreaches", "proto-unreaches",
        "port-unreaches", "echo-replies", "unknowns", "unknowns", "dest-unreaches",
        "source-quenches", "net-prohibiteds", "host-prohibiteds", "unknowns", 
        "unknowns", "admin-prohibiteds", "unknowns", "time-exceededs", "unknowns",
        "unknowns", "timestamp-replies", "unknowns", "unknowns", "unknowns", 
        "addressmask-replies", "no-ipid-changes", "ipid-changes", "arp-responses",
        "tcp-responses", "no-responses", "localhost-response", "unknown-responses"
};

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
		r = r->next;
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
			if((tmp->next = (state_reason_summary_t *)malloc(sizeof(state_reason_summary_t))) == NULL) {
				perror("malloc() -> Cannot allocate state reason structures");
				return -1;
			}
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
static unsigned int get_state_summary(state_reason_summary_t *head, PortList *Ports) {
	Port *current = NULL;
	state_reason_summary_t *reason;
	unsigned int total = 0;
	unsigned short proto = (o.ipprotscan) ? IPPROTO_IP : TCPANDUDP;

	if(head == NULL)
		return 0;
	reason = head;

	while((current = Ports->nextPort(current, proto, 0)) != NULL) {
		if(Ports->isIgnoredState(current->state)) {
			total++;
			update_state_summary(reason, current->reason.reason_id);
		}
	}
	return total;
}

/* parse and sort reason summary for main print_* functions */
static state_reason_summary_t *print_state_summary_internal(PortList *Ports) {
	state_reason_summary_t *reason_head;

	if((reason_head = (state_reason_summary_t *)malloc(sizeof(state_reason_summary_t))) == NULL)  {
		perror("malloc() -> Cannot allocate state reason structures");
		return NULL;
	}

	state_reason_summary_init(reason_head);

	if((get_state_summary(reason_head, Ports) < 1)) {
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
	if(reason_code > ER_MAX) 
		return "unknown";
	if(number == 1)
		return reason_text[reason_code];
	else
		return reason_pl_text[reason_code];
}

void state_reason_init(state_reason_t *reason) {
	reason->reason_id = ER_UNKNOWN;
	reason->ip_addr.s_addr = 0;
	reason->ttl = 0;
}

/* Main external interface to converting, building, sorting and
 * printing plain-text state reason summaries */
void print_state_summary(PortList *Ports, unsigned short type) {
	state_reason_summary_t *reason_head, *currentr;
	bool first_time = true;
	char *separator = ", ";
	int states;

	if((reason_head = print_state_summary_internal(Ports)) == NULL)
		return;
	
	if(type == STATE_REASON_EMPTY)
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, " because of"); 
	else if(type == STATE_REASON_FULL)
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "Reason:"); 
	else
		assert(0);

	states = state_summary_size(reason_head);
	currentr = reason_head;

	while(currentr != NULL) {
		if(states == 1 && (!first_time))
			separator = " and ";
		if(currentr->count > 0) {
			log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%s%d %s", (first_time) ? " " : separator, 
				currentr->count, reason_str(currentr->reason_id, currentr->count));
			first_time = false;

		}
		states--;
		currentr  = currentr->next;
	}
	if(type == STATE_REASON_FULL)
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "\n");
	state_reason_summary_dinit(reason_head);
}

void print_xml_state_summary(PortList *Ports) {
	state_reason_summary_t *reason_head, *currentr;

	if((currentr = reason_head = print_state_summary_internal(Ports)) == NULL)
		return;
	
	while(currentr != NULL) {
		if(currentr->count > 0)
			log_write(LOG_XML, "<extrareasons reason=\"%s\" count=\"%d\"/>\n",
			  reason_str(currentr->reason_id, currentr->count), currentr->count);
		currentr = currentr->next;
	}
    state_reason_summary_dinit(reason_head);
}

/* converts target into reason message for ping scans. Uses a static
 * buffer so new values overwrite old values */
char *target_reason_str(Target *t) {
	static char reason[128];
	memset(reason,'\0', 128);
	assert(t->reason.reason_id != ER_NORESPONSE);
	snprintf(reason, 128, ", received %s",reason_str(t->reason.reason_id, SINGULAR)); 
	return reason;
}

/* Build an output string based on reason and source ip address.
 * uses a static return value so previous values will be over
 * written by subsequent calls */
char *port_reason_str(state_reason_t r) {
	static char reason[128];
	memset(reason,'\0', 128);
	snprintf(reason, 128, "%s%s%s", reason_str(r.reason_id, SINGULAR),
            (r.ip_addr.s_addr==0)?"":" from ",
            (r.ip_addr.s_addr==0)?"":inet_ntoa(r.ip_addr));
	return reason;	
}
