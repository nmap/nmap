/*
 *  fad-sita.c: Packet capture interface additions for SITA ACN devices
 *
 *  Copyright (c) 2007 Fulko Hew, SITA INC Canada, Inc <fulko.hew@sita.aero>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

 /* $Id: fad-sita.c */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "pcap-int.h"

#include "pcap-sita.h"

extern pcap_if_t	*acn_if_list;								/* pcap's list of available interfaces */

int pcap_findalldevs_interfaces(pcap_if_t **alldevsp, char *errbuf) {

	//printf("pcap_findalldevs()\n");				// fulko

	*alldevsp = 0;												/* initialize the returned variables before we do anything */
	strcpy(errbuf, "");
	if (acn_parse_hosts_file(errbuf))							/* scan the hosts file for potential IOPs */
		{
		//printf("pcap_findalldevs() returning BAD after parsehosts\n");				// fulko
		return -1;
		}
	//printf("pcap_findalldevs() got hostlist now finding devs\n");				// fulko
	if (acn_findalldevs(errbuf))								/* then ask the IOPs for their monitorable devices */
		{
		//printf("pcap_findalldevs() returning BAD after findalldevs\n");				// fulko
		return -1;
		}
	*alldevsp = acn_if_list;
	acn_if_list = 0;											/* then forget our list head, because someone will call pcap_freealldevs() to empty the malloc'ed stuff */
	//printf("pcap_findalldevs() returning ZERO OK\n");				// fulko
	return 0;
}
