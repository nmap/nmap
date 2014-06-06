/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/fad-win32.c,v 1.15 2007-09-25 20:34:36 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include <pcap-int.h>
#include <Packet32.h>

#include <errno.h>
	
/*
 * Add an entry to the list of addresses for an interface.
 * "curdev" is the entry for that interface.
 */
static int
add_addr_to_list(pcap_if_t *curdev, struct sockaddr *addr,
    struct sockaddr *netmask, struct sockaddr *broadaddr,
    struct sockaddr *dstaddr, char *errbuf)
{
	pcap_addr_t *curaddr, *prevaddr, *nextaddr;

	/*
	 * Allocate the new entry and fill it in.
	 */
	curaddr = (pcap_addr_t*)malloc(sizeof(pcap_addr_t));
	if (curaddr == NULL) {
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "malloc: %s", pcap_strerror(errno));
		return (-1);
	}

	curaddr->next = NULL;
	if (addr != NULL) {
		curaddr->addr = (struct sockaddr*)dup_sockaddr(addr, sizeof(struct sockaddr_storage));
		if (curaddr->addr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->addr = NULL;

	if (netmask != NULL) {
		curaddr->netmask = (struct sockaddr*)dup_sockaddr(netmask, sizeof(struct sockaddr_storage));
		if (curaddr->netmask == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->netmask = NULL;
		
	if (broadaddr != NULL) {
		curaddr->broadaddr = (struct sockaddr*)dup_sockaddr(broadaddr, sizeof(struct sockaddr_storage));
		if (curaddr->broadaddr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->broadaddr = NULL;
		
	if (dstaddr != NULL) {
		curaddr->dstaddr = (struct sockaddr*)dup_sockaddr(dstaddr, sizeof(struct sockaddr_storage));
		if (curaddr->dstaddr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->dstaddr = NULL;
		
	/*
	 * Find the end of the list of addresses.
	 */
	for (prevaddr = curdev->addresses; prevaddr != NULL; prevaddr = nextaddr) {
		nextaddr = prevaddr->next;
		if (nextaddr == NULL) {
			/*
			 * This is the end of the list.
			 */
			break;
		}
	}

	if (prevaddr == NULL) {
		/*
		 * The list was empty; this is the first member.
		 */
		curdev->addresses = curaddr;
	} else {
		/*
		 * "prevaddr" is the last member of the list; append
		 * this member to it.
		 */
		prevaddr->next = curaddr;
	}

	return (0);
}


static int
pcap_add_if_win32(pcap_if_t **devlist, char *name, const char *desc,
    char *errbuf)
{
	pcap_if_t *curdev;
	npf_if_addr if_addrs[MAX_NETWORK_ADDRESSES];
	LONG if_addr_size;
	int res = 0;

	if_addr_size = MAX_NETWORK_ADDRESSES;

	/*
	 * Add an entry for this interface, with no addresses.
	 */
	if (add_or_find_if(&curdev, devlist, name, 0, desc, errbuf) == -1) {
		/*
		 * Failure.
		 */
		return (-1);
	}

	/*
	 * Get the list of addresses for the interface.
	 */
	if (!PacketGetNetInfoEx((void *)name, if_addrs, &if_addr_size)) {
		/*
		 * Failure.
		 *
		 * We don't return an error, because this can happen with
		 * NdisWan interfaces, and we want to supply them even
		 * if we can't supply their addresses.
		 *
		 * We return an entry with an empty address list.
		 */
		return (0);
	}

	/*
	 * Now add the addresses.
	 */
	while (if_addr_size-- > 0) {
		/*
		 * "curdev" is an entry for this interface; add an entry for
		 * this address to its list of addresses.
		 */
		if(curdev == NULL)
			break;
		res = add_addr_to_list(curdev,
		    (struct sockaddr *)&if_addrs[if_addr_size].IPAddress,
		    (struct sockaddr *)&if_addrs[if_addr_size].SubnetMask,
		    (struct sockaddr *)&if_addrs[if_addr_size].Broadcast,
		    NULL,
			errbuf);
		if (res == -1) {
			/*
			 * Failure.
			 */
			break;
		}
	}

	return (res);
}


/*
 * Get a list of all interfaces that are up and that we can open.
 * Returns -1 on error, 0 otherwise.
 * The list, as returned through "alldevsp", may be null if no interfaces
 * were up and could be opened.
 *
 * Win32 implementation, based on WinPcap
 */
int
pcap_findalldevs_interfaces(pcap_if_t **alldevsp, char *errbuf)
{
	pcap_if_t *devlist = NULL;
	int ret = 0;
	const char *desc;
	char *AdaptersName;
	ULONG NameLength;
	char *name;
	
	/*
	 * Find out how big a buffer we need.
	 *
	 * This call should always return FALSE; if the error is
	 * ERROR_INSUFFICIENT_BUFFER, NameLength will be set to
	 * the size of the buffer we need, otherwise there's a
	 * problem, and NameLength should be set to 0.
	 *
	 * It shouldn't require NameLength to be set, but,
	 * at least as of WinPcap 4.1.3, it checks whether
	 * NameLength is big enough before it checks for a
	 * NULL buffer argument, so, while it'll still do
	 * the right thing if NameLength is uninitialized and
	 * whatever junk happens to be there is big enough
	 * (because the pointer argument will be null), it's
	 * still reading an uninitialized variable.
	 */
	NameLength = 0;
	if (!PacketGetAdapterNames(NULL, &NameLength))
	{
		DWORD last_error = GetLastError();

		if (last_error != ERROR_INSUFFICIENT_BUFFER)
		{
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				"PacketGetAdapterNames: %s",
				pcap_win32strerror());
			return (-1);
		}
	}

	if (NameLength > 0)
		AdaptersName = (char*) malloc(NameLength);
	else
	{
		*alldevsp = NULL;
		return 0;
	}
	if (AdaptersName == NULL)
	{
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Cannot allocate enough memory to list the adapters.");
		return (-1);
	}			

	if (!PacketGetAdapterNames(AdaptersName, &NameLength)) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
			"PacketGetAdapterNames: %s",
			pcap_win32strerror());
		free(AdaptersName);
		return (-1);
	}
	
	/*
	 * "PacketGetAdapterNames()" returned a list of
	 * null-terminated ASCII interface name strings,
	 * terminated by a null string, followed by a list
	 * of null-terminated ASCII interface description
	 * strings, terminated by a null string.
	 * This means there are two ASCII nulls at the end
	 * of the first list.
	 *
	 * Find the end of the first list; that's the
	 * beginning of the second list.
	 */
	desc = &AdaptersName[0];
	while (*desc != '\0' || *(desc + 1) != '\0')
		desc++;
	
	/*
 	 * Found it - "desc" points to the first of the two
	 * nulls at the end of the list of names, so the
	 * first byte of the list of descriptions is two bytes
	 * after it.
	 */
	desc += 2;
	
	/*
	 * Loop over the elements in the first list.
	 */
	name = &AdaptersName[0];
	while (*name != '\0') {
		/*
		 * Add an entry for this interface.
		 */
		if (pcap_add_if_win32(&devlist, name, desc, errbuf) == -1) {
			/*
			 * Failure.
			 */
			ret = -1;
			break;
		}
		name += strlen(name) + 1;
		desc += strlen(desc) + 1;
	}

	if (ret != -1) {
		/*
		 * We haven't had any errors yet; do any platform-specific
		 * operations to add devices.
		 */
		if (pcap_platform_finddevs(&devlist, errbuf) < 0)
			ret = -1;
	}
	
	if (ret == -1) {
		/*
		 * We had an error; free the list we've been constructing.
		 */
		if (devlist != NULL) {
			pcap_freealldevs(devlist);
			devlist = NULL;
		}
	}
	
	*alldevsp = devlist;
	free(AdaptersName);
	return (ret);
}
