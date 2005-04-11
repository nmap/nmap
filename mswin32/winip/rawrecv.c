/*

rawrecv.c: implements a (very small) subset of libpcap over raw sockets
Copyright (C) 2000  Andy Lutomirski

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License, version 2.1, as published by the Free Software
Foundation, with the exception that if this copy of the library
is distributed under the Lesser GNU Public License (as opposed
to the ordinary GPL), you may ignore section 6b, and that all
copies distributed without exercising section 3 must retain this
paragraph in its entirety.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include "..\tcpip.h"
#include "winip.h"
#include "..\..\NmapOps.h"
#undef socket

#ifndef SIO_RCVALL
#define IOC_VENDOR 0x18000000
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif

extern NmapOps o;

static int nullfilter(const char *packet, unsigned int len)
{
	return 1;
}

static SOCKET s = INVALID_SOCKET;
static PFILTERFN filter;

static char buf[4096];

pcap_t *rawrecv_open(const char *dev)
{
	DWORD one = 1;
	u_long bufsz = 1<<20;
	DWORD bytesret;
	struct sockaddr_in sin;

	if(o.debugging > 1)
		printf("Trying to open %s for rawsock receive\n", dev);

	ZeroMemory(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	if(0 != devname2ipaddr((char*)dev, &sin.sin_addr))
		fatal("rawrecv_open: failed to find an IP for device %s\n", dev);

	if(s != INVALID_SOCKET)
		fatal("rawrecv: I can't handle more than one open connection\n");

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(s == INVALID_SOCKET)
		fatal("rawrecv: cannot open raw socket\n");

	if(bind(s, (struct sockaddr*)&sin, sizeof(sin)))
	  fatal("rawrecv_open: failed to bind to %s (%d)\n", inet_ntoa(sin.sin_addr), WSAGetLastError());

	if(setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&bufsz, sizeof(bufsz)))
		fatal("rawrecv_open: failed to set buffer size\n");

	if(WSAIoctl(s, SIO_RCVALL, &one, sizeof(one), NULL, 0,
		&bytesret, NULL, NULL))
		fatal("rawrecv_open: SIO_RCVALL failed (%lu) on device %s\n", WSAGetLastError(), dev);

	filter = nullfilter;

	return (pcap_t*)-2;
}

void rawrecv_close(pcap_t *pd)
{
	if(s == INVALID_SOCKET)
		fatal("rawrecv_close: nothing to do\n");

	closesocket(s);
	s = INVALID_SOCKET;
}

void rawrecv_setfilter(pcap_t *pd, PFILTERFN filterfn)
{
	if(-2 != (long)pd)
		fatal("rawrecv_setfilter: got non-rawrecv handle\n");

	if(filterfn) filter = filterfn;
	else filter = nullfilter;
}

char *rawrecv_readip(pcap_t *pd, unsigned int *len, long to_usec, struct timeval *rcvdtime)
{
	int rcvlen;
	DWORD time1, time2;
	fd_set fds;
	TIMEVAL tv;

	if(-2 != (long)pd)
		fatal("rawrecv_readip: called with non-rawrecv handle\n");

begin:

	//	Note: I could use SO_RCVTIMEO but I don't trust it...
	time1 = GetTickCount();
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	tv.tv_usec = to_usec % 1000000;
	tv.tv_sec = to_usec / 1000000;
	if(0 == select(0, &fds, 0, 0, &tv))
        {
          if(len) *len = 0;
          return 0;
        }

	rcvlen = recv(s, buf, sizeof(buf), 0);
	time2 = GetTickCount() + 10;

	if(rcvlen > 0)
	{
		if(rcvlen >= sizeof(struct ip) && filter(buf, rcvlen))
		{
			if (rcvdtime) {
				gettimeofday(rcvdtime, NULL);
			}
			if(len) *len = rcvlen;
			PacketTrace::trace(PacketTrace::RCVD, (u8 *) buf, rcvlen);
			return buf;
		}
		else
		{
			to_usec -= 1000 * (time2 - time1);
			if(to_usec < 0)
			{
				if(len) *len = 0;
				return 0;
			}
			goto begin;
		}
	}
	else
	{
		DWORD err = WSAGetLastError();
		if(err != WSAETIMEDOUT && err != WSAEWOULDBLOCK)
			fatal("rawrecv: recv failed (%lu)\n", err);

		if(len) *len = 0;
		return 0;
	}
}
