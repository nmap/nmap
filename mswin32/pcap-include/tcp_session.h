/*
 * Copyright (c) 2001 - 2003
 * NetGroup, Politecnico di Torino (Italy)
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
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

#ifndef __tcp_session
#define __tcp_session

#ifdef WIN32
#include "tme.h"
#endif

#ifdef __FreeBSD__

#ifdef _KERNEL
#include <net/tme/tme.h>
#else
#include <tme/tme.h>
#endif

#endif

#define UNKNOWN			0
#define SYN_RCV			1
#define SYN_ACK_RCV		2
#define ESTABLISHED		3
#define CLOSED_RST		4
#define FIN_CLN_RCV		5
#define FIN_SRV_RCV		6
#define CLOSED_FIN		7
#define ERROR_TCP		8
#define FIRST_IS_CLN	0
#define	FIRST_IS_SRV	0xffffffff
#define FIN_CLN			1
#define	FIN_SRV			2

#define MAX_WINDOW 65536

typedef struct __tcp_data
{
	struct timeval timestamp_block; /*DO NOT MOVE THIS VALUE*/
	struct timeval syn_timestamp;
	struct timeval last_timestamp;
	struct timeval syn_ack_timestamp;
	uint32 direction;
	uint32 seq_n_0_srv;
	uint32 seq_n_0_cln;
	uint32 ack_srv; /* acknowledge of (data sent by server) */
	uint32 ack_cln; /* acknowledge of (data sent by client) */
	uint32 status;
	uint32 pkts_cln_to_srv;
	uint32 pkts_srv_to_cln;
	uint32 bytes_srv_to_cln;
	uint32 bytes_cln_to_srv;
	uint32 close_state;
}
	 tcp_data;

#define FIN		1
#define	SYN		2
#define RST		4
#define PSH		8
#define ACK		16
#define URG		32

#define	TCP_SESSION						0x00000800
uint32 tcp_session(uint8 *block, uint32 pkt_size, TME_DATA *data, MEM_TYPE *mem_ex, uint8 *mem_data);

#endif