/*
 * Copyright (c) 1999 - 2003
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

/* Definitions */

/*!
  \brief A queue of raw packets that will be sent to the network with pcap_sendqueue_transmit().
*/
struct pcap_send_queue{
	u_int maxlen;		///< Maximum size of the the queue, in bytes. This variable contains the size of the buffer field.
	u_int len;			///< Current size of the queue, in bytes.
	char *buffer;		///< Buffer containing the packets to be sent.
};

typedef struct pcap_send_queue pcap_send_queue;

#define		BPF_MEM_EX_IMM	0xc0
#define		BPF_MEM_EX_IND	0xe0

/*used for ST*/
#define		BPF_MEM_EX		0xc0
#define		BPF_TME					0x08

#define		BPF_LOOKUP				0x90   
#define		BPF_EXECUTE				0xa0
#define		BPF_INIT				0xb0
#define		BPF_VALIDATE			0xc0
#define		BPF_SET_ACTIVE			0xd0
#define		BPF_RESET				0xe0
#define		BPF_SET_MEMORY			0x80
#define		BPF_GET_REGISTER_VALUE	0x70
#define		BPF_SET_REGISTER_VALUE	0x60
#define		BPF_SET_WORKING			0x50
#define		BPF_SET_ACTIVE_READ		0x40
#define		BPF_SET_AUTODELETION	0x30
#define		BPF_SEPARATION			0xff

/* Prototypes */
pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);

void pcap_sendqueue_destroy(pcap_send_queue* queue);

int pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);

HANDLE pcap_getevent(pcap_t *p);

struct pcap_stat *pcap_stats_ex(pcap_t *p, int *pcap_stat_size);

int pcap_setuserbuffer(pcap_t *p, int size);

int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);

int pcap_live_dump_ended(pcap_t *p, int sync);

int pcap_offline_filter(struct bpf_program *prog, const struct pcap_pkthdr *header, const u_char *pkt_data);
