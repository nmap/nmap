/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * pcap-util.c - common code for various files
 */

#include <config.h>

#include <pcap-types.h>

#include "pcap/can_socketcan.h"
#include "pcap/sll.h"
#include "pcap/usb.h"
#include "pcap/nflog.h"

#include "pcap-int.h"
#include "extract.h"
#include "pcap-usb-linux-common.h"

#include "pcap-util.h"
#include "pflog.h"

/*
 * Most versions of the DLT_PFLOG pseudo-header have UID and PID fields
 * that are saved in host byte order.
 *
 * When reading a DLT_PFLOG packet, we need to convert those fields from
 * the byte order of the host that wrote the file to this host's byte
 * order.
 */
static void
swap_pflog_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;
	u_int pfloghdr_length;
	struct pfloghdr *pflhdr = (struct pfloghdr *)buf;

	if (caplen < (u_int) (offsetof(struct pfloghdr, uid) + sizeof pflhdr->uid) ||
	    length < (u_int) (offsetof(struct pfloghdr, uid) + sizeof pflhdr->uid)) {
		/* Not enough data to have the uid field */
		return;
	}

	pfloghdr_length = pflhdr->length;

	if (pfloghdr_length < (u_int) (offsetof(struct pfloghdr, uid) + sizeof pflhdr->uid)) {
		/* Header doesn't include uid field */
		return;
	}
	pflhdr->uid = SWAPLONG(pflhdr->uid);

	if (caplen < (u_int) (offsetof(struct pfloghdr, pid) + sizeof pflhdr->pid) ||
	    length < (u_int) (offsetof(struct pfloghdr, pid) + sizeof pflhdr->pid)) {
		/* Not enough data to have the pid field */
		return;
	}
	if (pfloghdr_length < (u_int) (offsetof(struct pfloghdr, pid) + sizeof pflhdr->pid)) {
		/* Header doesn't include pid field */
		return;
	}
	pflhdr->pid = SWAPLONG(pflhdr->pid);

	if (caplen < (u_int) (offsetof(struct pfloghdr, rule_uid) + sizeof pflhdr->rule_uid) ||
	    length < (u_int) (offsetof(struct pfloghdr, rule_uid) + sizeof pflhdr->rule_uid)) {
		/* Not enough data to have the rule_uid field */
		return;
	}
	if (pfloghdr_length < (u_int) (offsetof(struct pfloghdr, rule_uid) + sizeof pflhdr->rule_uid)) {
		/* Header doesn't include rule_uid field */
		return;
	}
	pflhdr->rule_uid = SWAPLONG(pflhdr->rule_uid);

	if (caplen < (u_int) (offsetof(struct pfloghdr, rule_pid) + sizeof pflhdr->rule_pid) ||
	    length < (u_int) (offsetof(struct pfloghdr, rule_pid) + sizeof pflhdr->rule_pid)) {
		/* Not enough data to have the rule_pid field */
		return;
	}
	if (pfloghdr_length < (u_int) (offsetof(struct pfloghdr, rule_pid) + sizeof pflhdr->rule_pid)) {
		/* Header doesn't include rule_pid field */
		return;
	}
	pflhdr->rule_pid = SWAPLONG(pflhdr->rule_pid);
}

/*
 * Linux cooked capture packets with a protocol type of LINUX_SLL_P_CAN or
 * LINUX_SLL_P_CANFD have SocketCAN CAN classic/CAN FD headers in front
 * of the payload,with the CAN ID being in the byte order of the host
 * that wrote the packet, and Linux cooked capture packets with a protocol
 * type of LINUX_SLL_P_CANXL have SocketCAN CAN XL headers in front of the
 * payload with the protocol/VCID field, the payload length, and the
 * acceptance field in the byte order of the host that wrote the packet.
 *
 * When reading a Linux cooked capture packet, we need to check for those
 * packets and, if the byte order host that wrote the packet, as
 * indicated by the byte order of the pcap file or pcapng section
 * containing the packet, is the opposite of our byte order, convert
 * the header files to our byte order by byte-swapping them.
 */
static void
swap_socketcan_header(uint16_t protocol, u_int caplen, u_int length,
    u_char *buf)
{
	pcap_can_socketcan_hdr *hdrp;
	pcap_can_socketcan_xl_hdr *xl_hdrp;

	switch (protocol) {

	case LINUX_SLL_P_CAN:
	case LINUX_SLL_P_CANFD:
		/*
		 * CAN classic/CAN FD packet; fix up the packet's header
		 * by byte-swapping the CAN ID field.
		 */
		hdrp = (pcap_can_socketcan_hdr *)buf;
		if (caplen < (u_int) (offsetof(pcap_can_socketcan_hdr, can_id) + sizeof hdrp->can_id) ||
		    length < (u_int) (offsetof(pcap_can_socketcan_hdr, can_id) + sizeof hdrp->can_id)) {
			/* Not enough data to have the can_id field */
			return;
		}
		hdrp->can_id = SWAPLONG(hdrp->can_id);
		break;

	case LINUX_SLL_P_CANXL:
		/*
		 * CAN XL packet; fix up the packet's header by
		 * byte-swapping the priority/VCID field, the
		 * payload length, and the acceptance field.
		 */
		xl_hdrp = (pcap_can_socketcan_xl_hdr *)buf;
		if (caplen < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, priority_vcid) + sizeof xl_hdrp->priority_vcid) ||
		    length < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, priority_vcid) + sizeof xl_hdrp->priority_vcid)) {
			/* Not enough data to have the priority_vcid field */
			return;
		}
		xl_hdrp->priority_vcid = SWAPLONG(xl_hdrp->priority_vcid);
		if (caplen < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, payload_length) + sizeof xl_hdrp->payload_length) ||
		    length < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, payload_length) + sizeof xl_hdrp->payload_length)) {
			/* Not enough data to have the payload_length field */
			return;
		}
		xl_hdrp->payload_length = SWAPSHORT(xl_hdrp->payload_length);
		if (caplen < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, acceptance_field) + sizeof xl_hdrp->acceptance_field) ||
		    length < (u_int) (offsetof(pcap_can_socketcan_xl_hdr, acceptance_field) + sizeof xl_hdrp->acceptance_field)) {
			/* Not enough data to have the acceptance_field field */
			return;
		}
		xl_hdrp->acceptance_field = SWAPLONG(xl_hdrp->acceptance_field);
		break;

	default:
		/*
		 * Not a CAN packet; nothing to do.
		 */
		break;
	}
}

/*
 * DLT_LINUX_SLL packets with a protocol type of LINUX_SLL_P_CAN or
 * LINUX_SLL_P_CANFD have SocketCAN headers in front of the payload,
 * with the CAN ID being in host byte order.
 *
 * When reading a DLT_LINUX_SLL packet, we need to check for those
 * packets and convert the CAN ID from the byte order of the host that
 * wrote the file to this host's byte order.
 */
static void
swap_linux_sll_socketcan_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;
	struct sll_header *shdr = (struct sll_header *)buf;

	if (caplen < (u_int) sizeof(struct sll_header) ||
	    length < (u_int) sizeof(struct sll_header)) {
		/* Not enough data to have the protocol field */
		return;
	}

	/*
	 * Byte-swap what needs to be byte-swapped.
	 */
	swap_socketcan_header(EXTRACT_BE_U_2(&shdr->sll_protocol),
	    caplen - (u_int) sizeof(struct sll_header),
	    length - (u_int) sizeof(struct sll_header),
	    buf + sizeof(struct sll_header));
}

/*
 * The same applies for DLT_LINUX_SLL2.
 */
static void
swap_linux_sll2_socketcan_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;
	struct sll2_header *shdr = (struct sll2_header *)buf;

	if (caplen < (u_int) sizeof(struct sll2_header) ||
	    length < (u_int) sizeof(struct sll2_header)) {
		/* Not enough data to have the protocol field */
		return;
	}

	/*
	 * Byte-swap what needs to be byte-swapped.
	 */
	swap_socketcan_header(EXTRACT_BE_U_2(&shdr->sll2_protocol),
	    caplen - (u_int) sizeof(struct sll2_header),
	    length - (u_int) sizeof(struct sll2_header),
	    buf + sizeof(struct sll2_header));
}

/*
 * The DLT_USB_LINUX and DLT_USB_LINUX_MMAPPED headers are in host
 * byte order when capturing (it's supplied directly from a
 * memory-mapped buffer shared by the kernel).
 *
 * When reading a DLT_USB_LINUX or DLT_USB_LINUX_MMAPPED packet, we
 * need to convert it from the byte order of the host that wrote the
 * file to this host's byte order.
 */
static void
swap_linux_usb_header(const struct pcap_pkthdr *hdr, u_char *buf,
    int header_len_64_bytes)
{
	pcap_usb_header_mmapped *uhdr = (pcap_usb_header_mmapped *)buf;
	bpf_u_int32 offset = 0;

	/*
	 * "offset" is the offset *past* the field we're swapping;
	 * we skip the field *before* checking to make sure
	 * the captured data length includes the entire field.
	 */

	/*
	 * The URB id is a totally opaque value; do we really need to
	 * convert it to the reading host's byte order???
	 */
	offset += 8;			/* skip past id */
	if (hdr->caplen < offset)
		return;
	uhdr->id = SWAPLL(uhdr->id);

	offset += 4;			/* skip past various 1-byte fields */

	offset += 2;			/* skip past bus_id */
	if (hdr->caplen < offset)
		return;
	uhdr->bus_id = SWAPSHORT(uhdr->bus_id);

	offset += 2;			/* skip past various 1-byte fields */

	offset += 8;			/* skip past ts_sec */
	if (hdr->caplen < offset)
		return;
	uhdr->ts_sec = SWAPLL(uhdr->ts_sec);

	offset += 4;			/* skip past ts_usec */
	if (hdr->caplen < offset)
		return;
	uhdr->ts_usec = SWAPLONG(uhdr->ts_usec);

	offset += 4;			/* skip past status */
	if (hdr->caplen < offset)
		return;
	uhdr->status = SWAPLONG(uhdr->status);

	offset += 4;			/* skip past urb_len */
	if (hdr->caplen < offset)
		return;
	uhdr->urb_len = SWAPLONG(uhdr->urb_len);

	offset += 4;			/* skip past data_len */
	if (hdr->caplen < offset)
		return;
	uhdr->data_len = SWAPLONG(uhdr->data_len);

	if (uhdr->transfer_type == URB_ISOCHRONOUS) {
		offset += 4;			/* skip past s.iso.error_count */
		if (hdr->caplen < offset)
			return;
		uhdr->s.iso.error_count = SWAPLONG(uhdr->s.iso.error_count);

		offset += 4;			/* skip past s.iso.numdesc */
		if (hdr->caplen < offset)
			return;
		uhdr->s.iso.numdesc = SWAPLONG(uhdr->s.iso.numdesc);
	} else
		offset += 8;			/* skip USB setup header */

	/*
	 * With the old header, there are no isochronous descriptors
	 * after the header.
	 *
	 * With the new header, the actual number of descriptors in
	 * the header is not s.iso.numdesc, it's ndesc - only the
	 * first N descriptors, for some value of N, are put into
	 * the header, and ndesc is set to the actual number copied.
	 * In addition, if s.iso.numdesc is negative, no descriptors
	 * are captured, and ndesc is set to 0.
	 */
	if (header_len_64_bytes) {
		/*
		 * This is either the "version 1" header, with
		 * 16 bytes of additional fields at the end, or
		 * a "version 0" header from a memory-mapped
		 * capture, with 16 bytes of zeroed-out padding
		 * at the end.  Byte swap them as if this were
		 * a "version 1" header.
		 */
		offset += 4;			/* skip past interval */
		if (hdr->caplen < offset)
			return;
		uhdr->interval = SWAPLONG(uhdr->interval);

		offset += 4;			/* skip past start_frame */
		if (hdr->caplen < offset)
			return;
		uhdr->start_frame = SWAPLONG(uhdr->start_frame);

		offset += 4;			/* skip past xfer_flags */
		if (hdr->caplen < offset)
			return;
		uhdr->xfer_flags = SWAPLONG(uhdr->xfer_flags);

		offset += 4;			/* skip past ndesc */
		if (hdr->caplen < offset)
			return;
		uhdr->ndesc = SWAPLONG(uhdr->ndesc);

		if (uhdr->transfer_type == URB_ISOCHRONOUS) {
			/* swap the values in struct linux_usb_isodesc */
			usb_isodesc *pisodesc;
			uint32_t i;

			pisodesc = (usb_isodesc *)(void *)(buf+offset);
			for (i = 0; i < uhdr->ndesc; i++) {
				offset += 4;		/* skip past status */
				if (hdr->caplen < offset)
					return;
				pisodesc->status = SWAPLONG(pisodesc->status);

				offset += 4;		/* skip past offset */
				if (hdr->caplen < offset)
					return;
				pisodesc->offset = SWAPLONG(pisodesc->offset);

				offset += 4;		/* skip past len */
				if (hdr->caplen < offset)
					return;
				pisodesc->len = SWAPLONG(pisodesc->len);

				offset += 4;		/* skip past padding */

				pisodesc++;
			}
		}
	}
}

/*
 * The DLT_NFLOG "packets" have a mixture of big-endian and host-byte-order
 * data.  They begin with a fixed-length header with big-endian fields,
 * followed by a set of TLVs, where the type and length are in host
 * byte order but the values are either big-endian or are a raw byte
 * sequence that's the same regardless of the host's byte order.
 *
 * When reading a DLT_NFLOG packet, we need to convert the type and
 * length values from the byte order of the host that wrote the file
 * to the byte order of this host.
 */
static void
swap_nflog_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_char *p = buf;
	nflog_hdr_t *nfhdr = (nflog_hdr_t *)buf;
	nflog_tlv_t *tlv;
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;
	u_int size;

	if (caplen < (u_int) sizeof(nflog_hdr_t) ||
	    length < (u_int) sizeof(nflog_hdr_t)) {
		/* Not enough data to have any TLVs. */
		return;
	}

	if (nfhdr->nflog_version != 0) {
		/* Unknown NFLOG version */
		return;
	}

	length -= sizeof(nflog_hdr_t);
	caplen -= sizeof(nflog_hdr_t);
	p += sizeof(nflog_hdr_t);

	while (caplen >= sizeof(nflog_tlv_t)) {
		tlv = (nflog_tlv_t *) p;

		/* Swap the type and length. */
		tlv->tlv_type = SWAPSHORT(tlv->tlv_type);
		tlv->tlv_length = SWAPSHORT(tlv->tlv_length);

		/* Get the length of the TLV. */
		size = tlv->tlv_length;
		if (size % 4 != 0)
			size += 4 - size % 4;

		/* Is the TLV's length less than the minimum? */
		if (size < sizeof(nflog_tlv_t)) {
			/* Yes. Give up now. */
			return;
		}

		/* Do we have enough data for the full TLV? */
		if (caplen < size || length < size) {
			/* No. */
			return;
		}

		/* Skip over the TLV. */
		length -= size;
		caplen -= size;
		p += size;
	}
}

static void
swap_pseudo_headers(int linktype, struct pcap_pkthdr *hdr, u_char *data)
{
	/*
	 * Convert pseudo-headers from the byte order of
	 * the host on which the file was saved to our
	 * byte order, as necessary.
	 */
	switch (linktype) {

	case DLT_PFLOG:
		swap_pflog_header(hdr, data);
		break;

	case DLT_LINUX_SLL:
		swap_linux_sll_socketcan_header(hdr, data);
		break;

	case DLT_LINUX_SLL2:
		swap_linux_sll2_socketcan_header(hdr, data);
		break;

	case DLT_USB_LINUX:
		swap_linux_usb_header(hdr, data, 0);
		break;

	case DLT_USB_LINUX_MMAPPED:
		swap_linux_usb_header(hdr, data, 1);
		break;

	case DLT_NFLOG:
		swap_nflog_header(hdr, data);
		break;
	}
}

static inline int
packet_length_might_be_wrong(struct pcap_pkthdr *hdr,
    const pcap_usb_header_mmapped *usb_hdr)
{
	uint32_t old_style_packet_length;

	/*
	 * Calculate the packet length the old way.
	 * We know that the multiplication won't overflow, but
	 * we don't know that the additions won't.  Calculate
	 * it with no overflow checks, as that's how it
	 * would have been calculated when it was captured.
	 */
	old_style_packet_length = iso_pseudo_header_len(usb_hdr) +
	    usb_hdr->urb_len;
	return (hdr->len == old_style_packet_length);
}

void
pcapint_post_process(int linktype, int swapped, struct pcap_pkthdr *hdr,
    u_char *data)
{
	if (swapped)
		swap_pseudo_headers(linktype, hdr, data);

	/*
	 * Is this a memory-mapped Linux USB capture?
	 */
	if (linktype == DLT_USB_LINUX_MMAPPED) {
		/*
		 * Yes.
		 *
		 * In older versions of libpcap, in memory-mapped Linux
		 * USB captures, the original length of completion events
		 * for incoming isochronous transfers was miscalculated;
		 * it needed to be calculated based on the offsets and
		 * lengths in the descriptors, not on the raw URB length,
		 * but it wasn't.
		 *
		 * If this packet contains transferred data (yes, data_flag
		 * is 0 if we *do* have data), it's a completion event
		 * for an incoming isochronous transfer, and the
		 * transfer length appears to have been calculated
		 * from the raw URB length, fix it.
		 *
		 * We only do this if we have the full USB pseudo-header,
		 * because we will have to look at that header and at
		 * all of the isochronous descriptors.
		 */
		if (hdr->caplen < sizeof (pcap_usb_header_mmapped)) {
			/*
			 * We don't have the full pseudo-header.
			 */
			return;
		}

		const pcap_usb_header_mmapped *usb_hdr =
		    (const pcap_usb_header_mmapped *) data;

		/*
		 * Make sure the number of descriptors is sane.
		 *
		 * The Linux binary USB monitor code limits the number of
		 * isochronous descriptors to 128; if the number in the file
		 * is larger than that, either 1) the file's been damaged
		 * or 2) the file was produced after the number was raised
		 * in the kernel.
		 *
		 * In case 1), the number can't be trusted, so don't rely on
		 * it to attempt to fix the original length field in the pcap
		 * or pcapng header.
		 *
		 * In case 2), the system was probably running a version of
		 * libpcap that didn't miscalculate the original length, so
		 * it probably doesn't need to be fixed.
		 *
		 * This avoids the possibility of the product of the number of
		 * descriptors and the size of descriptors won't overflow an
		 * unsigned 32-bit integer.
		 */
		if (usb_hdr->ndesc > USB_MAXDESC)
			return;

		if (!usb_hdr->data_flag &&
		    is_isochronous_transfer_completion(usb_hdr) &&
		    packet_length_might_be_wrong(hdr, usb_hdr)) {
			u_int len;

			/*
			 * Make sure we have all of the descriptors,
			 * as we will have to look at all of them.
			 *
			 * If not, we don't bother trying to fix
			 * anything.
			 */
			if (hdr->caplen < iso_pseudo_header_len(usb_hdr))
				return;

			/*
			 * Calculate what the length should have been.
			 */
			len = incoming_isochronous_transfer_completed_len(hdr,
			    data);

			/*
			 * len is the smaller of UINT_MAX and the total
			 * header plus data length.  That's guaranteed
			 * to fit in a UINT_MAX.
			 *
			 * Don't reduce the original length to a value
			 * below the captured length, however, as that
			 * is bogus.
			 */
			if (len >= hdr->caplen)
				hdr->len = len;

			/*
			 * If the captured length is greater than the
			 * length, use the captured length.
			 *
			 * For completion events for incoming isochronous
			 * transfers, it's based on data_len, which is
			 * calculated the same way we calculated
			 * pre_truncation_data_len above, except that
			 * it has access to all the isochronous descriptors,
			 * not just the ones that the kernel were able to
			 * provide us or, for a capture file, that weren't
			 * sliced off by a snapshot length.
			 *
			 * However, it might have been reduced by the USB
			 * capture mechanism arbitrarily limiting the amount
			 * of data it provides to userland, or by the libpcap
			 * capture code limiting it to being no more than the
			 * snapshot, so we don't want to just use it all the
			 * time; we only do so to try to get a better estimate
			 * of the actual length - and to make sure the
			 * original length is always >= the captured length.
			 */
			if (hdr->caplen > hdr->len)
				hdr->len = hdr->caplen;
		}
	}
}
