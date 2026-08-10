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
 * pcap-usb-linux-common.h - common code for everything that needs to
 * deal with Linux USB captures, whether live or in a capture file;
 * the later means that this is *not* Linux-only.
 */

#include <limits.h>

/*
 * Return the sum of the two u_int arguments if that sum fits in a u_int,
 * and return UINT_MAX otherwise.
 */
static inline u_int
u_int_sum(u_int a, u_int b)
{
	return (((b) <= UINT_MAX - (a)) ? (a) + (b) : UINT_MAX);
}

/*
 * Is this a completion event for an isochronous transfer?
 */
static inline int
is_isochronous_transfer_completion(const pcap_usb_header_mmapped *hdr)
{
	return (hdr->transfer_type == URB_ISOCHRONOUS &&
	    hdr->event_type == URB_COMPLETE &&
	    (hdr->endpoint_number & URB_TRANSFER_IN));
}

/*
 * Total length of the pseudo-header, including the isochronous
 * descriptors.
 */
static inline uint32_t
iso_pseudo_header_len(const pcap_usb_header_mmapped *usb_hdr)
{
	return (sizeof(pcap_usb_header_mmapped) +
	    usb_hdr->ndesc * sizeof (usb_isodesc));
}

/*
 * Calculate the packet length for a "this is complete" incoming
 * isochronous transfer event.
 *
 * Calculating that from hdr->urb_len is not correct, because the
 * data is not contiguous, and the isochroous descriptors show how
 * it's scattered.
 */
static inline u_int
incoming_isochronous_transfer_completed_len(struct pcap_pkthdr *phdr,
    const u_char *bp)
{
	const pcap_usb_header_mmapped *hdr;
	u_int bytes_left;
	const usb_isodesc *descs;
	u_int pre_truncation_data_len;

	/*
	 * All callers of this routine must ensure that pkth->caplen is
	 * >= sizeof (pcap_usb_header_mmapped).
	 */
	bytes_left = phdr->caplen;
	bytes_left -= sizeof (pcap_usb_header_mmapped);

	hdr = (const pcap_usb_header_mmapped *) bp;
	descs = (const usb_isodesc *) (bp + sizeof(pcap_usb_header_mmapped));

	/*
	 * Find the end of the last chunk of data in the buffer
	 * referred to by the isochronous descriptors; that indicates
	 * how far into the buffer the data would have gone.
	 *
	 * Make sure we don't run past the end of the captured data
	 * while processing the isochronous descriptors.
	 */
	pre_truncation_data_len = 0;
	for (uint32_t desc = 0;
	    desc < hdr->ndesc && bytes_left >= sizeof (usb_isodesc);
	    desc++, bytes_left -= sizeof (usb_isodesc)) {
		u_int desc_end;

		if (descs[desc].len != 0) {
			/*
			 * Compute the end offset of the data
			 * for this descriptor, i.e. the offset
			 * of the byte after the data.  Clamp
			 * the sum at UINT_MAX, so that it fits
			 * in a u_int.
			 */
			desc_end = u_int_sum(descs[desc].offset,
			    descs[desc].len);
			if (desc_end > pre_truncation_data_len)
				pre_truncation_data_len = desc_end;
		}
	}

	/*
	 * Return the sum of the total header length (memory-mapped
	 * header and ISO descriptors) and the data length, clamped
	 * to UINT_MAX.
	 *
	 * We've made sure that the number of descriptors is
	 * <= USB_MAXDESC, so we know that the total size,
	 * in bytes, of the descriptors fits in a 32-bit
	 * integer.
	 */
	return (u_int_sum(iso_pseudo_header_len(hdr), pre_truncation_data_len));
}
