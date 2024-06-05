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
 * pcap-usb-linux-common.c - common code for everything that needs to
 * deal with Linux USB captures.
 */

#include "pcap/pcap.h"
#include "pcap/usb.h"

#include "pcap-usb-linux-common.h"

/*
 * Compute, from the data provided by the Linux USB memory-mapped capture
 * mechanism, the amount of packet data that would have been provided
 * had the capture mechanism not chopped off any data at the end, if, in
 * fact, it did so.
 *
 * Set the "unsliced length" field of the packet header to that value.
 */
void
fix_linux_usb_mmapped_length(struct pcap_pkthdr *pkth, const u_char *bp)
{
	const pcap_usb_header_mmapped *hdr;
	u_int bytes_left;

	/*
	 * All callers of this routine must ensure that pkth->caplen is
	 * >= sizeof (pcap_usb_header_mmapped).
	 */
	bytes_left = pkth->caplen;
	bytes_left -= sizeof (pcap_usb_header_mmapped);

	hdr = (const pcap_usb_header_mmapped *) bp;
	if (!hdr->data_flag && hdr->transfer_type == URB_ISOCHRONOUS &&
	    hdr->event_type == URB_COMPLETE &&
	    (hdr->endpoint_number & URB_TRANSFER_IN) &&
	    pkth->len == sizeof(pcap_usb_header_mmapped) +
	                 (hdr->ndesc * sizeof (usb_isodesc)) + hdr->urb_len) {
		usb_isodesc *descs;
		u_int pre_truncation_data_len, pre_truncation_len;

		descs = (usb_isodesc *) (bp + sizeof(pcap_usb_header_mmapped));

		/*
		 * We have data (yes, data_flag is 0 if we *do* have data),
		 * and this is a "this is complete" incoming isochronous
		 * transfer event, and the length was calculated based
		 * on the URB length.
		 *
		 * That's not correct, because the data isn't contiguous,
		 * and the isochronous descriptos show how it's scattered.
		 *
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
				desc_end = descs[desc].offset + descs[desc].len;
				if (desc_end > pre_truncation_data_len)
					pre_truncation_data_len = desc_end;
			}
		}

		/*
		 * Now calculate the total length based on that data
		 * length.
		 */
		pre_truncation_len = sizeof(pcap_usb_header_mmapped) +
		    (hdr->ndesc * sizeof (usb_isodesc)) +
		    pre_truncation_data_len;

		/*
		 * If that's greater than or equal to the captured length,
		 * use that as the length.
		 */
		if (pre_truncation_len >= pkth->caplen)
			pkth->len = pre_truncation_len;

		/*
		 * If the captured length is greater than the length,
		 * use the captured length.
		 *
		 * For completion events for incoming isochronous transfers,
		 * it's based on data_len, which is calculated the same way
		 * we calculated pre_truncation_data_len above, except that
		 * it has access to all the isochronous descriptors, not
		 * just the ones that the kernel were able to provide us or,
		 * for a capture file, that weren't sliced off by a snapshot
		 * length.
		 *
		 * However, it might have been reduced by the USB capture
		 * mechanism arbitrarily limiting the amount of data it
		 * provides to userland, or by the libpcap capture code
		 * limiting it to being no more than the snapshot, so
		 * we don't want to just use it all the time; we only
		 * do so to try to get a better estimate of the actual
		 * length - and to make sure the on-the-network length
		 * is always >= the captured length.
		 */
		if (pkth->caplen > pkth->len)
			pkth->len = pkth->caplen;
	}
}
