/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 2003  -	The tcpdump group.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header$ (LBL)
 */

/*
 * This file is never used in libpcap or tcpdump. It is provided as
 * documentation linktypes 139 through 142 only.
 */

/*
 * Date: Tue, 09 Sep 2003 09:41:04 -0400
 * From: Jeff Morriss <jeff.morriss[AT]ulticom.com>
 * To: tcpdump-workers@tcpdump.org
 * Subject: [tcpdump-workers] request for LINKTYPE_
 *
 * We've had some discussion over on ethereal-dev about a "fake link" or
 * "raw SS7" dissector that allows dumping an arbitrary protocol into a
 * file without any (otherwise necessary) lower level protocols.  The
 * common example has been dumping MTP3 into a file without, well, MTP2 or
 * M2PA.
 *
 * We want to store these protocols directly in PCAP file format because
 * it's well defined and there isn't another (popular) file format for
 * capturing SS7 messages that we can reverse engineer (and we want to read
 * these files into Ethereal).  Rather than creating a new file format, it's
 * a lot easier to just allocate a LINKTYPE_.
 *
 * Here is the original post thread:
 *
 * http://ethereal.com/lists/ethereal-dev/200306/threads.html#00200
 *
 * July's thread on the subject:
 * 
 * http://ethereal.com/lists/ethereal-dev/200307/threads.html#00124
 *
 * August's thread:
 *
 * http://ethereal.com/lists/ethereal-dev/200308/threads.html#00193
 *
 *
 * and one of the last messages--which is why I'm mailing you today:
 * 
 * http://ethereal.com/lists/ethereal-dev/200308/msg00193.html
 *
 *
 * Based on the message in the last URL, I'd like to request a new
 * LINKTYPE_:  LINKTYPE_RAWSS7.
 *
 * This packets in this file type will contain a header:
 */

typedef struct _rawss7_hdr {
         /* NOTE: These are in network-byte order. */
         guint32 type;
         guint16 length;
	 guint16 spare;
} rawss7_hdr;

/*
 *
 * followed by protocol data for whatever protocol 'type' indicates.
 *
 * There was some discussion about these protocol 'type's being allocated by
 * tcpdump-workers as well.  In fact it would be handy to have one place to
 * allocate such numbers, so what do you think about allocating 3 more (for
 * now) LINKTYPE_'s:
 */

#define LINKTYPE_RAWSS7_MTP2	140
#define LINKTYPE_RAWSS7_MTP3	141
#define LINKTYPE_RAWSS7_SCCP	142

/*
 *
 *  There is no reason this can't be used to store non-SS7 protocols, but
 *  it's what we need to use it for now...
 *
 */
