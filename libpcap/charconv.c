/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
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
 */

#ifdef _WIN32
#include <stdio.h>

#include <pcap/pcap.h>	/* Needed for PCAP_ERRBUF_SIZE */

#include "charconv.h"

wchar_t *
cp_to_utf_16le(UINT codepage, const char *cp_string, DWORD flags)
{
	int utf16le_len;
	wchar_t *utf16le_string;

	/*
	 * Map from the specified code page to UTF-16LE.
	 * First, find out how big a buffer we'll need.
	 */
	utf16le_len = MultiByteToWideChar(codepage, flags, cp_string, -1,
	    NULL, 0);
	if (utf16le_len == 0) {
		/*
		 * Error.  Fail with EINVAL.
		 */
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Now attempt to allocate a buffer for that.
	 */
	utf16le_string = malloc(utf16le_len * sizeof (wchar_t));
	if (utf16le_string == NULL) {
		/*
		 * Not enough memory; assume errno has been
		 * set, and fail.
		 */
		return (NULL);
	}

	/*
	 * Now convert.
	 */
	utf16le_len = MultiByteToWideChar(codepage, flags, cp_string, -1,
	    utf16le_string, utf16le_len);
	if (utf16le_len == 0) {
		/*
		 * Error.  Fail with EINVAL.
		 * XXX - should this ever happen, given that
		 * we already ran the string through
		 * MultiByteToWideChar() to find out how big
		 * a buffer we needed?
		 */
		free(utf16le_string);
		errno = EINVAL;
		return (NULL);
	}
	return (utf16le_string);
}

char *
utf_16le_to_cp(UINT codepage, const wchar_t *utf16le_string)
{
	int cp_len;
	char *cp_string;

	/*
	 * Map from UTF-16LE to the specified code page.
	 * First, find out how big a buffer we'll need.
	 * We convert composite characters to precomposed characters,
	 * as that's what Windows expects.
	 */
	cp_len = WideCharToMultiByte(codepage, WC_COMPOSITECHECK,
	    utf16le_string, -1, NULL, 0, NULL, NULL);
	if (cp_len == 0) {
		/*
		 * Error.  Fail with EINVAL.
		 */
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Now attempt to allocate a buffer for that.
	 */
	cp_string = malloc(cp_len * sizeof (char));
	if (cp_string == NULL) {
		/*
		 * Not enough memory; assume errno has been
		 * set, and fail.
		 */
		return (NULL);
	}

	/*
	 * Now convert.
	 */
	cp_len = WideCharToMultiByte(codepage, WC_COMPOSITECHECK,
	    utf16le_string, -1, cp_string, cp_len, NULL, NULL);
	if (cp_len == 0) {
		/*
		 * Error.  Fail with EINVAL.
		 * XXX - should this ever happen, given that
		 * we already ran the string through
		 * WideCharToMultiByte() to find out how big
		 * a buffer we needed?
		 */
		free(cp_string);
		errno = EINVAL;
		return (NULL);
	}
	return (cp_string);
}

/*
 * Convert an error message string from UTF-8 to the local code page, as
 * best we can.
 *
 * The buffer is assumed to be PCAP_ERRBUF_SIZE bytes long; we truncate
 * if it doesn't fit.
 */
void
utf_8_to_acp_truncated(char *errbuf)
{
	wchar_t *utf_16_errbuf;
	int retval;
	DWORD err;

	/*
	 * Do this by converting to UTF-16LE and then to the local
	 * code page.  That means we get to use Microsoft's
	 * conversion routines, rather than having to understand
	 * all the code pages ourselves, *and* that this routine
	 * can convert in place.
	 */

	/*
	 * Map from UTF-8 to UTF-16LE.
	 * First, find out how big a buffer we'll need.
	 * Convert any invalid characters to REPLACEMENT CHARACTER.
	 */
	utf_16_errbuf = cp_to_utf_16le(CP_UTF8, errbuf, 0);
	if (utf_16_errbuf == NULL) {
		/*
		 * Error.  Give up.
		 */
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "Can't convert error string to the local code page");
		return;
	}

	/*
	 * Now, convert that to the local code page.
	 * Use the current thread's code page.  For unconvertable
	 * characters, let it pick the "best fit" character.
	 *
	 * XXX - we'd like some way to do what utf_16le_to_utf_8_truncated()
	 * does if the buffer isn't big enough, but we don't want to have
	 * to handle all local code pages ourselves; doing so requires
	 * knowledge of all those code pages, including knowledge of how
	 * characters are formed in thoe code pages so that we can avoid
	 * cutting a multi-byte character into pieces.
	 *
	 * Converting to an un-truncated string using Windows APIs, and
	 * then copying to the buffer, still requires knowledge of how
	 * characters are formed in the target code page.
	 */
	retval = WideCharToMultiByte(CP_THREAD_ACP, 0, utf_16_errbuf, -1,
	    errbuf, PCAP_ERRBUF_SIZE, NULL, NULL);
	if (retval == 0) {
		err = GetLastError();
		free(utf_16_errbuf);
		if (err == ERROR_INSUFFICIENT_BUFFER)
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "The error string, in the local code page, didn't fit in the buffer");
		else
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "Can't convert error string to the local code page");
		return;
	}
	free(utf_16_errbuf);
}
#endif
