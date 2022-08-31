/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998
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

/*
 * Utilities for message formatting used both by libpcap and rpcapd.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ftmacros.h"

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "pcap-int.h"

#include "portability.h"

#include "fmtutils.h"

#ifdef _WIN32
#include "charconv.h"
#endif

/*
 * Set the encoding.
 */
#ifdef _WIN32
/*
 * True if we shouold use UTF-8.
 */
static int use_utf_8;

void
pcap_fmt_set_encoding(unsigned int opts)
{
	if (opts == PCAP_CHAR_ENC_UTF_8)
		use_utf_8 = 1;
}
#else
void
pcap_fmt_set_encoding(unsigned int opts _U_)
{
	/*
	 * Nothing to do here.
	 */
}
#endif

#ifdef _WIN32
/*
 * Convert a null-terminated UTF-16LE string to UTF-8, putting it into
 * a buffer starting at the specified location and stopping if we go
 * past the specified size.  This will only put out complete UTF-8
 * sequences.
 *
 * We do this ourselves because Microsoft doesn't offer a "convert and
 * stop at a UTF-8 character boundary if we run out of space" routine.
 */
#define IS_LEADING_SURROGATE(c) \
	((c) >= 0xd800 && (c) < 0xdc00)
#define IS_TRAILING_SURROGATE(c) \
	((c) >= 0xdc00 && (c) < 0xe000)
#define SURROGATE_VALUE(leading, trailing) \
	(((((leading) - 0xd800) << 10) | ((trailing) - 0xdc00)) + 0x10000)
#define REPLACEMENT_CHARACTER	0x0FFFD

static char *
utf_16le_to_utf_8_truncated(const wchar_t *utf_16, char *utf_8,
    size_t utf_8_len)
{
	wchar_t c, c2;
	uint32_t uc;

	if (utf_8_len == 0) {
		/*
		 * Not even enough room for a trailing '\0'.
		 * Don't put anything into the buffer.
		 */
		return (utf_8);
	}

	while ((c = *utf_16++) != '\0') {
		if (IS_LEADING_SURROGATE(c)) {
			/*
			 * Leading surrogate.  Must be followed by
			 * a trailing surrogate.
			 */
			c2 = *utf_16;
			if (c2 == '\0') {
				/*
				 * Oops, string ends with a lead
				 * surrogate.  Try to drop in
				 * a REPLACEMENT CHARACTER, and
				 * don't move the string pointer,
				 * so on the next trip through
				 * the loop we grab the terminating
				 * '\0' and quit.
				 */
				uc = REPLACEMENT_CHARACTER;
			} else {
				/*
				 * OK, we can consume this 2-octet
				 * value.
				 */
				utf_16++;
				if (IS_TRAILING_SURROGATE(c2)) {
					/*
					 * Trailing surrogate.
					 * This calculation will,
					 * for c being a leading
					 * surrogate and c2 being
					 * a trailing surrogate,
					 * produce a value between
					 * 0x100000 and 0x10ffff,
					 * so it's always going to be
					 * a valid Unicode code point.
					 */
					uc = SURROGATE_VALUE(c, c2);
				} else {
					/*
					 * Not a trailing surroage;
					 * try to drop in a
					 * REPLACEMENT CHARACTER.
					 */
					uc = REPLACEMENT_CHARACTER;
				}
			}
		} else {
			/*
			 * Not a leading surrogate.
			 */
			if (IS_TRAILING_SURROGATE(c)) {
				/*
				 * Trailing surrogate without
				 * a preceding leading surrogate.
				 * Try to drop in a REPLACEMENT
				 * CHARACTER.
				 */
				uc = REPLACEMENT_CHARACTER;
			} else {
				/*
				 * This is a valid BMP character;
				 * drop it in.
				 */
				uc = c;
			}
		}

		/*
		 * OK, uc is a valid Unicode character; how
		 * many bytes worth of UTF-8 does it require?
		 */
		if (uc < 0x0080) {
			/* 1 byte. */
			if (utf_8_len < 2) {
				/*
				 * Not enough room for that byte
				 * plus a trailing '\0'.
				 */
				break;
			}
			*utf_8++ = (char)uc;
			utf_8_len--;
		} else if (uc < 0x0800) {
			/* 2 bytes. */
			if (utf_8_len < 3) {
				/*
				 * Not enough room for those bytes
				 * plus a trailing '\0'.
				 */
				break;
			}
			*utf_8++ = ((uc >> 6) & 0x3F) | 0xC0;
			*utf_8++ = ((uc >> 0) & 0x3F) | 0x80;
			utf_8_len -= 2;
		} else if (uc < 0x010000) {
			/* 3 bytes. */
			if (utf_8_len < 4) {
				/*
				 * Not enough room for those bytes
				 * plus a trailing '\0'.
				 */
				break;
			}
			*utf_8++ = ((uc >> 12) & 0x0F) | 0xE0;
			*utf_8++ = ((uc >> 6) & 0x3F) | 0x80;
			*utf_8++ = ((uc >> 0) & 0x3F) | 0x80;
			utf_8_len -= 3;
		} else {
			/* 4 bytes. */
			if (utf_8_len < 5) {
				/*
				 * Not enough room for those bytes
				 * plus a trailing '\0'.
				 */
				break;
			}
			*utf_8++ = ((uc >> 18) & 0x03) | 0xF0;
			*utf_8++ = ((uc >> 12) & 0x3F) | 0x80;
			*utf_8++ = ((uc >> 6) & 0x3F) | 0x80;
			*utf_8++ = ((uc >> 0) & 0x3F) | 0x80;
			utf_8_len -= 3;
		}
	}

	/*
	 * OK, we have enough room for (at least) a trailing '\0'.
	 * (We started out with enough room, thanks to the test
	 * for a zero-length buffer at the beginning, and if
	 * there wasn't enough room for any character we wanted
	 * to put into the buffer *plus* a trailing '\0',
	 * we'd have quit before putting it into the buffer,
	 * and thus would have left enough room for the trailing
	 * '\0'.)
	 *
	 * Drop it in.
	 */
	*utf_8 = '\0';

	/*
	 * Return a pointer to the terminating '\0', in case we
	 * want to drop something in after that.
	 */
	return (utf_8);
}
#endif /* _WIN32 */

/*
 * Generate an error message based on a format, arguments, and an
 * errno, with a message for the errno after the formatted output.
 */
void
pcap_fmt_errmsg_for_errno(char *errbuf, size_t errbuflen, int errnum,
    const char *fmt, ...)
{
	va_list ap;
	size_t msglen;
	char *p;
	size_t errbuflen_remaining;

	va_start(ap, fmt);
	vsnprintf(errbuf, errbuflen, fmt, ap);
	va_end(ap);
	msglen = strlen(errbuf);

	/*
	 * Do we have enough space to append ": "?
	 * Including the terminating '\0', that's 3 bytes.
	 */
	if (msglen + 3 > errbuflen) {
		/* No - just give them what we've produced. */
		return;
	}
	p = errbuf + msglen;
	errbuflen_remaining = errbuflen - msglen;
	*p++ = ':';
	*p++ = ' ';
	*p = '\0';
	errbuflen_remaining -= 2;

	/*
	 * Now append the string for the error code.
	 */
#if defined(HAVE__WCSERROR_S)
	/*
	 * We have a Windows-style _wcserror_s().
	 * Generate a UTF-16LE error message.
	 */
	wchar_t utf_16_errbuf[PCAP_ERRBUF_SIZE];
	errno_t err = _wcserror_s(utf_16_errbuf, PCAP_ERRBUF_SIZE, errnum);
	if (err != 0) {
		/*
		 * It doesn't appear to be documented anywhere obvious
		 * what the error returns from _wcserror_s().
		 */
		snprintf(p, errbuflen_remaining, "Error %d", errnum);
		return;
	}

	/*
	 * Now convert it from UTF-16LE to UTF-8, dropping it in the
	 * remaining space in the buffer, and truncating it - cleanly,
	 * on a UTF-8 character boundary - if it doesn't fit.
	 */
	utf_16le_to_utf_8_truncated(utf_16_errbuf, p, errbuflen_remaining);

	/*
	 * Now, if we're not in UTF-8 mode, convert errbuf to the
	 * local code page.
	 */
	if (!use_utf_8)
		utf_8_to_acp_truncated(errbuf);
#elif defined(HAVE_GNU_STRERROR_R)
	/*
	 * We have a GNU-style strerror_r(), which is *not* guaranteed to
	 * do anything to the buffer handed to it, and which returns a
	 * pointer to the error string, which may or may not be in
	 * the buffer.
	 *
	 * It is, however, guaranteed to succeed.
	 */
	char strerror_buf[PCAP_ERRBUF_SIZE];
	char *errstring = strerror_r(errnum, strerror_buf, PCAP_ERRBUF_SIZE);
	snprintf(p, errbuflen_remaining, "%s", errstring);
#elif defined(HAVE_POSIX_STRERROR_R)
	/*
	 * We have a POSIX-style strerror_r(), which is guaranteed to fill
	 * in the buffer, but is not guaranteed to succeed.
	 */
	int err = strerror_r(errnum, p, errbuflen_remaining);
	if (err == EINVAL) {
		/*
		 * UNIX 03 says this isn't guaranteed to produce a
		 * fallback error message.
		 */
		snprintf(p, errbuflen_remaining, "Unknown error: %d",
		    errnum);
	} else if (err == ERANGE) {
		/*
		 * UNIX 03 says this isn't guaranteed to produce a
		 * fallback error message.
		 */
		snprintf(p, errbuflen_remaining,
		    "Message for error %d is too long", errnum);
	}
#else
	/*
	 * We have neither _wcserror_s() nor strerror_r(), so we're
	 * stuck with using pcap_strerror().
	 */
	snprintf(p, errbuflen_remaining, "%s", pcap_strerror(errnum));
#endif
}

#ifdef _WIN32
/*
 * Generate an error message based on a format, arguments, and a
 * Win32 error, with a message for the Win32 error after the formatted output.
 */
void
pcap_fmt_errmsg_for_win32_err(char *errbuf, size_t errbuflen, DWORD errnum,
    const char *fmt, ...)
{
	va_list ap;
	size_t msglen;
	char *p;
	size_t errbuflen_remaining;
	DWORD retval;
	wchar_t utf_16_errbuf[PCAP_ERRBUF_SIZE];
	size_t utf_8_len;

	va_start(ap, fmt);
	vsnprintf(errbuf, errbuflen, fmt, ap);
	va_end(ap);
	msglen = strlen(errbuf);

	/*
	 * Do we have enough space to append ": "?
	 * Including the terminating '\0', that's 3 bytes.
	 */
	if (msglen + 3 > errbuflen) {
		/* No - just give them what we've produced. */
		return;
	}
	p = errbuf + msglen;
	errbuflen_remaining = errbuflen - msglen;
	*p++ = ':';
	*p++ = ' ';
	*p = '\0';
	msglen += 2;
	errbuflen_remaining -= 2;

	/*
	 * Now append the string for the error code.
	 *
	 * XXX - what language ID to use?
	 *
	 * For UN*Xes, pcap_strerror() may or may not return localized
	 * strings.
	 *
	 * We currently don't have localized messages for libpcap, but
	 * we might want to do so.  On the other hand, if most of these
	 * messages are going to be read by libpcap developers and
	 * perhaps by developers of libpcap-based applications, English
	 * might be a better choice, so the developer doesn't have to
	 * get the message translated if it's in a language they don't
	 * happen to understand.
	 */
	retval = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_MAX_WIDTH_MASK,
	    NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	    utf_16_errbuf, PCAP_ERRBUF_SIZE, NULL);
	if (retval == 0) {
		/*
		 * Failed.
		 */
		snprintf(p, errbuflen_remaining,
		    "Couldn't get error message for error (%lu)", errnum);
		return;
	}

	/*
	 * Now convert it from UTF-16LE to UTF-8.
	 */
	p = utf_16le_to_utf_8_truncated(utf_16_errbuf, p, errbuflen_remaining);

	/*
	 * Now append the error number, if it fits.
	 */
	utf_8_len = p - errbuf;
	errbuflen_remaining -= utf_8_len;
	if (utf_8_len == 0) {
		/* The message was empty. */
		snprintf(p, errbuflen_remaining, "(%lu)", errnum);
	} else
		snprintf(p, errbuflen_remaining, " (%lu)", errnum);

	/*
	 * Now, if we're not in UTF-8 mode, convert errbuf to the
	 * local code page.
	 */
	if (!use_utf_8)
		utf_8_to_acp_truncated(errbuf);
}
#endif
