#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "portability.h"

/*
 * vasprintf() and asprintf() for platforms with a C99-compliant
 * snprintf() - so that, if you format into a 1-byte buffer, it
 * will return how many characters it would have produced had
 * it been given an infinite-sized buffer.
 */
int
pcapint_vasprintf(char **strp, const char *format, va_list args)
{
	char buf;
	int len;
	size_t str_size;
	char *str;
	int ret;

	/*
	 * XXX - the C99 standard says, in section 7.19.6.5 "The
	 * snprintf function":
	 *
	 *    The snprintf function is equivalent to fprintf, except that
	 *    the output is written into an array (specified by argument s)
	 *    rather than to a stream.  If n is zero, nothing is written,
	 *    and s may be a null pointer.  Otherwise, output characters
	 *    beyond the n-1st are discarded rather than being written
	 *    to the array, and a null character is written at the end
	 *    of the characters actually written into the array.
	 *
	 *        ...
	 *
	 *    The snprintf function returns the number of characters that
	 *    would have been written had n been sufficiently large, not
	 *    counting the terminating null character, or a negative value
	 *    if an encoding error occurred. Thus, the null-terminated
	 *    output has been completely written if and only if the returned
	 *    value is nonnegative and less than n.
	 *
	 * That doesn't make it entirely clear whether, if a null buffer
	 * pointer and a zero count are passed, it will return the number
	 * of characters that would have been written had a buffer been
	 * passed.
	 *
	 * And, even if C99 *does*, in fact, say it has to work, it
	 * doesn't work in Solaris 8, for example - it returns -1 for
	 * NULL/0, but returns the correct character count for a 1-byte
	 * buffer.
	 *
	 * So we pass a one-character pointer in order to find out how
	 * many characters this format and those arguments will need
	 * without actually generating any more of those characters
	 * than we need.
	 *
	 * (The fact that it might happen to work with GNU libc or with
	 * various BSD libcs is completely uninteresting, as those tend
	 * to have asprintf() already and thus don't even *need* this
	 * code; this is for use in those UN*Xes that *don't* have
	 * asprintf().)
	 */
	len = vsnprintf(&buf, sizeof buf, format, args);
	if (len == -1) {
		*strp = NULL;
		return (-1);
	}
	str_size = len + 1;
	str = malloc(str_size);
	if (str == NULL) {
		*strp = NULL;
		return (-1);
	}
	ret = vsnprintf(str, str_size, format, args);
	if (ret == -1) {
		free(str);
		*strp = NULL;
		return (-1);
	}
	*strp = str;
	/*
	 * vsnprintf() shouldn't truncate the string, as we have
	 * allocated a buffer large enough to hold the string, so its
	 * return value should be the number of characters written.
	 */
	return (ret);
}

int
pcapint_asprintf(char **strp, const char *format, ...)
{
	va_list args;
	int ret;

	va_start(args, format);
	ret = pcapint_vasprintf(strp, format, args);
	va_end(args);
	return (ret);
}

