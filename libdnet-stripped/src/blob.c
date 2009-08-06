/*
 * blob.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: blob.c 615 2006-01-08 16:06:49Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

static void	*(*bl_malloc)(size_t) = malloc;
static void	*(*bl_realloc)(void *, size_t) = realloc;
static void	 (*bl_free)(void *) = free;
static int	   bl_size = BUFSIZ;

static int	   fmt_D(int, int, blob_t *, va_list *);
static int	   fmt_H(int, int, blob_t *, va_list *);
static int	   fmt_b(int, int, blob_t *, va_list *);
static int	   fmt_c(int, int, blob_t *, va_list *);
static int	   fmt_d(int, int, blob_t *, va_list *);
static int	   fmt_h(int, int, blob_t *, va_list *);
static int	   fmt_s(int, int, blob_t *, va_list *);

static void	   print_hexl(blob_t *);

static blob_fmt_cb blob_ascii_fmt[] = {
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	fmt_D,	NULL,	NULL,	NULL,
	fmt_H,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	fmt_b,	fmt_c,	fmt_d,	NULL,	NULL,	NULL,
	fmt_h,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	fmt_s,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL
};

struct blob_printer {
	char	  *name;
	void	 (*print)(blob_t *);
} blob_printers[] = {
	{ "hexl",	print_hexl },
	{ NULL,		NULL },
};

blob_t *
blob_new(void)
{
	blob_t *b;

	if ((b = bl_malloc(sizeof(*b))) != NULL) {
		b->off = b->end = 0;
		b->size = bl_size;
		if ((b->base = bl_malloc(b->size)) == NULL) {
			bl_free(b);
			b = NULL;
		}
	}
	return (b);
}

static int
blob_reserve(blob_t *b, int len)
{
	void *p;
	int nsize;

	if (b->size < b->end + len) {
		if (b->size == 0)
			return (-1);

		if ((nsize = b->end + len) > bl_size)
			nsize = ((nsize / bl_size) + 1) * bl_size;
		
		if ((p = bl_realloc(b->base, nsize)) == NULL)
			return (-1);
		
		b->base = p;
		b->size = nsize;
	}
	b->end += len;
	
	return (0);
}

int
blob_read(blob_t *b, void *buf, int len)
{
	if (b->end - b->off < len)
		len = b->end - b->off;
	
	memcpy(buf, b->base + b->off, len);
	b->off += len;
	
	return (len);
}

int
blob_write(blob_t *b, const void *buf, int len)
{
	if (b->off + len <= b->end ||
	    blob_reserve(b, b->off + len - b->end) == 0) {
		memcpy(b->base + b->off, (u_char *)buf, len);
		b->off += len;
		return (len);
	}
	return (-1);
}

int
blob_insert(blob_t *b, const void *buf, int len)
{
	if (blob_reserve(b, len) == 0 && b->size) {
		if (b->end - b->off > 0)
			memmove( b->base + b->off + len, b->base + b->off, b->end - b->off);
		memcpy(b->base + b->off, buf, len);
		b->off += len;
		return (len);
	}
	return (-1);
}

int
blob_delete(blob_t *b, void *buf, int len)
{
	if (b->off + len <= b->end && b->size) {
		if (buf != NULL)
			memcpy(buf, b->base + b->off, len);
		memmove(b->base + b->off, b->base + b->off + len, b->end - (b->off + len));
		b->end -= len;
		return (len);
	}
	return (-1);
}

static int
blob_fmt(blob_t *b, int pack, const char *fmt, va_list *ap)
{
	blob_fmt_cb fmt_cb;
	char *p;
	int len;

	for (p = (char *)fmt; *p != '\0'; p++) {
		if (*p == '%') {
			p++;
			if (isdigit((int) (unsigned char) *p)) {
				len = strtol(p, &p, 10);
			} else if (*p == '*') {
				len = va_arg(*ap, int);
				p++;
			} else
				len = 0;
			
			if ((fmt_cb = blob_ascii_fmt[(int)*p]) == NULL)
				return (-1);

			if ((*fmt_cb)(pack, len, b, ap) < 0)
				return (-1);
		} else {
			if (pack) {
				if (b->off + 1 < b->end ||
				    blob_reserve(b, b->off + 1 - b->end) == 0)
					b->base[b->off++] = *p;
				else
					return (-1);
			} else {
				if (b->base[b->off++] != *p)
					return (-1);
			}
		}
	}
	return (0);
}

int
blob_pack(blob_t *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	return (blob_fmt(b, 1, fmt, &ap));
}

int
blob_unpack(blob_t *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	return (blob_fmt(b, 0, fmt, &ap));
}

int
blob_seek(blob_t *b, int off, int whence)
{
	if (whence == SEEK_CUR)
		off += b->off;
	else if (whence == SEEK_END)
		off += b->end;

	if (off < 0 || off > b->end)
		return (-1);
	
	return ((b->off = off));
}

int
blob_index(blob_t *b, const void *buf, int len)
{
	int i;

	for (i = b->off; i <= b->end - len; i++) {
		if (memcmp(b->base + i, buf, len) == 0)
			return (i);
	}
	return (-1);
}

int
blob_rindex(blob_t *b, const void *buf, int len)
{
	int i;

	for (i = b->end - len; i >= 0; i--) {
		if (memcmp(b->base + i, buf, len) == 0)
			return (i);
	}
	return (-1);
}

int
blob_print(blob_t *b, char *style, int len)
{
	struct blob_printer *bp;

	for (bp = blob_printers; bp->name != NULL; bp++) {
		if (strcmp(bp->name, style) == 0)
			bp->print(b);
	}
	return (0);
}

int
blob_sprint(blob_t *b, char *style, int len, char *dst, int size)
{
	return (0);
}

blob_t *
blob_free(blob_t *b)
{
	if (b->size)
		bl_free(b->base);
	bl_free(b);
	return (NULL);
}

int
blob_register_alloc(size_t size, void *(bmalloc)(size_t),
    void (*bfree)(void *), void *(*brealloc)(void *, size_t))
{
	bl_size = size;
	if (bmalloc != NULL)
		bl_malloc = bmalloc;
	if (bfree != NULL)
		bl_free = bfree;
	if (brealloc != NULL)
		bl_realloc = brealloc;
	return (0);
}

int
blob_register_pack(char c, blob_fmt_cb fmt_cb)
{
	if (blob_ascii_fmt[(int)c] == NULL) {
		blob_ascii_fmt[(int)c] = fmt_cb;
		return (0);
	}
	return (-1);
}

static int
fmt_D(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);
	
	if (pack) {
		uint32_t n = va_arg(*ap, uint32_t);
		n = htonl(n);
		if (blob_write(b, &n, sizeof(n)) < 0)
			return (-1);
	} else {
		uint32_t *n = va_arg(*ap, uint32_t *);
		if (blob_read(b, n, sizeof(*n)) != sizeof(*n))
			return (-1);
		*n = ntohl(*n);
	}
	return (0);
}

static int
fmt_H(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);
	
	if (pack) {
		uint16_t n = va_arg(*ap, int);
		n = htons(n);
		if (blob_write(b, &n, sizeof(n)) < 0)
			return (-1);
	} else {
		uint16_t *n = va_arg(*ap, uint16_t *);
		if (blob_read(b, n, sizeof(*n)) != sizeof(*n))
			return (-1);
		*n = ntohs(*n);
	}
	return (0);
}

static int
fmt_b(int pack, int len, blob_t *b, va_list *ap)
{
	void *p = va_arg(*ap, void *);
	
	if (len <= 0) return (-1);
	
	if (pack)
		return (blob_write(b, p, len));
	else
		return (blob_read(b, p, len));
}

static int
fmt_c(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);
	
	if (pack) {
		uint8_t n = va_arg(*ap, int);
		return (blob_write(b, &n, sizeof(n)));
	} else {
		uint8_t *n = va_arg(*ap, uint8_t *);
		return (blob_read(b, n, sizeof(*n)));
	}
}

static int
fmt_d(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);
	
	if (pack) {
		uint32_t n = va_arg(*ap, uint32_t);
		return (blob_write(b, &n, sizeof(n)));
	} else {
		uint32_t *n = va_arg(*ap, uint32_t *);
		return (blob_read(b, n, sizeof(*n)));
	}
}

static int
fmt_h(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);
	
	if (pack) {
		uint16_t n = va_arg(*ap, int);
		return (blob_write(b, &n, sizeof(n)));
	} else {
		uint16_t *n = va_arg(*ap, uint16_t *);
		return (blob_read(b, n, sizeof(*n)));
	}
}

static int
fmt_s(int pack, int len, blob_t *b, va_list *ap)
{
	char *p = va_arg(*ap, char *);
	char c = '\0';
	int i, end;
	
	if (pack) {
		if (len > 0) {
			if ((c = p[len - 1]) != '\0')
				p[len - 1] = '\0';
		} else
			len = strlen(p) + 1;
		
		if (blob_write(b, p, len) > 0) {
			if (c != '\0')
				p[len - 1] = c;
			return (len);
		}
	} else {
		if (len <= 0) return (-1);

		if ((end = b->end - b->off) < len)
			end = len;
		
		for (i = 0; i < end; i++) {
			if ((p[i] = b->base[b->off + i]) == '\0') {
				b->off += i + 1;
				return (i);
			}
		}
	}
	return (-1);
}

static void
print_hexl(blob_t *b)
{
	u_int i, j, jm, len;
	u_char *p;
	int c;

	p = b->base + b->off;
	len = b->end - b->off;
	
	printf("\n");
	
	for (i = 0; i < len; i += 0x10) {
		printf("  %04x: ", (u_int)(i + b->off));
		jm = len - i;
		jm = jm > 16 ? 16 : jm;
		
		for (j = 0; j < jm; j++) {
			printf((j % 2) ? "%02x " : "%02x", (u_int)p[i + j]);
		}
		for (; j < 16; j++) {
			printf((j % 2) ? "   " : "  ");
		}
		printf(" ");
		
		for (j = 0; j < jm; j++) {
			c = p[i + j];
			printf("%c", isprint(c) ? c : '.');
		}
		printf("\n");
	}
}
