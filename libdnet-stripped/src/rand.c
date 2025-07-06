/*
 * rand.c
 *
 * Pseudorandom number generation, based on OpenBSD arc4random().
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 1996 David Mazieres <dm@lcs.mit.edu>
 * Copyright (c) 2023-2024 Oliver Falk <oliver@linux-kernel.at>
 *
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#ifdef _WIN32
# ifndef _WIN32_WINNT
#  define _WIN32_WINNT _WIN32_WINNT_WIN7
# endif
# if _WIN32_WINNT >= _WIN32_WINNT_VISTA
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
# else
#  include <wincrypt.h>
# endif
# define inline __inline
#else
# include <sys/types.h>
# include <sys/time.h>
# include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

struct rand_handle {
	uint8_t		 i;
	uint8_t		 j;
	uint8_t		 s[256];
	u_char		*tmp;
	int		 tmplen;
};

static inline void
rand_init(rand_t *rand)
{
	int i;
	
	for (i = 0; i < 256; i++)
		rand->s[i] = i;
	rand->i = rand->j = 0;
}

static inline void
rand_addrandom(rand_t *rand, u_char *buf, int len)
{
	int i;
	uint8_t si;
	
	rand->i--;
	for (i = 0; i < 256; i++) {
		rand->i = (rand->i + 1);
		si = rand->s[rand->i];
		rand->j = (rand->j + si + buf[i % len]);
		rand->s[rand->i] = rand->s[rand->j];
		rand->s[rand->j] = si;
	}
	rand->j = rand->i;
}

rand_t *
rand_open(void)
{
	rand_t *r;
	u_char seed[256];
#ifdef _WIN32
# if _WIN32_WINNT >= _WIN32_WINNT_VISTA
	if (0 != BCryptGenRandom(NULL, seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
	  return NULL;
# else
	HCRYPTPROV hcrypt = 0;

	CryptAcquireContext(&hcrypt, NULL, NULL, PROV_RSA_FULL,
	    CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hcrypt, sizeof(seed), seed);
	CryptReleaseContext(hcrypt, 0);
#endif
#else
	struct timeval *tv = (struct timeval *)seed;
	int fd;

	if ((fd = open("/dev/arandom", O_RDONLY)) != -1 ||
	    (fd = open("/dev/urandom", O_RDONLY)) != -1) {
                /* This is ugly, as we may end up with nothing in buffer, but
		 * that's very unlikely, anyway, wrappping the read in a conditional
		 * avoids compiler warning about unused variable */
		if(read(fd, seed + sizeof(*tv), sizeof(seed) - sizeof(*tv))) {
			// NOOP
		}
		close(fd);
	}
	gettimeofday(tv, NULL);
#endif
	if ((r = malloc(sizeof(*r))) != NULL) {
		rand_init(r);
		rand_addrandom(r, seed, 128);
		rand_addrandom(r, seed + 128, 128);
		r->tmp = NULL;
		r->tmplen = 0;
	}
	return (r);
}

static uint8_t
rand_getbyte(rand_t *r)
{
	uint8_t si, sj;

	r->i = (r->i + 1);
	si = r->s[r->i];
	r->j = (r->j + si);
	sj = r->s[r->j];
	r->s[r->i] = sj;
	r->s[r->j] = si;
	return (r->s[(si + sj) & 0xff]);
}

int
rand_get(rand_t *r, void *buf, size_t len)
{
	u_char *p;
	u_int i;

	for (p = buf, i = 0; i < len; i++) {
		p[i] = rand_getbyte(r);
	}
	return (0);
}

int
rand_set(rand_t *r, const void *buf, size_t len)
{
	rand_init(r);
	rand_addrandom(r, (u_char *)buf, len);
	rand_addrandom(r, (u_char *)buf, len);
	return (0);
}

int
rand_add(rand_t *r, const void *buf, size_t len)
{
	rand_addrandom(r, (u_char *)buf, len);
	return (0);
}

uint8_t
rand_uint8(rand_t *r)
{
	return (rand_getbyte(r));
}

uint16_t
rand_uint16(rand_t *r)
{
	uint16_t val;

	val = rand_getbyte(r) << 8;
	val |= rand_getbyte(r);
	return (val);
}

uint32_t
rand_uint32(rand_t *r)
{
	uint32_t val;

	val = rand_getbyte(r) << 24;
	val |= rand_getbyte(r) << 16;
	val |= rand_getbyte(r) << 8;
	val |= rand_getbyte(r);
	return (val);
}

int
rand_shuffle(rand_t *r, void *base, size_t nmemb, size_t size)
{
	u_char *save, *src, *dst, *start = (u_char *)base;
	u_int i, j;

	if (nmemb < 2)
		return (0);
	
	if ((u_int)r->tmplen < size) {
		if (r->tmp == NULL) {
			if ((save = malloc(size)) == NULL)
				return (-1);
		} else if ((save = realloc(r->tmp, size)) == NULL)
			return (-1);
		
		r->tmp = save;
		r->tmplen = size;
	} else
		save = r->tmp;
	
	for (i = 0; i < nmemb; i++) {
		if ((j = rand_uint32(r) % (nmemb - 1)) != i) {
			src = start + (size * i);
			dst = start + (size * j);
			memcpy(save, dst, size);
			memcpy(dst, src, size);
			memcpy(src, save, size);
		}
	}
	return (0);
}

rand_t *
rand_close(rand_t *r)
{
	if (r != NULL) {
		if (r->tmp != NULL)
			free(r->tmp);
		free(r);
	}
	return (NULL);
}
