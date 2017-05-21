/*
 * addr-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: addr-util.c 539 2005-01-23 07:36:54Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

static const char *octet2dec[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
	"13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23",
	"24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34",
	"35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45",
	"46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56",
	"57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67",
	"68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78",
	"79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
	"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100",
	"101", "102", "103", "104", "105", "106", "107", "108", "109",
	"110", "111", "112", "113", "114", "115", "116", "117", "118",
	"119", "120", "121", "122", "123", "124", "125", "126", "127",
	"128", "129", "130", "131", "132", "133", "134", "135", "136",
	"137", "138", "139", "140", "141", "142", "143", "144", "145",
	"146", "147", "148", "149", "150", "151", "152", "153", "154",
	"155", "156", "157", "158", "159", "160", "161", "162", "163",
	"164", "165", "166", "167", "168", "169", "170", "171", "172",
	"173", "174", "175", "176", "177", "178", "179", "180", "181",
	"182", "183", "184", "185", "186", "187", "188", "189", "190",
	"191", "192", "193", "194", "195", "196", "197", "198", "199",
	"200", "201", "202", "203", "204", "205", "206", "207", "208",
	"209", "210", "211", "212", "213", "214", "215", "216", "217",
	"218", "219", "220", "221", "222", "223", "224", "225", "226",
	"227", "228", "229", "230", "231", "232", "233", "234", "235",
	"236", "237", "238", "239", "240", "241", "242", "243", "244",
	"245", "246", "247", "248", "249", "250", "251", "252", "253",
	"254", "255"
};

static const char *octet2hex[] = {
	"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a",
	"0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15",
	"16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20",
	"21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b",
	"2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36",
	"37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41",
	"42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c",
	"4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57",
	"58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62",
	"63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d",
	"6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78",
	"79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83",
	"84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e",
	"8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
	"9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4",
	"a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba",
	"bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5",
	"c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0",
	"d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db",
	"dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6",
	"e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1",
	"f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc",
	"fd", "fe", "ff"
};

char *
eth_ntop(const eth_addr_t *eth, char *dst, size_t len)
{
	const char *x;
	char *p = dst;
	int i;
	
	if (len < 18)
		return (NULL);
	
	for (i = 0; i < ETH_ADDR_LEN; i++) {
		for (x = octet2hex[eth->data[i]]; (*p = *x) != '\0'; x++, p++)
			;
		*p++ = ':';
	}
	p[-1] = '\0';
	
	return (dst);
}

char *
eth_ntoa(const eth_addr_t *eth)
{
	struct addr a;
	
	addr_pack(&a, ADDR_TYPE_ETH, ETH_ADDR_BITS, eth->data, ETH_ADDR_LEN);
	return (addr_ntoa(&a));
}

int
eth_pton(const char *p, eth_addr_t *eth)
{
	char *ep;
	long l;
	int i;
	
	for (i = 0; i < ETH_ADDR_LEN; i++) {
		l = strtol(p, &ep, 16);
		if (ep == p || l < 0 || l > 0xff ||
		    (i < ETH_ADDR_LEN - 1 && *ep != ':'))
			break;
		eth->data[i] = (u_char)l;
		p = ep + 1;
	}
	return ((i == ETH_ADDR_LEN && *ep == '\0') ? 0 : -1);
}

char *
ip_ntop(const ip_addr_t *ip, char *dst, size_t len)
{
	const char *d;
	char *p = dst;
	u_char *data = (u_char *)ip;
	int i;
	
	if (len < 16)
		return (NULL);
	
	for (i = 0; i < IP_ADDR_LEN; i++) {
		for (d = octet2dec[data[i]]; (*p = *d) != '\0'; d++, p++)
			;
		*p++ = '.';
	}
	p[-1] = '\0';
	
	return (dst);
}

char *
ip_ntoa(const ip_addr_t *ip)
{
	struct addr a;
	
	addr_pack(&a, ADDR_TYPE_IP, IP_ADDR_BITS, ip, IP_ADDR_LEN);
	return (addr_ntoa(&a));
}

int
ip_pton(const char *p, ip_addr_t *ip)
{
	u_char *data = (u_char *)ip;
	char *ep;
	long l;
	int i;

	for (i = 0; i < IP_ADDR_LEN; i++) {
		l = strtol(p, &ep, 10);
		if (ep == p || l < 0 || l > 0xff ||
		    (i < IP_ADDR_LEN - 1 && *ep != '.'))
			break;
		data[i] = (u_char)l;
		p = ep + 1;
	}
	return ((i == IP_ADDR_LEN && *ep == '\0') ? 0 : -1);
}

char *
ip6_ntop(const ip6_addr_t *ip6, char *dst, size_t len)
{
	uint16_t data[IP6_ADDR_LEN / 2];
	struct { int base, len; } best, cur;
	char *p = dst;
	int i;

	cur.len = best.len = 0;
	
	if (len < 46)
		return (NULL);
	
	/* Copy into 16-bit array. */
	for (i = 0; i < IP6_ADDR_LEN / 2; i++) {
		data[i] = ip6->data[2 * i] << 8;
		data[i] |= ip6->data[2 * i + 1];
	}
	
	best.base = cur.base = -1;
	/*
	 * Algorithm borrowed from Vixie's inet_pton6()
	 */
	for (i = 0; i < IP6_ADDR_LEN; i += 2) {
		if (data[i / 2] == 0) {
			if (cur.base == -1) {
				cur.base = i;
				cur.len = 0;
			} else
				cur.len += 2;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1 && (best.base == -1 || cur.len > best.len))
		best = cur;
	if (best.base != -1 && best.len < 2)
		best.base = -1;
	if (best.base == 0)
		*p++ = ':';

	for (i = 0; i < IP6_ADDR_LEN; i += 2) {
		if (i == best.base) {
			*p++ = ':';
			i += best.len;
		} else if (i == 12 && best.base == 0 &&
		    (best.len == 10 || (best.len == 8 &&
			data[5] == 0xffff))) {
			if (ip_ntop((ip_addr_t *)&data[6], p,
			    len - (p - dst)) == NULL)
				return (NULL);
			return (dst);
		} else p += sprintf(p, "%x:", data[i / 2]);
	}
	if (best.base + 2 + best.len == IP6_ADDR_LEN) {
		*p = '\0';
	} else
		p[-1] = '\0';

	return (dst);
}

char *
ip6_ntoa(const ip6_addr_t *ip6)
{
	struct addr a;
	
	addr_pack(&a, ADDR_TYPE_IP6, IP6_ADDR_BITS, ip6->data, IP6_ADDR_LEN);
	return (addr_ntoa(&a));
}

int
ip6_pton(const char *p, ip6_addr_t *ip6)
{
	uint16_t data[8], *u = (uint16_t *)ip6->data;
	int i, j, n, z = -1;
	char *ep;
	long l;
	
	if (*p == ':')
		p++;
	
	for (n = 0; n < 8; n++) {
		l = strtol(p, &ep, 16);
		
		if (ep == p) {
			if (ep[0] == ':' && z == -1) {
				z = n;
				p++;
			} else if (ep[0] == '\0') {
				break;
			} else {
				return (-1);
			}
		} else if (ep[0] == '.' && n <= 6) {
			if (ip_pton(p, (ip_addr_t *)(data + n)) < 0)
				return (-1);
			n += 2;
			ep = ""; /* XXX */
			break;
		} else if (l >= 0 && l <= 0xffff) {
			data[n] = htons((uint16_t)l);

			if (ep[0] == '\0') {
				n++;
				break;
			} else if (ep[0] != ':' || ep[1] == '\0')
				return (-1);

			p = ep + 1;
		} else
			return (-1);
	}
	if (n == 0 || *ep != '\0' || (z == -1 && n != 8))
		return (-1);
	
	for (i = 0; i < z; i++) {
		u[i] = data[i];
	}
	while (i < 8 - (n - z - 1)) {
		u[i++] = 0;
	}
	for (j = z + 1; i < 8; i++, j++) {
		u[i] = data[j];
	}
	return (0);
}
