/***************************************************************************
 * nbase_addrset.c -- Address set (addrset) management.                          *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

/* The code in this file has tests in the file ncat/tests/test-addrset.sh. Run that
   program after making any big changes. Also, please add tests for any new
   features. */

#include <limits.h> /* CHAR_BIT */
#include <errno.h>
#include <assert.h>

#include "nbase.h"

/* A fancy logging system to allow this file to take advantage of different logging
   systems used by various programs */

static void default_log_user(const char * a, ...){};

static void (*log_user)(const char *, ...) = default_log_user;

static void default_log_debug(const char * a, ...){};

static void (*log_debug)(const char *, ...) = default_log_debug;

void nbase_set_log(void (*log_user_func)(const char *, ...),void (*log_debug_func)(const char *, ...)){
    if (log_user_func == NULL)
        log_user = default_log_user;
    else
        log_user = log_user_func;
    if (log_debug_func == NULL)
        log_debug = default_log_debug;
    else
        log_debug = log_debug_func;
}

/* Node for a radix tree (trie) used to match certain addresses.
 * Currently, only individual numeric IP and IPv6 addresses are matched using
 * the trie. */
struct trie_node {
  /* The address prefix that this node represents. */
  u32 addr[4];
  /* The prefix mask. Bits in addr that are not within this mask are ignored. */
  u32 mask[4];
  /* Addresses with the next bit after the mask equal to 1 are on this branch. */
  struct trie_node *next_bit_one;
  /* Addresses with the next bit after the mask equal to 0 are on this branch. */
  struct trie_node *next_bit_zero;
};

/* We use bit vectors to represent what values are allowed in an IPv4 octet.
   Each vector is built up of an array of bitvector_t (any convenient integer
   type). */
typedef unsigned long bitvector_t;
/* A 256-element bit vector, representing legal values for one octet. */
typedef bitvector_t octet_bitvector[(256 - 1) / (sizeof(unsigned long) * CHAR_BIT) + 1];

/* A chain of tests for set inclusion. If one test is passed, the address is in
   the set. */
struct addrset_elem {
  struct {
    /* A bit vector for each address octet. */
    octet_bitvector bits[4];
  } ipv4;
  struct addrset_elem *next;
};

/* A set of addresses. Used to match against allow/deny lists. */
struct addrset {
    /* Linked list of struct addset_elem. */
    struct addrset_elem *head;
    /* Radix tree for faster matching of certain cases */
    struct trie_node *trie;
};

/* Special node pointer to represent "all possible addresses"
 * This will be used to represent netmask specifications. */
static struct trie_node g_TRIE_NODE_TRUE = {0};
#define TRIE_NODE_TRUE &g_TRIE_NODE_TRUE

struct addrset *addrset_new()
{
    struct addrset *set = (struct addrset *) safe_zalloc(sizeof(struct addrset));
    set->head = NULL;

    /* Allocate the first node of the IPv4 trie */
    set->trie = (struct trie_node *) safe_zalloc(sizeof(struct trie_node));
    return set;
}

static void trie_free(struct trie_node *curr)
{
  /* Since we descend only down one side, we at most accumulate one tree's-depth, or 128.
   * Add 4 for safety to account for special root node and special empty stack position 0.
   */
  struct trie_node *stack[128+4] = {NULL};
  int i = 1;

  while (i > 0 && curr != NULL && curr != TRIE_NODE_TRUE) {
    /* stash next_bit_one */
    if (curr->next_bit_one != NULL && curr->next_bit_one != TRIE_NODE_TRUE) {
      stack[i++] = curr->next_bit_one;
    }
    /* if next_bit_zero is valid, descend */
    if (curr->next_bit_zero != NULL && curr->next_bit_zero != TRIE_NODE_TRUE) {
      curr = curr->next_bit_zero;
    }
    else {
      /* next_bit_one was stashed, next_bit_zero is invalid. Free it and move back up the stack. */
      free(curr);
      curr = stack[--i];
    }
  }
}

void addrset_free(struct addrset *set)
{
    struct addrset_elem *elem, *next;

    for (elem = set->head; elem != NULL; elem = next) {
        next = elem->next;
        free(elem);
    }

    trie_free(set->trie);
    free(set);
}


/* Public domain log2 function. https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogLookup */
static const char LogTable256[256] = {
#define LT(n) n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n
  -1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
  LT(4), LT(5), LT(5), LT(6), LT(6), LT(6), LT(6),
  LT(7), LT(7), LT(7), LT(7), LT(7), LT(7), LT(7), LT(7)
};

/* Returns a mask representing the common prefix between 2 values. */
static u32 common_mask(u32 a, u32 b)
{
  u8 r;     // r will be lg(v)
  u32 t, tt; // temporaries
  u32 v = a ^ b;
  if (v == 0) {
    /* values are equal, all bits are the same */
    return 0xffffffff;
  }

  if ((tt = v >> 16))
  {
    r = (t = tt >> 8) ? 24 + LogTable256[t] : 16 + LogTable256[tt];
  }
  else
  {
    r = (t = v >> 8) ? 8 + LogTable256[t] : LogTable256[v];
  }
  if (r + 1 >= 32) {
    /* shifting this many bits would overflow. Just return max mask */
    return 0;
  }
  else {
    return ~((1 << (r + 1)) - 1);
  }
}

/* Given a mask and a value, return the value of the bit immediately following
 * the masked bits. */
static u32 next_bit_is_one(u32 mask, u32 value) {
  if (mask == 0) {
    /* no masked bits, check the first bit. */
    return (0x80000000 & value);
  }
  else if (mask == 0xffffffff) {
    /* Imaginary bit off the end we will say is 0 */
    return 0;
  }
  /* isolate the bit by overlapping the mask with its inverse */
  return ((mask >> 1) & ~mask) & value;
}

/* Given a mask and an address, return true if the first unmasked bit is one */
static u32 addr_next_bit_is_one(const u32 *mask, const u32 *addr) {
  u32 curr_mask;
  u8 i;
  for (i = 0; i < 4; i++) {
    curr_mask = mask[i];
    if (curr_mask < 0xffffffff) {
      /* Only bother checking the first not-completely-masked portion of the address */
      return next_bit_is_one(curr_mask, addr[i]);
    }
  }
  /* Mask must be all ones, meaning that the next bit is off the end, and clearly not 1. */
  return 0;
}

/* Return true if the masked portion of a and b is identical */
static int mask_matches(u32 mask, u32 a, u32 b)
{
  return !(mask & (a ^ b));
}

/* Apply a mask and check if 2 addresses are equal */
static int addr_matches(const u32 *mask, const u32 *sa, const u32 *sb)
{
  u32 curr_mask;
  u8 i;
  for (i = 0; i < 4; i++) {
    curr_mask = mask[i];
    if (curr_mask == 0) {
      /* No more applicable bits */
      break;
    }
    else if (!mask_matches(curr_mask, sa[i], sb[i])) {
      /* Doesn't match. */
      return 0;
    }
  }
  /* All applicable bits match. */
  return 1;
}

/* Helper function to allocate and initialize a new node */
static struct trie_node *new_trie_node(const u32 *addr, const u32 *mask)
{
  u8 i;
  struct trie_node *new_node = (struct trie_node *) safe_zalloc(sizeof(struct trie_node));
  for (i=0; i < 4; i++) {
    new_node->addr[i] = addr[i];
    new_node->mask[i] = mask[i];
  }
  /* New nodes default to matching true. Override if not. */
  new_node->next_bit_one = new_node->next_bit_zero = TRIE_NODE_TRUE;
  return new_node;
}

/* Split a node into 2: one that matches the greatest common prefix with addr
 * and one that does not. */
static void trie_split (struct trie_node *this, const u32 *addr, const u32 *mask)
{
  struct trie_node *new_node;
  u32 new_mask[4] = {0,0,0,0};
  u8 i;
  /* Calculate the mask of the common prefix */
  for (i=0; i < 4; i++) {
    new_mask[i] = common_mask(this->addr[i], addr[i]);
    if (new_mask[i] > this->mask[i]){
      /* Addrs have more bits in common than we care about for this node. */
      new_mask[i] = this->mask[i];
    }
    if (new_mask[i] > mask[i]) {
      /* new addr's mask is broader, so this node is superseded. */
      this->mask[i] = mask[i];
      for (i++; i < 4; i++) {
        this->mask[i] = 0;
      }
      /* The longer mask is superseded. Delete following nodes. */
      trie_free(this->next_bit_one);
      trie_free(this->next_bit_zero);
      /* Anything below here will always match. */
      this->next_bit_one = this->next_bit_zero = TRIE_NODE_TRUE;
      return;
    }
    if (new_mask[i] < 0xffffffff) {
      break;
    }
  }
  if (new_mask[i] >= this->mask[i]) {
    /* This node completely contains the new addr and mask. No need to split or add */
    return;
  }
  /* Make a copy of this node to continue matching what it has been */
  new_node = new_trie_node(this->addr, this->mask);
  new_node->next_bit_one = this->next_bit_one;
  new_node->next_bit_zero = this->next_bit_zero;
  /* Adjust this node to the smaller mask */
  for (i=0; i < 4; i++) {
    this->mask[i] = new_mask[i];
  }
  /* Put the new node on the appropriate branch */
  if (addr_next_bit_is_one(this->mask, this->addr)) {
    this->next_bit_one = new_node;
    this->next_bit_zero = NULL;
  }
  else {
    this->next_bit_zero = new_node;
    this->next_bit_one = NULL;
  }
}

/* Helper for address insertion */
static void _trie_insert (struct trie_node *this, const u32 *addr, const u32 *mask)
{
  /* On entry, at least the 1st bit must match this node */
  assert(this == TRIE_NODE_TRUE || (this->addr[0] ^ addr[0]) < (1 << 31));

  while (this != NULL && this != TRIE_NODE_TRUE) {
    /* Split the node if necessary to ensure a match */
    trie_split(this, addr, mask);

    /* At this point, this node matches the addr up to this->mask. */
    if (addr_next_bit_is_one(this->mask, addr)) {
      /* next bit is one: insert on the one branch */
      if (this->next_bit_one == NULL) {
        /* Previously unmatching branch, always the case when splitting */
        this->next_bit_one = new_trie_node(addr, mask);
        return;
      }
      else {
        this = this->next_bit_one;
      }
    }
    else {
      /* next bit is zero: insert on the zero branch */
      if (this->next_bit_zero == NULL) {
        /* Previously unmatching branch, always the case when splitting */
        this->next_bit_zero = new_trie_node(addr, mask);
        return;
      }
      else {
        this = this->next_bit_zero;
      }
    }
  }
}

/* Helper function to turn a sockaddr into an array of u32, used internally */
static int sockaddr_to_addr(const struct sockaddr *sa, u32 *addr)
{
  if (sa->sa_family == AF_INET) {
    /* IPv4-mapped IPv6 address */
    addr[0] = addr[1] = 0;
    addr[2] = 0xffff;
    addr[3] = ntohl(((struct sockaddr_in *) sa)->sin_addr.s_addr);
  }
#ifdef HAVE_IPV6
  else if (sa->sa_family == AF_INET6) {
    u8 i;
    unsigned char *addr6 = ((struct sockaddr_in6 *) sa)->sin6_addr.s6_addr;
    for (i=0; i < 4; i++) {
      addr[i] = (addr6[i*4] << 24) + (addr6[i*4+1] << 16) + (addr6[i*4+2] << 8) + addr6[i*4+3];
    }
  }
#endif
  else {
    return 0;
  }
  return 1;
}

static int sockaddr_to_mask (const struct sockaddr *sa, int bits, u32 *mask)
{
  int i, k;
  if (bits >= 0) {
    if (sa->sa_family == AF_INET) {
      bits += 96;
    }
#ifdef HAVE_IPV6
    else if (sa->sa_family == AF_INET6) {
      ; /* do nothing */
    }
#endif
    else {
      return 0;
    }
  }
  else
    bits = 128;
  k = bits / 32;
  for (i=0; i < 4; i++) {
    if (i < k) {
      mask[i] = 0xffffffff;
    }
    else if (i > k) {
      mask[i] = 0;
    }
    else {
      mask[i] = 0xfffffffe << (31 - bits % 32);
    }
  }
  return 1;
}

/* Insert a sockaddr into the trie */
static void trie_insert (struct trie_node *this, const struct sockaddr *sa, int bits)
{
  u32 addr[4] = {0};
  u32 mask[4] = {0};
  if (!sockaddr_to_addr(sa, addr)) {
    log_debug("Unknown address family %u, address not inserted.\n", sa->sa_family);
    return;
  }
  if (!sockaddr_to_mask(sa, bits, mask)) {
    log_debug("Bad netmask length %d for address family %u, address not inserted.\n", bits, sa->sa_family);
    return;
  }
  /* First node doesn't have a mask or address of its own; we have to check the
   * first bit manually. */
  if (0x80000000 & addr[0]) {
    /* First bit is 1, so insert on ones branch */
    if (this->next_bit_one == NULL) {
      /* Empty branch, just add it. */
      this->next_bit_one = new_trie_node(addr, mask);
      return;
    }
    _trie_insert(this->next_bit_one, addr, mask);
  }
  else {
    /* First bit is 0, so insert on zeros branch */
    if (this->next_bit_zero == NULL) {
      /* Empty branch, just add it. */
      this->next_bit_zero = new_trie_node(addr, mask);
      return;
    }
    _trie_insert(this->next_bit_zero, addr, mask);
  }
}

/* Helper for matching addresses */
static int _trie_match (const struct trie_node *this, const u32 *addr)
{
  while (this != TRIE_NODE_TRUE && this != NULL
    && addr_matches(this->mask, this->addr, addr)) {
    if (1 & this->mask[3]) {
      /* We've matched all possible bits! Yay! */
      return 1;
    }
    else if (addr_next_bit_is_one(this->mask, addr)) {
      this = this->next_bit_one;
    }
    else {
      this = this->next_bit_zero;
    }
  }
  if (this == TRIE_NODE_TRUE) {
    return 1;
  }
  return 0;
}

static int trie_match (const struct trie_node *this, const struct sockaddr *sa)
{
  u32 addr[4] = {0};
  if (!sockaddr_to_addr(sa, addr)) {
    log_debug("Unknown address family %u, cannot match.\n", sa->sa_family);
    return 0;
  }
  /* Manually check first bit to decide which branch to match against */
  if (0x80000000 & addr[0]) {
    return _trie_match(this->next_bit_one, addr);
  }
  else {
    return _trie_match(this->next_bit_zero, addr);
  }
  return 0;
}

/* A debugging function to print out the contents of an addrset_elem. For IPv4
   this is the four bit vectors. For IPv6 it is the address and netmask. */
static void addrset_elem_print(FILE *fp, const struct addrset_elem *elem)
{
    const size_t num_bitvector = sizeof(octet_bitvector) / sizeof(bitvector_t);
    int i;
    size_t j;

    for (i = 0; i < 4; i++) {
      for (j = 0; j < num_bitvector; j++)
        fprintf(fp, "%0*lX ", (int) (sizeof(bitvector_t) * 2), elem->ipv4.bits[i][num_bitvector - 1 - j]);
      fprintf(fp, "\n");
    }
}

void addrset_print(FILE *fp, const struct addrset *set)
{
  const struct addrset_elem *elem;
  for (elem = set->head; elem != NULL; elem = elem->next) {
    fprintf(fp, "addrset_elem: %p\n", elem);
    addrset_elem_print(fp, elem);
  }
}

/* This is a wrapper around getaddrinfo that automatically handles hints for
   IPv4/IPv6, TCP/UDP, and whether name resolution is allowed. */
static int resolve_name(const char *name, struct addrinfo **result, int af, int use_dns)
{
    struct addrinfo hints = { 0 };
    int rc;

    hints.ai_protocol = IPPROTO_TCP;

    /* First do a non-DNS lookup for any address family (just checks for a valid
       numeric address). We recognize numeric addresses no matter the setting of
       af. This is also the last step if use_dns is false. */
    hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    *result = NULL;
    rc = getaddrinfo(name, NULL, &hints, result);
    if (rc == 0 || !use_dns)
        return rc;

    /* Do a DNS lookup now. When we look up a name we only want addresses
       corresponding to the value of af. */
    hints.ai_flags &= ~AI_NUMERICHOST;
    hints.ai_family = af;
    *result = NULL;
    rc = getaddrinfo(name, NULL, &hints, result);

    return rc;
}

/* This is an address family-agnostic version of inet_ntop. */
static char *address_to_string(const struct sockaddr *sa, size_t sa_len,
                               char *buf, size_t len)
{
    getnameinfo(sa, sa_len, buf, len, NULL, 0, NI_NUMERICHOST);

    return buf;
}

/* Break an IPv4 address into an array of octets. octets[0] contains the most
   significant octet and octets[3] the least significant. */
static void in_addr_to_octets(const struct in_addr *ia, uint8_t octets[4])
{
    u32 hbo = ntohl(ia->s_addr);

    octets[0] = (uint8_t) ((hbo & (0xFFU << 24)) >> 24);
    octets[1] = (uint8_t) ((hbo & (0xFFU << 16)) >> 16);
    octets[2] = (uint8_t) ((hbo & (0xFFU << 8)) >> 8);
    octets[3] = (uint8_t) (hbo & 0xFFU);
}

#define BITVECTOR_BITS (sizeof(bitvector_t) * CHAR_BIT)
#define BIT_SET(v, n) ((v)[(n) / BITVECTOR_BITS] |= 1UL << ((n) % BITVECTOR_BITS))
#define BIT_IS_SET(v, n) (((v)[(n) / BITVECTOR_BITS] & 1UL << ((n) % BITVECTOR_BITS)) != 0)

static int parse_ipv4_ranges(struct addrset_elem *elem, const char *spec);
static void apply_ipv4_netmask_bits(struct addrset_elem *elem, int bits);

/* Add a host specification into the address set. Returns 1 on success, 0 on
   error. */
int addrset_add_spec(struct addrset *set, const char *spec, int af, int dns)
{
    char *local_spec;
    char *netmask_s;
    const char *tail;
    long netmask_bits;
    struct addrinfo *addrs, *addr;
    struct addrset_elem *elem;
    int rc;

    /* Make a copy of the spec to mess with. */
    local_spec = strdup(spec);
    if (local_spec == NULL)
        return 0;

    /* Read the CIDR netmask bits, if present. */
    netmask_s = strchr(local_spec, '/');
    if (netmask_s == NULL) {
        /* A negative value means unspecified; default depends on the address
           family. */
        netmask_bits = -1;
    } else {
        *netmask_s = '\0';
        netmask_s++;
        errno = 0;
        netmask_bits = parse_long(netmask_s, &tail);
        if (errno != 0 || *tail != '\0' || tail == netmask_s) {
            log_user("Error parsing netmask in \"%s\".\n", spec);
            free(local_spec);
            return 0;
        }
    }

    /* See if it's a plain IP address */
    rc = resolve_name(local_spec, &addrs, af, 0);
    if (rc == 0 && addrs != NULL) {
      /* Add all addresses to the trie */
      for (addr = addrs; addr != NULL; addr = addr->ai_next) {
        char addr_string[128];
        if ((addr->ai_family == AF_INET && netmask_bits > 32)
#ifdef HAVE_IPV6
          || (addr->ai_family == AF_INET6 && netmask_bits > 128)
#endif
          ) {
          log_user("Illegal netmask in \"%s\". Must be smaller than address bit length.\n", spec);
          free(local_spec);
          freeaddrinfo(addrs);
          return 0;
        }
        address_to_string(addr->ai_addr, addr->ai_addrlen, addr_string, sizeof(addr_string));
        trie_insert(set->trie, addr->ai_addr, netmask_bits);
        log_debug("Add IP %s/%d to addrset (trie).\n", addr_string, netmask_bits);
      }
      free(local_spec);
      freeaddrinfo(addrs);
      return 1;
    }

    elem = (struct addrset_elem *) safe_malloc(sizeof(*elem));
    memset(elem->ipv4.bits, 0, sizeof(elem->ipv4.bits));

    /* Check if this is an IPv4 address, with optional ranges and wildcards. */
    if (parse_ipv4_ranges(elem, local_spec)) {
        if (netmask_bits > 32) {
            log_user("Illegal netmask in \"%s\". Must be between 0 and 32.\n", spec);
            free(local_spec);
            free(elem);
            return 0;
        }
        apply_ipv4_netmask_bits(elem, netmask_bits);
        log_debug("Add IPv4 range %s/%ld to addrset.\n", local_spec, netmask_bits > 0 ? netmask_bits : 32);
        elem->next = set->head;
        set->head = elem;
        free(local_spec);
        return 1;
    } else {
        free(elem);
    }

    /* When all else fails, resolve the name. */
    rc = resolve_name(local_spec, &addrs, af, dns);
    if (rc != 0) {
        log_user("Error resolving name \"%s\": %s\n", local_spec, gai_strerror(rc));
        free(local_spec);
        return 0;
    }
    if (addrs == NULL)
        log_user("Warning: no addresses found for %s.\n", local_spec);
    free(local_spec);

    /* Walk the list of addresses and add them all to the set with netmasks. */
    for (addr = addrs; addr != NULL; addr = addr->ai_next) {
        char addr_string[128];

        address_to_string(addr->ai_addr, addr->ai_addrlen, addr_string, sizeof(addr_string));

        /* Note: it is possible that in this loop we are dealing with addresses
           of more than one family (e.g., IPv4 and IPv6). But we have at most
           one netmask value for all of them. Whatever netmask we have is
           applied blindly to whatever addresses there are, which may not be
           what you want if a /24 is applied to IPv6 and will cause an error if
           a /120 is applied to IPv4. */
        if (addr->ai_family == AF_INET) {

            if (netmask_bits > 32) {
                log_user("Illegal netmask in \"%s\". Must be between 0 and 32.\n", spec);
                freeaddrinfo(addrs);
                return 0;
            }
            log_debug("Add IPv4 %s/%ld to addrset (trie).\n", addr_string, netmask_bits > 0 ? netmask_bits : 32);

#ifdef HAVE_IPV6
        } else if (addr->ai_family == AF_INET6) {
            if (netmask_bits > 128) {
                log_user("Illegal netmask in \"%s\". Must be between 0 and 128.\n", spec);
                freeaddrinfo(addrs);
                return 0;
            }
            log_debug("Add IPv6 %s/%ld to addrset (trie).\n", addr_string, netmask_bits > 0 ? netmask_bits : 128);
#endif
        } else {
            log_debug("ignoring address %s for %s. Family %d socktype %d protocol %d.\n", addr_string, spec, addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            continue;
        }

        trie_insert(set->trie, addr->ai_addr, netmask_bits);
    }

    if (addrs != NULL)
        freeaddrinfo(addrs);

    return 1;
}

/* Add whitespace-separated host specifications from fd into the address set.
   Returns 1 on success, 0 on error. */
int addrset_add_file(struct addrset *set, FILE *fd, int af, int dns)
{
    char buf[1024];
    int c, i;

    for (;;) {
        /* Skip whitespace. */
        while ((c = getc(fd)) != EOF) {
            if (!isspace(c))
                break;
        }
        if (c == EOF)
            break;
        ungetc(c, fd);

        i = 0;
        while ((c = getc(fd)) != EOF) {
            if (isspace(c))
                break;
            if (i + 1 > sizeof(buf) - 1) {
                /* Truncate the specification to give a little context. */
                buf[11] = '\0';
                log_user("Host specification starting with \"%s\" is too long.\n", buf);
                return 0;
            }
            buf[i++] = c;
        }
        buf[i] = '\0';

        if (!addrset_add_spec(set, buf, af, dns))
            return 0;
    }

    return 1;
}

/* Parse an IPv4 address with optional ranges and wildcards into bit vectors.
   Each octet must match the regular expression '(\*|#?(-#?)?(,#?(-#?)?)*)',
   where '#' stands for an integer between 0 and 255. Return 1 on success, 0 on
   error. */
static int parse_ipv4_ranges(struct addrset_elem *elem, const char *spec)
{
    const char *p;
    int octet_index, i;

    p = spec;
    octet_index = 0;
    while (*p != '\0' && octet_index < 4) {
        if (*p == '*') {
            for (i = 0; i < 256; i++)
                BIT_SET(elem->ipv4.bits[octet_index], i);
            p++;
        } else {
            for (;;) {
                long start, end;
                const char *tail;

                errno = 0;
                start = parse_long(p, &tail);
                /* Is this a range open on the left? */
                if (tail == p) {
                    if (*p == '-')
                        start = 0;
                    else
                        return 0;
                }
                if (errno != 0 || start < 0 || start > 255)
                    return 0;
                p = tail;

                /* Look for a range. */
                if (*p == '-') {
                    p++;
                    errno = 0;
                    end = parse_long(p, &tail);
                    /* Is this range open on the right? */
                    if (tail == p)
                        end = 255;
                    if (errno != 0 || end < 0 || end > 255 || end < start)
                        return 0;
                    p = tail;
                } else {
                    end = start;
                }

                /* Fill in the range in the bit vector. */
                for (i = start; i <= end; i++)
                    BIT_SET(elem->ipv4.bits[octet_index], i);

                if (*p != ',')
                    break;
                p++;
            }
        }
        octet_index++;
        if (octet_index < 4) {
            if (*p != '.')
                return 0;
            p++;
        }
    }
    if (*p != '\0' || octet_index < 4)
        return 0;

    return 1;
}

/* Expand a single-octet bit vector to include any additional addresses that
   result when mask is applied. */
static void apply_ipv4_netmask_octet(octet_bitvector bits, uint8_t mask)
{
    unsigned int i, j;
    uint32_t chunk_size;

    /* Process the bit vector in chunks, first of size 1, then of size 2, up to
       size 128. Check the next bit of the mask. If it is 1, do nothing.
       Otherwise, pair up the chunks (first with the second, third with the
       fourth, etc.). For each pair of chunks, set a bit in one chunk if it is
       set in the other. chunk_size also serves as an index into the mask. */
    for (chunk_size = 1; chunk_size < 256; chunk_size <<= 1) {
        if ((mask & chunk_size) != 0)
            continue;
        for (i = 0; i < 256; i += chunk_size * 2) {
            for (j = 0; j < chunk_size; j++) {
                if (BIT_IS_SET(bits, i + j))
                    BIT_SET(bits, i + j + chunk_size);
                else if (BIT_IS_SET(bits, i + j + chunk_size))
                    BIT_SET(bits, i + j);
            }
        }
    }
}

/* Expand an addrset_elem's IPv4 bit vectors to include any additional addresses
   that result when the given netmask is applied. The mask is in network byte
   order. */
static void apply_ipv4_netmask(struct addrset_elem *elem, uint32_t mask)
{
    mask = ntohl(mask);
    /* Apply the mask one octet at a time. It's done this way because ranges
       span exactly one octet. */
    apply_ipv4_netmask_octet(elem->ipv4.bits[0], (mask & 0xFF000000) >> 24);
    apply_ipv4_netmask_octet(elem->ipv4.bits[1], (mask & 0x00FF0000) >> 16);
    apply_ipv4_netmask_octet(elem->ipv4.bits[2], (mask & 0x0000FF00) >> 8);
    apply_ipv4_netmask_octet(elem->ipv4.bits[3], (mask & 0x000000FF));
}

/* Expand an addrset_elem's IPv4 bit vectors to include any additional addresses
   that result from the application of a CIDR-style netmask with the given
   number of bits. If bits is negative it is taken to be 32. */
static void apply_ipv4_netmask_bits(struct addrset_elem *elem, int bits)
{
    uint32_t mask;

    if (bits > 32)
        return;
    if (bits < 0)
        bits = 32;

    if (bits == 0)
        mask = htonl(0x00000000);
    else
        mask = htonl(0xFFFFFFFF << (32 - bits));
    apply_ipv4_netmask(elem, mask);
}

static int match_ipv4_bits(const octet_bitvector bits[4], const struct sockaddr *sa)
{
    uint8_t octets[4];

    if (sa->sa_family != AF_INET)
        return 0;

    in_addr_to_octets(&((const struct sockaddr_in *) sa)->sin_addr, octets);

    return BIT_IS_SET(bits[0], octets[0])
        && BIT_IS_SET(bits[1], octets[1])
        && BIT_IS_SET(bits[2], octets[2])
        && BIT_IS_SET(bits[3], octets[3]);
}

static int addrset_elem_match(const struct addrset_elem *elem, const struct sockaddr *sa)
{
  return match_ipv4_bits(elem->ipv4.bits, sa);
}

int addrset_contains(const struct addrset *set, const struct sockaddr *sa)
{
    struct addrset_elem *elem;

    /* First check the trie. */
    if (trie_match(set->trie, sa))
      return 1;

    /* If that didn't match, check the rest of the addrset_elem in order */
    if (sa->sa_family == AF_INET) {
      for (elem = set->head; elem != NULL; elem = elem->next) {
        if (addrset_elem_match(elem, sa))
          return 1;
      }
    }

    return 0;
}
