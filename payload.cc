
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <map>

#include "NmapOps.h"
#include "nbase.h"
#include "payload.h"
#include "utils.h"

extern NmapOps o;

struct payload {
  std::string data;
  /* Extra data such as source port goes here. */
};

/* The key for the payload lookup map is a (proto, port) pair. */
struct proto_dport {
  u8 proto;
  u16 dport;

  proto_dport(u8 proto, u16 dport) {
    this->proto = proto;
    this->dport = dport;
  }

  bool operator<(const proto_dport& other) const {
    if (proto == other.proto)
      return dport < other.dport;
    else
      return proto < other.proto;
  }
};

static std::map<struct proto_dport, struct payload> payloads;

/* Newlines are significant because keyword directives (like "source") that
   follow the payload string are significant to the end of the line. */
enum token_type {
  TOKEN_EOF = 0,
  TOKEN_NEWLINE,
  TOKEN_SYMBOL,
  TOKEN_STRING,
};

struct token {
  char text[1024];
  size_t len;
};

/* Returns a malloc-allocated list of the ports in portlist. portlist must
   contain one or more integers 0 <= p < 65536, separated by commas. */
static unsigned short *parse_portlist(const char *portlist, unsigned int *count) {
  uint32_t bitmap[65536 / 32];
  unsigned short *result;
  unsigned short i;
  unsigned int p;

  memset(bitmap, 0, sizeof(bitmap));
  *count = 0;
  for (;;) {
    long l;
    char *tail;

    errno = 0;
    l = strtol(portlist, &tail, 10);
    if (portlist == tail || errno != 0 || l < 0 || l > 65535)
      return NULL;
      if (!(bitmap[l / 32] & (1 << (l % 32)))) {
        bitmap[l / 32] |= (1 << (l % 32));
        (*count)++;
      }
    if (*tail == '\0')
      break;
    else if (*tail == ',')
      portlist = tail + 1;
    else
      return NULL;
  }

  result = (unsigned short *) malloc(sizeof(*result) * *count);
  if (result == NULL)
    return NULL;
  i = 0;
  for (p = 0; p < 65536 && i < *count; p++) {
    if (bitmap[p / 32] & (1 << (p % 32)))
      result[i++] = p;
  }

  return result;
}

static unsigned long line_no;

/* Get the next token from fp. The return value is the token type, or -1 on
   error. The token type is also stored in token->type. For TOKEN_SYMBOL and
   TOKEN_STRING, the text is stored in token->text and token->len. The text is
   null terminated. */
static int next_token(FILE *fp, struct token *token) {
  unsigned int i, tmplen;
  int c;

  token->len = 0;

  /* Skip whitespace and comments. */
  while (isspace(c = fgetc(fp)) && c != '\n')
    ;

  if (c == EOF) {
    return TOKEN_EOF;
  } else if (c == '\n') {
    line_no++;
    return TOKEN_NEWLINE;
  } else if (c == '#') {
    while ((c = fgetc(fp)) != EOF && c != '\n')
      ;
    if (c == EOF) {
      return TOKEN_EOF;
    } else {
      line_no++;
      return TOKEN_NEWLINE;
    }
  } else if (c == '"') {
    i = 0;
    while ((c = fgetc(fp)) != EOF && c != '\n' && c != '"') {
      if (i + 1 >= sizeof(token->text))
        return -1;
      if (c == '\\') {
        token->text[i++] = '\\';
        if (i + 1 >= sizeof(token->text))
          return -1;
        c = fgetc(fp);
        if (c == EOF)
          return -1;
      }
      token->text[i++] = c;
    }
    if (c != '"')
      return -1;
    token->text[i] = '\0';
    if (cstring_unescape(token->text, &tmplen) == NULL)
      return -1;
    token->len = tmplen;
    return TOKEN_STRING;
  } else {
    i = 0;
    if (i + 1 >= sizeof(token->text))
      return -1;
    token->text[i++] = c;
    while ((c = fgetc(fp)) != EOF && (isalnum(c) || c == ',')) {
      if (i + 1 >= sizeof(token->text))
        return -1;
      token->text[i++] = c;
    }
    ungetc(c, fp);
    token->text[i] = '\0';
    token->len = i;
    return TOKEN_SYMBOL;
  }

  return -1;
}

/* Loop over fp, reading tokens and adding payloads to the global payloads map
   as they are completed. Returns -1 on error. */
static int load_payloads_from_file(FILE *fp) {
  struct token token;
  int type;

  line_no = 1;
  type = next_token(fp, &token);
  for (;;) {
    unsigned short *ports;
    unsigned int count, p;
    std::string payload_data;

    while (type == TOKEN_NEWLINE)
      type = next_token(fp, &token);
    if (type == TOKEN_EOF)
      break;
    if (type != TOKEN_SYMBOL || strcmp(token.text, "udp") != 0) {      fprintf(stderr, "Expected \"udp\" at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      return -1;
    }

    type = next_token(fp, &token);
    if (type != TOKEN_SYMBOL) {      fprintf(stderr, "Expected a port list at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      return -1;
    }
    ports = parse_portlist(token.text, &count);
    if (ports == NULL) {
      fprintf(stderr, "Can't parse port list \"%s\" at line %lu of %s.\n", token.text, line_no, PAYLOAD_FILENAME);
      return -1;
    }

    payload_data.clear();
    for (;;) {
      type = next_token(fp, &token);
      if (type == TOKEN_STRING)
        payload_data.append(token.text, token.len);
      else if (type == TOKEN_NEWLINE)
        ; /* Nothing. */
      else
        break;
    }

    /* Ignore keywords like "source" to the end of the line. */
    if (type == TOKEN_SYMBOL && strcmp(token.text, "udp") != 0) {
      while (type != -1 && type != TOKEN_EOF && type != TOKEN_NEWLINE)
        type = next_token(fp, &token);
    }

    for (p = 0; p < count; p++) {
      struct proto_dport key(IPPROTO_UDP, ports[p]);
      struct payload payload;

      payload.data = payload_data;
      payloads[key] = payload;
    }

    free(ports);
  }

  return 0;
}

/* Ensure that the payloads map is initialized from the nmap-payloads file. This
   function keeps track of whether it has been called and does nothing after it
   is called the first time. */
int init_payloads(void) {
  static bool payloads_loaded = false;
  char filename[256];
  FILE *fp;
  int ret;

  if (payloads_loaded)
    return 0;

  payloads_loaded = true;

  if (nmap_fetchfile(filename, sizeof(filename), PAYLOAD_FILENAME) != 1){
    fatal("Service scan requested but I cannot find %s file.  It should be in %s, ~/.nmap/ or .", PAYLOAD_FILENAME, NMAPDATADIR);
  }

  /* Record where this data file was found. */
  o.loaded_data_files[PAYLOAD_FILENAME] = filename;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    fprintf(stderr, "Can't open %s for reading.\n", filename);
    return -1;
  }

  ret = load_payloads_from_file(fp);
  fclose(fp);

  return ret;
}

/* Get a payload appropriate for the given UDP port. For certain selected ports
   a payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *udp_port2payload(u16 dport, size_t *length) {
  static const char *payload_null = "";
  std::map<struct proto_dport, struct payload>::iterator it;
  proto_dport pp(IPPROTO_UDP, dport);

  it = payloads.find(pp);
  if (it != payloads.end()) {
    *length = it->second.data.size();
    return it->second.data.data();
  } else {
    *length = 0;
    return payload_null;
  }
}

/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *get_udp_payload(u16 dport, size_t *length) {
  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  } else {
    return udp_port2payload(dport, length);
  }
}
