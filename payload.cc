
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nmap.h"

#include <errno.h>
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
    if (type != TOKEN_SYMBOL || strcmp(token.text, "udp") != 0) {
      fprintf(stderr, "Expected \"udp\" at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      return -1;
    }

    type = next_token(fp, &token);
    if (type != TOKEN_SYMBOL) {
      fprintf(stderr, "Expected a port list at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
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

  if (nmap_fetchfile(filename, sizeof(filename), PAYLOAD_FILENAME) != 1) {
    error("Cannot find %s. UDP payloads are disabled.", PAYLOAD_FILENAME);
    return 0;
  }

  fp = fopen(filename, "r");
  if (fp == NULL) {
    fprintf(stderr, "Can't open %s for reading.\n", filename);
    return -1;
  }
  /* Record where this data file was found. */
  o.loaded_data_files[PAYLOAD_FILENAME] = filename;

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
