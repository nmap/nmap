
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl. This header  *
 * summarizes some key points from the Nmap license, but is no substitute  *
 * for the actual license text.                                            *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem                                  *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.org) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem.                            *
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
#include "nmap_error.h"
#include "scan_lists.h"

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

static std::map<struct proto_dport, std::vector<struct payload> > portPayloads;

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
    token->text[i++] = c;
    while ((c = fgetc(fp)) != EOF && (isalnum(c) || c == ',' || c == '-')) {
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
    int count;
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
    getpts_simple(token.text, SCAN_UDP_PORT, &ports, &count);
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

    for (int p = 0; p < count; p++) {
      std::map<struct proto_dport, std::vector<struct payload> >::iterator portPayloadIterator;
      std::vector<struct payload> portPayloadVector;
      std::vector<struct payload>::iterator portPayloadVectorIterator;
      struct proto_dport key(IPPROTO_UDP, ports[p]);
      struct payload portPayload;
      bool duplicate = false;

      portPayloadIterator = portPayloads.find(key);

      if (portPayloadIterator != portPayloads.end()) {
        portPayloadVector = portPayloadIterator->second;
        portPayloadVectorIterator = portPayloadVector.begin();

        while (portPayloadVectorIterator != portPayloadVector.end()) {
          if (portPayloadVectorIterator->data == payload_data) {
            log_write(LOG_STDERR, "UDP port payload duplication found on port: %u\n", ports[p]);
            duplicate = true;
            break;
          }

          portPayloadVectorIterator++;
        }
      }

      if (!duplicate) {
        portPayload.data = payload_data;
        portPayloadVector.push_back(portPayload);
        portPayloads[key] = portPayloadVector;
      }
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
const char *udp_port2payload(u16 dport, size_t *length, u8 tryno) {
  static const char *payload_null = "";
  std::map<struct proto_dport, std::vector<struct payload> >::iterator portPayloadIterator;
  std::vector<struct payload> portPayloadVector;
  std::vector<struct payload>::iterator portPayloadVectorIterator;
  proto_dport key(IPPROTO_UDP, dport);
  int portPayloadVectorSize;

  portPayloadIterator = portPayloads.find(key);

  if (portPayloadIterator != portPayloads.end()) {
    portPayloadVector = portPayloads.find(key)->second;
    portPayloadVectorSize = portPayloadVector.size();

    tryno %= portPayloadVectorSize;

    if (portPayloadVectorSize > 0) {
      portPayloadVectorIterator = portPayloadVector.begin();

      while (tryno > 0 && portPayloadVectorIterator != portPayloadVector.end()) {
        tryno--;
        portPayloadVectorIterator++;
      }

      assert (tryno == 0);
      assert (portPayloadVectorIterator != portPayloadVector.end());

      *length = portPayloadVectorIterator->data.size();
      return portPayloadVectorIterator->data.data();
    } else {
      *length = 0;
      return payload_null;
    }
  } else {
    *length = 0;
    return payload_null;
  }
}

/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *get_udp_payload(u16 dport, size_t *length, u8 tryno) {
  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  } else {
    return udp_port2payload(dport, length, tryno);
  }
}
