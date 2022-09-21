
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2022 Nmap Software LLC ("The Nmap *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl/ . This       *
 * header summarizes some key points from the Nmap license, but is no      *
 * substitute for the actual license text.                                 *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem/                                 *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.com) for packet capture and transmission. It is under    *
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
 * changes as a GitHub PR or by email to the dev@nmap.org mailing list     *
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
 * Npcap OEM program--see https://nmap.org/oem/                            *
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

  payload (const char *c, size_t n)
    : data(c, n)
    {}
  /* Extra data such as source port goes here. */

  /* If 2 payloads are equivalent according to this operator, we'll only keep
   * the first one, so be sure you update it when adding other attributes. */
  bool operator==(const payload& other) const {
    return data == other.data;
  }
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

static std::map<struct proto_dport, std::vector<struct payload *> > portPayloads;
static std::vector<struct payload *> uniquePayloads; // for accounting

/* Newlines are significant because keyword directives (like "source") that
   follow the payload string are significant to the end of the line. */
typedef enum token_type {
  TOKEN_ERROR = -1,
  TOKEN_EOF = 0,
  TOKEN_NEWLINE,
  TOKEN_SYMBOL,
  TOKEN_STRING,
} token_t;

struct token {
  token_t type;
  size_t len;
  char text[1024];
};

static unsigned long line_no;

/* Get the next token from fp. The return value is the token type, or -1 on
   error. The token type is also stored in token->type. For TOKEN_SYMBOL and
   TOKEN_STRING, the text is stored in token->text and token->len. The text is
   null terminated. */
static token_t next_token(FILE *fp, struct token *token) {
  unsigned int i, tmplen;
  int c;

  token->len = 0;

  /* Skip whitespace and comments. */
  while (isspace(c = fgetc(fp)) && c != '\n')
    ;

  switch(c) {
    case EOF:
      token->type = TOKEN_EOF;
      break;
    case '\n':
      line_no++;
      token->type = TOKEN_NEWLINE;
      break;
    case '#':
      while ((c = fgetc(fp)) != EOF && c != '\n')
        ;
      if (c == EOF) {
        token->type = TOKEN_EOF;
      } else {
        line_no++;
        token->type = TOKEN_NEWLINE;
      }
      break;
    case '"':
      token->type = TOKEN_STRING;
      i = 0;
      while ((c = fgetc(fp)) != EOF && c != '\n' && c != '"') {
        if (i + 1 >= sizeof(token->text))
          return TOKEN_ERROR;
        if (c == '\\') {
          token->text[i++] = '\\';
          if (i + 1 >= sizeof(token->text))
            return TOKEN_ERROR;
          c = fgetc(fp);
          if (c == EOF)
            return TOKEN_ERROR;
        }
        token->text[i++] = c;
      }
      if (c != '"')
        return TOKEN_ERROR;
      token->text[i] = '\0';
      if (cstring_unescape(token->text, &tmplen) == NULL)
        return TOKEN_ERROR;
      token->len = tmplen;
      break;
    default:
      token->type = TOKEN_SYMBOL;
      i = 0;
      token->text[i++] = c;
      while ((c = fgetc(fp)) != EOF && (isalnum(c) || c == ',' || c == '-')) {
        if (i + 1 >= sizeof(token->text))
          return TOKEN_ERROR;
        token->text[i++] = c;
      }
      ungetc(c, fp);
      token->text[i] = '\0';
      token->len = i;
      break;
  }

  return token->type;
}

/* Loop over fp, reading tokens and adding payloads to the global payloads map
   as they are completed. Returns -1 on error. */
static int load_payloads_from_file(FILE *fp) {
  struct token token;
  unsigned long firstline = 0;

  line_no = 1;
  token_t type = next_token(fp, &token);
  for (;;) {
    unsigned short *ports;
    int count;
    bool duplicate = false;

    /* Skip everything (unknown keywords from previous payload, unknown file
     * keywords, etc.) until the next payload entry or EOF */
    while (type != TOKEN_EOF && !(type == TOKEN_SYMBOL && strcmp(token.text, "udp") == 0))
      type = next_token(fp, &token);
    if (type == TOKEN_EOF)
      break;

    firstline = line_no;

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

    while(TOKEN_NEWLINE == (type = next_token(fp, &token)))
      ; // skip newlines

    if (type != TOKEN_STRING) {
      log_write(LOG_STDERR, "Payload missing data at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      // Try a new payload
      free(ports);
      continue;
    }

    struct payload *portPayload = NULL;
    // Peek at the next significant token
    struct token peek_token;
    while (TOKEN_NEWLINE == (type = next_token(fp, &peek_token)))
      ; // skip newlines

    // If it's a string continuation, see if we can squeeze it into the current token.
    while (type == TOKEN_STRING) {
      if (token.len + peek_token.len < sizeof(token.text)) {
        // Next string fits in this one's buffer!
        memcpy(token.text + token.len, peek_token.text, peek_token.len);
        token.len += peek_token.len;
      }
      else {
        // Token is full
        if (portPayload == NULL) {
          // Allocate new payload
          portPayload = new struct payload (token.text, token.len);
        }
        else {
          // append token to current payload
          portPayload->data.append(token.text, token.len);
        }
        // peek_token becomes the previous token
        token = peek_token;
      }
      // Keep peeking forward
      while (TOKEN_NEWLINE == (type = next_token(fp, &peek_token)))
        ; // skip newlines
    }

    // If the string is still going, but we got an error, abandon this payload.
    if (type == TOKEN_ERROR && peek_token.type == TOKEN_STRING) {
      log_write(LOG_STDERR, "Error parsing payload data at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      if (portPayload)
        delete portPayload;
      // maybe we can pick up at the next payload.
      type = next_token(fp, &token);
      free(ports);
      continue;
    }

    // Otherwise, stash the last token in the payload and move on.
    if (portPayload == NULL) {
      // Allocate new payload
      portPayload = new struct payload (token.text, token.len);
    }
    else {
      // append token to current payload
      portPayload->data.append(token.text, token.len);
    }
    token = peek_token;

    // Here we would parse additional keywords like "source" that we might care about.

    // Make sure these payloads are actually unique!
    for (std::vector<struct payload *>::const_iterator it = uniquePayloads.begin();
        it != uniquePayloads.end(); ++it) {
      if (**it == *portPayload) {
        // Probably not what they intended.
        log_write(LOG_STDERR, "Duplicate payload on line %lu of %s.\n", firstline, PAYLOAD_FILENAME);
        // Since they're functionally equivalent, only keep one copy.
        duplicate = true;
        delete portPayload;
        portPayload = *it;
        break;
      }
    }
    if (!duplicate) {
      uniquePayloads.push_back(portPayload);
      duplicate = false;
    }

    for (int p = 0; p < count; p++) {
      const struct proto_dport key(IPPROTO_UDP, ports[p]);

      std::vector<struct payload *> &portPayloadVector = portPayloads[key];

      // Ports are unique, and we ensured payloads are unique earlier, so no chance of duplicate here.
      portPayloadVector.push_back(portPayload);
      if (portPayloadVector.size() > MAX_PAYLOADS_PER_PORT) {
        fatal("Number of UDP payloads for port %u exceeds the limit of %u.\n", ports[p], MAX_PAYLOADS_PER_PORT);
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
    gh_perror("Can't open %s for reading.\n", filename);
    return -1;
  }
  /* Record where this data file was found. */
  o.loaded_data_files[PAYLOAD_FILENAME] = filename;

  ret = load_payloads_from_file(fp);
  fclose(fp);

  return ret;
}

void free_payloads(void) {
  std::vector<struct payload *>::iterator vec_it;

  for (vec_it = uniquePayloads.begin(); vec_it != uniquePayloads.end(); ++vec_it) {
    delete *vec_it;
  }
  uniquePayloads.clear();
  portPayloads.clear();
}

/* Get a payload appropriate for the given UDP port. For certain selected ports
   a payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *udp_port2payload(u16 dport, size_t *length, u8 index) {
  static const char *payload_null = "";
  std::map<struct proto_dport, std::vector<struct payload *> >::const_iterator portPayloadIterator;
  std::vector<struct payload *>::const_iterator portPayloadVectorIterator;
  const proto_dport key(IPPROTO_UDP, dport);
  int portPayloadVectorSize;

  portPayloadIterator = portPayloads.find(key);

  if (portPayloadIterator != portPayloads.end()) {
    const std::vector<struct payload *>& portPayloadVector = portPayloads.find(key)->second;
    portPayloadVectorSize = portPayloadVector.size();

    index %= portPayloadVectorSize;

    if (portPayloadVectorSize > 0) {
      portPayloadVectorIterator = portPayloadVector.begin();

      while (index > 0 && portPayloadVectorIterator != portPayloadVector.end()) {
        index--;
        portPayloadVectorIterator++;
      }

      assert (index == 0);
      assert (portPayloadVectorIterator != portPayloadVector.end());

      const std::string &data = (*portPayloadVectorIterator)->data;
      *length = data.size();
      return data.data();
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
const char *get_udp_payload(u16 dport, size_t *length, u8 index) {
  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  } else {
    return udp_port2payload(dport, length, index);
  }
}

u8 udp_payload_count(u16 dport) {
  std::map<struct proto_dport, std::vector<struct payload *> >::const_iterator portPayloadIterator;
  const proto_dport key(IPPROTO_UDP, dport);
  size_t portPayloadVectorSize = 0;

  portPayloadIterator = portPayloads.find(key);

  if (portPayloadIterator != portPayloads.end()) {
    portPayloadVectorSize = portPayloadIterator->second.size();
  }

  return portPayloadVectorSize;
}
