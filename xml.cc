/***************************************************************************
 * xml.cc -- Simple library to emit XML.                                   *
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

/* $Id: xml.cc 15135 2009-08-19 21:05:21Z david $ */

/*
This is a simple library for writing XML. It handles two main things:
keeping track of the element stack, and escaping text where necessary.
If you wanted to write this XML:
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE elem>
  <elem name="&amp;10.5"></elem>
these are the functions you would call. Each one is followed by the text
it prints enclosed in ||.

xml_start_document("elem")             |<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE elem>|
xml_newline();                         |\n|
xml_open_start_tag("elem");            |<elem|
xml_attribute("name", "&%.1f", 10.5);  | name="&amp;10.5"|
xml_close_start_tag();                 |>|
xml_end_tag();                         |</elem>|

The typical use is to call xml_open_start_tag, then call xml_attribute a
number of times. That is followed by xml_close_empty_tag, or else
xml_close_start_tag followed by xml_end_tag later on. You can call
xml_start_tag if there are no attributes. Whenever a start tag is opened
with xml_open_start_tag or xml_start_tag, the element name is pushed on
the tag stack. xml_end_tag pops the element stack and closes the element
it finds.

Here is a summary of all the elementary writing functions. The functions
return 0 on success and -1 on error. The terms "start" and "end" refer
to start and end tags and the start and end of comments. The terms
"open" and "close" refer only to start tags and processing instructions.

xml_start_comment()           |<!--|
xml_end_comment()             |-->|
xml_open_pi("elem")           |<?elem|
xml_close_pi()                |?>|
xml_open_start_tag("elem")    |<elem|
xml_close_start_tag()         |>|
xml_close_empty_tag()         |/>|
xml_start_tag("elem")         |<elem>|
xml_end_tag()                 |</elem>|
xml_attribute("name", "val")  | name="val"|
xml_newline()                 |\n|

Additional functions are

xml_write_raw                 Raw unescaped output.
xml_write_escaped             XML-escaped output.
xml_write_escaped_v           XML-escaped output, with a va_list.
xml_start_document            Writes <?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE elem>.
xml_depth                     Returns the size of the element stack.

The library makes it harder but not impossible to make non-well-formed
XML. For example, you can call xml_start_tag, xml_end_tag,
xml_start_tag, xml_end_tag to create a document with two root elements.
Things like element names aren't checked to be sure they're legal. Text
given to these functions should be ASCII or UTF-8.

All writing is done with log_write(LOG_XML), so if LOG_XML hasn't been
opened, calling these functions has no effect.
*/

#include "output.h"
#include "xml.h"
#include <nbase.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <list>

struct xml_writer {
  /* Sanity checking: Don't open a new tag while still defining
     attributes for another, like "<elem1<elem2". */
  bool tag_open;
  /* Has the root element been started yet? If so, and if
     element_stack.size() == 0, then the document is finished. */
  bool root_written;
  std::list<const char *> element_stack;
};

static struct xml_writer xml;

char *xml_unescape(const char *str) {
  char *result = NULL;
  size_t n = 0, len;
  const char *p;
  int i;

  i = 0;
  for (p = str; *p != '\0'; p++) {
    const char *repl;
    char buf[32];

    if (*p != '&') {
      /* Based on the asumption that ampersand is only used for escaping. */
      buf[0] = *p;
      buf[1] = '\0';
      repl = buf;
    } else if (strncmp(p, "&lt;", 4) == 0) {
      repl = "<";
      p += 3;
    } else if (strncmp(p, "&gt;", 4) == 0) {
      repl = ">";
      p += 3;
    } else if (strncmp(p, "&amp;", 5) == 0) {
      repl = "&";
      p += 4;
    } else if (strncmp(p, "&quot;", 6) == 0) {
      repl = "\"";
      p += 5;
    } else if (strncmp(p, "&apos;", 6) == 0) {
      repl = "\'";
      p += 5;
    } else if (strncmp(p, "&#45;", 5) == 0) {
      repl = "-";
      p += 4;
    } else {
      /* Escaped control characters and anything outside of ASCII. */
      Strncpy(buf, p + 3, sizeof(buf));
      char *q;
      q = strchr(buf, ';');
      if(!q)
        buf[0] = '\0';
      else
        *q = '\0';
      repl = buf;
    }

    len = strlen(repl);
    /* Double the size of the result buffer if necessary. */
    if (i == 0 || i + len > n) {
      n = (i + len) * 2;
      result = (char *) safe_realloc(result, n + 1);
    }
    memcpy(result + i, repl, len);
    i += len;
  }
  /* Trim to length. (Also does initial allocation when str is empty.) */
  result = (char *) safe_realloc(result, i + 1);
  result[i] = '\0';

  return result;
}

/* Escape a string for inclusion in XML. This gets <>&, "' for attribute
   values, -- for inside comments, and characters with value > 0x7F. It
   also gets control characters with value < 0x20 to avoid parser
   normalization of \r\n\t in attribute values. If this is not desired
   in some cases, we'll have to add a parameter to control this. */
static char *escape(const char *str) {
  /* result is the result buffer; n + 1 is the allocated size. Double the
     allocation when space runs out. */
  char *result = NULL;
  size_t n = 0, len;
  const char *p;
  int i;

  i = 0;
  for (p = str; *p != '\0'; p++) {
    const char *repl;
    char buf[32];

    if (*p == '<')
      repl = "&lt;";
    else if (*p == '>')
      repl = "&gt;";
    else if (*p == '&')
      repl = "&amp;";
    else if (*p == '"')
      repl = "&quot;";
    else if (*p == '\'')
      repl = "&apos;";
    else if (*p == '-' && p > str && *(p - 1) == '-') {
      /* Escape -- for comments. */
      repl = "&#45;";
    } else if (*p < 0x20 || (unsigned char) *p > 0x7F) {
      /* Escape control characters and anything outside of ASCII. We have to
         emit UTF-8 and an easy way to do that is to emit ASCII. */
      Snprintf(buf, sizeof(buf), "&#x%x;", (unsigned char) *p);
      repl = buf;
    } else {
      /* Unescaped character. */
      buf[0] = *p;
      buf[1] = '\0';
      repl = buf;
    }

    len = strlen(repl);
    /* Double the size of the result buffer if necessary. */
    if (i == 0 || i + len > n) {
      n = (i + len) * 2;
      result = (char *) safe_realloc(result, n + 1);
    }
    memcpy(result + i, repl, len);
    i += len;
  }
  /* Trim to length. (Also does initial allocation when str is empty.) */
  result = (char *) safe_realloc(result, i + 1);
  result[i] = '\0';

  return result;
}

/* Write data directly to the XML file with no escaping. Make sure you
   know what you're doing. */
int xml_write_raw(const char *fmt, ...) {
  va_list va;
  char *s;

  va_start(va, fmt);
  alloc_vsprintf(&s, fmt, va);
  va_end(va);
  if (s == NULL)
    return -1;

  log_write(LOG_XML, "%s", s);
  free(s);

  return 0;
}

/* Write data directly to the XML file after escaping it. */
int xml_write_escaped(const char *fmt, ...) {
  va_list va;
  int n;

  va_start(va, fmt);
  n = xml_write_escaped_v(fmt, va);
  va_end(va);

  return n;
}

/* Write data directly to the XML file after escaping it. This version takes a
   va_list like vprintf. */
int xml_write_escaped_v(const char *fmt, va_list va) {
  char *s, *esc_s;

  alloc_vsprintf(&s, fmt, va);
  if (s == NULL)
    return -1;
  esc_s = escape(s);
  free(s);
  if (esc_s == NULL)
    return -1;

  log_write(LOG_XML, "%s", esc_s);
  free(esc_s);

  return 0;
}

/* Write the XML declaration: <?xml version="1.0" encoding="UTF-8"?>
 * and the DOCTYPE declaration: <!DOCTYPE rootnode>
 */
int xml_start_document(const char *rootnode) {
  if (xml_open_pi("xml") < 0)
    return -1;
  if (xml_attribute("version", "1.0") < 0)
    return -1;
  /* Practically, Nmap only uses ASCII, but UTF-8 encompasses ASCII and allows
   * for future expansion */
  if (xml_attribute("encoding", "UTF-8") < 0)
    return -1;
  if (xml_close_pi() < 0)
    return -1;
  if (xml_newline() < 0)
    return -1;

  log_write(LOG_XML, "<!DOCTYPE %s>\n", rootnode);

  return 0;
}

int xml_start_comment() {
  log_write(LOG_XML, "<!--");

  return 0;
}

int xml_end_comment() {
  log_write(LOG_XML, "-->");

  return 0;
}

int xml_open_pi(const char *name) {
  assert(!xml.tag_open);
  log_write(LOG_XML, "<?%s", name);
  xml.tag_open = true;

  return 0;
}

int xml_close_pi() {
  assert(xml.tag_open);
  log_write(LOG_XML, "?>");
  xml.tag_open = false;

  return 0;
}

/* Open a start tag, like "<name". The tag must be later closed with
   xml_close_start_tag or xml_close_empty_tag. Usually the tag is closed
   after writing some attributes. */
int xml_open_start_tag(const char *name, const bool write) {
  assert(!xml.tag_open);
  if (write)
    log_write(LOG_XML, "<%s", name);
  xml.element_stack.push_back(name);
  xml.tag_open = true;
  xml.root_written = true;

  return 0;
}

int xml_close_start_tag(const bool write) {
  assert(xml.tag_open);
  if(write)
    log_write(LOG_XML, ">");
  xml.tag_open = false;

  return 0;
}

/* Close an empty-element tag. It should have been opened with
   xml_open_start_tag. */
int xml_close_empty_tag() {
  assert(xml.tag_open);
  assert(!xml.element_stack.empty());
  xml.element_stack.pop_back();
  log_write(LOG_XML, "/>");
  xml.tag_open = false;

  return 0;
}

int xml_start_tag(const char *name, const bool write) {
  if (xml_open_start_tag(name, write) < 0)
    return -1;
  if (xml_close_start_tag(write) < 0)
    return -1;

  return 0;
}

/* Write an end tag for the element at the top of the element stack. */
int xml_end_tag() {
  const char *name;

  assert(!xml.tag_open);
  assert(!xml.element_stack.empty());
  name = xml.element_stack.back();
  xml.element_stack.pop_back();

  log_write(LOG_XML, "</%s>", name);

  return 0;
}

/* Write an attribute. The only place this makes sense is between
   xml_open_start_tag and either xml_close_start_tag or
   xml_close_empty_tag. */
int xml_attribute(const char *name, const char *fmt, ...) {
  va_list va;
  char *val, *esc_val;

  assert(xml.tag_open);

  va_start(va, fmt);
  alloc_vsprintf(&val, fmt, va);
  va_end(va);
  if (val == NULL)
    return -1;
  esc_val = escape(val);
  free(val);
  if (esc_val == NULL)
    return -1;

  log_write(LOG_XML, " %s=\"%s\"", name, esc_val);
  free(esc_val);

  return 0;
}

int xml_newline() {
  log_write(LOG_XML, "\n");

  return 0;
}

/* Return the size of the element stack. */
int xml_depth() {
  return xml.element_stack.size();
}

/* Return true iff a root element has been started. */
bool xml_tag_open() {
  return xml.tag_open;
}

/* Return true iff a root element has been started. */
bool xml_root_written() {
  return xml.root_written;
}
