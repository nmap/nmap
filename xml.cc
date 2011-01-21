/***************************************************************************
 * xml.cc -- Simple library to emit XML.                                   *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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

/* $Id: xml.cc 15135 2009-08-19 21:05:21Z david $ */

/*
This is a simple library for writing XML. It handles two main things:
keeping track of the element stack, and escaping text where necessary.
Here is an example of writing
  <?xml version="1.0"?>
  <elem name="&amp;10.5"></elem>
Each function call is followed by the text it prints enclosed in ||.

xml_start_document()                   |<?xml version="1.0"?>
xml_newline();                         |\n|
xml_open_start_tag("elem");            |<elem|
xml_attribute("name", "&%.1f", 10.5);  | name="&amp;10.5"|
xml_close_start_tag();                 |>|
xml_end_tag();                         |</elem>|

The typical use is to call xml_open_start_tag, then call xml_attribute a
number of times. That is followed by xml_close_empty_tag, or else
xml_close_start_tag followed by xml_end_tag later one. You can call
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
xml_write_escaped_v           XML_escaped output, with a va_list.
xml_start_document            Writes <?xml version="1.0"?>.
xml_depth                     Returns the size of the element stack.

The library makes it harder but not impossible to make non-well-formed
XML. For example, you can call xml_start_tag, xml_end_tag,
xml_start_tag, xml_end_tag to create a document with two root elements.
Things like element names aren't checked to be sure they're legal. Text
given to these functions should be ASCII or UTF-8.

All writing is done with log_write(LOG_XML), so if LOG_XML hasn't been
opened, calling these functions has no effect.
*/

#include "nmap.h"
#include "output.h"
#include "xml.h"

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

static char *alloc_vsprintf(const char *fmt, va_list va) __attribute__ ((format (printf, 1, 0)));

/* vsprintf into a dynamically allocated buffer, similar to asprintf in
   Glibc. Return the buffer or NULL on error. */
static char *alloc_vsprintf(const char *fmt, va_list va) {
  va_list va_tmp;
  char *s, *p;
  int size = 32;
  int n;

  s = NULL;
  size = 32;
  for (;;) {
    p = (char *) safe_realloc(s, size);
    if (p == NULL)
      return NULL;
    s = p;

#ifdef WIN32
    va_tmp = va;
#else
    va_copy(va_tmp, va);
#endif
    n = vsnprintf(s, size, fmt, va_tmp);

    if (n >= size)
      size = n + 1;
    else if (n < 0)
      size = size * 2;
    else
      break;
  }

  return s;
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
  s = alloc_vsprintf(fmt, va);
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

  s = alloc_vsprintf(fmt, va);
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

/* Write the XML declaration: <?xml version="1.0"?>. */
int xml_start_document() {
  if (xml_open_pi("xml") < 0)
    return -1;
  if (xml_attribute("version", "1.0") < 0)
    return -1;
  if (xml_close_pi() < 0)
    return -1;
  if (xml_newline() < 0)
    return -1;

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
int xml_open_start_tag(const char *name) {
  assert(!xml.tag_open);
  log_write(LOG_XML, "<%s", name);
  xml.element_stack.push_back(name);
  xml.tag_open = true;
  xml.root_written = true;

  return 0;
}

int xml_close_start_tag() {
  assert(xml.tag_open);
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

int xml_start_tag(const char *name) {
  if (xml_open_start_tag(name) < 0)
    return -1;
  if (xml_close_start_tag() < 0)
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
  val = alloc_vsprintf(fmt, va);
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
bool xml_root_written() {
  return xml.root_written;
}
