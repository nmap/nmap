/***************************************************************************
 * xml.cc -- Simple library to emit XML.                                   *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id: xml.cc 15135 2009-08-19 21:05:21Z david $ */

/*
This is a simple library for writing XML. It handles two main things:
keeping track of the element stack, and escaping text where necessary.
If you wanted to write this XML:
  <?xml version="1.0"?>
  <elem name="&amp;10.5"></elem>
these are the functions you would call. Each one is followed by the text
it prints enclosed in ||.

xml_start_document()                   |<?xml version="1.0"?>|
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
