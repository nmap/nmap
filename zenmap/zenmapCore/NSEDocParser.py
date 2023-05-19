#!/usr/bin/env python3

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
# * Project"). Nmap is also a registered trademark of the Nmap Project.
# *
# * This program is distributed under the terms of the Nmap Public Source
# * License (NPSL). The exact license text applying to a particular Nmap
# * release or source code control revision is contained in the LICENSE
# * file distributed with that version of Nmap or source code control
# * revision. More Nmap copyright/legal information is available from
# * https://nmap.org/book/man-legal.html, and further information on the
# * NPSL license itself can be found at https://nmap.org/npsl/ . This
# * header summarizes some key points from the Nmap license, but is no
# * substitute for the actual license text.
# *
# * Nmap is generally free for end users to download and use themselves,
# * including commercial use. It is available from https://nmap.org.
# *
# * The Nmap license generally prohibits companies from using and
# * redistributing Nmap in commercial products, but we sell a special Nmap
# * OEM Edition with a more permissive license and special features for
# * this purpose. See https://nmap.org/oem/
# *
# * If you have received a written Nmap license agreement or contract
# * stating terms other than these (such as an Nmap OEM license), you may
# * choose to use and redistribute Nmap under those terms instead.
# *
# * The official Nmap Windows builds include the Npcap software
# * (https://npcap.com) for packet capture and transmission. It is under
# * separate license terms which forbid redistribution without special
# * permission. So the official Nmap Windows builds may not be redistributed
# * without special permission (such as an Nmap OEM license).
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# * This also allows you to audit the software for security holes.
# *
# * Source code also allows you to port Nmap to new platforms, fix bugs, and add
# * new features. You are highly encouraged to submit your changes as a Github PR
# * or by email to the dev@nmap.org mailing list for possible incorporation into
# * the main distribution. Unless you specify otherwise, it is understood that
# * you are offering us very broad rights to use your submissions as described in
# * the Nmap Public Source License Contributor Agreement. This is important
# * because we fund the project by selling licenses with various terms, and also
# * because the inability to relicense code has caused devastating problems for
# * other Free Software projects (such as KDE and NASM).
# *
# * The free version of Nmap is distributed in the hope that it will be
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
# * indemnification and commercial support are all available through the
# * Npcap OEM program--see https://nmap.org/oem/
# *
# ***************************************************************************/

import re


class NSEDocEvent (object):
    def __init__(self, type, text=None):
        self.type = type
        self.text = text


def nsedoc_parse_sub(text, pos):
    """Parse paragraph-level NSEDoc markup, inside of paragraphs and lists.
    Returns the position after the end of parsing followed by a list of
    events."""
    events = []
    m = re.match(r'([^\n]*?)<code>(.*?)</code>', text[pos:], re.S)
    if m:
        if m.group(1):
            events.append(NSEDocEvent("text", m.group(1).replace("\n", " ")))
        events.append(NSEDocEvent("code", m.group(2)))
        return pos + m.end(), events
    m = re.match(r'[^\n]*(\n|$)', text[pos:])
    if m:
        if m.group():
            events.append(NSEDocEvent("text", m.group().replace("\n", " ")))
        return pos + m.end(), events
    return pos, events


def nsedoc_parse(text):
    """Parse text marked up for NSEDoc. This is a generator that returns a
    sequence of NSEDocEvents. The type of the event may be "paragraph_start",
    "paragraph_end", "list_start", "list_end", "list_item_start",
    "list_item_end", "text", or "code". The types "text" and "code" have a text
    member with the text that they contain."""
    i = 0
    in_list = False

    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        yield NSEDocEvent("paragraph_start")
        while i < len(text):
            if re.match(r'\s*(\n|$)', text[i:]):
                break
            if text.startswith("* ", i):
                if not in_list:
                    yield NSEDocEvent("list_start")
                    in_list = True
                i += 2
                yield NSEDocEvent("list_item_start")
                i, events = nsedoc_parse_sub(text, i)
                for event in events:
                    yield event
                yield NSEDocEvent("list_item_end")
            else:
                if in_list:
                    yield NSEDocEvent("list_end")
                    in_list = False
                i, events = nsedoc_parse_sub(text, i)
                for event in events:
                    yield event
        if in_list:
            yield NSEDocEvent("list_end")
            in_list = False
        yield NSEDocEvent("paragraph_end")
