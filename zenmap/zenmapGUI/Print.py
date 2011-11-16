#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

# This prints the normal (text) output of a single scan. Ideas for further
# development:
#
# Print the topology graphic. The graphic is already made with Cairo so the same
# code can be used to draw on the print context.
#
# Print in color with highlighting, like NmapOutputViewer.
#
# Add a header to each page with the Nmap command and page number.
#
# Add options to the print dialog to control the font, coloring, and anything
# else. This might go in a separate Print Setup dialog.

import gtk
import pango

MONOSPACE_FONT_DESC = pango.FontDescription("Monospace 12")

class PrintState (object):
    """This is the userdatum passed to gtk.PrintOperation callbacks."""

    def __init__(self, inventory, entry):
        """entry is a ScansListStoreEntry."""
        if entry.parsed:
            # Finished scan.
            output = entry.parsed.nmap_output
        else:
            # Still running, failed, or cancelled.
            output = entry.command.get_output()
        if not output:
            output = u"\n"
        self.lines = output.splitlines()

    def begin_print(self, op, context):
        """Calculates the number of printed pages."""
        # Typeset a dummy line to get the exact line height.
        layout = context.create_pango_layout()
        layout.set_font_description(MONOSPACE_FONT_DESC)
        layout.set_text("dummy")
        line = layout.get_line(0)
        # get_extents()[1][3] is the height of the logical rectangle.
        line_height = line.get_extents()[1][3] / float(pango.SCALE)

        page_height = context.get_height()
        self.lines_per_page = int(page_height / line_height)
        op.set_n_pages((len(self.lines) - 1) / self.lines_per_page + 1)

    def draw_page(self, op, context, page_nr):
        this_page_lines = self.lines[page_nr * self.lines_per_page:(page_nr + 1) * self.lines_per_page]
        layout = context.create_pango_layout()
        # Do no wrapping.
        layout.set_width(-1)
        layout.set_font_description(MONOSPACE_FONT_DESC)
        text = "\n".join(this_page_lines).encode("utf8")
        layout.set_text(text)

        cr = context.get_cairo_context()
        cr.show_layout(layout)

def run_print_operation(inventory, entry):
    op = gtk.PrintOperation()
    state = PrintState(inventory, entry)
    op.connect("begin-print", state.begin_print)
    op.connect("draw-page", state.draw_page)
    op.run(gtk.PRINT_OPERATION_ACTION_PRINT_DIALOG, None)
