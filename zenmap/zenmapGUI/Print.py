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

# This prints the normal (text) output of a single scan. Ideas for further
# development:
#
# Print the topology graphic. The graphic is already made with Cairo so the
# same code can be used to draw on the print context.
#
# Print in color with highlighting, like NmapOutputViewer.
#
# Add a header to each page with the Nmap command and page number.
#
# Add options to the print dialog to control the font, coloring, and anything
# else. This might go in a separate Print Setup dialog.

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("PangoCairo", "1.0")
from gi.repository import Gtk, GLib, Pango, PangoCairo

MONOSPACE_FONT_DESC = Pango.FontDescription("Monospace 12")


class PrintState(object):
    """This is the userdatum passed to Gtk.PrintOperation callbacks."""

    def __init__(self, inventory, entry):
        """entry is a ScansListStoreEntry."""
        if entry.parsed:
            # Finished scan.
            output = entry.parsed.nmap_output
        else:
            # Still running, failed, or cancelled.
            output = entry.command.get_output()
        if not output:
            output = "\n"
        self.lines = output.splitlines()

    def begin_print(self, op, context):
        """Calculates the number of printed pages."""
        # Typeset a dummy line to get the exact line height.
        layout = context.create_pango_layout()
        layout.set_font_description(MONOSPACE_FONT_DESC)
        layout.set_text("dummy", -1)
        line = layout.get_line(0)
        # get_extents()[1].height is the height of the logical rectangle.
        line_height = line.get_extents()[1].height / Pango.SCALE

        page_height = context.get_height()
        self.lines_per_page = int(page_height / line_height)
        op.set_n_pages((len(self.lines) - 1) // self.lines_per_page + 1)

    def draw_page(self, op, context, page_nr):
        this_page_lines = self.lines[
                page_nr * self.lines_per_page:
                (page_nr + 1) * self.lines_per_page]
        layout = context.create_pango_layout()
        # Do no wrapping.
        layout.set_width(-1)
        layout.set_font_description(MONOSPACE_FONT_DESC)
        text = "\n".join(this_page_lines)
        layout.set_text(text, -1)

        cr = context.get_cairo_context()
        PangoCairo.show_layout(cr, layout)


def run_print_operation(inventory, entry):
    op = Gtk.PrintOperation()
    state = PrintState(inventory, entry)
    op.connect("begin-print", state.begin_print)
    op.connect("draw-page", state.draw_page)
    try:
        op.run(Gtk.PrintOperationAction.PRINT_DIALOG, None)
    except GLib.GError:
        # Canceling the print operation can result in the error
        #   GError: Error from StartDoc
        # http://seclists.org/nmap-dev/2012/q4/161
        pass
