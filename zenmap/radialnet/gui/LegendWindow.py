# vim: set fileencoding=utf-8 :

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

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, Pango

import math
import cairo

import zenmapCore.I18N  # lgtm[py/unused-import]

from radialnet.gui.Image import Pixmaps
DIMENSION_NORMAL = (350, 450)


def draw_pixmap(context, x, y, name, label):
    # This is pretty hideous workaround
    Gdk.cairo_set_source_pixbuf(context, Pixmaps().get_pixbuf(name), x, y)
    #context.set_source_pixbuf()
    context.paint()
    context.move_to(x + 50, y + 10)
    context.set_source_rgb(0, 0, 0)
    context.show_text(label)


def reset_font(context):
    context.select_font_face(
            "Monospace", cairo.FONT_SLANT_NORMAL, cairo.FONT_SLANT_NORMAL)
    context.set_font_size(11)


def draw_heading(context, x, y, label):
    context.select_font_face(
            "Monospace", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
    context.set_font_size(13)
    context.move_to(x - 15, y)
    context.set_source_rgb(0, 0, 0)
    context.show_text(label)
    reset_font(context)


def draw_circle(context, x, y, size, color, label):
    context.set_source_rgb(0, 0, 0)
    context.move_to(x, y)
    context.arc(x, y, size, 0, 2 * math.pi)
    context.stroke_preserve()
    context.set_source_rgb(*color)
    context.fill()
    context.set_source_rgb(0, 0, 0)
    context.move_to(x + 50, y + 5)
    context.show_text(label)


def draw_square(context, x, y, size, color):
    context.set_source_rgb(0, 0, 0)
    context.rectangle(x, y - size / 2, size, size)
    context.stroke_preserve()
    context.set_source_rgb(*color)
    context.fill()


def draw_line(context, x, y, dash, color, label):
    context.set_source_rgb(*color)
    context.move_to(x - 20, y)
    context.set_dash(dash)
    context.line_to(x + 25, y)
    context.stroke()
    context.set_dash([])
    context.set_source_rgb(0, 0, 0)
    context.move_to(x + 50, y + 5)
    context.show_text(label)


class LegendWindow(Gtk.Window):
    """
    """
    def __init__(self):
        """
        """
        Gtk.Window.__init__(self, type=Gtk.WindowType.TOPLEVEL)
        self.set_default_size(DIMENSION_NORMAL[0], DIMENSION_NORMAL[1])
        self.__title_font = Pango.FontDescription("Monospace Bold")
        self.set_title(_("Topology Legend"))

        self.vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
        self.add(self.vbox)

        self.drawing_area = Gtk.DrawingArea()
        self.vbox.pack_start(self.drawing_area, True, True, 0)
        self.drawing_area.connect("draw", self.draw_event_handler)
        self.more_uri = Gtk.LinkButton.new_with_label(
                "https://nmap.org/book/zenmap-topology.html#zenmap-topology-legend",
                _("View full legend online"))
        self.vbox.pack_start(self.more_uri, False, False, 0)

    def draw_event_handler(self, widget, graphic_context):
        """
        """
        x, y = 45, 20
        draw_heading(graphic_context, x, y, _("Hosts"))

        # white circle
        y += 20
        draw_circle(graphic_context, x, y, 3, (1, 1, 1),
                _("host was not port scanned"))
        # green circle
        y += 20
        draw_circle(graphic_context, x, y, 4, (0, 1, 0),
                _("host with fewer than 3 open ports"))
        # yellow circle
        y += 20
        draw_circle(graphic_context, x, y, 5, (1, 1, 0),
                _("host with 3 to 6 open ports"))
        # red circle
        y += 20
        draw_circle(graphic_context, x, y, 6, (1, 0, 0),
                _("host with more than 6 open ports"))

        # green square
        y += 20
        rx = x - 20
        draw_square(graphic_context, rx, y, 10, (0, 1, 0))
        rx += 10 + 5
        # yellow square
        draw_square(graphic_context, rx, y, 12, (1, 1, 0))
        rx += 12 + 5
        # red square
        draw_square(graphic_context, rx, y, 14, (1, 0, 0))

        graphic_context.move_to(x + 50, y + 5)
        graphic_context.set_source_rgb(0, 0, 0)
        graphic_context.show_text(_("host is a router, switch, or WAP"))

        # connections between hosts
        y += 30
        draw_heading(graphic_context, x, y, _("Traceroute connections"))

        y += 20
        graphic_context.move_to(x, y)
        graphic_context.show_text(_("Thicker line means higher round-trip time"))
        # primary traceroute (blue line)
        y += 20
        draw_line(graphic_context, x, y, [], (0, 0, 1),
                _("primary traceroute connection"))
        # Alternate route (orange line)
        y += 20
        draw_line(graphic_context, x, y, [], (1, 0.5, 0),
                _("alternate path"))
        # no traceroute
        y += 20
        draw_line(graphic_context, x, y, [4.0, 2.0], (0, 0, 0),
                _("no traceroute information"))
        # missing traceroute
        y += 20
        graphic_context.set_source_rgb(0.5, 0.7, 0.95)
        graphic_context.move_to(x - 15, y)
        graphic_context.arc(x - 25, y, 5, 0, 2 * math.pi)
        graphic_context.stroke_preserve()
        draw_line(graphic_context, x, y, [4.0, 2.0], (0.5, 0.7, 0.95),
                _("missing traceroute hop"))

        # special purpose hosts
        y += 30
        draw_heading(graphic_context, x, y, _("Additional host icons"))

        # router image
        y += 20
        draw_pixmap(graphic_context, x, y, "router", _("router"))

        # switch image
        y += 20
        draw_pixmap(graphic_context, x, y, "switch", _("switch"))

        # wap image
        y += 20
        draw_pixmap(graphic_context, x, y, "wireless",
                _("wireless access point"))

        # firewall image
        y += 20
        draw_pixmap(graphic_context, x, y, "firewall", _("firewall"))

        # host with filtered ports
        y += 20
        draw_pixmap(graphic_context, x, y, "padlock",
                _("host with some filtered ports"))
