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

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, Pango, GLib

import gobject
import re

import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConf import NmapOutputHighlight

from zenmapGUI.NmapOutputProperties import NmapOutputProperties


class NmapOutputViewer(Gtk.Box):
    HIGHLIGHT_PROPERTIES = ["details", "date", "hostname", "ip", "port_list",
            "open_port", "closed_port", "filtered_port"]

    def __init__(self, refresh=1, stop=1):
        self.nmap_highlight = NmapOutputHighlight()
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.VERTICAL)

        # Creating widgets
        self.__create_widgets()

        # Setting scrolled window
        self.__set_scrolled_window()

        # Setting text view
        self.__set_text_view()

        buffer = self.text_view.get_buffer()
        # The end mark is used to scroll to the bottom of the display.
        self.end_mark = buffer.create_mark(None, buffer.get_end_iter(), False)

        self.refreshing = True

        # Adding widgets to the VBox
        self.pack_start(self.scrolled, True, True, 0)

        # The NmapCommand instance, if any, whose output is shown in this
        # display.
        self.command_execution = None
        # The position of the last read from the output stream.
        self.output_file_pointer = None

    def __create_widgets(self):
        # Creating widgets
        self.scrolled = Gtk.ScrolledWindow()
        self.text_view = Gtk.TextView()

    def __set_scrolled_window(self):
        # Seting scrolled window
        self.scrolled.set_border_width(5)
        self.scrolled.add(self.text_view)
        self.scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    def __set_text_view(self):
        self.text_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.text_view.set_editable(False)

        self.tag_font = self.text_view.get_buffer().create_tag(None)
        self.tag_font.set_property("family", "Monospace")
        for property in self.HIGHLIGHT_PROPERTIES:
            settings = self.nmap_highlight.__getattribute__(property)
            tag = self.text_view.get_buffer().create_tag(property)

            if settings[0]:
                tag.set_property("weight", Pango.Weight.HEAVY)
            else:
                tag.set_property("weight", Pango.Weight.NORMAL)

            if settings[1]:
                tag.set_property("style", Pango.Style.ITALIC)
            else:
                tag.set_property("style", Pango.Style.NORMAL)

            if settings[2]:
                tag.set_property("underline", Pango.Underline.SINGLE)
            else:
                tag.set_property("underline", Pango.Underline.NONE)

            text_color = settings[3]
            highlight_color = settings[4]

            tag.set_property(
                    "foreground", Gdk.Color(*text_color).to_string())
            tag.set_property(
                    "background", Gdk.Color(*highlight_color).to_string())

    def go_to_host(self, host):
        """Go to host line on nmap output result"""
        buff = self.text_view.get_buffer()
        start_iter = buff.get_start_iter()

        found_tuple = start_iter.forward_search(
                "\nNmap scan report for %s\n" % host, Gtk.TextSearchFlags.TEXT_ONLY
                )
        if found_tuple is None:
                return

        found = found_tuple[0]
        if not found.forward_line():
            return
        self.text_view.scroll_to_iter(found, 0, True, 0, 0)

    def show_output_properties(self, widget):
        nmap_out_prop = NmapOutputProperties(self.text_view)

        nmap_out_prop.run()

        for prop in nmap_out_prop.property_names:
            widget = nmap_out_prop.property_names[prop][8]

            wid_props = []

            if widget.bold:
                wid_props.append(1)
            else:
                wid_props.append(0)

            if widget.italic:
                wid_props.append(1)
            else:
                wid_props.append(0)

            if widget.underline:
                wid_props.append(1)
            else:
                wid_props.append(0)

            wid_props.append("(%s, %s, %s)" % (widget.text_color.red,
                                               widget.text_color.green,
                                               widget.text_color.blue))
            wid_props.append("(%s, %s, %s)" % (widget.highlight_color.red,
                                               widget.highlight_color.green,
                                               widget.highlight_color.blue))

            self.nmap_highlight.__setattr__(widget.property_name, wid_props)

        nmap_out_prop.destroy()
        self.nmap_highlight.save_changes()
        self.apply_highlighting()

    def apply_highlighting(self, start_iter=None, end_iter=None):
        buf = self.text_view.get_buffer()

        if start_iter is None:
            start_iter = buf.get_start_iter()
        else:
            # Patterns are line-oriented; start on a line boundary.
            start_iter.backward_line()
        if end_iter is None:
            end_iter = buf.get_end_iter()

        buf.apply_tag(self.tag_font, start_iter, end_iter)

        if not self.nmap_highlight.enable:
            return

        text = buf.get_text(start_iter, end_iter, include_hidden_chars=True)

        for property in self.HIGHLIGHT_PROPERTIES:
            settings = self.nmap_highlight.__getattribute__(property)
            for m in re.finditer(settings[5], text, re.M):
                m_start_iter = start_iter.copy()
                m_start_iter.forward_chars(m.start())
                m_end_iter = start_iter.copy()
                m_end_iter.forward_chars(m.end())
                buf.apply_tag_by_name(property, m_start_iter, m_end_iter)

    def show_nmap_output(self, output):
        """Show the string (or unicode) output in the output display."""
        try:
            self.text_view.get_buffer().set_text(output)
            self.apply_highlighting()
        except MemoryError:
            self.show_large_output_message(self.command_execution)

    def set_command_execution(self, command):
        """Set the live running command whose output is shown by this display.
        The current output is extracted from the command object."""
        self.command_execution = command
        if command is not None:
            self.text_view.get_buffer().set_text("")
            self.output_file_pointer = 0
        else:
            self.output_file_pointer = None
        self.refresh_output()

    def show_large_output_message(self, command=None):
        buf = self.text_view.get_buffer()
        try:
            running = (command is not None and command.scan_state() is True)
        except Exception:
            running = False
            complete = False
        else:
            complete = not running
        if running:
            buf.set_text("Warning: You have insufficient resources for Zenmap "
                "to be able to display the complete output from Nmap here. \n"
                "Zenmap will continue to run the scan to completion. However,"
                " some features of Zenmap might not work as expected.")
        elif complete:
            buf.set_text("Warning: You have insufficient resources for Zenmap "
                "to be able to display the complete output from Nmap here. \n"
                "The scan has completed. However, some features of Zenmap "
                "might not work as expected.")
        else:
            buf.set_text("Warning: You have insufficient resources for Zenmap "
                "to be able to display the complete output from Nmap here. \n"
                "The scan has been stopped. Some features of Zenmap might not "
                "work as expected.")

    def refresh_output(self, widget=None):
        """Update the output from the latest output of the command associated
        with this view, as set by set_command_execution. It has no effect if no
        command has been set."""
        log.debug("Refresh nmap output")

        if self.command_execution is None:
            return

        # Seek to the end of the most recent read.
        self.command_execution.stdout_file.seek(self.output_file_pointer)

        try:
            new_output = self.command_execution.stdout_file.read()
        except MemoryError:
            self.show_large_output_message(self.command_execution)
            return

        self.output_file_pointer = self.command_execution.stdout_file.tell()

        v_adj = self.scrolled.get_vadjustment()
        if new_output and v_adj is not None:
            # Find out if the view is already scrolled to the bottom.
            at_end = (v_adj.get_value() >= v_adj.get_upper() - v_adj.get_page_size())

            buf = self.text_view.get_buffer()
            prev_end_mark = buf.create_mark(
                    None, buf.get_end_iter(), left_gravity=True)
            try:
                buf.insert(buf.get_end_iter(), new_output)
                # Highlight the new text.
                self.apply_highlighting(
                        buf.get_iter_at_mark(prev_end_mark),
                        buf.get_end_iter())
            except MemoryError:
                self.show_large_output_message(self.command_execution)
                return

            if at_end:
                # If we were already scrolled to the bottom, scroll back to the
                # bottom again. Also do it in an idle handler in case the added
                # text causes a scroll bar to appear and reflow the text,
                # making the text a bit taller.
                self.text_view.scroll_mark_onscreen(self.end_mark)
                GLib.idle_add(
                        lambda: self.text_view.scroll_mark_onscreen(
                            self.end_mark))
