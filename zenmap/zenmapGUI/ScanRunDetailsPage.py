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
from gi.repository import Gtk

from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox,\
        hig_box_space_holder
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel

import zenmapCore.I18N  # lgtm[py/unused-import]


class ScanRunDetailsPage(HIGVBox):
    def __init__(self, scan):
        HIGVBox.__init__(self)

        na = _('Not available')

        # Command info
        self.command_label = HIGEntryLabel(_('Command:'))
        self.info_command_label = HIGEntryLabel(na)

        self.nmap_version_label = HIGEntryLabel(_('Nmap Version:'))
        self.info_nmap_version_label = HIGEntryLabel(na)

        self.verbose_label = HIGEntryLabel(_('Verbosity level:'))
        self.info_verbose_label = HIGEntryLabel(na)

        self.debug_label = HIGEntryLabel(_('Debug level:'))
        self.info_debug_label = HIGEntryLabel(na)

        self.command_expander = Gtk.Expander.new(
                "<b>" + _("Command Info") + "</b>")
        self.command_expander.set_use_markup(True)

        self.command_table = HIGTable()
        self.command_table.set_border_width(5)
        self.command_table.set_row_spacings(6)
        self.command_table.set_col_spacings(6)

        self.command_hbox = HIGHBox()
        self.command_hbox._pack_noexpand_nofill(hig_box_space_holder())
        self.command_hbox._pack_noexpand_nofill(self.command_table)

        self.command_table.attach(self.command_label, 0, 1, 0, 1)
        self.command_table.attach(self.info_command_label, 1, 2, 0, 1)

        self.command_table.attach(self.nmap_version_label, 0, 1, 1, 2)
        self.command_table.attach(self.info_nmap_version_label, 1, 2, 1, 2)

        self.command_table.attach(self.verbose_label, 0, 1, 2, 3)
        self.command_table.attach(self.info_verbose_label, 1, 2, 2, 3)

        self.command_table.attach(self.debug_label, 0, 1, 3, 4)
        self.command_table.attach(self.info_debug_label, 1, 2, 3, 4)

        self.command_expander.add(self.command_hbox)
        self._pack_noexpand_nofill(self.command_expander)
        self.command_expander.set_expanded(True)

        # General info:
        self.start_label = HIGEntryLabel(_('Started on:'))
        self.info_start_label = HIGEntryLabel(na)

        self.finished_label = HIGEntryLabel(_('Finished on:'))
        self.info_finished_label = HIGEntryLabel(na)

        self.host_up_label = HIGEntryLabel(_('Hosts up:'))
        self.info_hosts_up_label = HIGEntryLabel(na)

        self.host_down_label = HIGEntryLabel(_('Hosts down:'))
        self.info_hosts_down_label = HIGEntryLabel(na)

        self.host_scanned_label = HIGEntryLabel(_('Hosts scanned:'))
        self.info_hosts_scanned_label = HIGEntryLabel(na)

        self.open_label = HIGEntryLabel(_('Open ports:'))
        self.info_open_label = HIGEntryLabel(na)

        self.filtered_label = HIGEntryLabel(_('Filtered ports:'))
        self.info_filtered_label = HIGEntryLabel(na)

        self.closed_label = HIGEntryLabel(_('Closed ports:'))
        self.info_closed_label = HIGEntryLabel(na)

        self.general_expander = Gtk.Expander.new(
                "<b>" + _("General Info") + "</b>")
        self.general_expander.set_use_markup(True)

        self.general_table = HIGTable()
        self.general_table.set_border_width(5)
        self.general_table.set_row_spacings(6)
        self.general_table.set_col_spacings(6)

        self.general_hbox = HIGHBox()
        self.general_hbox._pack_noexpand_nofill(hig_box_space_holder())
        self.general_hbox._pack_noexpand_nofill(self.general_table)

        self.general_table.attach(self.start_label, 0, 1, 0, 1)
        self.general_table.attach(self.info_start_label, 1, 2, 0, 1)

        self.general_table.attach(self.finished_label, 0, 1, 1, 2)
        self.general_table.attach(self.info_finished_label, 1, 2, 1, 2)

        self.general_table.attach(self.host_up_label, 0, 1, 2, 3)
        self.general_table.attach(self.info_hosts_up_label, 1, 2, 2, 3)

        self.general_table.attach(self.host_down_label, 0, 1, 3, 4)
        self.general_table.attach(self.info_hosts_down_label, 1, 2, 3, 4)

        self.general_table.attach(self.host_scanned_label, 0, 1, 4, 5)
        self.general_table.attach(self.info_hosts_scanned_label, 1, 2, 4, 5)

        self.general_table.attach(self.open_label, 0, 1, 5, 6)
        self.general_table.attach(self.info_open_label, 1, 2, 5, 6)

        self.general_table.attach(self.filtered_label, 0, 1, 6, 7)
        self.general_table.attach(self.info_filtered_label, 1, 2, 6, 7)

        self.general_table.attach(self.closed_label, 0, 1, 7, 8)
        self.general_table.attach(self.info_closed_label, 1, 2, 7, 8)

        self.general_expander.add(self.general_hbox)
        self._pack_noexpand_nofill(self.general_expander)
        self.general_expander.set_expanded(True)

        self._set_from_scan(scan)

    def _set_from_scan(self, scan):
        """Initialize the display from a parsed scan."""
        # Command info.
        self.info_command_label.set_text(scan.get_nmap_command())
        self.info_nmap_version_label.set_text(scan.get_scanner_version())
        self.info_verbose_label.set_text(scan.get_verbose_level())
        self.info_debug_label.set_text(scan.get_debugging_level())

        # General info.
        self.info_start_label.set_text(scan.get_formatted_date())
        self.info_finished_label.set_text(scan.get_formatted_finish_date())
        self.info_hosts_up_label.set_text(str(scan.get_hosts_up()))
        self.info_hosts_down_label.set_text(str(scan.get_hosts_down()))
        self.info_hosts_scanned_label.set_text(str(scan.get_hosts_scanned()))
        self.info_open_label.set_text(str(scan.get_open_ports()))
        self.info_filtered_label.set_text(str(scan.get_filtered_ports()))
        self.info_closed_label.set_text(str(scan.get_closed_ports()))

        for scaninfo in scan.get_scaninfo():
            exp = Gtk.Expander.new('<b>%s - %s</b>' % (
                _('Scan Info'), scaninfo['type'].capitalize()))
            exp.set_use_markup(True)

            display = self.make_scaninfo_display(scaninfo)

            exp.add(display)
            self._pack_noexpand_nofill(exp)

    def make_scaninfo_display(self, scaninfo):
        """Return a widget displaying a scan's "scaninfo" information: type,
        protocol, number of scanned ports, and list of services."""
        hbox = HIGHBox()
        table = HIGTable()
        table.set_border_width(5)
        table.set_row_spacings(6)
        table.set_col_spacings(6)

        table.attach(HIGEntryLabel(_('Scan type:')), 0, 1, 0, 1)
        table.attach(HIGEntryLabel(scaninfo['type']), 1, 2, 0, 1)

        table.attach(HIGEntryLabel(_('Protocol:')), 0, 1, 1, 2)
        table.attach(HIGEntryLabel(scaninfo['protocol']), 1, 2, 1, 2)

        table.attach(HIGEntryLabel(_('# scanned ports:')), 0, 1, 2, 3)
        table.attach(HIGEntryLabel(scaninfo['numservices']), 1, 2, 2, 3)

        table.attach(HIGEntryLabel(_('Services:')), 0, 1, 3, 4)
        table.attach(
                self.make_services_display(scaninfo['services']), 1, 2, 3, 4)

        hbox._pack_noexpand_nofill(hig_box_space_holder())
        hbox._pack_noexpand_nofill(table)

        return hbox

    def make_services_display(self, services):
        """Return a widget displaying a list of services like
        1-1027,1029-1033,1040,1043,1050,1058-1059,1067-1068,1076,1080"""
        combo = Gtk.ComboBoxText()

        for i in services.split(","):
            combo.append_text(i)

        return combo

if __name__ == "__main__":
    import sys
    from zenmapCore.NmapParser import NmapParser

    filename = sys.argv[1]
    parsed = NmapParser()
    parsed.parse_file(filename)
    run_details = ScanRunDetailsPage(parsed)
    window = Gtk.Window()
    window.add(run_details)
    window.connect("delete-event", lambda *args: Gtk.main_quit())
    window.show_all()
    Gtk.main()
