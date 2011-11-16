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

import gtk
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, hig_box_space_holder
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel

import zenmapCore.I18N

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

        self.command_expander = gtk.Expander("<b>"+_("Command Info")+"</b>")
        self.command_expander.set_use_markup(True)

        self.command_table = HIGTable()
        self.command_table.set_border_width(5)
        self.command_table.set_row_spacings(6)
        self.command_table.set_col_spacings(6)

        self.command_hbox = HIGHBox()
        self.command_hbox._pack_noexpand_nofill(hig_box_space_holder())
        self.command_hbox._pack_noexpand_nofill(self.command_table)

        self.command_table.attach(self.command_label,0,1,0,1)
        self.command_table.attach(self.info_command_label,1,2,0,1)

        self.command_table.attach(self.nmap_version_label,0,1,1,2)
        self.command_table.attach(self.info_nmap_version_label,1,2,1,2)

        self.command_table.attach(self.verbose_label,0,1,2,3)
        self.command_table.attach(self.info_verbose_label,1,2,2,3)

        self.command_table.attach(self.debug_label,0,1,3,4)
        self.command_table.attach(self.info_debug_label,1,2,3,4)

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

        self.general_expander = gtk.Expander("<b>"+_("General Info")+"</b>")
        self.general_expander.set_use_markup(True)

        self.general_table = HIGTable()
        self.general_table.set_border_width(5)
        self.general_table.set_row_spacings(6)
        self.general_table.set_col_spacings(6)

        self.general_hbox = HIGHBox()
        self.general_hbox._pack_noexpand_nofill(hig_box_space_holder())
        self.general_hbox._pack_noexpand_nofill(self.general_table)

        self.general_table.attach(self.start_label,0,1,0,1)
        self.general_table.attach(self.info_start_label,1,2,0,1)

        self.general_table.attach(self.finished_label,0,1,1,2)
        self.general_table.attach(self.info_finished_label,1,2,1,2)

        self.general_table.attach(self.host_up_label,0,1,2,3)
        self.general_table.attach(self.info_hosts_up_label,1,2,2,3)

        self.general_table.attach(self.host_down_label,0,1,3,4)
        self.general_table.attach(self.info_hosts_down_label,1,2,3,4)

        self.general_table.attach(self.host_scanned_label,0,1,4,5)
        self.general_table.attach(self.info_hosts_scanned_label,1,2,4,5)

        self.general_table.attach(self.open_label,0,1,5,6)
        self.general_table.attach(self.info_open_label,1,2,5,6)

        self.general_table.attach(self.filtered_label,0,1,6,7)
        self.general_table.attach(self.info_filtered_label,1,2,6,7)

        self.general_table.attach(self.closed_label,0,1,7,8)
        self.general_table.attach(self.info_closed_label,1,2,7,8)

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
            exp = gtk.Expander('<b>%s - %s</b>' % (_('Scan Info'), scaninfo['type'].capitalize()))
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

        table.attach(HIGEntryLabel(_('Scan type:')),0,1,0,1)
        table.attach(HIGEntryLabel(scaninfo['type']),1,2,0,1)

        table.attach(HIGEntryLabel(_('Protocol:')),0,1,1,2)
        table.attach(HIGEntryLabel(scaninfo['protocol']),1,2,1,2)

        table.attach(HIGEntryLabel(_('# scanned ports:')),0,1,2,3)
        table.attach(HIGEntryLabel(scaninfo['numservices']),1,2,2,3)

        table.attach(HIGEntryLabel(_('Services:')),0,1,3,4)
        table.attach(self.make_services_display(scaninfo['services']),1,2,3,4)

        hbox._pack_noexpand_nofill(hig_box_space_holder())
        hbox._pack_noexpand_nofill(table)

        return hbox

    def make_services_display(self, services):
        """Return a widget displaying a list of services like
        1-1027,1029-1033,1040,1043,1050,1058-1059,1067-1068,1076,1080"""
        combo = gtk.combo_box_new_text()

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
    window = gtk.Window()
    window.add(run_details)
    window.connect("delete-event", lambda *args: gtk.main_quit())
    window.show_all()
    gtk.main()
