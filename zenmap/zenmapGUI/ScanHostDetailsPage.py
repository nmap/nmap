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

from zenmapGUI.higwidgets.higexpanders import HIGExpander
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox,\
        hig_box_space_holder
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.Icons import get_os_logo, get_vulnerability_logo

import zenmapCore.I18N  # lgtm[py/unused-import]

na = _('Not available')


class ScanHostDetailsPage(HIGExpander):
    def __init__(self, host):
        HIGExpander.__init__(self, host.get_hostname())

        self.host_details = HostDetails(host)
        self.hbox._pack_expand_fill(self.host_details)


class HostDetails(HIGVBox):
    def __init__(self, host):
        HIGVBox.__init__(self)

        self.__create_widgets()

        self.set_os_image(get_os_logo(host))

        self.set_vulnerability_image(
                get_vulnerability_logo(host.get_open_ports()))

        self.set_host_status({'state': host.get_state(),
            'open': str(host.get_open_ports()),
            'filtered': str(host.get_filtered_ports()),
            'closed': str(host.get_closed_ports()),
            'scanned': str(host.get_scanned_ports()),
            'uptime': host.get_uptime()['seconds'],
            'lastboot': host.get_uptime()['lastboot']})

        addresses = {}
        if host.ip is not None:
            addresses['ipv4'] = host.ip['addr']
        if host.ipv6 is not None:
            addresses['ipv6'] = host.ipv6['addr']
        if host.mac is not None:
            addresses['mac'] = host.mac['addr']
        self.set_addresses(addresses)

        self.set_hostnames(host.get_hostnames())

        os = host.get_best_osmatch()
        if os:
            os['portsused'] = host.get_ports_used()

        self.set_os(os)
        self.set_tcpseq(host.get_tcpsequence())
        self.set_ipseq(host.get_ipidsequence())
        self.set_tcptsseq(host.get_tcptssequence())
        self.set_comment(host.comment)

    def __create_widgets(self):
        self.host_status_expander = Gtk.Expander.new(
                '<b>' + _('Host Status') + '</b>')
        self.address_expander = Gtk.Expander.new('<b>' + _('Addresses') + '</b>')
        self.hostnames_expander = Gtk.Expander.new('<b>' + _('Hostnames') + '</b>')
        self.os_expander = Gtk.Expander.new('<b>' + _('Operating System') + '</b>')
        self.portsused_expander = Gtk.Expander.new(
                '<b>' + _('Ports used') + '</b>')
        self.osclass_expander = Gtk.Expander.new('<b>' + _('OS Classes') + '</b>')
        self.tcp_expander = Gtk.Expander.new('<b>' + _('TCP Sequence') + '</b>')
        self.ip_expander = Gtk.Expander.new('<b>' + _('IP ID Sequence') + '</b>')
        self.tcpts_expander = Gtk.Expander.new(
                '<b>' + _('TCP TS Sequence') + '</b>')
        self.comment_expander = Gtk.Expander.new('<b>' + _('Comments') + '</b>')
        self.os_image = Gtk.Image()
        self.vulnerability_image = Gtk.Image()

        # Host Status expander
        self.host_state_label = HIGEntryLabel(_('State:'))
        self.info_host_state_label = HIGEntryLabel(na)

        self.open_label = HIGEntryLabel(_('Open ports:'))
        self.info_open_ports = HIGEntryLabel(na)

        self.filtered_label = HIGEntryLabel(_('Filtered ports:'))
        self.info_filtered_label = HIGEntryLabel(na)

        self.closed_label = HIGEntryLabel(_('Closed ports:'))
        self.info_closed_ports = HIGEntryLabel(na)

        self.scanned_label = HIGEntryLabel(_('Scanned ports:'))
        self.info_scanned_label = HIGEntryLabel(na)

        self.uptime_label = HIGEntryLabel(_('Up time:'))
        self.info_uptime_label = HIGEntryLabel(na)

        self.lastboot_label = HIGEntryLabel(_('Last boot:'))
        self.info_lastboot_label = HIGEntryLabel(na)

        # Addresses expander
        self.ipv4_label = HIGEntryLabel('IPv4:')
        self.info_ipv4_label = HIGEntryLabel(na)

        self.ipv6_label = HIGEntryLabel('IPv6:')
        self.info_ipv6_label = HIGEntryLabel(na)

        self.mac_label = HIGEntryLabel('MAC:')
        self.info_mac_label = HIGEntryLabel(na)

        self.vendor_label = HIGEntryLabel(_('Vendor:'))
        self.info_vendor_label = HIGEntryLabel(na)

    def create_table_hbox(self):
        table = HIGTable()
        hbox = HIGHBox()

        hbox._pack_noexpand_nofill(hig_box_space_holder())
        hbox._pack_noexpand_nofill(table)

        return table, hbox

    def set_host_status(self, status):
        self.host_status_expander.set_use_markup(True)
        self.host_status_expander.set_expanded(True)
        table, hbox = self.create_table_hbox()

        if ('state' in status and
                status['state'] != ''):
            self.info_host_state_label.set_text(status['state'])

        if ('open' in status and
                status['open'] != ''):
            self.info_open_ports.set_text(status['open'])

        if ('filtered' in status and
                status['filtered'] != ''):
            self.info_filtered_label.set_text(status['filtered'])

        if ('closed' in status and
                status['closed'] != ''):
            self.info_closed_ports.set_text(status['closed'])

        if ('scanned' in status and
                status['scanned'] != ''):
            self.info_scanned_label.set_text(status['scanned'])

        if ('uptime' in status and
                status['uptime'] != ''):
            self.info_uptime_label.set_text(status['uptime'])

        if ('lastboot' in status and
                status['lastboot'] != ''):
            self.info_lastboot_label.set_text(status['lastboot'])

        table.attach(self.host_state_label, 0, 1, 0, 1)
        table.attach(self.info_host_state_label, 1, 2, 0, 1)

        table.attach(self.open_label, 0, 1, 1, 2)
        table.attach(self.info_open_ports, 1, 2, 1, 2)

        table.attach(self.filtered_label, 0, 1, 2, 3)
        table.attach(self.info_filtered_label, 1, 2, 2, 3)

        table.attach(self.closed_label, 0, 1, 3, 4)
        table.attach(self.info_closed_ports, 1, 2, 3, 4)

        table.attach(self.scanned_label, 0, 1, 4, 5)
        table.attach(self.info_scanned_label, 1, 2, 4, 5)

        table.attach(self.uptime_label, 0, 1, 5, 6)
        table.attach(self.info_uptime_label, 1, 2, 5, 6)

        table.attach(self.lastboot_label, 0, 1, 6, 7)
        table.attach(self.info_lastboot_label, 1, 2, 6, 7)

        table.attach(self.os_image, 2, 4, 0, 3, xoptions=Gtk.AttachOptions.EXPAND)
        table.attach(
                self.vulnerability_image, 2, 4, 4, 7, xoptions=Gtk.AttachOptions.EXPAND)

        table.set_col_spacing(1, 50)

        self.host_status_expander.add(hbox)
        self._pack_noexpand_nofill(self.host_status_expander)

    def set_os_image(self, image):
            self.os_image.set_from_stock(image, Gtk.IconSize.DIALOG)

    def set_vulnerability_image(self, image):
        self.vulnerability_image.set_from_stock(image, Gtk.IconSize.DIALOG)

    def set_addresses(self, address):
        self.address_expander.set_use_markup(True)
        table, hbox = self.create_table_hbox()
        self.address_expander.set_expanded(True)

        #print '>>> Address:', address
        if ('ipv4' in address and
                address['ipv4'] != 1):
            self.info_ipv4_label.set_text(address['ipv4'])

        if ('ipv6' in address and
                address['ipv6'] != 1):
            self.info_ipv6_label.set_text(address['ipv6'])

        if ('mac' in address and
                address['mac'] != 1):
            self.info_mac_label.set_text(address['mac'])

        table.attach(self.ipv4_label, 0, 1, 0, 1)
        table.attach(self.info_ipv4_label, 1, 2, 0, 1)

        table.attach(self.ipv6_label, 0, 1, 1, 2)
        table.attach(self.info_ipv6_label, 1, 2, 1, 2)

        table.attach(self.mac_label, 0, 1, 2, 3)
        table.attach(self.info_mac_label, 1, 2, 2, 3)

        self.address_expander.add(hbox)
        self._pack_noexpand_nofill(self.address_expander)

    def set_hostnames(self, hostname):
        if hostname:
            self.hostnames_expander.set_use_markup(True)
            self.hostnames_expander.set_expanded(True)
            table, hbox = self.create_table_hbox()

            y1 = 1
            y2 = 2

            for h in hostname:
                name = h.get('hostname', na)
                type = h.get('hostname_type', na)

                table.attach(HIGEntryLabel(_('Name - Type:')), 0, 1, y1, y2)
                table.attach(HIGEntryLabel(name + ' - ' + type), 1, 2, y1, y2)
                y1 += 1
                y2 += 1

            self.hostnames_expander.add(hbox)
            self._pack_noexpand_nofill(self.hostnames_expander)

    def set_os(self, os):
        if os:
            self.os_expander.set_use_markup(True)
            self.os_expander.set_expanded(True)
            table, hbox = self.create_table_hbox()
            progress = Gtk.ProgressBar()

            if 'accuracy' in os:
                progress.set_fraction(float(os['accuracy']) / 100.0)
                progress.set_text(os['accuracy'] + '%')
            else:
                progress.set_text(_('Not Available'))

            table.attach(HIGEntryLabel(_('Name:')), 0, 1, 0, 1)
            table.attach(HIGEntryLabel(os['name']), 1, 2, 0, 1)

            table.attach(HIGEntryLabel(_('Accuracy:')), 0, 1, 1, 2)
            table.attach(progress, 1, 2, 1, 2)

            y1 = 2
            y2 = 3

            if 'portsused' in os:
                self.set_ports_used(os['portsused'])
                table.attach(self.portsused_expander, 0, 2, y1, y2)
                y1 += 1
                y2 += 1

            if 'osclasses' in os:
                self.set_osclass(os['osclasses'])
                self.osclass_expander.set_use_markup(True)
                table.attach(self.osclass_expander, 0, 2, y1, y2)

            self.os_expander.add(hbox)
            self._pack_noexpand_nofill(self.os_expander)

    def set_ports_used(self, ports):
        self.portsused_expander.set_use_markup(True)
        table, hbox = self.create_table_hbox()

        y1 = 0
        y2 = 1

        for p in ports:
            table.attach(HIGEntryLabel(
                _('Port-Protocol-State:')), 0, 1, y1, y2)
            table.attach(HIGEntryLabel(
                p['portid'] + ' - ' + p['proto'] + ' - ' + p['state']
                ), 1, 2, y1, y2)
            y1 += 1
            y2 += 1

        self.portsused_expander.add(hbox)

    def set_osclass(self, osclass):
        if osclass:
            self.osclass_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            table.attach(HIGEntryLabel(_('Type')), 0, 1, 0, 1)
            table.attach(HIGEntryLabel(_('Vendor')), 1, 2, 0, 1)
            table.attach(HIGEntryLabel(_('OS Family')), 2, 3, 0, 1)
            table.attach(HIGEntryLabel(_('OS Generation')), 3, 4, 0, 1)
            table.attach(HIGEntryLabel(_('Accuracy')), 4, 5, 0, 1)

            y1 = 1
            y2 = 2

            for o in osclass:
                table.attach(HIGEntryLabel(o['type']), 0, 1, y1, y2)
                table.attach(HIGEntryLabel(o['vendor']), 1, 2, y1, y2)
                table.attach(HIGEntryLabel(o['osfamily']), 2, 3, y1, y2)
                table.attach(HIGEntryLabel(o['osgen']), 3, 4, y1, y2)

                progress = Gtk.ProgressBar()
                progress.set_text(o['accuracy'] + '%')
                progress.set_fraction(float(o['accuracy']) / 100.0)
                table.attach(progress, 4, 5, y1, y2)
                y1 += 1
                y2 += 1

            self.osclass_expander.add(hbox)

    def set_tcpseq(self, tcpseq):
        if tcpseq:
            self.tcp_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = Gtk.ComboBoxText()
            for v in tcpseq['values'].split(','):
                combo.append_text(v)

            table.attach(HIGEntryLabel(_('Difficulty:')), 0, 1, 1, 2)
            table.attach(HIGEntryLabel(tcpseq['difficulty']), 1, 2, 1, 2)

            table.attach(HIGEntryLabel(_('Index:')), 0, 1, 2, 3)
            table.attach(HIGEntryLabel(tcpseq['index']), 1, 2, 2, 3)

            table.attach(HIGEntryLabel(_('Values:')), 0, 1, 3, 4)
            table.attach(combo, 1, 2, 3, 4)

            self.tcp_expander.add(hbox)
            self._pack_noexpand_nofill(self.tcp_expander)

    def set_ipseq(self, ipseq):
        if ipseq:
            self.ip_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = Gtk.ComboBoxText()

            for i in ipseq['values'].split(','):
                combo.append_text(i)

            table.attach(HIGEntryLabel(_('Class:')), 0, 1, 0, 1)
            table.attach(HIGEntryLabel(ipseq['class']), 1, 2, 0, 1)

            table.attach(HIGEntryLabel(_('Values:')), 0, 1, 1, 2)
            table.attach(combo, 1, 2, 1, 2)

            self.ip_expander.add(hbox)
            self._pack_noexpand_nofill(self.ip_expander)

    def set_tcptsseq(self, tcptsseq):
        if tcptsseq:
            self.tcpts_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = Gtk.ComboBoxText()

            for i in tcptsseq['values'].split(','):
                combo.append_text(i)

            table.attach(HIGEntryLabel(_('Class:')), 0, 1, 0, 1)
            table.attach(HIGEntryLabel(tcptsseq['class']), 1, 2, 0, 1)

            table.attach(HIGEntryLabel(_('Values:')), 0, 1, 1, 2)
            table.attach(combo, 1, 2, 1, 2)

            self.tcpts_expander.add(hbox)
            self._pack_noexpand_nofill(self.tcpts_expander)

    def set_comment(self, comment=''):
        self.comment_expander.set_use_markup(True)
        if comment:
            self.comment_expander.set_expanded(True)

        hbox = HIGHBox()

        self.comment_scrolled = Gtk.ScrolledWindow()
        self.comment_scrolled.set_border_width(5)
        self.comment_scrolled.set_policy(
                Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.comment_txt_vw = Gtk.TextView()
        self.comment_txt_vw.set_wrap_mode(Gtk.WrapMode.WORD)
        self.comment_txt_vw.get_buffer().set_text(comment)

        self.comment_scrolled.add(self.comment_txt_vw)
        hbox._pack_expand_fill(self.comment_scrolled)

        self.comment_expander.add(hbox)
        self._pack_noexpand_nofill(self.comment_expander)

    def get_comment(self):
        buffer = self.comment_txt_vw.get_buffer()
        return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
