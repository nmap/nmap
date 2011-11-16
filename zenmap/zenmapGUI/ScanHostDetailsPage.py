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

from zenmapGUI.higwidgets.higexpanders import HIGExpander
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, hig_box_space_holder
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.Icons import get_os_logo, get_vulnerability_logo

import zenmapCore.I18N

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

        self.set_vulnerability_image(get_vulnerability_logo(host.get_open_ports()))

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
            os['osclass'] = host.get_osclasses()

        self.set_os(os)
        self.set_tcpseq(host.get_tcpsequence())
        self.set_ipseq(host.get_ipidsequence())
        self.set_tcptsseq(host.get_tcptssequence())
        self.set_comment(host.comment)

    def __create_widgets(self):
        self.host_status_expander = gtk.Expander('<b>'+_('Host Status')+'</b>')
        self.address_expander = gtk.Expander('<b>'+_('Addresses')+'</b>')
        self.hostnames_expander = gtk.Expander('<b>'+_('Hostnames')+'</b>')
        self.os_expander = gtk.Expander('<b>'+_('Operating System')+'</b>')
        self.portsused_expander = gtk.Expander('<b>'+_('Ports used')+'</b>')
        self.osclass_expander = gtk.Expander('<b>'+_('OS Class')+'</b>')
        self.tcp_expander = gtk.Expander('<b>'+_('TCP Sequence')+'</b>')
        self.ip_expander = gtk.Expander('<b>'+_('IP ID Sequence')+'</b>')
        self.tcpts_expander = gtk.Expander('<b>'+_('TCP TS Sequence')+'</b>')
        self.comment_expander = gtk.Expander('<b>'+_('Comments')+'</b>')
        self.os_image = gtk.Image()
        self.vulnerability_image = gtk.Image()

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
        self.ipv4_label = HIGEntryLabel(_('IPv4:'))
        self.info_ipv4_label = HIGEntryLabel(na)

        self.ipv6_label = HIGEntryLabel(_('IPv6:'))
        self.info_ipv6_label = HIGEntryLabel(na)

        self.mac_label = HIGEntryLabel(_('MAC:'))
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

        try:
            if status['state'] == '': raise Exception
            self.info_host_state_label.set_text(status['state'])
        except:pass

        try:
            if status['open'] == '': raise Exception
            self.info_open_ports.set_text(status['open'])
        except:pass

        try:
            if status['filtered'] == '': raise Exception
            self.info_filtered_label.set_text(status['filtered'])
        except:pass

        try:
            if status['closed'] == '': raise Exception
            self.info_closed_ports.set_text(status['closed'])
        except:pass

        try:
            if status['scanned'] == '': raise Exception
            self.info_scanned_label.set_text(status['scanned'])
        except:pass

        try:
            if status['uptime'] == '': raise Exception
            self.info_uptime_label.set_text(status['uptime'])
        except:pass

        try:
            if status['lastboot'] == '': raise Exception
            self.info_lastboot_label.set_text(status['lastboot'])
        except:pass

        table.attach(self.host_state_label,0,1,0,1)
        table.attach(self.info_host_state_label,1,2,0,1)

        table.attach(self.open_label,0,1,1,2)
        table.attach(self.info_open_ports,1,2,1,2)

        table.attach(self.filtered_label,0,1,2,3)
        table.attach(self.info_filtered_label,1,2,2,3)

        table.attach(self.closed_label,0,1,3,4)
        table.attach(self.info_closed_ports,1,2,3,4)

        table.attach(self.scanned_label,0,1,4,5)
        table.attach(self.info_scanned_label,1,2,4,5)

        table.attach(self.uptime_label,0,1,5,6)
        table.attach(self.info_uptime_label,1,2,5,6)

        table.attach(self.lastboot_label,0,1,6,7)
        table.attach(self.info_lastboot_label,1,2,6,7)

        table.attach(self.os_image,2,4,0,3,xoptions=1,yoptions=0)
        table.attach(self.vulnerability_image,2,4,4,7,xoptions=1,yoptions=0)

        table.set_col_spacing(1, 50)

        self.host_status_expander.add(hbox)
        self._pack_noexpand_nofill(self.host_status_expander)

    def set_os_image(self, image):
            self.os_image.set_from_stock(image,gtk.ICON_SIZE_DIALOG)

    def set_vulnerability_image(self, image):
        self.vulnerability_image.set_from_stock(image,gtk.ICON_SIZE_DIALOG)

    def set_addresses(self, address):
        self.address_expander.set_use_markup(True)
        table, hbox = self.create_table_hbox()
        self.address_expander.set_expanded(True)

        #print '>>> Address:', address
        try:
            if address['ipv4'] == 1: raise Exception
            self.info_ipv4_label.set_text(address['ipv4'])
        except:pass

        try:
            if address['ipv6'] == 1: raise Exception
            self.info_ipv6_label.set_text(address['ipv6'])
        except:pass

        try:
            if address['mac'] == 1: raise Exception
            self.info_mac_label.set_text(address['mac'])
        except:pass

        table.attach(self.ipv4_label,0,1,0,1)
        table.attach(self.info_ipv4_label,1,2,0,1)

        table.attach(self.ipv6_label,0,1,1,2)
        table.attach(self.info_ipv6_label,1,2,1,2)

        table.attach(self.mac_label,0,1,2,3)
        table.attach(self.info_mac_label,1,2,2,3)

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
                name = na
                try:name = h['hostname']
                except:pass

                type = na
                try:type = h['hostname_type']
                except:pass

                table.attach(HIGEntryLabel(_('Name - Type:')),0,1,y1,y2)
                table.attach(HIGEntryLabel(name+' - '+\
                                           type),1,2,y1,y2)
                y1+=1;y2+=1

            self.hostnames_expander.add(hbox)
            self._pack_noexpand_nofill(self.hostnames_expander)

    def set_os(self, os):
        if os:
            self.os_expander.set_use_markup(True)
            self.os_expander.set_expanded(True)
            table, hbox = self.create_table_hbox()
            progress = gtk.ProgressBar()

            try:
                progress.set_fraction(float(os['accuracy'])/100.0)
                progress.set_text(os['accuracy']+'%')
            except:progress.set_text(_('Not Available'))

            table.attach(HIGEntryLabel(_('Name:')),0,1,0,1)
            table.attach(HIGEntryLabel(os['name']),1,2,0,1)

            table.attach(HIGEntryLabel(_('Accuracy:')),0,1,1,2)
            table.attach(progress,1,2,1,2)

            y1=2;y2=3

            try:
                self.set_ports_used(os['portsused'])
                table.attach(self.portsused_expander,0,2,y1,y2)
                y1+=1;y2+=1
            except:pass

            try:
                self.set_osclass(os['osclass'])
                self.osclass_expander.set_use_markup(True)
                table.attach(self.osclass_expander,0,2,y1,y2)
            except:pass

            self.os_expander.add(hbox)
            self._pack_noexpand_nofill(self.os_expander)

    def set_ports_used(self, ports):
        self.portsused_expander.set_use_markup(True)
        table, hbox = self.create_table_hbox()

        y1=0;y2=1

        for p in ports:
            table.attach(HIGEntryLabel(_('Port-Protocol-State:')),0,1,y1,y2)
            table.attach(HIGEntryLabel(p['portid']+' - '+p['proto']+' - '+\
                                       p['state']),1,2,y1,y2)
            y1+=1;y2+=1

        self.portsused_expander.add(hbox)

    def set_osclass(self, osclass):
        if osclass:
            self.osclass_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            table.attach(HIGEntryLabel(_('Type')),0,1,0,1)
            table.attach(HIGEntryLabel(_('Vendor')),1,2,0,1)
            table.attach(HIGEntryLabel(_('OS Family')),2,3,0,1)
            table.attach(HIGEntryLabel(_('OS Generation')),3,4,0,1)
            table.attach(HIGEntryLabel(_('Accuracy')),4,5,0,1)

            y1=1;y2=2

            for o in osclass:
                table.attach(HIGEntryLabel(o['type']),0,1,y1,y2)
                table.attach(HIGEntryLabel(o['vendor']),1,2,y1,y2)
                table.attach(HIGEntryLabel(o['osfamily']),2,3,y1,y2)
                table.attach(HIGEntryLabel(o['osgen']),3,4,y1,y2)

                progress = gtk.ProgressBar()
                progress.set_text(o['accuracy']+'%')
                progress.set_fraction(float(o['accuracy'])/100.0)
                table.attach(progress,4,5,y1,y2)
                y1+=1;y2+=1

            self.osclass_expander.add(hbox)

    def set_tcpseq(self, tcpseq):
        if tcpseq:
            self.tcp_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = gtk.combo_box_new_text()
            for v in tcpseq['values'].split(','):
                combo.append_text(v)

            table.attach(HIGEntryLabel(_('Difficulty:')),0,1,1,2)
            table.attach(HIGEntryLabel(tcpseq['difficulty']),1,2,1,2)

            table.attach(HIGEntryLabel(_('Index:')),0,1,2,3)
            table.attach(HIGEntryLabel(tcpseq['index']),1,2,2,3)

            table.attach(HIGEntryLabel(_('Values:')),0,1,3,4)
            table.attach(combo,1,2,3,4)

            self.tcp_expander.add(hbox)
            self._pack_noexpand_nofill(self.tcp_expander)

    def set_ipseq(self, ipseq):
        if ipseq:
            self.ip_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = gtk.combo_box_new_text()

            for i in ipseq['values'].split(','):
                combo.append_text(i)

            table.attach(HIGEntryLabel(_('Class:')),0,1,0,1)
            table.attach(HIGEntryLabel(ipseq['class']),1,2,0,1)

            table.attach(HIGEntryLabel(_('Values:')),0,1,1,2)
            table.attach(combo,1,2,1,2)

            self.ip_expander.add(hbox)
            self._pack_noexpand_nofill(self.ip_expander)

    def set_tcptsseq(self, tcptsseq):
        if tcptsseq:
            self.tcpts_expander.set_use_markup(True)
            table, hbox = self.create_table_hbox()

            combo = gtk.combo_box_new_text()

            for i in tcptsseq['values'].split(','):
                combo.append_text(i)

            table.attach(HIGEntryLabel(_('Class:')),0,1,0,1)
            table.attach(HIGEntryLabel(tcptsseq['class']),1,2,0,1)

            table.attach(HIGEntryLabel(_('Values:')),0,1,1,2)
            table.attach(combo,1,2,1,2)

            self.tcpts_expander.add(hbox)
            self._pack_noexpand_nofill(self.tcpts_expander)

    def set_comment(self, comment=''):
        self.comment_expander.set_use_markup(True)
        if comment:
            self.comment_expander.set_expanded(True)

        hbox = HIGHBox()

        self.comment_scrolled = gtk.ScrolledWindow()
        self.comment_scrolled.set_border_width(5)
        self.comment_scrolled.set_policy(gtk.POLICY_AUTOMATIC,\
                                         gtk.POLICY_AUTOMATIC)

        self.comment_txt_vw = gtk.TextView()
        self.comment_txt_vw.set_wrap_mode(gtk.WRAP_WORD)
        self.comment_txt_vw.get_buffer().set_text(comment)

        self.comment_scrolled.add(self.comment_txt_vw)
        hbox._pack_expand_fill(self.comment_scrolled)

        self.comment_expander.add(hbox)
        self._pack_noexpand_nofill(self.comment_expander)

    def get_comment(self):
        buffer = self.comment_txt_vw.get_buffer()
        return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
