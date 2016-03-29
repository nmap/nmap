# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
# *                                                                         *
# ***************************************************************************/

import gtk
import pango
import gobject

from radialnet.bestwidgets.boxes import *
from radialnet.bestwidgets.expanders import BWExpander
from radialnet.bestwidgets.labels import *
from radialnet.bestwidgets.textview import *
import zenmapCore.I18N


PORTS_HEADER = [
        _('Port'), _('Protocol'), _('State'), _('Service'), _('Method')]
EXTRAPORTS_HEADER = [_('Count'), _('State'), _('Reasons')]

SERVICE_COLORS = {'open':            '#ffd5d5',  # noqa
                  'closed':          '#d5ffd5',  # noqa
                  'filtered':        '#ffffd5',  # noqa
                  'unfiltered':      '#ffd5d5',  # noqa
                  'open|filtered':   '#ffd5d5',  # noqa
                  'closed|filtered': '#d5ffd5'}  # noqa
UNKNOWN_SERVICE_COLOR = '#d5d5d5'

TRACE_HEADER = [_('TTL'), _('RTT'), _('IP'), _('Hostname')]

TRACE_TEXT = _(
    "Traceroute on port <b>%s/%s</b> totalized <b>%d</b> known hops.")

NO_TRACE_TEXT = _("No traceroute information available.")

HOP_COLOR = {'known':   '#ffffff',  # noqa
             'unknown': '#cccccc'}  # noqa

SYSTEM_ADDRESS_TEXT = "[%s] %s"

OSMATCH_HEADER = ['%', _('Name'), _('DB Line')]
OSCLASS_HEADER = ['%', _('Vendor'), _('Type'), _('Family'), _('Version')]

USED_PORTS_TEXT = "%d/%s %s"

TCP_SEQ_NOTE = _("""\
<b>*</b> TCP sequence <i>index</i> equal to %d and <i>difficulty</i> is "%s".\
""")


def get_service_color(state):
    color = SERVICE_COLORS.get(state)
    if color is None:
        color = UNKNOWN_SERVICE_COLOR
    return color


class NodeNotebook(gtk.Notebook):
    """
    """
    def __init__(self, node):
        """
        """
        gtk.Notebook.__init__(self)
        self.set_tab_pos(gtk.POS_TOP)

        self.__node = node

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        # create body elements
        self.__services_page = ServicesPage(self.__node)
        self.__system_page = SystemPage(self.__node)
        self.__trace_page = TraceroutePage(self.__node)

        # packing notebook elements
        self.append_page(self.__system_page, BWLabel(_('General')))
        self.append_page(self.__services_page, BWLabel(_('Services')))
        self.append_page(self.__trace_page, BWLabel(_('Traceroute')))


class ServicesPage(gtk.Notebook):
    """
    """
    def __init__(self, node):
        """
        """
        gtk.Notebook.__init__(self)
        self.set_border_width(6)
        self.set_tab_pos(gtk.POS_TOP)

        self.__node = node
        self.__font = pango.FontDescription('Monospace')

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__cell = gtk.CellRendererText()

        # texteditor widgets
        self.__texteditor = BWTextEditor()
        self.__texteditor.bw_modify_font(self.__font)
        self.__texteditor.bw_set_editable(False)
        self.__texteditor.set_border_width(0)

        self.__select_combobox = gtk.combo_box_new_text()
        self.__select_combobox.connect('changed', self.__change_text_value)

        self.__viewer = BWVBox(spacing=6)
        self.__viewer.set_border_width(6)

        self.__viewer.bw_pack_start_noexpand_nofill(self.__select_combobox)
        self.__viewer.bw_pack_start_expand_fill(self.__texteditor)

        self.__text = list()

        # ports information
        number_of_ports = len(self.__node.get_info('ports'))
        self.__ports_label = BWLabel(_('Ports (%s)') % number_of_ports)

        self.__ports_scroll = BWScrolledWindow()

        self.__ports_store = gtk.TreeStore(gobject.TYPE_INT,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_BOOLEAN)

        self.__ports_treeview = gtk.TreeView(self.__ports_store)

        for port in self.__node.get_info('ports'):

            color = get_service_color(port['state']['state'])

            service_name = port['service'].get('name', _('<unknown>'))

            service_method = port['service'].get('method', _('<none>'))

            reference = self.__ports_store.append(None,
                                                  [port['id'],
                                                   port['protocol'],
                                                   port['state']['state'],
                                                   service_name,
                                                   service_method,
                                                   color,
                                                   True])

            for key in port['state']:
                self.__ports_store.append(reference,
                                          [port['id'],
                                           'state',
                                           key,
                                           port['state'][key],
                                           '',
                                           'white',
                                           True])

            for key in port['service']:

                if key in ['servicefp']:

                    text = _('[%d] service: %s') % (port['id'], key)

                    self.__select_combobox.append_text(text)
                    self.__text.append(port['service'][key])

                    value = _('<special field>')

                else:
                    value = port['service'][key]

                self.__ports_store.append(reference,
                                          [port['id'],
                                           'service',
                                           key,
                                           value,
                                           '',
                                           'white',
                                           True])

            #for script in port['scripts']:
            #    text = _('[%d] script: %s') % (port['id'], script['id'])
            #    self.__select_combobox.append_text(text)
            #    self.__text.append(script['output'])
            #
            #    self.__ports_store.append(reference,
            #                              [port['id'],
            #                               'script',
            #                               'id',
            #                               script['id'],
            #                               _('<special field>'),
            #                               'white',
            #                               True])

        self.__ports_column = list()

        for i in range(len(PORTS_HEADER)):

            column = gtk.TreeViewColumn(PORTS_HEADER[i],
                                        self.__cell,
                                        text=i)

            self.__ports_column.append(column)

            self.__ports_column[i].set_reorderable(True)
            self.__ports_column[i].set_resizable(True)
            self.__ports_column[i].set_sort_column_id(i)
            self.__ports_column[i].set_attributes(self.__cell,
                                                  text=i,
                                                  background=5,
                                                  editable=6)

            self.__ports_treeview.append_column(self.__ports_column[i])

        self.__ports_scroll.add_with_viewport(self.__ports_treeview)

        # extraports information
        number_of_xports = 0

        self.__xports_scroll = BWScrolledWindow()

        self.__xports_store = gtk.TreeStore(gobject.TYPE_INT,
                                            gobject.TYPE_STRING,
                                            gobject.TYPE_STRING,
                                            gobject.TYPE_STRING,
                                            gobject.TYPE_BOOLEAN)

        self.__xports_treeview = gtk.TreeView(self.__xports_store)

        for xports in self.__node.get_info('extraports'):

            color = get_service_color(xports['state'])
            number_of_xports += xports['count']

            reference = self.__xports_store.append(
                    None, [xports['count'], xports['state'],
                    ", ".join(xports['reason']), color, True])

            for xreason in xports['all_reason']:
                self.__xports_store.append(reference,
                                           [xreason['count'],
                                            xports['state'],
                                            xreason['reason'],
                                            'white',
                                            True])

        self.__xports_column = list()

        for i in range(len(EXTRAPORTS_HEADER)):

            column = gtk.TreeViewColumn(EXTRAPORTS_HEADER[i],
                                        self.__cell,
                                        text=i)

            self.__xports_column.append(column)

            self.__xports_column[i].set_reorderable(True)
            self.__xports_column[i].set_resizable(True)
            self.__xports_column[i].set_sort_column_id(i)
            self.__xports_column[i].set_attributes(self.__cell,
                                                   text=i,
                                                   background=3,
                                                   editable=4)

            self.__xports_treeview.append_column(self.__xports_column[i])

        xports_label_text = _('Extraports (%s)') % number_of_xports
        self.__xports_label = BWLabel(xports_label_text)

        self.__xports_scroll.add_with_viewport(self.__xports_treeview)

        self.append_page(self.__ports_scroll, self.__ports_label)
        self.append_page(self.__xports_scroll, self.__xports_label)
        self.append_page(self.__viewer, BWLabel(_('Special fields')))

        if len(self.__text) > 0:
            self.__select_combobox.set_active(0)

    def __change_text_value(self, widget):
        """
        """
        id = self.__select_combobox.get_active()

        self.__texteditor.bw_set_text(self.__text[id])


class SystemPage(BWScrolledWindow):
    """
    """
    def __init__(self, node):
        """
        """
        BWScrolledWindow.__init__(self)

        self.__node = node
        self.__font = pango.FontDescription('Monospace')

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__vbox = BWVBox()
        self.__vbox.set_border_width(6)

        self.__cell = gtk.CellRendererText()

        self.__general_frame = BWExpander(_('General information'))
        self.__sequences_frame = BWExpander(_('Sequences'))
        self.__os_frame = BWExpander(_('Operating System'))

        self.__sequences_frame.bw_add(gtk.Label(_('No sequence information.')))
        self.__os_frame.bw_add(gtk.Label(_('No OS information.')))

        # general information widgets
        self.__general = BWTable(3, 2)

        self.__address_label = BWSectionLabel(_('Address:'))
        self.__address_list = gtk.combo_box_entry_new_text()
        self.__address_list.child.set_editable(False)

        for address in self.__node.get_info('addresses'):

            params = address['type'], address['addr']
            address_text = SYSTEM_ADDRESS_TEXT % params

            if address['vendor'] is not None and address['vendor'] != '':
                address_text += " (%s)" % address['vendor']

            self.__address_list.append_text(address_text)

        self.__address_list.set_active(0)

        self.__general.bw_attach_next(self.__address_label,
                                      yoptions=gtk.FILL,
                                      xoptions=gtk.FILL)
        self.__general.bw_attach_next(self.__address_list, yoptions=gtk.FILL)

        if self.__node.get_info('hostnames') is not None:

            self.__hostname_label = BWSectionLabel(_('Hostname:'))
            self.__hostname_list = gtk.combo_box_entry_new_text()
            self.__hostname_list.child.set_editable(False)

            for hostname in self.__node.get_info('hostnames'):

                params = hostname['type'], hostname['name']
                self.__hostname_list.append_text(SYSTEM_ADDRESS_TEXT % params)

            self.__hostname_list.set_active(0)

            self.__general.bw_attach_next(self.__hostname_label,
                                          yoptions=gtk.FILL,
                                          xoptions=gtk.FILL)
            self.__general.bw_attach_next(self.__hostname_list,
                                          yoptions=gtk.FILL)

        if self.__node.get_info('uptime') is not None:

            self.__uptime_label = BWSectionLabel(_('Last boot:'))

            seconds = self.__node.get_info('uptime')['seconds']
            lastboot = self.__node.get_info('uptime')['lastboot']

            text = _('%s (%s seconds).') % (lastboot, seconds)

            self.__uptime_value = BWLabel(text)
            self.__uptime_value.set_selectable(True)
            self.__uptime_value.set_line_wrap(False)

            self.__general.bw_attach_next(self.__uptime_label,
                                          yoptions=gtk.FILL,
                                          xoptions=gtk.FILL)
            self.__general.bw_attach_next(self.__uptime_value,
                                          yoptions=gtk.FILL)

        self.__general_frame.bw_add(self.__general)
        self.__general_frame.set_expanded(True)

        sequences = self.__node.get_info('sequences')
        if len(sequences) > 0:
            self.__sequences_frame.bw_add(
                    self.__create_sequences_widget(sequences))

        # operating system information widgets
        self.__os = gtk.Notebook()

        os = self.__node.get_info('os')

        if os is not None:

            if 'matches' in os:

                self.__match_scroll = BWScrolledWindow()

                self.__match_store = gtk.ListStore(gobject.TYPE_STRING,
                                                   gobject.TYPE_STRING,
                                                   gobject.TYPE_INT,
                                                   gobject.TYPE_BOOLEAN)

                self.__match_treeview = gtk.TreeView(self.__match_store)

                for os_match in os['matches']:

                    self.__match_store.append([os_match['accuracy'],
                                               os_match['name'],
                                               #os_match['db_line'],
                                               0,   # unsupported
                                               True])

                self.__match_column = list()

                for i in range(len(OSMATCH_HEADER)):

                    column = gtk.TreeViewColumn(OSMATCH_HEADER[i],
                                                self.__cell,
                                                text=i)

                    self.__match_column.append(column)

                    self.__match_column[i].set_reorderable(True)
                    self.__match_column[i].set_resizable(True)
                    self.__match_column[i].set_attributes(self.__cell,
                                                          text=i,
                                                          editable=3)

                    self.__match_column[i].set_sort_column_id(i)
                    self.__match_treeview.append_column(self.__match_column[i])

                self.__match_scroll.add_with_viewport(self.__match_treeview)

                self.__os.append_page(self.__match_scroll, BWLabel(_('Match')))

            if 'classes' in os:

                self.__class_scroll = BWScrolledWindow()

                self.__class_store = gtk.ListStore(gobject.TYPE_STRING,
                                                   gobject.TYPE_STRING,
                                                   gobject.TYPE_STRING,
                                                   gobject.TYPE_STRING,
                                                   gobject.TYPE_STRING,
                                                   gobject.TYPE_BOOLEAN)

                self.__class_treeview = gtk.TreeView(self.__class_store)

                for os_class in os['classes']:

                    os_gen = os_class.get('os_gen', '')

                    self.__class_store.append([os_class['accuracy'],
                                               os_class['vendor'],
                                               os_class['type'],
                                               os_class['os_family'],
                                               os_gen,
                                               True])

                self.__class_column = list()

                for i in range(len(OSCLASS_HEADER)):

                    column = gtk.TreeViewColumn(OSCLASS_HEADER[i],
                                                self.__cell,
                                                text=i)

                    self.__class_column.append(column)

                    self.__class_column[i].set_reorderable(True)
                    self.__class_column[i].set_resizable(True)
                    self.__class_column[i].set_attributes(self.__cell,
                                                          text=i,
                                                          editable=5)

                    self.__class_column[i].set_sort_column_id(i)
                    self.__class_treeview.append_column(self.__class_column[i])

                self.__class_scroll.add_with_viewport(self.__class_treeview)

                self.__os.append_page(self.__class_scroll, BWLabel(_('Class')))

            self.__fp_viewer = BWTextEditor()
            self.__fp_viewer.bw_modify_font(self.__font)
            self.__fp_viewer.bw_set_editable(False)
            self.__fp_viewer.bw_set_text(os['fingerprint'])

            self.__fp_ports = BWHBox()
            self.__fp_label = BWSectionLabel(_('Used ports:'))

            self.__fp_ports_list = gtk.combo_box_entry_new_text()
            self.__fp_ports_list.child.set_editable(False)

            self.__fp_vbox = BWVBox()

            if 'used_ports' in os:

                used_ports = os['used_ports']

                for port in used_ports:

                    params = port['id'], port['protocol'], port['state']
                    self.__fp_ports_list.append_text(USED_PORTS_TEXT % params)

                self.__fp_ports_list.set_active(0)

                self.__fp_ports.bw_pack_start_noexpand_nofill(self.__fp_label)
                self.__fp_ports.bw_pack_start_expand_fill(self.__fp_ports_list)

                self.__fp_vbox.bw_pack_start_noexpand_nofill(self.__fp_ports)

            self.__os.append_page(self.__fp_viewer, BWLabel(_('Fingerprint')))
            self.__fp_vbox.bw_pack_start_expand_fill(self.__os)

            self.__os_frame.bw_add(self.__fp_vbox)
            self.__os_frame.set_expanded(True)

        self.__vbox.bw_pack_start_noexpand_nofill(self.__general_frame)
        self.__vbox.bw_pack_start_expand_fill(self.__os_frame)
        self.__vbox.bw_pack_start_noexpand_nofill(self.__sequences_frame)

        self.add_with_viewport(self.__vbox)

    def __create_sequences_widget(self, sequences):
        """Return a widget representing various OS detection sequences. The
        sequences argument is a dict with zero or more of the keys 'tcp',
        'ip_id', and 'tcp_ts'."""
        # sequences information widgets
        table = BWTable(5, 3)

        table.attach(BWSectionLabel(_('Class')), 1, 2, 0, 1)
        table.attach(BWSectionLabel(_('Values')), 2, 3, 0, 1)

        table.attach(BWSectionLabel(_('TCP *')), 0, 1, 1, 2)
        table.attach(BWSectionLabel(_('IP ID')), 0, 1, 2, 3)
        table.attach(BWSectionLabel(_('TCP Timestamp')), 0, 1, 3, 4)

        tcp = sequences.get('tcp')
        if tcp is not None:
            tcp_class = BWLabel(tcp['class'])
            tcp_class.set_selectable(True)

            table.attach(tcp_class, 1, 2, 1, 2)

            tcp_values = gtk.combo_box_entry_new_text()

            for value in tcp['values']:
                tcp_values.append_text(value)

            tcp_values.set_active(0)

            table.attach(tcp_values, 2, 3, 1, 2)

            tcp_note = BWLabel()
            tcp_note.set_selectable(True)
            tcp_note.set_line_wrap(False)
            tcp_note.set_alignment(1.0, 0.5)
            tcp_note.set_markup(
                    TCP_SEQ_NOTE % (tcp['index'], tcp['difficulty']))

            table.attach(tcp_note, 0, 3, 4, 5)

        ip_id = sequences.get('ip_id')
        if ip_id is not None:
            ip_id_class = BWLabel(ip_id['class'])
            ip_id_class.set_selectable(True)

            table.attach(ip_id_class, 1, 2, 2, 3)

            ip_id_values = gtk.combo_box_entry_new_text()

            for value in ip_id['values']:
                ip_id_values.append_text(value)

            ip_id_values.set_active(0)

            table.attach(ip_id_values, 2, 3, 2, 3)

        tcp_ts = sequences.get('tcp_ts')
        if tcp_ts is not None:
            tcp_ts_class = BWLabel(tcp_ts['class'])
            tcp_ts_class.set_selectable(True)

            table.attach(tcp_ts_class, 1, 2, 3, 4)

            if tcp_ts['values'] is not None:

                tcp_ts_values = gtk.combo_box_entry_new_text()

                for value in tcp_ts['values']:
                    tcp_ts_values.append_text(value)

                tcp_ts_values.set_active(0)

                table.attach(tcp_ts_values, 2, 3, 3, 4)

        return table


class TraceroutePage(BWVBox):
    """
    """
    def __init__(self, node):
        """
        """
        BWVBox.__init__(self)
        self.set_border_width(6)

        self.__node = node

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        trace = self.__node.get_info('trace')
        hops = None
        if trace is not None:
            hops = trace.get("hops")
        if hops is None or len(hops) == 0:

            self.__trace_label = gtk.Label(NO_TRACE_TEXT)
            self.pack_start(self.__trace_label, True, True)

        else:

            # add hops
            hops = self.__node.get_info('trace')['hops']
            ttls = [int(i['ttl']) for i in hops]

            self.__cell = gtk.CellRendererText()

            self.__trace_scroll = BWScrolledWindow()
            self.__trace_scroll.set_border_width(0)

            self.__trace_store = gtk.ListStore(gobject.TYPE_INT,
                                               gobject.TYPE_STRING,
                                               gobject.TYPE_STRING,
                                               gobject.TYPE_STRING,
                                               gobject.TYPE_STRING,
                                               gobject.TYPE_BOOLEAN)

            self.__trace_treeview = gtk.TreeView(self.__trace_store)

            count = 0

            for i in range(1, max(ttls) + 1):

                if i in ttls:

                    hop = hops[count]
                    count += 1

                    self.__trace_store.append([hop['ttl'],
                                               hop['rtt'],
                                               hop['ip'],
                                               hop['hostname'],
                                               HOP_COLOR['known'],
                                               True])

                else:
                    self.__trace_store.append([i,
                                               '',
                                               _('<unknown>'),
                                               '',
                                               HOP_COLOR['unknown'],
                                               True])

            self.__trace_column = list()

            for i in range(len(TRACE_HEADER)):

                column = gtk.TreeViewColumn(TRACE_HEADER[i],
                                            self.__cell,
                                            text=i)

                self.__trace_column.append(column)

                self.__trace_column[i].set_reorderable(True)
                self.__trace_column[i].set_resizable(True)
                self.__trace_column[i].set_attributes(self.__cell,
                                                      text=i,
                                                      background=4,
                                                      editable=5)

                self.__trace_treeview.append_column(self.__trace_column[i])

            self.__trace_column[0].set_sort_column_id(0)

            self.__trace_scroll.add_with_viewport(self.__trace_treeview)

            self.__trace_info = (self.__node.get_info('trace')['port'],
                                 self.__node.get_info('trace')['protocol'],
                                 len(self.__node.get_info('trace')['hops']))

            self.__trace_label = BWLabel(TRACE_TEXT % self.__trace_info)
            self.__trace_label.set_use_markup(True)

            self.bw_pack_start_expand_fill(self.__trace_scroll)
            self.bw_pack_start_noexpand_nofill(self.__trace_label)
