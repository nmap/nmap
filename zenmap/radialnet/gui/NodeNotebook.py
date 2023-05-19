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
from gi.repository import Gtk, GObject, Pango

from radialnet.bestwidgets.boxes import BWVBox, BWHBox, BWScrolledWindow, BWTable
from radialnet.bestwidgets.expanders import BWExpander
from radialnet.bestwidgets.labels import BWLabel, BWSectionLabel
from radialnet.bestwidgets.textview import BWTextEditor
import zenmapCore.I18N  # lgtm[py/unused-import]


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

TRACE_HEADER = ['TTL', 'RTT', 'IP', _('Hostname')]

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


class NodeNotebook(Gtk.Notebook):
    """
    """
    def __init__(self, node):
        """
        """
        Gtk.Notebook.__init__(self)
        self.set_tab_pos(Gtk.PositionType.TOP)

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


class ServicesPage(Gtk.Notebook):
    """
    """
    def __init__(self, node):
        """
        """
        Gtk.Notebook.__init__(self)
        self.set_border_width(6)
        self.set_tab_pos(Gtk.PositionType.TOP)

        self.__node = node
        self.__font = Pango.FontDescription('Monospace')

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__cell = Gtk.CellRendererText()

        # texteditor widgets
        self.__texteditor = BWTextEditor()
        self.__texteditor.bw_modify_font(self.__font)
        self.__texteditor.bw_set_editable(False)
        self.__texteditor.set_border_width(0)

        self.__select_combobox = Gtk.ComboBoxText()
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

        self.__ports_store = Gtk.TreeStore.new([GObject.TYPE_INT,
                                                GObject.TYPE_STRING,
                                                GObject.TYPE_STRING,
                                                GObject.TYPE_STRING,
                                                GObject.TYPE_STRING,
                                                GObject.TYPE_STRING,
                                                GObject.TYPE_BOOLEAN])

        self.__ports_treeview = Gtk.TreeView.new_with_model(self.__ports_store)

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

            column = Gtk.TreeViewColumn(title=PORTS_HEADER[i],
                                        cell_renderer=self.__cell,
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

        self.__xports_store = Gtk.TreeStore.new([GObject.TYPE_INT,
                                                 GObject.TYPE_STRING,
                                                 GObject.TYPE_STRING,
                                                 GObject.TYPE_STRING,
                                                 GObject.TYPE_BOOLEAN])

        self.__xports_treeview = Gtk.TreeView.new_with_model(self.__xports_store)

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

            column = Gtk.TreeViewColumn(title=EXTRAPORTS_HEADER[i],
                                        cell_renderer=self.__cell,
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
        self.__font = Pango.FontDescription('Monospace')

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__vbox = BWVBox()
        self.__vbox.set_border_width(6)

        self.__cell = Gtk.CellRendererText()

        self.__general_frame = BWExpander(_('General information'))
        self.__sequences_frame = BWExpander(_('Sequences'))
        self.__os_frame = BWExpander(_('Operating System'))

        self.__sequences_frame.bw_add(Gtk.Label.new(_('No sequence information.')))
        self.__os_frame.bw_add(Gtk.Label.new(_('No OS information.')))

        # general information widgets
        self.__general = BWTable(3, 2)

        self.__address_label = BWSectionLabel(_('Address:'))
        self.__address_list = Gtk.ComboBoxText.new_with_entry()
        self.__address_list.get_child().set_editable(False)

        for address in self.__node.get_info('addresses'):

            params = address['type'], address['addr']
            address_text = SYSTEM_ADDRESS_TEXT % params

            if address['vendor'] is not None and address['vendor'] != '':
                address_text += " (%s)" % address['vendor']

            self.__address_list.append_text(address_text)

        self.__address_list.set_active(0)

        self.__general.bw_attach_next(self.__address_label,
                                      yoptions=Gtk.AttachOptions.FILL,
                                      xoptions=Gtk.AttachOptions.FILL)
        self.__general.bw_attach_next(self.__address_list, yoptions=Gtk.AttachOptions.FILL)

        if self.__node.get_info('hostnames') is not None:

            self.__hostname_label = BWSectionLabel(_('Hostname:'))
            self.__hostname_list = Gtk.ComboBoxText.new_with_entry()
            self.__hostname_list.get_child().set_editable(False)

            for hostname in self.__node.get_info('hostnames'):

                params = hostname['type'], hostname['name']
                self.__hostname_list.append_text(SYSTEM_ADDRESS_TEXT % params)

            self.__hostname_list.set_active(0)

            self.__general.bw_attach_next(self.__hostname_label,
                                          yoptions=Gtk.AttachOptions.FILL,
                                          xoptions=Gtk.AttachOptions.FILL)
            self.__general.bw_attach_next(self.__hostname_list,
                                          yoptions=Gtk.AttachOptions.FILL)

        if self.__node.get_info('uptime') is not None:

            self.__uptime_label = BWSectionLabel(_('Last boot:'))

            seconds = self.__node.get_info('uptime')['seconds']
            lastboot = self.__node.get_info('uptime')['lastboot']

            text = _('%s (%s seconds).') % (lastboot, seconds)

            self.__uptime_value = BWLabel(text)
            self.__uptime_value.set_selectable(True)
            self.__uptime_value.set_line_wrap(False)

            self.__general.bw_attach_next(self.__uptime_label,
                                          yoptions=Gtk.AttachOptions.FILL,
                                          xoptions=Gtk.AttachOptions.FILL)
            self.__general.bw_attach_next(self.__uptime_value,
                                          yoptions=Gtk.AttachOptions.FILL)

        self.__general_frame.bw_add(self.__general)
        self.__general_frame.set_expanded(True)

        sequences = self.__node.get_info('sequences')
        if len(sequences) > 0:
            self.__sequences_frame.bw_add(
                    self.__create_sequences_widget(sequences))

        # operating system information widgets
        self.__os = Gtk.Notebook()

        os = self.__node.get_info('os')

        if os is not None:

            if 'matches' in os:

                self.__match_scroll = BWScrolledWindow()

                self.__match_store = Gtk.ListStore.new([str, str, int, bool])
                self.__match_treeview = Gtk.TreeView.new_with_model(self.__match_store)

                for os_match in os['matches']:

                    self.__match_store.append([os_match['accuracy'],
                                               os_match['name'],
                                               #os_match['db_line'],
                                               0,   # unsupported
                                               True])

                self.__match_column = list()

                for i in range(len(OSMATCH_HEADER)):

                    column = Gtk.TreeViewColumn(title=OSMATCH_HEADER[i],
                                                cell_renderer=self.__cell,
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

                self.__class_store = Gtk.ListStore.new([str, str, str, str, str, bool])
                self.__class_treeview = Gtk.TreeView.new_with_model(self.__class_store)

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

                    column = Gtk.TreeViewColumn(title=OSCLASS_HEADER[i],
                                                cell_renderer=self.__cell,
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

            self.__fp_ports_list = Gtk.ComboBoxText.new_with_entry()
            self.__fp_ports_list.get_child().set_editable(False)

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

        table.attach(BWSectionLabel('TCP *'), 0, 1, 1, 2)
        table.attach(BWSectionLabel('IP ID'), 0, 1, 2, 3)
        table.attach(BWSectionLabel(_('TCP Timestamp')), 0, 1, 3, 4)

        tcp = sequences.get('tcp')
        if tcp is not None:
            tcp_class = BWLabel(tcp['class'])
            tcp_class.set_selectable(True)

            table.attach(tcp_class, 1, 2, 1, 2)

            tcp_values = Gtk.ComboBoxText.new_with_entry()

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

            ip_id_values = Gtk.ComboBoxText.new_with_entry()

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

                tcp_ts_values = Gtk.ComboBoxText.new_with_entry()

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

            self.__trace_label = Gtk.Label.new(NO_TRACE_TEXT)
            self.pack_start(self.__trace_label, True, True, 0)

        else:

            # add hops
            hops = self.__node.get_info('trace')['hops']
            ttls = [int(i['ttl']) for i in hops]

            self.__cell = Gtk.CellRendererText()

            self.__trace_scroll = BWScrolledWindow()
            self.__trace_scroll.set_border_width(0)

            self.__trace_store = Gtk.ListStore.new([int, str, str, str, str, bool])
            self.__trace_treeview = Gtk.TreeView.new_with_model(self.__trace_store)

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

                column = Gtk.TreeViewColumn(title=TRACE_HEADER[i],
                                            cell_renderer=self.__cell,
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
