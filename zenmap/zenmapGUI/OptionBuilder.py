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
from gi.repository import Gtk, GObject


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

from xml.dom import minidom

from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higbuttons import HIGButton

from zenmapGUI.FileChoosers import AllFilesFileChooserDialog
from zenmapGUI.ProfileHelp import ProfileHelp

from zenmapCore.NmapOptions import NmapOptions, split_quoted, join_quoted
import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapGUI.ScriptInterface import ScriptInterface


def get_option_check_auxiliary_widget(option, ops, check):
    if option in ("-sI", "-b", "--script", "--script-args", "--exclude", "-p",
            "-D", "-S", "--source-port", "-e", "--ttl", "-iR", "--max-retries",
            "--host-timeout", "--max-rtt-timeout", "--min-rtt-timeout",
            "--initial-rtt-timeout", "--max-hostgroup", "--min-hostgroup",
            "--max-parallelism", "--min-parallelism", "--max-scan-delay",
            "--scan-delay", "-PA", "-PS", "-PU", "-PO", "-PY"):
        return OptionEntry(option, ops, check)
    elif option in ("-d", "-v"):
        return OptionLevel(option, ops, check)
    elif option in ("--excludefile", "-iL"):
        return OptionFile(option, ops, check)
    elif option in ("-A", "-O", "-sV", "-n", "-6", "-Pn", "-PE", "-PP", "-PM",
            "-PB", "-sC", "--script-trace", "-F", "-f", "--packet-trace", "-r",
            "--traceroute"):
        return None
    elif option in ("",):
        return OptionExtras(option, ops, check)
    else:
        assert False, "Unknown option %s" % option


class OptionEntry(Gtk.Entry):
    def __init__(self, option, ops, check):
        Gtk.Entry.__init__(self)
        self.option = option
        self.ops = ops
        self.check = check
        self.connect("changed", self.changed_cb)
        self.check.connect("toggled", self.check_toggled_cb)
        self.update()

    def update(self):
        if self.ops[self.option] is not None:
            self.set_text(str(self.ops[self.option]))
            self.check.set_active(True)
        else:
            self.set_text("")
            self.check.set_active(False)

    def check_toggled_cb(self, check):
        if check.get_active():
            self.ops[self.option] = self.get_text()
        else:
            self.ops[self.option] = None

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops[self.option] = self.get_text()


class OptionExtras(Gtk.Entry):
    def __init__(self, option, ops, check):
        Gtk.Entry.__init__(self)
        self.ops = ops
        self.check = check
        self.connect("changed", self.changed_cb)
        self.check.connect("toggled", self.check_toggled_cb)
        self.update()

    def update(self):
        if len(self.ops.extras) > 0:
            self.set_text(" ".join(self.ops.extras))
            self.check.set_active(True)
        else:
            self.set_text("")
            self.check.set_active(False)

    def check_toggled_cb(self, check):
        if check.get_active():
            self.ops.extras = [self.get_text()]
        else:
            self.ops.extras = []

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops.extras = [self.get_text()]


class OptionLevel(Gtk.SpinButton):
    def __init__(self, option, ops, check):
        adjustment = Gtk.Adjustment.new(0, 0, 10, 1, 0, 0)
        Gtk.SpinButton.__init__(self, adjustment=adjustment, climb_rate=0.0, digits=0)
        self.option = option
        self.ops = ops
        self.check = check
        self.connect("changed", self.changed_cb)
        self.check.connect("toggled", self.check_toggled_cb)
        self.update()

    def update(self):
        level = self.ops[self.option]
        if level is not None and level > 0:
            self.get_adjustment().set_value(int(level))
            self.check.set_active(True)
        else:
            self.get_adjustment().set_value(0)
            self.check.set_active(False)

    def check_toggled_cb(self, check):
        if check.get_active():
            self.ops[self.option] = int(self.get_adjustment().get_value())
        else:
            self.ops[self.option] = 0

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops[self.option] = int(self.get_adjustment().get_value())


class OptionFile(Gtk.Box):
    __gsignals__ = {
        "changed": (GObject.SignalFlags.RUN_FIRST, GObject.TYPE_NONE, ())
    }

    def __init__(self, option, ops, check):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL)

        self.option = option
        self.ops = ops
        self.check = check

        self.entry = Gtk.Entry()
        self.pack_start(self.entry, True, True, 0)
        button = HIGButton(stock=Gtk.STOCK_OPEN)
        self.pack_start(button, False, True, 0)

        button.connect("clicked", self.clicked_cb)

        self.entry.connect("changed", lambda x: self.emit("changed"))
        self.entry.connect("changed", self.changed_cb)
        self.check.connect("toggled", self.check_toggled_cb)
        self.update()

    def update(self):
        if self.ops[self.option] is not None:
            self.entry.set_text(self.ops[self.option])
            self.check.set_active(True)
        else:
            self.entry.set_text("")
            self.check.set_active(False)

    def check_toggled_cb(self, check):
        if check.get_active():
            self.ops[self.option] = self.entry.get_text()
        else:
            self.ops[self.option] = None

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops[self.option] = self.entry.get_text()

    def clicked_cb(self, button):
        dialog = AllFilesFileChooserDialog(_("Choose file"))
        if dialog.run() == Gtk.ResponseType.OK:
            self.entry.set_text(dialog.get_filename())
        dialog.destroy()


class TargetEntry(Gtk.Entry):
    def __init__(self, ops):
        Gtk.Entry.__init__(self)
        self.ops = ops
        self.connect("changed", self.changed_cb)
        self.update()

    def update(self):
        self.set_text(" ".join(self.ops.target_specs))

    def changed_cb(self, widget):
        self.ops.target_specs = self.get_targets()

    def get_targets(self):
        return split_quoted(self.get_text())


class OptionTab(object):
    def __init__(self, root_tab, ops, update_command, help_buf):
        actions = {'target': self.__parse_target,
                   'option_list': self.__parse_option_list,
                   'option_check': self.__parse_option_check}

        self.ops = ops
        self.update_command = update_command
        self.help_buf = help_buf

        self.profilehelp = ProfileHelp()
        self.notscripttab = False  # assume every tab is scripting tab
        self.widgets_list = []
        for option_element in root_tab.childNodes:
            if (hasattr(option_element, "tagName") and
                    option_element.tagName in actions.keys()):
                parse_func = actions[option_element.tagName]
                widget = parse_func(option_element)
                self.widgets_list.append(widget)

    def __parse_target(self, target_element):
        label = _(target_element.getAttribute('label'))
        label_widget = HIGEntryLabel(label)
        target_widget = TargetEntry(self.ops)
        target_widget.connect("changed", self.update_target)
        return label_widget, target_widget

    def __parse_option_list(self, option_list_element):
        children = option_list_element.getElementsByTagName('option')

        label_widget = HIGEntryLabel(
                _(option_list_element.getAttribute('label')))
        option_list_widget = OptionList(self.ops)

        for child in children:
            option = child.getAttribute('option')
            argument = child.getAttribute('argument')
            label = _(child.getAttribute('label'))
            option_list_widget.append(option, argument, label)
            self.profilehelp.add_label(option, label)
            self.profilehelp.add_shortdesc(
                    option, _(child.getAttribute('short_desc')))
            self.profilehelp.add_example(
                    option, child.getAttribute('example'))

        option_list_widget.update()

        option_list_widget.connect("changed", self.update_list_option)

        return label_widget, option_list_widget

    def __parse_option_check(self, option_check):
        option = option_check.getAttribute('option')
        label = _(option_check.getAttribute('label'))
        short_desc = _(option_check.getAttribute('short_desc'))
        example = option_check.getAttribute('example')

        self.profilehelp.add_label(option, label)
        self.profilehelp.add_shortdesc(option, short_desc)
        self.profilehelp.add_example(option, example)

        check = OptionCheck(option, label)
        auxiliary_widget = get_option_check_auxiliary_widget(
                option, self.ops, check)
        if auxiliary_widget is not None:
            auxiliary_widget.connect("changed", self.update_auxiliary_widget)
            auxiliary_widget.connect(
                    'enter-notify-event', self.enter_notify_event_cb, option)
        else:
            check.set_active(not not self.ops[option])

        check.connect('toggled', self.update_check, auxiliary_widget)
        check.connect('enter-notify-event', self.enter_notify_event_cb, option)

        return check, auxiliary_widget

    def fill_table(self, table, expand_fill=True):
        yopt = (0, Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL)[expand_fill]
        for y, widget in enumerate(self.widgets_list):
            if widget[1] is None:
                table.attach(widget[0], 0, 2, y, y + 1, yoptions=yopt)
            else:
                table.attach(widget[0], 0, 1, y, y + 1, yoptions=yopt)
                table.attach(widget[1], 1, 2, y, y + 1, yoptions=yopt)

    def update_auxiliary_widget(self, auxiliary_widget):
        self.update_command()

    def update(self):
        for check, auxiliary_widget in self.widgets_list:
            if auxiliary_widget is not None:
                auxiliary_widget.update()
            else:
                check.set_active(not not self.ops[check.option])

    def update_target(self, entry):
        self.ops.target_specs = entry.get_targets()
        self.update_command()

    def update_check(self, check, auxiliary_widget):
        if auxiliary_widget is None:
            if check.get_active():
                self.ops[check.option] = True
            else:
                self.ops[check.option] = False
        self.update_command()

    def update_list_option(self, widget):
        if widget.last_selected:
            self.ops[widget.last_selected] = None

        opt, arg, label = widget.list[widget.get_active()]
        if opt:
            if arg:
                self.ops[opt] = arg
            else:
                self.ops[opt] = True

        widget.last_selected = opt

        self.show_help_for_option(opt)

        self.update_command()

    def show_help_for_option(self, option):
        self.profilehelp.handler(option)
        text = ""
        if self.profilehelp.get_currentstate() == "Default":
            text = ""
        else:
            text += self.profilehelp.get_label()
            text += "\n\n"
            text += self.profilehelp.get_shortdesc()
            if self.profilehelp.get_example():
                text += "\n\nExample input:\n"
                text += self.profilehelp.get_example()
        self.help_buf.set_text(text)

    def enter_notify_event_cb(self, event, widget, option):
        self.show_help_for_option(option)


class OptionBuilder(object):
    def __init__(self, xml_file, ops, update_func, help_buf):
        """
        xml_file is a UI description xml-file
        ops is an NmapOptions instance
        """
        xml_desc = open(xml_file)
        self.xml = minidom.parse(xml_desc)
        # Closing file to avoid problems with file descriptors
        xml_desc.close()

        self.ops = ops
        self.help_buf = help_buf
        self.update_func = update_func

        self.root_tag = "interface"

        self.xml = self.xml.getElementsByTagName(self.root_tag)[0]

        self.groups = self.__parse_groups()
        self.section_names = self.__parse_section_names()
        self.tabs = self.__parse_tabs()

    def update(self):
        for tab in self.tabs.values():
            tab.update()

    def __parse_section_names(self):
        dic = {}
        for group in self.groups:
            grp = self.xml.getElementsByTagName(group)[0]
            dic[group] = grp.getAttribute('label')
        return dic

    def __parse_groups(self):
        return [g_name.getAttribute('name') for g_name in
                self.xml.getElementsByTagName('groups')[0].getElementsByTagName('group')]  # noqa

    def __parse_tabs(self):
        dic = {}
        for tab_name in self.groups:
            if tab_name != "Scripting":
                dic[tab_name] = OptionTab(
                        self.xml.getElementsByTagName(tab_name)[0], self.ops,
                        self.update_func, self.help_buf)
                dic[tab_name].notscripttab = True
            else:
                dic[tab_name] = ScriptInterface(
                        None, self.ops, self.update_func, self.help_buf)
        return dic


class OptionList(Gtk.ComboBox):
    def __init__(self, ops):
        self.ops = ops

        self.list = Gtk.ListStore.new([str, str, str])
        Gtk.ComboBox.__init__(self, model=self.list)

        cell = Gtk.CellRendererText()
        self.pack_start(cell, True)
        self.add_attribute(cell, 'text', 2)

        self.last_selected = None
        self.options = []

    def update(self):
        selected = 0
        for i, row in enumerate(self.list):
            opt, arg = row[0], row[1]
            if opt == "":
                continue
            if ((not arg and self.ops[opt]) or
                    (arg and str(self.ops[opt]) == arg)):
                selected = i
        self.set_active(selected)

    def append(self, option, argument, label):
        opt = label
        ops = NmapOptions()
        if option is not None and option != "":
            if argument:
                ops[option] = argument
            else:
                ops[option] = True
            opt += " (%s)" % join_quoted(ops.render()[1:])

        self.list.append([option, argument, opt])
        self.options.append(option)


class OptionCheck(Gtk.CheckButton):
    def __init__(self, option, label):
        opt = label
        if option is not None and option != "":
            opt += " (%s)" % option

        Gtk.CheckButton.__init__(self, label=opt, use_underline=False)

        self.option = option
