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

import gobject
import gtk

from xml.dom import minidom

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higbuttons import HIGButton

from zenmapGUI.FileChoosers import AllFilesFileChooserDialog
from zenmapGUI.ProfileHelp import ProfileHelp

from zenmapCore.Paths import Path
from zenmapCore.NmapOptions import NmapOptions, split_quoted, join_quoted
import zenmapCore.I18N
from zenmapCore.UmitLogging import log
from zenmapGUI.ScriptInterface import *

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

class OptionEntry(gtk.Entry):
    def __init__(self, option, ops, check):
        gtk.Entry.__init__(self)
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
            self.ops[self.option] = self.get_text().decode("UTF-8")
        else:
            self.ops[self.option] = None

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops[self.option] = self.get_text().decode("UTF-8")

class OptionExtras(gtk.Entry):
    def __init__(self, option, ops, check):
        gtk.Entry.__init__(self)
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
            self.ops.extras = [self.get_text().decode("UTF-8")]
        else:
            self.ops.extras = []

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops.extras = [self.get_text().decode("UTF-8")]

class OptionLevel(gtk.SpinButton):
    def __init__(self, option, ops, check):
        gtk.SpinButton.__init__(self, gtk.Adjustment(0, 0, 10, 1), 0.0, 0)
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

class OptionFile(gtk.HBox):
    __gsignals__ = {
        "changed": (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ())
    }

    def __init__(self, option, ops, check):
        gtk.HBox.__init__(self)

        self.option = option
        self.ops = ops
        self.check = check

        self.entry = gtk.Entry()
        self.pack_start(self.entry, True, True)
        button = HIGButton(stock = gtk.STOCK_OPEN)
        self.pack_start(button, False)

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
            self.ops[self.option] = self.entry.get_text().decode("UTF-8")
        else:
            self.ops[self.option] = None

    def changed_cb(self, widget):
        self.check.set_active(True)
        self.ops[self.option] = self.entry.get_text().decode("UTF-8")

    def clicked_cb(self, button):
        dialog = AllFilesFileChooserDialog(_("Choose file"))
        if dialog.run() == gtk.RESPONSE_OK:
            self.entry.set_text(dialog.get_filename())
        dialog.destroy()

class TargetEntry(gtk.Entry):
    def __init__(self, ops):
        gtk.Entry.__init__(self)
        self.ops = ops
        self.connect("changed", self.changed_cb)
        self.update()

    def update(self):
        self.set_text(u" ".join(self.ops.target_specs))

    def changed_cb(self, eidget):
        self.ops.target_specs = self.get_targets()

    def get_targets(self):
        return split_quoted(self.get_text().decode("UTF-8"))

class OptionTab(object):
    def __init__(self, root_tab, ops, update_command, help_buf):
        actions = {'target':self.__parse_target,
                   'option_list':self.__parse_option_list,
                   'option_check':self.__parse_option_check}

        self.ops = ops
        self.update_command = update_command
        self.help_buf = help_buf

        self.profilehelp = ProfileHelp()
        self.notscripttab = False  # assume every tab is scripting tab
        self.widgets_list = []
        for option_element in root_tab.childNodes:
            try:option_element.tagName
            except:pass
            else:
                if option_element.tagName in actions.keys():
                    parse_func = actions[option_element.tagName]
                    widget = parse_func(option_element)
                    self.widgets_list.append(widget)

    def __parse_target(self, target_element):
        label = _(target_element.getAttribute(u'label'))
        label_widget = HIGEntryLabel(label)
        target_widget = TargetEntry(self.ops)
        target_widget.connect("changed", self.update_target)
        return label_widget, target_widget

    def __parse_option_list(self, option_list_element):
        children = option_list_element.getElementsByTagName(u'option')

        label_widget = HIGEntryLabel(_(option_list_element.getAttribute(u'label')))
        option_list_widget = OptionList(self.ops)

        for child in children:
            option = child.getAttribute(u'option')
            argument = child.getAttribute(u'argument')
            label = _(child.getAttribute(u'label'))
            option_list_widget.append(option, argument, label)
            self.profilehelp.add_label(option, label)
            self.profilehelp.add_shortdesc(option, _(child.getAttribute(u'short_desc')))
            self.profilehelp.add_example(option, child.getAttribute(u'example'))

        option_list_widget.update()

        option_list_widget.connect("changed", self.update_list_option)

        return label_widget, option_list_widget

    def __parse_option_check(self, option_check):
        arg_type = option_check.getAttribute(u'arg_type')
        option = option_check.getAttribute(u'option')
        label = _(option_check.getAttribute(u'label'))
        short_desc = _(option_check.getAttribute(u'short_desc'))
        example = option_check.getAttribute(u'example')

        self.profilehelp.add_label(option, label)
        self.profilehelp.add_shortdesc(option, short_desc)
        self.profilehelp.add_example(option, example)

        check = OptionCheck(option, label)
        auxiliary_widget = get_option_check_auxiliary_widget(option, self.ops, check)
        if auxiliary_widget is not None:
            auxiliary_widget.connect("changed", self.update_auxiliary_widget)
            auxiliary_widget.connect('enter-notify-event', self.enter_notify_event_cb, option)
        else:
            check.set_active(not not self.ops[option])

        check.connect('toggled', self.update_check, auxiliary_widget)
        check.connect('enter-notify-event', self.enter_notify_event_cb, option)

        return check, auxiliary_widget

    def fill_table(self, table, expand_fill = True):
        yopt = (0, gtk.EXPAND | gtk.FILL)[expand_fill]
        for y, widget in enumerate(self.widgets_list):
            if widget[1] == None:
                table.attach(widget[0], 0, 2, y, y+1, yoptions=yopt)
            else:
                table.attach(widget[0], 0, 1, y, y+1, yoptions=yopt)
                table.attach(widget[1], 1, 2, y, y+1, yoptions=yopt)

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
            dic[group] = grp.getAttribute(u'label')
        return dic

    def __parse_groups(self):
        return [g_name.getAttribute(u'name') for g_name in \
                  self.xml.getElementsByTagName(u'groups')[0].\
                  getElementsByTagName(u'group')]

    def __parse_tabs(self):
        dic = {}
        for tab_name in self.groups:
            if tab_name != "Scripting":
                dic[tab_name] = OptionTab(self.xml.getElementsByTagName(tab_name)[0],
                                      self.ops, self.update_func, self.help_buf)
                dic[tab_name].notscripttab = True
            else:
                dic[tab_name] =ScriptInterface(None,self.ops, self.update_func, self.help_buf)
        return dic


class OptionList(gtk.ComboBox):
    def __init__(self, ops):
        self.ops = ops

        self.list = gtk.ListStore(str, str, str)
        gtk.ComboBox.__init__(self, self.list)

        cell = gtk.CellRendererText()
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
            if (not arg and self.ops[opt]) or (arg and str(self.ops[opt]) == arg):
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

class OptionCheck(gtk.CheckButton):
    def __init__(self, option, label):
        opt = label
        if option is not None and option != "":
            opt += " (%s)" % option

        gtk.CheckButton.__init__(self, opt, use_underline=False)

        self.option = option
