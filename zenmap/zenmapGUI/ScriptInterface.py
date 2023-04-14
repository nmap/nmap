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

# This module is responsible for interface present under "Scripting" tab.

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

import os
import tempfile

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax

from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapCore.ScriptMetadata import get_script_entries
from zenmapCore.ScriptArgsParser import parse_script_args_dict
from zenmapCore.NmapCommand import NmapCommand
from zenmapCore.NmapOptions import NmapOptions
import zenmapCore.NSEDocParser
import zenmapGUI.FileChoosers
from zenmapCore.UmitConf import PathsConfig
from zenmapCore.UmitLogging import log
from zenmapCore.Name import APP_NAME

paths_config = PathsConfig()


def text_buffer_insert_nsedoc(buf, nsedoc):
    """Inserts NSEDoc at the end of the buffer, with markup turned into proper
    tags."""
    if not buf.get_tag_table().lookup("NSEDOC_CODE_TAG"):
        buf.create_tag("NSEDOC_CODE_TAG", font="Monospace")
    for event in zenmapCore.NSEDocParser.nsedoc_parse(nsedoc):
        if event.type == "paragraph_start":
            buf.insert(buf.get_end_iter(), "\n")
        elif event.type == "paragraph_end":
            buf.insert(buf.get_end_iter(), "\n")
        elif event.type == "list_start":
            buf.insert(buf.get_end_iter(), "\n")
        elif event.type == "list_end":
            pass
        elif event.type == "list_item_start":
            buf.insert(buf.get_end_iter(), "\u2022\u00a0")  # bullet nbsp
        elif event.type == "list_item_end":
            buf.insert(buf.get_end_iter(), "\n")
        elif event.type == "text":
            buf.insert(buf.get_end_iter(), event.text)
        elif event.type == "code":
            buf.insert_with_tags_by_name(
                    buf.get_end_iter(), event.text, "NSEDOC_CODE_TAG")


class ScriptHelpXMLContentHandler (xml.sax.handler.ContentHandler):
    """A very simple parser for --script-help XML output. This could extract
    other information like categories and description, but all it gets is
    filenames. (ScriptMetadata gets the other information.)"""
    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)
        self.script_filenames = []
        self.scripts_dir = None
        self.nselib_dir = None

    def startElement(self, name, attrs):
        if name == "directory":
            if "name" not in attrs:
                raise ValueError(
                        '"directory" element did not have "name" attribute')
            dirname = attrs["name"]
            if "path" not in attrs:
                raise ValueError(
                        '"directory" element did not have "path" attribute')
            path = attrs["path"]
            if dirname == "scripts":
                self.scripts_dir = path
            elif dirname == "nselib":
                self.nselib_dir = path
            else:
                # Ignore.
                pass
        elif name == "script":
            if "filename" not in attrs:
                raise ValueError(
                        '"script" element did not have "filename" attribute')
            self.script_filenames.append(attrs["filename"])

    @staticmethod
    def parse_nmap_script_help(f):
        parser = xml.sax.make_parser()
        handler = ScriptHelpXMLContentHandler()
        parser.setContentHandler(handler)
        parser.parse(f)
        return handler


class ScriptInterface:
    # Timeout, in milliseconds, after the user stops typing and we update the
    # interface from --script.
    SCRIPT_LIST_DELAY = 500
    # Timeout, in milliseconds, between polls of the Nmap subprocess.
    NMAP_DELAY = 200

    def __init__(self, root_tabs, ops, update_command, help_buf):
        self.hmainbox = HIGHBox(False, 0)
        self.notscripttab = False  # show profile editor it is a script tab
        self.nmap_process = None
        self.script_list_timeout_id = None
        self.nmap_timeout_id = None
        self.chk_nmap_timeout_id = None
        self.script_file_chooser = None
        self.ops = ops
        self.update_command = update_command
        self.help_buf = help_buf
        self.arg_values = {}
        self.current_arguments = []
        self.set_help_texts()
        self.prev_script_spec = None
        self.focusedentry = None

        self.liststore = Gtk.ListStore.new([str, bool, object])

        self.file_liststore = Gtk.ListStore.new([str, bool])

        # Arg name, arg value, (name, desc) tuple.
        self.arg_liststore = Gtk.ListStore.new([str, str, object])

        # This is what is shown initially. After the initial Nmap run to get
        # the list of script is finished, this will be replaced with a TreeView
        # showing the scripts or an error message.
        self.script_list_container = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
        self.script_list_container.pack_start(self.make_please_wait_widget(), True, True, 0)
        self.hmainbox.pack_start(self.script_list_container, False, False, 0)

        self.nmap_error_widget = Gtk.Label.new(_(
            "There was an error getting the list of scripts from Nmap. "
            "Try upgrading Nmap."))
        self.nmap_error_widget.set_line_wrap(True)
        self.nmap_error_widget.show_all()

        self.script_list_widget = self.make_script_list_widget()
        self.script_list_widget.show_all()

        vbox = HIGVBox(False, 5)
        vbox.pack_start(self.make_description_widget(), True, True, 0)
        vbox.pack_start(self.make_arguments_widget(), True, True, 0)
        self.hmainbox.pack_end(vbox, True, True, 0)

        self.update_argument_values(self.ops["--script-args"])

        # Start the initial backgrounded Nmap run to get the list of all
        # available scripts.
        self.get_script_list("all", self.initial_script_list_cb)

    def get_script_list(self, rules, callback):
        """Start an Nmap subprocess in the background with
        "--script-help=<rules> -oX -", and set it up to call the given callback
        when finished."""

        ops = NmapOptions()
        ops.executable = paths_config.nmap_command_path
        ops["--script-help"] = rules
        ops["-oX"] = "-"
        command_string = ops.render_string()
        # Separate stderr to avoid breaking XML parsing with "Warning: File
        # ./nse_main.lua exists, but Nmap is using...".
        stderr = tempfile.TemporaryFile(
                mode="r", prefix=APP_NAME + "-script-help-stderr-")
        log.debug("Script interface: running %s" % repr(command_string))
        nmap_process = NmapCommand(command_string)
        try:
            nmap_process.run_scan(stderr=stderr)
        except Exception as e:
            callback(False, None)
            stderr.close()
            return
        stderr.close()

        self.script_list_widget.set_sensitive(False)

        GLib.timeout_add(
                self.NMAP_DELAY, self.script_list_timer_callback,
                nmap_process, callback)

    def script_list_timer_callback(self, process, callback):
        try:
            status = process.scan_state()
        except Exception:
            status = None
        log.debug("Script interface: script_list_timer_callback %s" %
                repr(status))

        if status is True:
            # Still running, schedule this timer to check again.
            return True

        self.script_list_widget.set_sensitive(True)

        if status is False:
            # Finished with success.
            callback(True, process)
        else:
            # Finished with error.
            callback(False, process)

    def initial_script_list_cb(self, status, process):
        log.debug("Script interface: initial_script_list_cb %s" % repr(status))
        for child in self.script_list_container.get_children():
            self.script_list_container.remove(child)
        if status and self.handle_initial_script_list_output(process):
            self.script_list_container.pack_start(self.script_list_widget, True, True, 0)
        else:
            self.script_list_container.pack_start(self.nmap_error_widget, True, True, 0)

    def handle_initial_script_list_output(self, process):
        process.stdout_file.seek(0)
        try:
            handler = ScriptHelpXMLContentHandler.parse_nmap_script_help(
                    process.stdout_file)
        except (ValueError, xml.sax.SAXParseException) as e:
            log.debug("--script-help parse exception: %s" % str(e))
            return False

        # Check if any scripts were output; if not, Nmap is probably too old.
        if len(handler.script_filenames) == 0:
            return False

        if not handler.scripts_dir:
            log.debug("--script-help error: no scripts directory")
            return False
        if not handler.nselib_dir:
            log.debug("--script-help error: no nselib directory")
            return False

        log.debug("Script interface: scripts dir %s" % repr(
            handler.scripts_dir))
        log.debug("Script interface: nselib dir %s" % repr(handler.nselib_dir))

        # Make a dict of script metadata entries.
        entries = {}
        for entry in get_script_entries(
                handler.scripts_dir, handler.nselib_dir):
            entries[entry.filename] = entry

        self.liststore.clear()
        for filename in handler.script_filenames:
            basename = os.path.basename(filename)
            entry = entries.get(basename)
            if entry:
                script_id = self.strip_file_name(basename)
                self.liststore.append([script_id, False, entry])
            else:
                # ScriptMetadata found nothing for this script?
                self.file_liststore.append([filename, False])

        # Now figure out which scripts are selected.
        self.update_script_list_from_spec(self.ops["--script"])
        return True

    def update_script_list_from_spec(self, spec):
        """Callback method for user edit delay."""
        log.debug("Script interface: update_script_list_from_spec %s" % repr(
            spec))
        if spec:
            self.get_script_list(spec, self.update_script_list_cb)
        else:
            self.refresh_list_scripts([])

    def update_script_list_cb(self, status, process):
        log.debug("Script interface: update_script_list_cb %s" % repr(status))
        if status:
            self.handle_update_script_list_output(process)
        else:
            self.refresh_list_scripts([])

    def handle_update_script_list_output(self, process):
        process.stdout_file.seek(0)
        try:
            handler = ScriptHelpXMLContentHandler.parse_nmap_script_help(
                    process.stdout_file)
        except (ValueError, xml.sax.SAXParseException) as e:
            log.debug("--script-help parse exception: %s" % str(e))
            return False

        self.refresh_list_scripts(handler.script_filenames)

    def get_hmain_box(self):
        """Returns main Hbox to ProfileEditor."""
        return self.hmainbox

    def update(self):
        """Updates the interface when the command entry is changed."""
        # updates list of scripts
        rules = self.ops["--script"]
        if (self.prev_script_spec != rules):
            self.renew_script_list_timer(rules)
        self.prev_script_spec = rules
        # updates arguments..
        raw_argument = self.ops["--script-args"]
        if raw_argument is not None:
            self.parse_script_args(raw_argument)
        self.arg_liststore.clear()
        for arg in self.current_arguments:
            arg_name, arg_desc = arg
            value = self.arg_values.get(arg_name)
            if not value:
                self.arg_liststore.append([arg_name, None, arg])
            else:
                self.arg_liststore.append([arg_name, value, arg])

    def renew_script_list_timer(self, spec):
        """Restart the timer to update the script list when the user edits the
        command. Because updating the script list is an expensive operation
        involving the creation of a subprocess, we don't do it for every typed
        character."""
        if self.script_list_timeout_id:
            GLib.source_remove(self.script_list_timeout_id)
        self.script_list_timeout_id = GLib.timeout_add(
                self.SCRIPT_LIST_DELAY,
                self.update_script_list_from_spec, spec)

    def parse_script_args(self, raw_argument):
        """When the command line is edited, this function is called to update
        the script arguments display according to the value of
        --script-args."""
        arg_dict = parse_script_args_dict(raw_argument)
        if arg_dict is None:  # if there is parsing error args_dict holds none
            self.arg_values.clear()
        else:
            for key in arg_dict.keys():
                self.arg_values[key] = arg_dict[key]

    def update_argument_values(self, raw_argument):
        """When scripting tab starts up, argument values are updated."""
        if raw_argument is not None:
            self.parse_script_args(raw_argument)

    def set_help_texts(self):
        """Sets the help texts to be displayed."""
        self.list_scripts_help = _("""List of scripts

A list of all installed scripts. Activate or deactivate a script \
by clicking the box next to the script name.""")
        self.description_help = _("""Description

This box shows the categories a script belongs to. In addition, it gives a \
detailed description of the script which is present in script. A URL points \
to online NSEDoc documentation.""")
        self.argument_help = _("""Arguments

A list of arguments that affect the selected script. Enter a value by \
clicking in the value field beside the argument name.""")

    def make_please_wait_widget(self):
        vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
        label = Gtk.Label.new(_("Please wait."))
        label.set_line_wrap(True)
        vbox.pack_start(label, True, True, 0)
        return vbox

    def make_script_list_widget(self):
        """Creates and packs widgets associated with left hand side of
        Interface."""
        vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)

        scrolled_window = HIGScrolledWindow()
        scrolled_window.set_policy(Gtk.PolicyType.ALWAYS, Gtk.PolicyType.ALWAYS)
        # Expand only vertically.
        scrolled_window.set_size_request(175, -1)
        listview = Gtk.TreeView.new_with_model(self.liststore)
        listview.set_headers_visible(False)
        listview.connect("enter-notify-event", self.update_help_ls_cb)
        selection = listview.get_selection()
        selection.connect("changed", self.selection_changed_cb)
        cell = Gtk.CellRendererText()
        togglecell = Gtk.CellRendererToggle()
        togglecell.set_property("activatable", True)
        togglecell.connect("toggled", self.toggled_cb, self.liststore)
        col = Gtk.TreeViewColumn(title=_('Names'))
        col.set_sizing(Gtk.TreeViewColumnSizing.GROW_ONLY)
        col.set_resizable(True)
        togglecol = Gtk.TreeViewColumn(title=None, cell_renderer=togglecell)
        togglecol.add_attribute(togglecell, "active", 1)
        listview.append_column(togglecol)
        listview.append_column(col)
        col.pack_start(cell, True)
        col.add_attribute(cell, "text", 0)
        scrolled_window.add(listview)
        scrolled_window.show()
        vbox.pack_start(scrolled_window, True, True, 0)

        self.file_scrolled_window = HIGScrolledWindow()
        self.file_scrolled_window.set_policy(
                Gtk.PolicyType.ALWAYS, Gtk.PolicyType.ALWAYS)
        self.file_scrolled_window.set_size_request(175, -1)
        self.file_scrolled_window.hide()
        self.file_scrolled_window.set_no_show_all(True)

        self.file_listview = Gtk.TreeView.new_with_model(self.file_liststore)
        self.file_listview.set_headers_visible(False)
        col = Gtk.TreeViewColumn(title=None)
        self.file_listview.append_column(col)
        cell = Gtk.CellRendererToggle()
        col.pack_start(cell, True)
        cell.set_property("activatable", True)
        col.add_attribute(cell, "active", 1)
        cell.connect("toggled", self.toggled_cb, self.file_liststore)

        col = Gtk.TreeViewColumn(title=None)
        self.file_listview.append_column(col)
        cell = Gtk.CellRendererText()
        col.pack_start(cell, True)
        col.add_attribute(cell, "text", 0)

        self.file_listview.show_all()
        self.file_scrolled_window.add(self.file_listview)
        vbox.pack_start(self.file_scrolled_window, False, True, 0)

        hbox = HIGHBox(False, 2)
        self.remove_file_button = HIGButton(stock=Gtk.STOCK_REMOVE)
        self.remove_file_button.connect(
                "clicked", self.remove_file_button_clicked_cb)
        self.remove_file_button.set_sensitive(False)
        hbox.pack_end(self.remove_file_button, True, True, 0)
        add_file_button = HIGButton(stock=Gtk.STOCK_ADD)
        add_file_button.connect("clicked", self.add_file_button_clicked_cb)
        hbox.pack_end(add_file_button, True, True, 0)

        vbox.pack_start(hbox, False, False, 0)

        return vbox

    def refresh_list_scripts(self, selected_scripts):
        """The list of selected scripts is refreshed in the list store."""
        for row in self.liststore:
            row[1] = False
        for row in self.file_liststore:
            row[1] = False
        for filename in selected_scripts:
            for row in self.liststore:
                if row[0] == self.strip_file_name(os.path.basename(filename)):
                    row[1] = True
                    break
            else:
                for row in self.file_liststore:
                    if row[0] == filename:
                        row[1] = True
                        break
                else:
                    self.file_liststore.append([filename, True])

    def strip_file_name(self, filename):
        """Removes a ".nse" extension from filename if present."""
        if(filename.endswith(".nse")):
            return filename[:-4]
        else:
            return filename

    def set_script_from_selection(self):
        scriptsname = []
        for entry in self.liststore:
            if entry[1]:
                scriptsname.append(self.strip_file_name(entry[0]))
        for entry in self.file_liststore:
            if entry[1]:
                scriptsname.append(entry[0])
        if len(scriptsname) == 0:
            self.ops["--script"] = None
        else:
            self.ops["--script"] = ",".join(scriptsname)
        self.update_command()

    def toggled_cb(self, cell, path, model):
        """Callback method, called when the check box in list of scripts is
        toggled."""
        model[path][1] = not model[path][1]
        self.set_script_from_selection()

    def make_description_widget(self):
        """Creates and packs widgets related to displaying the description
        box."""
        sw = HIGScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)
        sw.set_shadow_type(Gtk.ShadowType.OUT)
        sw.set_border_width(5)
        text_view = Gtk.TextView()
        text_view.connect("enter-notify-event", self.update_help_desc_cb)
        self.text_buffer = text_view.get_buffer()
        self.text_buffer.create_tag("Usage", font="Monospace")
        self.text_buffer.create_tag("Output", font="Monospace")
        text_view.set_wrap_mode(Gtk.WrapMode.WORD)
        text_view.set_editable(False)
        text_view.set_justification(Gtk.Justification.LEFT)
        sw.add(text_view)
        return sw

    def make_arguments_widget(self):
        """Creates and packs widgets related to arguments box."""
        vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
        vbox.pack_start(Gtk.Label.new(_("Arguments")), False, False, 0)
        arg_window = HIGScrolledWindow()
        arg_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)
        arg_window.set_shadow_type(Gtk.ShadowType.OUT)

        arg_listview = Gtk.TreeView.new_with_model(self.arg_liststore)
        arg_listview.connect("motion-notify-event", self.update_help_arg_cb)
        argument = Gtk.CellRendererText()
        self.value = Gtk.CellRendererText()
        self.value.connect("edited", self.value_edited_cb, self.arg_liststore)
        arg_col = Gtk.TreeViewColumn(title="Arguments\t")
        val_col = Gtk.TreeViewColumn(title="values")
        arg_listview.append_column(arg_col)
        arg_listview.append_column(val_col)
        arg_col.pack_start(argument, True)
        arg_col.add_attribute(argument, "text", 0)
        val_col.pack_start(self.value, True)
        val_col.add_attribute(self.value, "text", 1)

        arg_window.add(arg_listview)
        vbox.pack_start(arg_window, True, True, 0)

        return vbox

    def value_edited_cb(self, cell, path, new_text, model):
        """Called when the argument cell is edited."""
        self.arg_list = []
        model[path][1] = new_text
        argument_name = model[path][0]
        self.arg_values[argument_name] = new_text
        self.update_arg_values()

    def update_arg_values(self):
        """When the widget is updated with argument value, correspondingly
        update the command line."""
        for key in self.arg_values.keys():
            if len(self.arg_values[key]) == 0:
                del self.arg_values[key]
            else:
                self.arg_list.append(key + "=" + self.arg_values[key])
        if len(self.arg_list) == 0:
            self.ops["--script-args"] = None
            self.arg_values.clear()
        else:
            self.ops["--script-args"] = ",".join(self.arg_list)
        self.update_command()

    def selection_changed_cb(self, selection):
        """Called back when the list of scripts is selected."""
        model, selection = selection.get_selected_rows()
        for path in selection:
            entry = model.get_value(model.get_iter(path), 2)
            self.set_description(entry)
            self.populate_arg_list(entry)
            # Remember the currently pointing script entry
            self.focusedentry = entry

    def update_help_ls_cb(self, widget, extra):  # list of scripts
        """Callback method to display the help for the list of scripts."""
        self.help_buf.set_text(self.list_scripts_help)

    def update_help_desc_cb(self, widget, extra):
        """Callback method for displaying description."""
        self.help_buf.set_text(self.description_help)

    def update_help_arg_cb(self, treeview, event):
        """Callback method for displaying argument help."""
        wx, wy = treeview.get_pointer()
        x, y = treeview.convert_widget_to_bin_window_coords(wx, wy)
        path = treeview.get_path_at_pos(x, y)
        if not path or not self.focusedentry:
            self.help_buf.set_text("")
            return
        path = path[0]
        model, selected = treeview.get_selection().get_selected()
        arg_name, arg_desc = model.get_value(model.get_iter(path), 2)
        if arg_desc is not None:
            self.help_buf.set_text("")
            self.help_buf.insert(
                    self.help_buf.get_end_iter(), text="%s\n" % arg_name)
            text_buffer_insert_nsedoc(self.help_buf, arg_desc)
        else:
            self.help_buf.set_text("")

    def add_file_button_clicked_cb(self, button):
        if self.script_file_chooser is None:
            self.script_file_chooser = \
                    zenmapGUI.FileChoosers.ScriptFileChooserDialog(
                            title=_("Select script files"))
        response = self.script_file_chooser.run()
        filenames = self.script_file_chooser.get_filenames()
        self.script_file_chooser.hide()
        if response != Gtk.ResponseType.OK:
            return
        for filename in filenames:
            self.file_liststore.append([filename, True])
        if len(self.file_liststore) > 0:
            self.file_scrolled_window.show()
            self.remove_file_button.set_sensitive(True)
        self.set_script_from_selection()

    def remove_file_button_clicked_cb(self, button):
        selection = self.file_listview.get_selection()
        model, selection = selection.get_selected_rows()
        for path in selection:
            self.file_liststore.remove(model.get_iter(path))
        if len(self.file_liststore) == 0:
            self.file_scrolled_window.hide()
            self.remove_file_button.set_sensitive(False)
        self.set_script_from_selection()

    def set_description(self, entry):
        """Sets the content that is to be displayed in the description box."""
        self.text_buffer.set_text("")

        self.text_buffer.insert(self.text_buffer.get_end_iter(), """\
Categories: %(cats)s
""" % {"cats": ", ".join(entry.categories)})
        text_buffer_insert_nsedoc(self.text_buffer, entry.description)
        if entry.usage:
            self.text_buffer.insert(
                    self.text_buffer.get_end_iter(), "\nUsage\n")
            self.text_buffer.insert_with_tags_by_name(
                    self.text_buffer.get_end_iter(), entry.usage, "Usage")
        if entry.output:
            self.text_buffer.insert(
                    self.text_buffer.get_end_iter(), "\nOutput\n")
            self.text_buffer.insert_with_tags_by_name(
                    self.text_buffer.get_end_iter(), entry.output, "Output")
        if entry.url:
            self.text_buffer.insert(
                    self.text_buffer.get_end_iter(), "\n" + entry.url)

    def populate_arg_list(self, entry):
        """Called when a particular script is hovered over to display its
        arguments and values (if any)."""
        self.arg_liststore.clear()
        self.current_arguments = []
        self.value.set_property('editable', True)
        for arg in entry.arguments:
            arg_name, arg_desc = arg
            self.current_arguments.append(arg)
            value = self.arg_values.get(arg_name)
            if not value:
                self.arg_liststore.append([arg_name, None, arg])
            else:
                self.arg_liststore.append([arg_name, value, arg])
