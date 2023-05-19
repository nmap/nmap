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

import re
import copy

from zenmapGUI.higwidgets.higbuttons import HIGButton, HIGToggleButton
from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higlabels import HIGSectionLabel, HintWindow
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog

import datetime

from zenmapCore.Name import APP_DISPLAY_NAME
import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.NmapOptions import split_quoted
from zenmapCore.SearchResult import SearchDir, SearchDB, SearchDummy
from zenmapCore.UmitConf import SearchConfig

from zenmapGUI.FileChoosers import DirectoryChooserDialog

search_config = SearchConfig()


class SearchParser(object):
    """This class is responsible for parsing the search string, and updating
    the search dictionary (which is, in turn, passed to classes that perform
    the actual search). It holds a reference to the SearchGUI object, which is
    used to access its search_dict dictionary, so that all dictionary handling
    is performed here. It is also responsible for adding additional directories
    to the SearchGUI object via the 'dir:' operator."""

    def __init__(self, search_gui, search_keywords):
        self.search_gui = search_gui
        self.search_dict = search_gui.search_dict

        # We need to make an operator->searchkey mapping, since the search
        # entry field and the search classes have different syntax.
        #
        # NOTE: if you want to add a new search key not handled by the
        # SearchResult class, you should add a new method match_CRITERIANAME to
        # the SearchResult class.  For example, if you'd like a "noodles"
        # criteria, you need to create the method
        # SearchResult.match_noodles(self, noodles_string). To see how searches
        # are actually performed, start reading from the SearchResult.search()
        # method.
        self.ops2keys = copy.deepcopy(search_keywords)

        # This is not really an operator (see below)
        self.ops2keys["dir"] = "dir"

    def update(self, search):
        """Updates the search dictionary by parsing the input string."""

        # Kill leftover keys and parse again. SLOW? Not really.
        self.search_dict.clear()

        for word in split_quoted(search):
            if word.find(":") != -1:
                # We have an operator in our word, so we make the part left of
                # the semicolon a key, and the part on the right a value
                op, arg = word.split(":", 1)
                if op in self.ops2keys:
                    key = self.ops2keys[op]
                    if key in self.search_dict:
                        self.search_dict[key].append(arg)
                    else:
                        self.search_dict[key] = [arg]
            else:
                # Just a simple keyword
                if "keyword" in self.search_dict:
                    self.search_dict["keyword"].append(word)
                else:
                    self.search_dict["keyword"] = [word]

        # Check if we have any dir: operators in our map, and if so, add them
        # to the search_gui object and remove them from the map. The dir:
        # operator isn't a real operator, in a sense that it doesn't need to be
        # processed by the SearchResult.search() function. It is needed only to
        # create a new SearchDir object, which is then used to perform the
        # actual search().
        self.search_gui.init_search_dirs(self.search_dict.pop("dir", []))


class SearchGUI(Gtk.Box, object):
    """This class is a VBox that holds the search entry field and buttons on
    top, and the results list on the bottom. The "Cancel" and "Open" buttons
    are a part of the SearchWindow class, not SearchGUI."""
    def __init__(self, search_window):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.VERTICAL)

        self._create_widgets()
        self._pack_widgets()
        self._connect_events()

        # Search options
        self.options = {}
        self.options["file_extension"] = search_config.file_extension
        self.options["directory"] = search_config.directory
        self.options["search_db"] = search_config.search_db

        self.parsed_results = {}
        self._set_result_view()
        self.id = 0
        self.search_window = search_window

        # The Search* objects are created once per Search Window invocation, so
        # that they get a list of scans only once, not whenever the search
        # conditions change
        if self.options["search_db"]:
            try:
                self.search_db = SearchDB()
            except ImportError as e:
                self.search_db = SearchDummy()
                self.no_db_warning.show()
                self.no_db_warning.set_text(
                        'Warning: The database of saved scans is not '
                        'available. (%s.) Use "Include Directory" under '
                        '"Expressions" to search a directory.' % str(e))

        # Search directories can be added via the "dir:" operator, so it needs
        # to be a map
        self.search_dirs = {}
        self.init_search_dirs()

        # We create an empty search dictionary, since SearchParser will fill it
        # with keywords as it encounters different operators in the search
        # string.
        self.search_dict = dict()
        # We need to define our own keyword search dictionary
        search_keywords = dict()
        search_keywords["keyword"] = "keyword"
        search_keywords["profile"] = "profile"
        search_keywords["pr"] = "profile"
        search_keywords["target"] = "target"
        search_keywords["t"] = "target"
        search_keywords["option"] = "option"
        search_keywords["o"] = "option"
        search_keywords["date"] = "date"
        search_keywords["d"] = "date"
        search_keywords["after"] = "after"
        search_keywords["a"] = "after"
        search_keywords["before"] = "before"
        search_keywords["b"] = "before"
        search_keywords["os"] = "os"
        search_keywords["scanned"] = "scanned"
        search_keywords["sp"] = "scanned"
        search_keywords["open"] = "open"
        search_keywords["op"] = "open"
        search_keywords["closed"] = "closed"
        search_keywords["cp"] = "closed"
        search_keywords["filtered"] = "filtered"
        search_keywords["fp"] = "filtered"
        search_keywords["unfiltered"] = "unfiltered"
        search_keywords["ufp"] = "unfiltered"
        search_keywords["open|filtered"] = "open_filtered"
        search_keywords["ofp"] = "open_filtered"
        search_keywords["closed|filtered"] = "closed_filtered"
        search_keywords["cfp"] = "closed_filtered"
        search_keywords["service"] = "service"
        search_keywords["s"] = "service"
        search_keywords["inroute"] = "in_route"
        search_keywords["ir"] = "in_route"
        self.search_parser = SearchParser(self, search_keywords)

        # This list holds the (operator, argument) tuples, parsed from the GUI
        # criteria rows
        self.gui_criteria_list = []

        # Do an initial "empty" search, so that the results window initially
        # holds all scans in the database
        self.search_parser.update("")
        self.start_search()

    def init_search_dirs(self, dirs=[]):
        # Start fresh
        self.search_dirs.clear()

        # If specified, add the search directory from the Zenmap config file to
        # the map
        conf_dir = self.options["directory"]
        if conf_dir:
            self.search_dirs[conf_dir] = SearchDir(
                    conf_dir, self.options["file_extension"])

        # Process any other dirs (as added by the dir: operator)
        for dir in dirs:
            self.search_dirs[dir] = SearchDir(
                    dir, self.options["file_extension"])

    def _create_widgets(self):
        # Search box and buttons
        self.search_top_hbox = HIGHBox()
        self.search_label = HIGSectionLabel(_("Search:"))
        self.search_entry = Gtk.Entry()
        self.expressions_btn = HIGToggleButton(
                _("Expressions "), Gtk.STOCK_EDIT)

        # The quick reference tooltip button
        self.search_tooltip_btn = HIGButton(" ", Gtk.STOCK_INFO)

        # The expression VBox. This is only visible once the user clicks on
        # "Expressions". The expressions (if any) should be tightly packed so
        # that they don't take too much screen real-estate
        self.expr_vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)

        # Results section
        self.result_list = Gtk.ListStore.new([str, str, int])  # title, date, id
        self.result_view = Gtk.TreeView.new_with_model(self.result_list)
        self.result_scrolled = Gtk.ScrolledWindow()
        self.result_title_column = Gtk.TreeViewColumn(title=_("Scan"))
        self.result_date_column = Gtk.TreeViewColumn(title=_("Date"))

        self.no_db_warning = Gtk.Label()
        self.no_db_warning.set_line_wrap(True)
        self.no_db_warning.set_no_show_all(True)

        self.expr_window = None

    def _pack_widgets(self):
        # Packing label, search box and buttons
        self.search_top_hbox.set_spacing(4)
        self.search_top_hbox.pack_start(self.search_label, False, True, 0)
        self.search_top_hbox.pack_start(self.search_entry, True, True, 0)
        self.search_top_hbox.pack_start(self.expressions_btn, False, True, 0)
        self.search_top_hbox.pack_start(self.search_tooltip_btn, False, True, 0)

        # Packing the result section
        self.result_scrolled.add(self.result_view)
        self.result_scrolled.set_policy(
                Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Packing it all together
        self.set_spacing(4)
        self.pack_start(self.search_top_hbox, False, True, 0)
        self.pack_start(self.expr_vbox, False, True, 0)
        self.pack_start(self.result_scrolled, True, True, 0)
        self.pack_start(self.no_db_warning, False, True, 0)

    def _connect_events(self):
        self.search_entry.connect("changed", self.update_search_entry)
        self.search_tooltip_btn.connect("clicked", self.show_quick_help)
        self.expressions_btn.connect("toggled", self.expressions_clicked)

    def show_quick_help(self, widget=None, extra=None):
        hint_window = HintWindow(QUICK_HELP_TEXT)
        hint_window.show_all()

    def expressions_clicked(self, widget=None, extra=None):
        if (len(self.expr_vbox.get_children()) == 0 and
                self.search_entry.get_text() == ""):
            # This is the first time the user has clicked on "Show Expressions"
            # and the search entry box is empty, so we add a single Criterion
            # row
            self.expr_vbox.pack_start(Criterion(self), True, True, 0)

        if self.expressions_btn.get_active():
            # The Expressions GUI is about to be displayed. It needs to reflect
            # all the conditions in the search entry field, so a comparison
            # between the entry field and the GUI needs to be performed.

            # Make the search entry field insensitive while expressions are
            # visible
            self.search_entry.set_sensitive(False)

            # Get a map of operator => argument from the Expressions GUI so
            # that we can compare them with the ones in the search entry field
            gui_ops = {}
            for criterion in self.expr_vbox.get_children():
                if criterion.operator in gui_ops:
                    gui_ops[criterion.operator].append(criterion.argument)
                else:
                    gui_ops[criterion.operator] = [criterion.argument]

            # We compare the search entry field to the Expressions GUI. Every
            # (operator, value) pair must be present in the GUI after this loop
            # is done.
            for op, args in self.search_dict.items():
                for arg in args:
                    if (op not in gui_ops) or (arg not in gui_ops[op]):
                        # We need to add this pair to the GUI
                        self.expr_vbox.pack_start(
                                Criterion(self, op, arg), False, True, 0)

            # Now we check if there are any leftover criterion rows that aren't
            # present in the search_dict (for example, if a user has deleted
            # something from the search entry field)
            for criterion in self.expr_vbox.get_children():
                if (criterion.operator not in self.search_dict or
                        criterion.argument not in self.search_dict[
                            criterion.operator]):
                    criterion.destroy()
            # If we have deleted all rows, add an empty one
            if len(self.expr_vbox.get_children()) == 0:
                self.expr_vbox.pack_start(Criterion(self), True, True, 0)

            # Display all elements
            self.expr_vbox.show_all()
        else:
            # The Expressions GUI is about to be hidden. No updates to the
            # search entry field are necessary, since it gets updated on every
            # change in one of the criterion rows.
            self.expr_vbox.hide()
            self.search_entry.set_sensitive(True)

    def close(self):
        if self.expr_window is not None:
            self.expr_window.close()

    def add_criterion(self, caller):
        # We need to find where the caller (Criteria object) is located among
        # all the rows, so that we can insert the new row after it
        caller_index = self.expr_vbox.get_children().index(caller)

        # Make a new Criteria row and insert it after the calling row
        criteria = Criterion(self, "keyword")
        self.expr_vbox.pack_start(criteria, False, True, 0)
        self.expr_vbox.reorder_child(criteria, caller_index + 1)
        criteria.show_all()

    def remove_criterion(self, c):
        if len(self.expr_vbox.get_children()) > 1:
            c.destroy()
            self.criterion_changed()

    def criterion_changed(self):
        # We go through all criteria rows and make a new search string
        search_string = ""
        for criterion in self.expr_vbox.get_children():
            if criterion.operator != "keyword":
                search_string += criterion.operator + ":"
            search_string += criterion.argument.replace(" ", "") + " "

        self.search_entry.set_text(search_string.strip())

        self.search_parser.update(self.search_entry.get_text())
        self.start_search()

    def add_search_dir(self, dir):
        if dir not in self.search_dirs:
            self.search_dirs[dir] = SearchDir(
                    dir, self.options["file_extension"])

    def update_search_entry(self, widget, extra=None):
        """Called when the search entry field is modified."""
        self.search_parser.update(widget.get_text())
        self.start_search()

    def start_search(self):
        if not self.options["search_db"] and not self.options["directory"]:
            d = HIGAlertDialog(
                    message_format=_("No search method selected!"),
                    secondary_text=_(
                        "%s can search results on directories or inside its "
                        "own database. Please select a method by choosing a "
                        "directory or by checking the search data base option "
                        "in the 'Search options' tab before starting a search"
                        ) % APP_DISPLAY_NAME)
            d.run()
            d.destroy()
            return

        self.clear_result_list()

        matched = 0
        total = 0
        if self.options["search_db"]:
            total += len(self.search_db.get_scan_results())
            for result in self.search_db.search(**self.search_dict):
                self.append_result(result)
                matched += 1

        for search_dir in self.search_dirs.values():
            total += len(search_dir.get_scan_results())
            for result in search_dir.search(**self.search_dict):
                self.append_result(result)
                matched += 1

        #total += len(self.search_tabs.get_scan_results())
        #for result in self.search_tabs.search(**self.search_dict):
        #    self.append_result(result)
        #    matched += 1

        self.search_window.set_label_text(
                "Matched <b>%s</b> out of <b>%s</b> scans." % (
                    str(matched), str(total)))

    def clear_result_list(self):
        for i in range(len(self.result_list)):
            iter = self.result_list.get_iter_first()
            del(self.result_list[iter])

    def append_result(self, parsed_result):
        title = parsed_result.scan_name

        try:
            date = datetime.datetime.fromtimestamp(float(parsed_result.start))
            date_field = date.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            date_field = _("Unknown")

        self.parsed_results[self.id] = [title, parsed_result]
        self.result_list.append([title, date_field, self.id])
        self.id += 1

    def get_selected_results(self):
        selection = self.result_view.get_selection()
        rows = selection.get_selected_rows()
        list_store = rows[0]

        results = {}
        for row in rows[1]:
            r = row[0]
            results[list_store[r][2]] = self.parsed_results[list_store[r][2]]

        return results

    def _set_result_view(self):
        self.result_view.set_enable_search(True)
        self.result_view.set_search_column(0)

        selection = self.result_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.MULTIPLE)

        self.result_view.append_column(self.result_title_column)
        self.result_view.append_column(self.result_date_column)

        self.result_title_column.set_resizable(True)
        self.result_title_column.set_min_width(200)
        self.result_date_column.set_resizable(True)

        self.result_title_column.set_sort_column_id(0)
        self.result_date_column.set_sort_column_id(1)

        self.result_title_column.set_reorderable(True)
        self.result_date_column.set_reorderable(True)

        cell = Gtk.CellRendererText()

        self.result_title_column.pack_start(cell, True)
        self.result_date_column.pack_start(cell, True)

        self.result_title_column.set_attributes(cell, text=0)
        self.result_date_column.set_attributes(cell, text=1)

    selected_results = property(get_selected_results)


class Criterion(Gtk.Box):
    """This class holds one criterion row, represented as an HBox.  It holds a
    ComboBox and a Subcriterion's subclass instance, depending on the selected
    entry in the ComboBox. For example, when the 'Target' option is selected, a
    SimpleSubcriterion widget is displayed, but when the 'Date' operator is
    selected, a DateSubcriterion widget is displayed."""

    def __init__(self, search_window, operator="keyword", argument=""):
        """A reference to the search window is passed so that we can call
        add_criterion and remove_criterion."""
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL)

        self.search_window = search_window
        self.default_operator = operator
        self.default_argument = argument

        # We need this as a map, so that we can pass the operator into
        # the SimpleSubcriterion instance
        self.combo_entries = {"Keyword": ["keyword"],
                              "Profile Name": ["profile"],
                              "Target": ["target"],
                              "Options": ["option"],
                              "Date": ["date", "after", "before"],
                              "Operating System": ["os"],
                              "Port": ["open", "scanned", "closed", "filtered",
                                  "unfiltered", "open_filtered",
                                  "closed_filtered"],
                              "Service": ["service"],
                              "Host In Route": ["inroute"],
                              "Include Directory": ["dir"]}

        self._create_widgets()
        self._pack_widgets()
        self._connect_events()

    def _create_widgets(self):
        # A ComboBox containing the list of operators
        self.operator_combo = Gtk.ComboBoxText()

        # Sort all the keys from combo_entries and make an entry for each of
        # them
        sorted_entries = list(self.combo_entries.keys())
        sorted_entries.sort()
        for name in sorted_entries:
            self.operator_combo.append_text(name)

        # Select the default operator
        for entry, operators in self.combo_entries.items():
            for operator in operators:
                if operator == self.default_operator:
                    self.operator_combo.set_active(sorted_entries.index(entry))
                    break

        # Create a subcriterion
        self.subcriterion = self.new_subcriterion(
                self.default_operator, self.default_argument)

        # The "add" and "remove" buttons
        self.add_btn = HIGButton(" ", Gtk.STOCK_ADD)
        self.remove_btn = HIGButton(" ", Gtk.STOCK_REMOVE)

    def _pack_widgets(self):
        self.pack_start(self.operator_combo, False, True, 0)
        self.pack_start(self.subcriterion, True, True, 0)
        self.pack_start(self.add_btn, False, True, 0)
        self.pack_start(self.remove_btn, False, True, 0)

    def _connect_events(self):
        self.operator_combo.connect("changed", self.operator_changed)
        self.add_btn.connect("clicked", self.add_clicked)
        self.remove_btn.connect("clicked", self.remove_clicked)

    def get_operator(self):
        return self.subcriterion.operator

    def get_argument(self):
        return self.subcriterion.argument

    def add_clicked(self, widget=None, extra=None):
        self.search_window.add_criterion(self)

    def remove_clicked(self, widget=None, extra=None):
        self.search_window.remove_criterion(self)

    def value_changed(self, op, arg):
        """Subcriterion instances call this method when something changes
        inside of them."""
        # We let the search window know about the change
        self.search_window.criterion_changed()

    def new_subcriterion(self, operator="keyword", argument=""):
        if operator in self.combo_entries["Date"]:
            return DateSubcriterion(operator, argument)
        elif operator in self.combo_entries["Port"]:
            return PortSubcriterion(operator, argument)
        elif operator == "dir":
            return DirSubcriterion(operator, argument)
        else:
            return SimpleSubcriterion(operator, argument)

    def operator_changed(self, widget=None, extra=None):
        """This function is called when the user selects a different entry in
        the Criterion's ComboBox."""
        # Destroy the previous subcriterion
        self.subcriterion.destroy()

        # Create a new subcriterion depending on the selected operator
        selected = self.operator_combo.get_active_text()
        operator = self.combo_entries[selected][0]
        self.subcriterion = self.new_subcriterion(operator)

        # Pack it, and place it on the right side of the ComboBox
        self.pack_start(self.subcriterion, True, True, 0)
        self.reorder_child(self.subcriterion, 1)

        # Notify the search window about the change
        self.search_window.criterion_changed()

        # Good to go
        self.subcriterion.show_all()

    operator = property(get_operator)
    argument = property(get_argument)


class Subcriterion(Gtk.Box):
    """This class is a base class for all subcriterion types. Depending on the
    criterion selected in the Criterion's ComboBox, a subclass of Subcriterion
    is created to display the appropriate GUI."""
    def __init__(self):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL)

        self.operator = ""
        self.argument = ""

    def value_changed(self):
        """Propagates the operator and the argument up to the Criterion
        parent."""
        self.get_parent().value_changed(self.operator, self.argument)


class SimpleSubcriterion(Subcriterion):
    """This class represents all 'simple' criterion types that need only an
    entry box in order to define the criterion."""
    def __init__(self, operator="keyword", argument=""):
        Subcriterion.__init__(self)

        self.operator = operator
        self.argument = argument

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.entry = Gtk.Entry()
        if self.argument:
            self.entry.set_text(self.argument)

    def _pack_widgets(self):
        self.pack_start(self.entry, True, True, 0)

    def _connect_widgets(self):
        self.entry.connect("changed", self.entry_changed)

    def entry_changed(self, widget=None, extra=None):
        self.argument = widget.get_text()
        self.value_changed()


class PortSubcriterion(Subcriterion):
    """This class shows the port criterion GUI."""
    def __init__(self, operator="open", argument=""):
        Subcriterion.__init__(self)

        self.operator = operator
        self.argument = argument

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.entry = Gtk.Entry()
        if self.argument:
            self.entry.set_text(self.argument)

        self.label = Gtk.Label.new("  is  ")

        self.port_state_combo = Gtk.ComboBoxText()
        states = ["open", "scanned", "closed", "filtered", "unfiltered",
                "open|filtered", "closed|filtered"]
        for state in states:
            self.port_state_combo.append_text(state)
        self.port_state_combo.set_active(
                states.index(self.operator.replace("_", "|")))

    def _pack_widgets(self):
        self.pack_start(self.entry, True, True, 0)
        self.pack_start(self.label, False, True, 0)
        self.pack_start(self.port_state_combo, False, True, 0)

    def _connect_widgets(self):
        self.entry.connect("changed", self.entry_changed)
        self.port_state_combo.connect("changed", self.port_criterion_changed)

    def entry_changed(self, widget=None, extra=None):
        self.argument = widget.get_text()
        self.value_changed()

    def port_criterion_changed(self, widget=None, extra=None):
        self.operator = widget.get_active_text()
        self.value_changed()


class DirSubcriterion(Subcriterion):
    def __init__(self, operator="dir", argument=""):
        Subcriterion.__init__(self)

        self.operator = operator
        self.argument = argument

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.dir_entry = Gtk.Entry()
        if self.argument:
            self.dir_entry.set_text(self.argument)
        self.chooser_btn = HIGButton("Choose...", Gtk.STOCK_OPEN)

    def _pack_widgets(self):
        self.pack_start(self.dir_entry, True, True, 0)
        self.pack_start(self.chooser_btn, False, True, 0)

    def _connect_widgets(self):
        self.chooser_btn.connect("clicked", self.choose_clicked)
        self.dir_entry.connect("changed", self.dir_entry_changed)

    def choose_clicked(self, widget=None, extra=None):
        # Display a directory chooser dialog
        chooser_dlg = DirectoryChooserDialog("Include folder in search")

        if chooser_dlg.run() == Gtk.ResponseType.OK:
            self.dir_entry.set_text(chooser_dlg.get_filename())

        chooser_dlg.destroy()

    def dir_entry_changed(self, widget=None, extra=None):
        self.argument = widget.get_text()
        self.value_changed()


class DateSubcriterion(Subcriterion):
    def __init__(self, operator="date", argument=""):
        Subcriterion.__init__(self)

        self.text2op = {"is": "date",
                        "after": "after",
                        "before": "before"}

        self.operator = operator

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

        # Count the fuzzy operators, so that we can append them to the argument
        # later
        self.fuzzies = argument.count("~")
        argument = argument.replace("~", "")
        self.minus_notation = False
        if re.match(r"\d\d\d\d-\d\d-\d\d$", argument) is not None:
            year, month, day = argument.split("-")
            self.date = datetime.date(int(year), int(month), int(day))
            self.argument = argument
        elif re.match(r"[-|\+]\d+$", argument) is not None:
            # Convert the date from the "-n" notation into YYYY-MM-DD
            parsed_date = datetime.date.fromordinal(
                    datetime.date.today().toordinal() + int(argument))
            self.argument = argument
            self.date = datetime.date(
                    parsed_date.year, parsed_date.month, parsed_date.day)

            self.minus_notation = True
        else:
            self.date = datetime.date.today()
            self.argument = self.date.isoformat()

        # Append fuzzy operators, if any
        self.argument += "~" * self.fuzzies

    def _create_widgets(self):
        self.date_criterion_combo = Gtk.ComboBoxText()
        self.date_criterion_combo.append_text("is")
        self.date_criterion_combo.append_text("after")
        self.date_criterion_combo.append_text("before")
        if self.operator == "date":
            self.date_criterion_combo.set_active(0)
        elif self.operator == "after":
            self.date_criterion_combo.set_active(1)
        else:
            self.date_criterion_combo.set_active(2)
        self.date_button = HIGButton()

    def _pack_widgets(self):
        self.pack_start(self.date_criterion_combo, False, True, 0)
        self.pack_start(self.date_button, True, True, 0)

    def _connect_widgets(self):
        self.date_criterion_combo.connect(
                "changed", self.date_criterion_changed)
        self.date_button.connect("clicked", self.show_calendar)

    def date_criterion_changed(self, widget=None, extra=None):
        self.operator = self.text2op[widget.get_active_text()]

        # Let the parent know that the operator has changed
        self.value_changed()

    def show_calendar(self, widget):
        calendar = DateCalendar()
        calendar.connect_calendar(self.update_button)
        calendar.show_all()

    def update_button(self, widget):
        cal_date = widget.get_date()
        # Add 1 to month because Gtk.Calendar date is zero-based.
        self.date = datetime.date(cal_date[0], cal_date[1] + 1, cal_date[2])

        # Set the argument, using the search format
        if self.minus_notation:
            # We need to calculate the date's offset from today, so that we can
            # represent the date in the "-n" notation
            today = datetime.date.today()
            offset = self.date.toordinal() - today.toordinal()
            if offset > 0:
                self.argument = "+" + str(offset)
            else:
                self.argument = str(offset)
        else:
            self.argument = self.date.isoformat()
        self.argument += "~" * self.fuzzies

        # Let the parent know about the change
        self.value_changed()

    def set_date(self, date):
        self.date_button.set_label(date.strftime("%d %b %Y"))
        self._date = date

    def get_date(self):
        return self._date

    date = property(get_date, set_date)
    _date = datetime.date.today()


class DateCalendar(Gtk.Window, object):
    def __init__(self):
        Gtk.Window.__init__(self, type=Gtk.WindowType.POPUP)
        self.set_position(Gtk.WindowPosition.MOUSE)

        self.calendar = Gtk.Calendar()
        self.add(self.calendar)

    def connect_calendar(self, update_button_cb):
        self.calendar.connect("day-selected-double-click",
                              self.kill_calendar, update_button_cb)

    def kill_calendar(self, widget, method):
        method(widget)
        self.destroy()

QUICK_HELP_TEXT = _("""\
Entering the text into the search performs a <b>keyword search</b> - the \
search string is matched against the entire output of each scan.

To refine the search, you can use <b>operators</b> to search only within \
a specific part of a scan. Operators can be added to the search \
interactively if you click on the <b>Expressions</b> button, or you can \
enter them manually into the search field. Most operators have a short \
form, listed.

<b>profile: (pr:)</b> - Profile used.
<b>target: (t:)</b> - User-supplied target, or a rDNS result.
<b>option: (o:)</b> - Scan options.
<b>date: (d:)</b> - The date when scan was performed. Fuzzy matching is \
possible using the "~" suffix. Each "~" broadens the search by one day \
on "each side" of the date. In addition, it is possible to use the \
\"date:-n\" notation which means "n days ago".
<b>after: (a:)</b> - Matches scans made after the supplied date \
(<i>YYYY-MM-DD</i> or <i>-n</i>).
<b>before (b:)</b> - Matches scans made before the supplied \
date(<i>YYYY-MM-DD</i> or <i>-n</i>).
<b>os:</b> - All OS-related fields.
<b>scanned: (sp:)</b> - Matches a port if it was among those scanned.
<b>open: (op:)</b> - Open ports discovered in a scan.
<b>closed: (cp:)</b> - Closed ports discovered in a scan.
<b>filtered: (fp:)</b> - Filtered ports discovered in scan.
<b>unfiltered: (ufp:)</b> - Unfiltered ports found in a scan (using, for \
example, an ACK scan).
<b>open|filtered: (ofp:)</b> - Ports in the \"open|filtered\" state.
<b>closed|filtered: (cfp:)</b> - Ports in the \"closed|filtered\" state.
<b>service: (s:)</b> - All service-related fields.
<b>inroute: (ir:)</b> - Matches a router in the scan's traceroute output.
""")
