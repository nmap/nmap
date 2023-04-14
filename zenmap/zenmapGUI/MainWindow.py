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

import sys
import os
from os.path import split, isfile, join, abspath

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax.saxutils

from zenmapGUI.higwidgets.higwindows import HIGMainWindow
from zenmapGUI.higwidgets.higdialogs import HIGDialog, HIGAlertDialog
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox

import zenmapGUI.App
from zenmapGUI.FileChoosers import RESPONSE_OPEN_DIRECTORY, \
        ResultsFileChooserDialog, SaveResultsFileChooserDialog, \
        SaveToDirectoryChooserDialog
from zenmapGUI.ScanInterface import ScanInterface
from zenmapGUI.ProfileEditor import ProfileEditor
from zenmapGUI.About import About
from zenmapGUI.DiffCompare import DiffWindow
from zenmapGUI.SearchWindow import SearchWindow
from zenmapGUI.BugReport import BugReport

from zenmapCore.Name import APP_DISPLAY_NAME, APP_DOCUMENTATION_SITE
from zenmapCore.Paths import Path
from zenmapCore.RecentScans import recent_scans
from zenmapCore.UmitLogging import log
import zenmapCore.I18N  # lgtm[py/unused-import]
import zenmapGUI.Print
from zenmapCore.UmitConf import SearchConfig, is_maemo, WindowConfig, config_parser

UmitScanWindow = None
hildon = None

if is_maemo():
    import hildon

    class UmitScanWindow(hildon.Window):
        def __init__(self):
            hildon.Window.__init__(self)
            self.set_resizable(False)
            self.set_border_width(0)
            self.vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
            self.vbox.set_border_width(0)

else:
    class UmitScanWindow(HIGMainWindow):
        def __init__(self):
            HIGMainWindow.__init__(self)
            self.vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)


def can_print():
    """Return true if we have printing operations (PyGTK 2.10 or later) or
    false otherwise."""
    try:
        Gtk.PrintOperation
    except AttributeError:
        return False
    else:
        return True


class ScanWindow(UmitScanWindow):
    def __init__(self):
        UmitScanWindow.__init__(self)

        window = WindowConfig()

        self.set_title(_(APP_DISPLAY_NAME))
        self.move(window.x, window.y)
        self.set_default_size(window.width, window.height)

        self.scan_interface = ScanInterface()

        self.main_accel_group = Gtk.AccelGroup()

        self.add_accel_group(self.main_accel_group)

        # self.vbox is a container for the menubar and the scan interface
        self.add(self.vbox)

        self.connect('delete-event', self._exit_cb)
        self._create_ui_manager()
        self._create_menubar()
        self._create_scan_interface()

        self._results_filechooser_dialog = None
        self._about_dialog = None

    def _create_ui_manager(self):
        """Creates the UI Manager and a default set of actions, and builds
        the menus using those actions."""
        self.ui_manager = Gtk.UIManager()

        # See info on ActionGroup at:
        # * http://www.pygtk.org/pygtk2reference/class-gtkactiongroup.html
        # * http://www.gtk.org/api/2.6/gtk/GtkActionGroup.html
        self.main_action_group = Gtk.ActionGroup.new('MainActionGroup')

        # See info on Action at:
        # * http://www.pygtk.org/pygtk2reference/class-gtkaction.html
        # * http://www.gtk.org/api/2.6/gtk/GtkAction.html

        # Each action tuple can go from 1 to six fields, example:
        # ('Open Scan Results',      -> Name of the action
        #   gtk.STOCK_OPEN,          ->
        #   _('_Open Scan Results'), ->
        #   None,
        #   _('Open the results of a previous scan'),
        #   lambda x: True)

        self.main_actions = [
            # Top level
            ('Scan', None, _('Sc_an'), None),

            ('Save Scan',
                Gtk.STOCK_SAVE,
                _('_Save Scan'),
                None,
                _('Save current scan results'),
                self._save_scan_results_cb),

            ('Save All Scans to Directory',
                Gtk.STOCK_SAVE,
                _('Save All Scans to _Directory'),
                "<Control><Alt>s",
                _('Save all scans into a directory'),
                self._save_to_directory_cb),

            ('Open Scan',
                Gtk.STOCK_OPEN,
                _('_Open Scan'),
                None,
                _('Open the results of a previous scan'),
                self._load_scan_results_cb),

            ('Append Scan',
                Gtk.STOCK_ADD,
                _('_Open Scan in This Window'),
                None,
                _('Append a saved scan to the list of scans in this window.'),
                self._append_scan_results_cb),


            ('Tools', None, _('_Tools'), None),

            ('New Window',
                Gtk.STOCK_NEW,
                _('_New Window'),
                "<Control>N",
                _('Open a new scan window'),
                self._new_scan_cb),

            ('Close Window',
                Gtk.STOCK_CLOSE,
                _('Close Window'),
                "<Control>w",
                _('Close this scan window'),
                self._exit_cb),

            ('Print...',
                Gtk.STOCK_PRINT,
                _('Print...'),
                None,
                _('Print the current scan'),
                self._print_cb),

            ('Quit',
                Gtk.STOCK_QUIT,
                _('Quit'),
                "<Control>q",
                _('Quit the application'),
                self._quit_cb),

            ('New Profile',
                Gtk.STOCK_JUSTIFY_LEFT,
                _('New _Profile or Command'),
                '<Control>p',
                _('Create a new scan profile using the current command'),
                self._new_scan_profile_cb),

            ('Search Scan',
                Gtk.STOCK_FIND,
                _('Search Scan Results'),
                '<Control>f',
                _('Search for a scan result'),
                self._search_scan_result),

            ('Filter Hosts',
                Gtk.STOCK_FIND,
                _('Filter Hosts'),
                '<Control>l',
                _('Search for host by criteria'),
                self._filter_cb),

            ('Edit Profile',
                Gtk.STOCK_PROPERTIES,
                _('_Edit Selected Profile'),
                '<Control>e',
                _('Edit selected scan profile'),
                self._edit_scan_profile_cb),

            # Top Level
            ('Profile', None, _('_Profile'), None),

            ('Compare Results',
                Gtk.STOCK_DND_MULTIPLE,
                _('Compare Results'),
                "<Control>D",
                _('Compare Scan Results using Diffies'),
                self._load_diff_compare_cb),


            # Top Level
            ('Help', None, _('_Help'), None),

            ('Report a bug',
                Gtk.STOCK_DIALOG_INFO,
                _('_Report a bug'),
                '<Control>b',
                _("Report a bug"),
                self._show_bug_report
                ),

            ('About',
                Gtk.STOCK_ABOUT,
                _('_About'),
                None,
                _("About %s") % APP_DISPLAY_NAME,
                self._show_about_cb
                ),

            ('Show Help',
                Gtk.STOCK_HELP,
                _('_Help'),
                None,
                _('Shows the application help'),
                self._help_cb),
            ]

        # See info on UIManager at:
        # * http://www.pygtk.org/pygtk2reference/class-gtkuimanager.html
        # * http://www.gtk.org/api/2.6/gtk/GtkUIManager.html

        # UIManager supports UI "merging" and "unmerging". So, suppose there's
        # no scan running or scan results opened, we should have a minimal
        # interface. When we one scan running, we should "merge" the scan UI.
        # When we get multiple tabs opened, we might merge the tab UI.

        # This is the default, minimal UI
        self.default_ui = """<menubar>
        <menu action='Scan'>
            <menuitem action='New Window'/>
            <menuitem action='Open Scan'/>
            <menuitem action='Append Scan'/>
             %s
            <separator/>
            <menuitem action='Save Scan'/>
            <menuitem action='Save All Scans to Directory'/>
        """
        if can_print():
            self.default_ui += """
            <separator/>
            <menuitem action='Print...'/>
            """
        self.default_ui += """
            <separator/>
            <menuitem action='Close Window'/>
            <menuitem action='Quit'/>
        </menu>

        <menu action='Tools'>
            <menuitem action='Compare Results'/>
            <menuitem action='Search Scan'/>
            <menuitem action='Filter Hosts'/>
         </menu>

        <menu action='Profile'>
            <menuitem action='New Profile'/>
            <menuitem action='Edit Profile'/>
        </menu>

        <menu action='Help'>
            <menuitem action='Show Help'/>
            <menuitem action='Report a bug'/>
            <menuitem action='About'/>
        </menu>

        </menubar>
        """

        self.get_recent_scans()

        self.main_action_group.add_actions(self.main_actions)

        for action in self.main_action_group.list_actions():
            action.set_accel_group(self.main_accel_group)
            action.connect_accelerator()

        self.ui_manager.insert_action_group(self.main_action_group, 0)
        self.ui_manager.add_ui_from_string(self.default_ui)

    def _show_bug_report(self, widget):
        """Displays a 'How to report a bug' window."""
        bug = BugReport()
        bug.show_all()

    def _search_scan_result(self, widget):
        """Displays a search window."""
        search_window = SearchWindow(
                self._load_search_result, self._append_search_result)
        search_window.show_all()

    def _filter_cb(self, widget):
        self.scan_interface.toggle_filter_bar()

    def _load_search_result(self, results):
        """This function is passed as an argument to the SearchWindow.__init__
        method.  When the user selects scans in the search window and clicks on
        "Open", this function is called to load each of the selected scans into
        a new window."""
        for result in results:
            self._load(self.get_empty_interface(),
                    parsed_result=results[result][1])

    def _append_search_result(self, results):
        """This function is passed as an argument to the SearchWindow.__init__
        method.  When the user selects scans in the search window and clicks on
        "Append", this function is called to append the selected scans into the
        current window."""
        for result in results:
            self._load(self.scan_interface, parsed_result=results[result][1])

    def store_result(self, scan_interface):
        """Stores the network inventory into the database."""
        log.debug(">>> Saving result into database...")
        try:
            scan_interface.inventory.save_to_db()
        except Exception as e:
            alert = HIGAlertDialog(
                    message_format=_("Can't save to database"),
                    secondary_text=_("Can't store unsaved scans to the "
                        "recent scans database:\n%s") % str(e))
            alert.run()
            alert.destroy()
            log.debug(">>> Can't save result to database: %s." % str(e))

    def get_recent_scans(self):
        """Gets seven most recent scans and appends them to the default UI
        definition."""
        r_scans = recent_scans.get_recent_scans_list()
        new_rscan_xml = ''

        for scan in r_scans[:7]:
            scan = scan.replace('\n', '')
            if os.access(split(scan)[0], os.R_OK) and isfile(scan):
                scan = scan.replace('\n', '')
                new_rscan = (
                        scan, None, scan, None, scan, self._load_recent_scan)
                new_rscan_xml += "<menuitem action=%s/>\n" % (
                        xml.sax.saxutils.quoteattr(scan))

                self.main_actions.append(new_rscan)

        new_rscan_xml += "<separator />\n"

        self.default_ui %= new_rscan_xml

    def _create_menubar(self):
        # Get and pack the menubar
        menubar = self.ui_manager.get_widget('/menubar')

        if is_maemo():
            menu = Gtk.Menu()
            for child in menubar.get_children():
                child.reparent(menu)
            self.set_menu(menu)
            menubar.destroy()
            self.menubar = menu
        else:
            self.menubar = menubar
            self.vbox.pack_start(self.menubar, False, False, 0)

        self.menubar.show_all()

    def _create_scan_interface(self):
        notebook = self.scan_interface.scan_result.scan_result_notebook
        notebook.scans_list.append_button.connect(
                "clicked", self._append_scan_results_cb)
        notebook.nmap_output.connect("changed", self._displayed_scan_change_cb)
        self._displayed_scan_change_cb(None)
        self.scan_interface.show_all()
        self.vbox.pack_start(self.scan_interface, True, True, 0)

    def show_open_dialog(self, title=None):
        """Show a load file chooser and return the filename chosen."""
        if self._results_filechooser_dialog is None:
            self._results_filechooser_dialog = ResultsFileChooserDialog(
                    title=title)

        filename = None
        response = self._results_filechooser_dialog.run()
        if response == Gtk.ResponseType.OK:
            filename = self._results_filechooser_dialog.get_filename()
        elif response == RESPONSE_OPEN_DIRECTORY:
            filename = self._results_filechooser_dialog.get_filename()

            # Check if the selected filename is a directory. If not, we take
            # only the directory part of the path, omitting the actual name of
            # the selected file.
            if filename is not None and not os.path.isdir(filename):
                filename = os.path.dirname(filename)

        self._results_filechooser_dialog.hide()
        return filename

    def _load_scan_results_cb(self, p):
        """'Open Scan' callback function. Displays a file chooser dialog and
        loads the scan from the selected file or from the selected
        directory."""
        filename = self.show_open_dialog(p.get_name())
        if filename is not None:
            scan_interface = self.get_empty_interface()
            if os.path.isdir(filename):
                self._load_directory(scan_interface, filename)
            else:
                self._load(scan_interface, filename)

    def _append_scan_results_cb(self, p):
        """'Append Scan' callback function. Displays a file chooser dialog and
        appends the scan from the selected file into the current window."""
        filename = self.show_open_dialog(p.get_name())
        if filename is not None:
            if os.path.isdir(filename):
                self._load_directory(self.scan_interface, filename)
            else:
                self._load(self.scan_interface, filename)

    def _displayed_scan_change_cb(self, widget):
        """Called when the currently shown scan output is changed."""
        # Set the Print... menu item sensitive if there is something to print.
        widget = self.ui_manager.get_widget("/ui/menubar/Scan/Print...")
        if widget is None:
            # Don't have a Print menu item for lack of support.
            return
        entry = self.scan_interface.scan_result.scan_result_notebook.nmap_output.get_active_entry()  # noqa
        widget.set_sensitive(entry is not None)

    def _load_recent_scan(self, widget):
        """A helper function for loading a recent scan directly from the
        menu."""
        self._load(self.get_empty_interface(), widget.get_name())

    def _load(self, scan_interface, filename=None, parsed_result=None):
        """Loads the scan from a file or from a parsed result into the given
        scan interface."""
        if not (filename or parsed_result):
            return None

        if filename:
            # Load scan result from file
            log.debug(">>> Loading file: %s" % filename)
            try:
                # Parse result
                scan_interface.load_from_file(filename)
            except Exception as e:
                alert = HIGAlertDialog(message_format=_('Error loading file'),
                                       secondary_text=str(e))
                alert.run()
                alert.destroy()
                return
            scan_interface.saved_filename = filename
        elif parsed_result:
            # Load scan result from parsed object
            scan_interface.load_from_parsed_result(parsed_result)

    def _load_directory(self, scan_interface, directory):
        for file in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, file)):
                continue
            self._load(scan_interface, filename=os.path.join(directory, file))

    def _save_scan_results_cb(self, widget):
        """'Save Scan' callback function. If it's OK to save the scan, it
        displays a 'Save File' dialog and saves the scan. If not, it displays
        an appropriate alert dialog."""
        num_scans = len(self.scan_interface.inventory.get_scans())
        if num_scans == 0:
            alert = HIGAlertDialog(
                    message_format=_('Nothing to save'),
                    secondary_text=_(
                        'There are no scans with results to be saved. '
                        'Run a scan with the "Scan" button first.'))
            alert.run()
            alert.destroy()
            return
        num_scans_running = self.scan_interface.num_scans_running()
        if num_scans_running > 0:
            if num_scans_running == 1:
                text = _("There is a scan still running. "
                        "Wait until it finishes and then save.")
            else:
                text = _("There are %u scans still running. Wait until they "
                        "finish and then save.") % num_scans_running
            alert = HIGAlertDialog(message_format=_('Scan is running'),
                                   secondary_text=text)
            alert.run()
            alert.destroy()
            return

        # If there's more than one scan in the inventory, display a warning
        # dialog saying that only the most recent scan will be saved
        selected = 0
        if num_scans > 1:
            #text = _("You have %u scans loaded in the current view. "
            #        "Only the most recent scan will be saved." % num_scans)
            #alert = HIGAlertDialog(
            #        message_format=_("More than one scan loaded"),
            #       secondary_text=text)
            #alert.run()
            #alert.destroy()
            dlg = HIGDialog(
                    title="Choose a scan to save",
                    parent=self,
                    flags=Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
                    buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
            dlg.vbox.pack_start(Gtk.Label.new(
                "You have %u scans loaded in the current view.\n"
                "Select the scan which you would like to save." % num_scans),
                False, True, 0)
            scan_combo = Gtk.ComboBoxText()
            for scan in self.scan_interface.inventory.get_scans():
                scan_combo.append_text(scan.nmap_command)
            scan_combo.set_active(0)
            dlg.vbox.pack_start(scan_combo, False, True, 0)
            dlg.vbox.show_all()
            if dlg.run() == Gtk.ResponseType.OK:
                selected = scan_combo.get_active()
                dlg.destroy()
            else:
                dlg.destroy()
                return

        # Show the dialog to choose the path to save scan result
        self._save_results_filechooser_dialog = \
            SaveResultsFileChooserDialog(title=_('Save Scan'))
        # Supply a default file name if this scan was previously saved.
        if self.scan_interface.saved_filename:
            self._save_results_filechooser_dialog.set_filename(
                    self.scan_interface.saved_filename)

        response = self._save_results_filechooser_dialog.run()

        filename = None
        if (response == Gtk.ResponseType.OK):
            filename = self._save_results_filechooser_dialog.get_filename()
            format = self._save_results_filechooser_dialog.get_format()
            # add .xml to filename if there is no other extension
            if filename.find('.') == -1:
                filename += ".xml"
            self._save(self.scan_interface, filename, selected, format)

        self._save_results_filechooser_dialog.destroy()
        self._save_results_filechooser_dialog = None

    def _save_to_directory_cb(self, widget):
        if self.scan_interface.empty:
            alert = HIGAlertDialog(message_format=_('Nothing to save'),
                                   secondary_text=_('\
This scan has not been run yet. Start the scan with the "Scan" button first.'))
            alert.run()
            alert.destroy()
            return
        num_scans_running = self.scan_interface.num_scans_running()
        if num_scans_running > 0:
            if num_scans_running == 1:
                text = _("There is a scan still running. "
                        "Wait until it finishes and then save.")
            else:
                text = _("There are %u scans still running. Wait until they "
                        "finish and then save.") % num_scans_running
            alert = HIGAlertDialog(message_format=_('Scan is running'),
                                   secondary_text=text)
            alert.run()
            alert.destroy()
            return

        # We have multiple scans in our network inventory, so we need to
        # display a directory chooser dialog
        dir_chooser = SaveToDirectoryChooserDialog(
                title=_("Choose a directory to save scans into"))
        if dir_chooser.run() == Gtk.ResponseType.OK:
            self._save_all(self.scan_interface, dir_chooser.get_filename())
        dir_chooser.destroy()

    def _about_cb_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.DELETE_EVENT:
            self._about_dialog = None
        else:
            self._about_dialog.hide()

    def _show_about_cb(self, widget):
        if self._about_dialog is None:
            self._about_dialog = About()
            self._about_dialog.connect("response", self._about_cb_response)
        self._about_dialog.present()

    def _save_all(self, scan_interface, directory):
        """Saves all scans in saving_page's inventory to a given directory.
        Displays an alert dialog if the save fails."""
        try:
            filenames = scan_interface.inventory.save_to_dir(directory)
            for scan in scan_interface.inventory.get_scans():
                scan.unsaved = False
        except Exception as ex:
            alert = HIGAlertDialog(message_format=_('Can\'t save file'),
                        secondary_text=str(ex))
            alert.run()
            alert.destroy()
        else:
            scan_interface.saved_filename = directory

            # Saving recent scan information
            try:
                for filename in filenames:
                    recent_scans.add_recent_scan(filename)
                recent_scans.save()
            except (OSError, IOError) as e:
                alert = HIGAlertDialog(
                        message_format=_(
                            "Can't save recent scan information"),
                        secondary_text=_(
                            "Can't open file to write.\n%s") % str(e))
                alert.run()
                alert.destroy()

    def _save(self, scan_interface, saved_filename, selected_index,
            format="xml"):
        """Saves the scan into a file with a given filename. Displays an alert
        dialog if the save fails."""
        log.debug(">>> File being saved: %s" % saved_filename)
        try:
            scan_interface.inventory.save_to_file(
                    saved_filename, selected_index, format)
            scan_interface.inventory.get_scans()[selected_index].unsaved = False  # noqa
        except (OSError, IOError) as e:
            alert = HIGAlertDialog(
                    message_format=_("Can't save file"),
                    secondary_text=_("Can't open file to write.\n%s") % str(e))
            alert.run()
            alert.destroy()
        else:
            scan_interface.saved_filename = saved_filename

            log.debug(">>> Changes on page? %s" % scan_interface.changed)
            log.debug(">>> File saved at: %s" % scan_interface.saved_filename)

            if format == "xml":
                # Saving recent scan information
                try:
                    recent_scans.add_recent_scan(saved_filename)
                    recent_scans.save()
                except (OSError, IOError) as e:
                    alert = HIGAlertDialog(
                            message_format=_(
                                "Can't save recent scan information"),
                            secondary_text=_(
                                "Can't open file to write.\n%s") % str(e))
                    alert.run()
                    alert.destroy()

    def get_empty_interface(self):
        """Return this window if it is empty, otherwise create and return a new
        one."""
        if self.scan_interface.empty:
            return self.scan_interface
        return self._new_scan_cb().scan_interface

    def _new_scan_cb(self, widget=None, data=None):
        """Create a new scan window."""
        w = zenmapGUI.App.new_window()
        w.show_all()
        return w

    def _new_scan_profile_cb(self, p):
        pe = ProfileEditor(
                command=self.scan_interface.command_toolbar.command,
                deletable=False)
        pe.set_scan_interface(self.scan_interface)
        pe.show_all()

    def _edit_scan_profile_cb(self, p):
        pe = ProfileEditor(
                profile_name=self.scan_interface.toolbar.selected_profile,
                deletable=True, overwrite=True)
        pe.set_scan_interface(self.scan_interface)
        pe.show_all()

    def _help_cb(self, action):
        self.show_help()

    def _exit_cb(self, *args):
        """Closes the window, prompting for confirmation if necessary. If one
        of the tabs couldn't be closed, the function returns True and doesn't
        exit the application."""
        if self.scan_interface.changed:
            log.debug("Found changes on closing window")
            dialog = HIGDialog(
                    buttons=(_('Close anyway'),
                        Gtk.ResponseType.CLOSE, Gtk.STOCK_CANCEL,
                        Gtk.ResponseType.CANCEL))

            alert = HIGEntryLabel('<b>%s</b>' % _("Unsaved changes"))

            text = HIGEntryLabel(_("The given scan has unsaved changes.\n"
                "What do you want to do?"))
            hbox = HIGHBox()
            hbox.set_border_width(5)
            hbox.set_spacing(12)

            vbox = HIGVBox()
            vbox.set_border_width(5)
            vbox.set_spacing(12)

            image = Gtk.Image()
            image.set_from_stock(
                    Gtk.STOCK_DIALOG_QUESTION, Gtk.IconSize.DIALOG)

            vbox.pack_start(alert, True, True, 0)
            vbox.pack_start(text, True, True, 0)
            hbox.pack_start(image, True, True, 0)
            hbox.pack_start(vbox, True, True, 0)

            dialog.vbox.pack_start(hbox, True, True, 0)
            dialog.vbox.show_all()

            response = dialog.run()
            dialog.destroy()

            if response == Gtk.ResponseType.CANCEL:
                return True

            search_config = SearchConfig()
            if search_config.store_results:
                self.store_result(self.scan_interface)

        elif self.scan_interface.num_scans_running() > 0:
            log.debug("Trying to close a window with a running scan")
            dialog = HIGDialog(
                    buttons=(_('Close anyway'),
                        Gtk.ResponseType.CLOSE, Gtk.STOCK_CANCEL,
                        Gtk.ResponseType.CANCEL))

            alert = HIGEntryLabel('<b>%s</b>' % _("Trying to close"))

            text = HIGEntryLabel(_(
                "The window you are trying to close has a scan running in "
                "the background.\nWhat do you want to do?"))
            hbox = HIGHBox()
            hbox.set_border_width(5)
            hbox.set_spacing(12)

            vbox = HIGVBox()
            vbox.set_border_width(5)
            vbox.set_spacing(12)

            image = Gtk.Image()
            image.set_from_stock(
                    Gtk.STOCK_DIALOG_WARNING, Gtk.IconSize.DIALOG)

            vbox.pack_start(alert, True, True, 0)
            vbox.pack_start(text, True, True, 0)
            hbox.pack_start(image, True, True, 0)
            hbox.pack_start(vbox, True, True, 0)

            dialog.vbox.pack_start(hbox, True, True, 0)
            dialog.vbox.show_all()

            response = dialog.run()
            dialog.destroy()

            if response == Gtk.ResponseType.CLOSE:
                self.scan_interface.kill_all_scans()
            elif response == Gtk.ResponseType.CANCEL:
                return True

        window = WindowConfig()
        window.x, window.y = self.get_position()
        window.width, window.height = self.get_size()
        window.save_changes()
        if config_parser.failed:
            alert = HIGAlertDialog(
                    message_format=_("Can't save Zenmap configuration"),
                    # newline before path to help avoid weird line wrapping
                    secondary_text=_(
                        'An error occurred when saving to\n%s'
                        '\nThe error was: %s.'
                        ) % (Path.user_config_file, config_parser.failed))
            alert.run()
            alert.destroy()

        self.destroy()

        return False

    def _print_cb(self, *args):
        """Show a print dialog."""
        entry = self.scan_interface.scan_result.scan_result_notebook.nmap_output.get_active_entry()  # noqa
        if entry is None:
            return False
        zenmapGUI.Print.run_print_operation(
                self.scan_interface.inventory, entry)

    def _quit_cb(self, *args):
        """Close all open windows."""
        for window in zenmapGUI.App.open_windows[:]:
            window.present()
            if window._exit_cb():
                break

    def _load_diff_compare_cb(self, widget=None, extra=None):
        """Loads all active scans into a dictionary, passes it to the
        DiffWindow constructor, and then displays the 'Compare Results'
        window."""
        self.diff_window = DiffWindow(
                self.scan_interface.inventory.get_scans())
        self.diff_window.show_all()


    def show_help(self):
        import urllib.request
        import webbrowser

        doc_path = abspath(join(Path.docs_dir, "help.html"))
        url = "file:" + urllib.request.pathname2url(doc_path)

        try:
            webbrowser.open(url, new=2)
        except OSError as e:
            d = HIGAlertDialog(parent=self,
                               message_format=_("Can't find documentation files"),
                               secondary_text=_("""\
There was an error loading the documentation file %s (%s). See the \
online documentation at %s.\
""") % (doc_path, str(e), APP_DOCUMENTATION_SITE))
            d.run()
            d.destroy()

if __name__ == '__main__':
    w = ScanWindow()
    w.show_all()
    Gtk.main()
