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
from gi.repository import Gtk

from radialnet.bestwidgets.buttons import BWStockButton, BWToggleStockButton
from radialnet.gui.SaveDialog import SaveDialog
from radialnet.gui.Dialogs import AboutDialog
from radialnet.gui.LegendWindow import LegendWindow
from radialnet.gui.HostsViewer import HostsViewer
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog


SHOW = True
HIDE = False

REFRESH_RATE = 500


class ToolsMenu(Gtk.Menu):
    """
    """
    def __init__(self, radialnet):
        """
        """
        Gtk.Menu.__init__(self)

        self.radialnet = radialnet

        self.__create_items()

    def __create_items(self):
        """
        """
        self.__hosts = Gtk.ImageMenuItem.new_with_label(_('Hosts viewer'))
        self.__hosts.connect("activate", self.__hosts_viewer_callback)
        self.__hosts_image = Gtk.Image()
        self.__hosts_image.set_from_stock(Gtk.STOCK_INDEX, Gtk.IconSize.MENU)
        self.__hosts.set_image(self.__hosts_image)

        self.append(self.__hosts)

        self.__hosts.show_all()

    def __hosts_viewer_callback(self, widget):
        """
        """
        window = HostsViewer(self.radialnet.get_scanned_nodes())
        window.show_all()
        window.set_keep_above(True)

    def enable_dependents(self):
        """
        """
        self.__hosts.set_sensitive(True)

    def disable_dependents(self):
        """
        """
        self.__hosts.set_sensitive(False)


class Toolbar(Gtk.Box):
    """
    """
    def __init__(self, radialnet, window, control, fisheye):
        """
        """
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL)
        #self.set_style(gtk.TOOLBAR_BOTH_HORIZ)
        #self.set_tooltips(True)

        self.radialnet = radialnet

        self.__window = window
        self.__control_widget = control
        self.__fisheye_widget = fisheye

        self.__control_widget.show_all()
        self.__control_widget.set_no_show_all(True)
        self.__control_widget.hide()

        self.__fisheye_widget.show_all()
        self.__fisheye_widget.set_no_show_all(True)
        self.__fisheye_widget.hide()

        self.__save_chooser = None

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        # self.__tooltips = gtk.Tooltips()

        #self.__tools_menu = ToolsMenu(self.radialnet)

        #self.__tools_button = gtk.MenuToolButton(gtk.STOCK_PREFERENCES)
        #self.__tools_button.set_label(_('Tools'))
        #self.__tools_button.set_is_important(True)
        #self.__tools_button.set_menu(self.__tools_menu)
        #self.__tools_button.connect('clicked', self.__tools_callback)

        self.__save_button = BWStockButton(Gtk.STOCK_SAVE, _("Save Graphic"))
        self.__save_button.connect("clicked", self.__save_image_callback)

        self.__hosts_button = BWStockButton(Gtk.STOCK_INDEX, _("Hosts Viewer"))
        self.__hosts_button.connect("clicked", self.__hosts_viewer_callback)

        self.__control = BWToggleStockButton(
                Gtk.STOCK_PROPERTIES, _("Controls"))
        self.__control.connect('clicked', self.__control_callback)
        self.__control.set_active(False)

        self.__fisheye = BWToggleStockButton(Gtk.STOCK_ZOOM_FIT, _("Fisheye"))
        self.__fisheye.connect('clicked', self.__fisheye_callback)
        self.__fisheye.set_active(False)

        self.__legend_button = BWStockButton(Gtk.STOCK_INDEX, _("Legend"))
        self.__legend_button.connect('clicked', self.__legend_callback)

        #self.__fullscreen = gtk.ToggleToolButton(gtk.STOCK_FULLSCREEN)
        #self.__fullscreen.set_label(_('Fullscreen'))
        #self.__fullscreen.set_is_important(True)
        #self.__fullscreen.connect('clicked', self.__fullscreen_callback)
        #self.__fullscreen.set_tooltip(self.__tooltips, _('Toggle fullscreen'))

        #self.__about = gtk.ToolButton(gtk.STOCK_ABOUT)
        #self.__about.set_label(_('About'))
        #self.__about.set_is_important(True)
        #self.__about.connect('clicked', self.__about_callback)
        #self.__about.set_tooltip(self.__tooltips, _('About RadialNet'))

        self.__separator = Gtk.SeparatorToolItem()
        self.__expander = Gtk.SeparatorToolItem()
        self.__expander.set_expand(True)
        self.__expander.set_draw(False)

        #self.insert(self.__open,         0)
        #self.insert(self.__separator,    1)
        #self.insert(self.__tools_button, 2)
        #self.insert(self.__expander,     3)
        #self.insert(self.__control,      4)
        #self.insert(self.__fisheye,      5)
        #self.insert(self.__fullscreen,   6)
        #self.insert(self.__about,        7)

        #self.pack_start(self.__tools_button, False)
        self.pack_start(self.__hosts_button, False, True, 0)
        self.pack_start(self.__fisheye, False, True, 0)
        self.pack_start(self.__control, False, True, 0)
        self.pack_end(self.__save_button, False, True, 0)
        self.pack_end(self.__legend_button, False, True, 0)

    def disable_controls(self):
        """
        """
        self.__control.set_sensitive(False)
        self.__fisheye.set_sensitive(False)
        self.__hosts_button.set_sensitive(False)
        self.__legend_button.set_sensitive(False)
        #self.__tools_menu.disable_dependents()

    def enable_controls(self):
        """
        """
        self.__control.set_sensitive(True)
        self.__fisheye.set_sensitive(True)
        self.__hosts_button.set_sensitive(True)
        self.__legend_button.set_sensitive(True)
        #self.__tools_menu.enable_dependents()

    def __tools_callback(self, widget):
        """
        """
        self.__tools_menu.popup(None, None, None, 1, 0)

    def __hosts_viewer_callback(self, widget):
        """
        """
        window = HostsViewer(self.radialnet.get_scanned_nodes())
        window.show_all()
        window.set_keep_above(True)

    def __save_image_callback(self, widget):
        """
        """
        if self.__save_chooser is None:
            self.__save_chooser = SaveDialog()

        response = self.__save_chooser.run()

        if response == Gtk.ResponseType.OK:
            filename = self.__save_chooser.get_filename()
            filetype = self.__save_chooser.get_filetype()

            try:
                self.radialnet.save_drawing_to_file(filename, filetype)
            except Exception as e:
                alert = HIGAlertDialog(parent=self.__save_chooser,
                        type=Gtk.MessageType.ERROR,
                        message_format=_("Error saving snapshot"),
                        secondary_text=str(e))
                alert.run()
                alert.destroy()

        self.__save_chooser.hide()

    def __control_callback(self, widget=None):
        """
        """
        if self.__control.get_active():
            self.__control_widget.show()

        else:
            self.__control_widget.hide()

    def __fisheye_callback(self, widget=None):
        """
        """
        if not self.radialnet.is_in_animation():

            if self.__fisheye.get_active():

                self.__fisheye_widget.active_fisheye()
                self.__fisheye_widget.show()

            else:

                self.__fisheye_widget.deactive_fisheye()
                self.__fisheye_widget.hide()

    def __legend_callback(self, widget):
        """
        """
        self.__legend_window = LegendWindow()
        self.__legend_window.show_all()

    def __about_callback(self, widget):
        """
        """
        self.__about_dialog = AboutDialog()
        self.__about_dialog.show_all()

    def __fullscreen_callback(self, widget=None):
        """
        """
        if self.__fullscreen.get_active():
            self.__window.fullscreen()

        else:
            self.__window.unfullscreen()
