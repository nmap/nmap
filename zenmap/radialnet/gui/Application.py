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

from radialnet.util.integration import make_graph_from_nmap_parser
from radialnet.core.Info import INFO
from radialnet.core.XMLHandler import XMLReader
from radialnet.gui.ControlWidget import ControlWidget, ControlFisheye
from radialnet.gui.Toolbar import Toolbar
from radialnet.gui.Image import Pixmaps
import radialnet.gui.RadialNet as RadialNet
from radialnet.bestwidgets.windows import BWMainWindow, BWAlertDialog
from radialnet.bestwidgets.boxes import BWHBox, BWVBox, BWStatusbar


DIMENSION = (640, 480)


class Application(BWMainWindow):
    """
    """
    def __init__(self):
        """
        """
        BWMainWindow.__init__(self)
        self.set_default_size(DIMENSION[0], DIMENSION[1])

        self.set_icon(Pixmaps().get_pixbuf('logo'))

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__hbox = BWHBox(spacing=0)
        self.__vbox = BWVBox(spacing=0)

        self.__radialnet = RadialNet.RadialNet(RadialNet.LAYOUT_WEIGHTED)
        self.__control = ControlWidget(self.__radialnet)
        self.__fisheye = ControlFisheye(self.__radialnet)
        self.__toolbar = Toolbar(self.__radialnet,
                                        self,
                                        self.__control,
                                        self.__fisheye)
        self.__statusbar = BWStatusbar()

        self.__hbox.bw_pack_start_expand_fill(self.__radialnet)
        self.__hbox.bw_pack_start_noexpand_nofill(self.__control)

        self.__vbox.bw_pack_start_noexpand_nofill(self.__toolbar)
        self.__vbox.bw_pack_start_expand_fill(self.__hbox)
        self.__vbox.bw_pack_start_noexpand_nofill(self.__fisheye)
        self.__vbox.bw_pack_start_noexpand_nofill(self.__statusbar)

        self.add(self.__vbox)
        self.set_title(" ".join([INFO['name'], INFO['version']]))
        self.set_position(Gtk.WindowPosition.CENTER)
        self.show_all()
        self.connect('destroy', Gtk.main_quit)

        self.__radialnet.set_no_show_all(True)
        self.__control.set_no_show_all(True)
        self.__fisheye.set_no_show_all(True)

        self.__radialnet.hide()
        self.__control.hide()
        self.__fisheye.hide()
        self.__toolbar.disable_controls()

    def parse_nmap_xml_file(self, file):
        """
        """
        try:

            self.__parser = XMLReader(file)
            self.__parser.parse()

        except Exception as e:

            text = 'It is not possible open file %s: %s' % (file, e)

            alert = BWAlertDialog(self,
                                  primary_text='Error opening file.',
                                  secondary_text=text)

            alert.show_all()

            return False

        self.__radialnet.set_empty()
        self.__radialnet.set_graph(make_graph_from_nmap_parser(self.__parser))
        self.__radialnet.show()

        self.__toolbar.enable_controls()

        return True

    def start(self):
        """
        """
        Gtk.main()
