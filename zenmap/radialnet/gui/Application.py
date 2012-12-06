# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, version detection, and the Nmap Scripting Engine.            *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
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
# * works of Nmap, as well as other software we distribute under this       *
# * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
# * but is meant to clarify our interpretation of derived works with some   *
# * common examples.  Our interpretation applies only to Nmap--we don't     *
# * speak for other people's GPL works.                                     *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@insecure.com for     *
# * further information.                                                    *
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
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
# *                                                                         *
# ***************************************************************************/

import gtk

from radialnet.util.integration import make_graph_from_nmap_parser
from radialnet.core.Info import INFO
from radialnet.core.XMLHandler import XMLReader
from radialnet.gui.ControlWidget import ControlWidget, ControlFisheye
from radialnet.gui.Toolbar import Toolbar
from radialnet.gui.Image import Pixmaps
from radialnet.gui.RadialNet import *
from radialnet.bestwidgets.windows import *
from radialnet.bestwidgets.boxes import *


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

        self.__radialnet = RadialNet(LAYOUT_WEIGHTED)
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
        self.set_position(gtk.WIN_POS_CENTER)
        self.show_all()
        self.connect('destroy', gtk.main_quit)

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

        except:

            text = 'It is not possible open file: %s.' % file

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
        gtk.main()
