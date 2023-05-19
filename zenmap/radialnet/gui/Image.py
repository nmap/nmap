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
from gi.repository import GdkPixbuf

import os
import array

from zenmapCore.Paths import Path


FORMAT_RGBA = 4
FORMAT_RGB = 3


def get_pixels_for_cairo_image_surface(pixbuf):
    """
    This method return the image stride and a python array.ArrayType
    containing the icon pixels of a gtk.gdk.Pixbuf that can be used by
    cairo.ImageSurface.create_for_data() method.
    """
    data = array.array('B')
    image_format = pixbuf.get_rowstride() // pixbuf.get_width()

    i = 0
    j = 0
    while i < len(pixbuf.get_pixels()):

        b, g, r = pixbuf.get_pixels()[i:i + FORMAT_RGB]

        if image_format == FORMAT_RGBA:
            a = pixbuf.get_pixels()[i + FORMAT_RGBA - 1]
        elif image_format == FORMAT_RGB:
            a = 255
        else:
            raise TypeError('unknown image format')

        data[j:j + FORMAT_RGBA] = array.array('B', [r, g, b, a])

        i += image_format
        j += FORMAT_RGBA

    return (FORMAT_RGBA * pixbuf.get_width(), data)


class Image:
    """
    """
    def __init__(self, path=None):
        """
        """
        self.__path = path
        self.__cache = dict()

    def set_path(self, path):
        """
        """
        self.__path = path

    def get_pixbuf(self, icon, image_type='png'):
        """
        """
        if self.__path is None:
            return False

        if icon + image_type not in self.__cache.keys():

            file = self.get_icon(icon, image_type)
            self.__cache[icon + image_type] = \
                    GdkPixbuf.Pixbuf.new_from_file(file)

        return self.__cache[icon + image_type]

    def get_icon(self, icon, image_type='png'):
        """
        """
        if self.__path is None:
            return False

        return os.path.join(self.__path, icon + "." + image_type)


class Pixmaps(Image):
    """
    """
    def __init__(self):
        """
        """
        Image.__init__(self, os.path.join(Path.pixmaps_dir, "radialnet"))


class Icons(Image):
    """
    """
    def __init__(self):
        """
        """
        Image.__init__(self, os.path.join(Path.pixmaps_dir, "radialnet"))


class Application(Image):
    """
    """
    def __init__(self):
        """
        """
        Image.__init__(self, os.path.join(Path.pixmaps_dir, "radialnet"))
