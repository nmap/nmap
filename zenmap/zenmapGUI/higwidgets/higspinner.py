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

"""
higwidgets/higspinner.py

   a pygtk spinner, based on the epiphany/nautilus implementation
"""

__all__ = ['HIGSpinner']

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk, GdkPixbuf


class HIGSpinnerImages:
    def __init__(self):
        """This class holds list of GDK Pixbuffers.

        - static_pixbufs is used for multiple static pixbuffers
        - self.animated_pixbufs is used for the pixbuffers that make up the
          animation
        """

        dprint('HIGSpinnerImages::__init__')

        # The Nautilus/Epiphany implementation uses a single "rest/quiescent"
        # static pixbuffer. We'd rather allow the developer to choose from
        # multiple static states, such as "done" or "failed".
        # Index it by a name like that.
        self.static_pixbufs = {}

        # We should have a default rest pixbuf, set it with set_rest_pixbuf()
        self.rest_pixbuf = None

        # This is a list of pixbufs to be used on the animation
        # For now, we're only implementing a single animation. Inconsistent!
        self.animated_pixbufs = []

    def add_static_pixbuf(self, name, pixbuf, default_on_rest=False):
        """Add a static pixbuf.

        If this is the first one, make it the default pixbuffer on rest.
        The user can make some other pixbuf the new default on rest, by setting
        default_on_rest to True.
        """

        dprint('HIGSpinnerImages::add_static_pixbuf')

        self.static_pixbufs[name] = pixbuf
        if (len(self.static_pixbufs) == 1) or default_on_rest:
            self.set_rest_pixbuf(name)

    def add_animated_pixbuf(self, pixbuf):

        dprint('HIGSpinnerImages::add_animated_pixbuf')

        self.animated_pixbufs.append(pixbuf)

    def set_rest_pixbuf(self, name):
        """Sets the pixbuf that will be used on the default, 'rest' state. """

        dprint('HIGSpinnerImages::set_rest_pixbuf')

        if name not in self.static_pixbufs:
            raise StaticPixbufNotFound

        # self.rest_pixbuf holds the *real* pixbuf, not its name
        self.rest_pixbuf = self.static_pixbufs[name]

    def set_size(self, width, height):
        """Sets the size of each pixbuf (static and animated)"""
        new_animated = []
        for p in self.animated_pixbufs:
            new_animated.append(p.scale_simple(width, height,
                                               GdkPixbuf.InterpType.BILINEAR))
        self.animated_pixbufs = new_animated

        for k in self.static_pixbufs:
            self.static_pixbufs[k] = self.static_pixbufs[k].scale_simple(
                    width, height, GdkPixbuf.InterpType.BILINEAR)

        self.rest_pixbuf = self.rest_pixbuf.scale_simple(
                width, height, GdkPixbuf.InterpType.BILINEAR)

        self.images_width = width
        self.images_height = height


class HIGSpinnerCache:
    """This hols a copy of the images used on the HIGSpinners instances."""
    def __init__(self):

        dprint('HIGSpinnerCache::__init__')

        # Our own instance of a HIGSpinnerImages
        self.spinner_images = HIGSpinnerImages()

        # These are on Private member in the C implementation
        self.icon_theme = Gtk.IconTheme()
        self.originals = None
        self.images = None

        # We might have access to a "default" animated icon.
        # For example, if we're on a GNOME desktop, and have the (default)
        # "gnome-icon-theme" package installed, we might have access
        # to "gnome-spinner". Check it before using, though
        if (self.icon_theme.lookup_icon("gnome-spinner", -1, 0)):
            self.default_animated_icon_name = "gnome-spinner"
        else:
            self.default_animated_icon_name = None

    def load_animated_from_lookup(self, icon_name=None):
        """Loads an animated icon by doing a lookup on the icon theme."""

        # If user do not choose a icon_name, use the default one
        if icon_name is None:
            icon_name = self.default_animated_icon_name

        # Even the default one (now on icon_name) might not be available
        if icon_name is None:
            raise AnimatedIconNotFound

        # Try to lookup the icon
        icon_info = self.icon_theme.lookup_icon(icon_name, -1, 0)
        # Even if icon_name exists, it might not be found by lookup
        if icon_info is None:
            raise AnimatedIconNotFound

        # Base size is, according to PyGTK docs:
        # "a size for the icon that was specified by the icon theme creator,
        #  This may be different than the actual size of image."
        # Ouch! We are acting on blind faith here...
        size = icon_info.get_base_size()

        # NOTE: If the icon is a builtin, it will not have a filename, see:
        # http://www.pygtk.org/pygtk2reference/class-gtkicontheme.html
        # But, we are not using the gtk.ICON_LOOKUP_USE_BUILTIN flag, nor does
        # GTK+ has a builtin animation, so we are safe ;-)
        filename = icon_info.get_filename()

        # Now that we have a filename, call load_animated_from_filename()
        self.load_animated_from_filename(filename, size)

    def load_animated_from_filename(self, filename, size):
        # grid_pixbuf is a pixbuf that holds the entire
        grid_pixbuf = GdkPixbuf.Pixbuf.new_from_file(filename)
        grid_width = grid_pixbuf.get_width()
        grid_height = grid_pixbuf.get_height()

        for x in range(0, grid_width, size):
            for y in range(0, grid_height, size):
                self.spinner_images.add_animated_pixbuf(
                        self.__extract_frame(grid_pixbuf, x, y, size, size))

    def load_static_from_lookup(self, icon_name="gnome-spinner-rest",
                                key_name=None):
        icon_info = self.icon_theme.lookup_icon(icon_name, -1, 0)
        filename = icon_info.get_filename()

        # Now that we have a filename, call load_static_from_filename()
        self.load_static_from_filename(filename)

    def load_static_from_filename(self, filename, key_name=None):
        icon_pixbuf = GdkPixbuf.Pixbuf.new_from_file(filename)

        if key_name is None:
            key_name = filename.split(".")[0]

        self.spinner_images.add_static_pixbuf(key_name, icon_pixbuf)

    def __extract_frame(self, pixbuf, x, y, w, h):
        """Cuts a sub pixbuffer, usually a frame of an animation.

        - pixbuf is the complete pixbuf, from which a frame will be cut off
        - x/y are the position
        - w (width) is the is the number of pixels to move right
        - h (height) is the is the number of pixels to move down
        """
        if (x + w > pixbuf.get_width()) or (y + h > pixbuf.get_height()):
            raise PixbufSmallerThanRequiredError
        return pixbuf.subpixbuf(x, y, w, h)

    def _write_animated_pixbuf_to_files(self, path_format, image_format):
        """Writes image files from self.spinner_images.animated_pixbufs

        - path_format should be a format string with one occurrence of a
          string substitution, such as '/tmp/animation_%s.png'
        - image_format can be either 'png' or 'jpeg'
        """
        counter = 0
        for i in self.spinner_images.animated_pixbufs:
            i.save(path_format % counter, "png")
            counter += 1

    def _write_static_pixbuf_to_file(self, key_name, path_name, image_format):
        self.spinner_images.static_pixbufs[key_name].save(path_name,
                                                          image_format)


class HIGSpinner(Gtk.EventBox):
    """Simple spinner, such as the one found in webbrowsers and file managers.

    You can construct it with the optional parameters:
    * images, a list of images that will make up the animation
    * width, the width that will be set for the images
    * height, the height that will be set for the images
    """

    #__gsignals__ = {'expose-event': 'override',
    #                'size-request': 'override'}

    def __init__(self):
        Gtk.EventBox.__init__(self)

        #self.set_events(self.get_events())

        # This holds a GDK Graphic Context
        self.gc = None

        # These are sane defaults, but should really come from the images
        self.images_width = 32
        self.images_height = 32

        # Timeout set to 100 milliseconds per frame, just as the
        # Nautilus/Epiphany implementation
        self.timeout = 120

        # Initialize a cache for ourselves
        self.cache = HIGSpinnerCache()
        self.cache.load_static_from_lookup()
        self.cache.load_animated_from_lookup()

        # timer_task it the gobject.timeout_add identifier (when the animation
        # is in progress, and __bump_frame is being continually called). If the
        # spinner is static, timer_task is 0
        self.timer_task = 0
        # animated_pixbuf_index is a index on
        self.animated_pixbuf_index = 0
        # current_pixbuf is initially the default rest_pixbuf
        self.current_pixbuf = self.cache.spinner_images.rest_pixbuf

    def __bump_frame(self):
        """This function moves the animated frame to the next one, or, if it's
        currently the last one, back to the first one"""
        animated_list = self.cache.spinner_images.animated_pixbufs
        if self.animated_pixbuf_index == (len(animated_list) - 1):
            # back to the first one
            self.animated_pixbuf_index = 0
        else:
            # go the next one
            self.animated_pixbuf_index += 1

        self.queue_draw()
        return True

    def __select_pixbuf(self):
        """This selects either a rest pixbuf or a animation frame based on the
        status of timer_task."""
        if self.timer_task == 0:
            self.current_pixbuf = self.cache.spinner_images.rest_pixbuf
        else:
            self.current_pixbuf = self.cache.spinner_images.animated_pixbufs[
                    self.animated_pixbuf_index]

    def start(self):
        """Starts the animation"""
        if self.timer_task == 0:
            self.timer_task = GLib.timeout_add(self.timeout,
                                                  self.__bump_frame)

    def pause(self):
        """Pauses the animation"""
        if self.timer_task != 0:
            GLib.source_remove(self.timer_task)

        self.timer_task = 0
        self.queue_draw()

    def stop(self):
        """Stops the animation

        Do the same stuff as pause, but returns the animation to the
        beginning."""
        self.pause()
        self.animated_pixbuf_index = 0

    def set_speed(speed_in_milliseconds):
        self.timeout = speed_in_milliseconds
        self.pause()
        self.start()

    def do_expose_event(self, event):
        #self.chain(event)

        if self.cache.spinner_images.rest_pixbuf is None:
            raise RestPixbufNotFound

        self.__select_pixbuf()

        width = self.current_pixbuf.get_width()
        height = self.current_pixbuf.get_height()
        x_offset = (self.allocation.width - width) // 2
        y_offset = (self.allocation.height - height) // 2

        pix_area = Gdk.Rectangle(x_offset + self.allocation.x,
                                 y_offset + self.allocation.y,
                                 width, height)

        dest = event.area.intersect(pix_area)

#        # If a graphic context doesn't not exist yet, create one
#        if self.gc is None:
#            self.gc = gtk.gdk.GC(self.window)
#        #gc = self.gc
#
#        cairo = self.window.cairo_create()
#
#
#        self.window.draw_pixbuf(self.gc,
#                                self.current_pixbuf,
#                                dest.x - x_offset - self.allocation.x,
#                                dest.y - y_offset - self.allocation.y,
#                                dest.x, dest.y,
#                                dest.width, dest.height)

    def do_size_request(self, requisition):
        # http://www.pygtk.org/pygtk2reference/class-gtkrequisition.html

        # FIXME, this should really come from the pixbuf size + margins
        requisition.width = self.cache.spinner_images.images_width
        requisition.height = self.cache.spinner_images.images_height
