# vim: set encoding=utf-8 :

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
from gi.repository import Gtk, GLib, Gdk

import math
import cairo

from functools import reduce

import radialnet.util.geometry as geometry
import radialnet.util.misc as misc

from radialnet.core.Coordinate import PolarCoordinate, CartesianCoordinate
from radialnet.core.Interpolation import Linear2DInterpolator
from radialnet.core.Graph import Node
from radialnet.gui.NodeWindow import NodeWindow
from radialnet.gui.Image import Icons, get_pixels_for_cairo_image_surface

REGION_COLORS = [(1.0, 0.0, 0.0), (1.0, 1.0, 0.0), (0.0, 1.0, 0.0)]
REGION_RED = 0
REGION_YELLOW = 1
REGION_GREEN = 2

SQUARE_TYPES = ['router', 'switch', 'wap']

ICON_DICT = {'router': 'router',
             'switch': 'switch',
             'wap': 'wireless',
             'firewall': 'firewall'}

POINTER_JUMP_TO = 0
POINTER_INFO = 1
POINTER_GROUP = 2
POINTER_FILL = 3

LAYOUT_SYMMETRIC = 0
LAYOUT_WEIGHTED = 1

INTERPOLATION_CARTESIAN = 0
INTERPOLATION_POLAR = 1

FILE_TYPE_PDF = 1
FILE_TYPE_PNG = 2
FILE_TYPE_PS = 3
FILE_TYPE_SVG = 4


class RadialNet(Gtk.DrawingArea):
    """
    Radial network visualization widget
    """
    def __init__(self, layout=LAYOUT_SYMMETRIC):
        """
        Constructor method of RadialNet widget class
        @type  number_of_rings: number
        @param number_of_rings: Number of rings in radial layout
        """
        self.__center_of_widget = (0, 0)
        self.__graph = None

        self.__number_of_rings = 0
        self.__ring_gap = 30
        self.__min_ring_gap = 10

        self.__layout = layout
        self.__interpolation = INTERPOLATION_POLAR
        self.__interpolation_slow_in_out = True

        self.__animating = False
        self.__animation_rate = 1000 // 60  # 60Hz (human perception factor)
        self.__number_of_frames = 60

        self.__scale = 1.0
        # rotated so that single-host traceroute doesn't have overlapping hosts
        self.__rotate = 225
        self.__translation = (0, 0)

        self.__button1_press = False
        self.__button2_press = False
        self.__button3_press = False

        self.__last_motion_point = None

        self.__fisheye = False
        self.__fisheye_ring = 0
        self.__fisheye_spread = 0.5
        self.__fisheye_interest = 2

        self.__show_address = True
        self.__show_hostname = True
        self.__show_icon = True
        self.__show_latency = False
        self.__show_ring = True
        self.__show_region = True
        self.__region_color = REGION_RED

        self.__node_views = dict()
        self.__last_group_node = None

        self.__pointer_status = POINTER_JUMP_TO

        self.__sorted_nodes = list()

        self.__icon = Icons()

        super(RadialNet, self).__init__()

        self.connect('draw', self.draw)
        self.connect('button_press_event', self.button_press)
        self.connect('button_release_event', self.button_release)
        self.connect('motion_notify_event', self.motion_notify)
        self.connect('enter_notify_event', self.enter_notify)
        self.connect('leave_notify_event', self.leave_notify)
        self.connect('key_press_event', self.key_press)
        self.connect('key_release_event', self.key_release)
        self.connect('scroll_event', self.scroll_event)

        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK |
                        Gdk.EventMask.BUTTON_RELEASE_MASK |
                        Gdk.EventMask.ENTER_NOTIFY_MASK |
                        Gdk.EventMask.LEAVE_NOTIFY_MASK |
                        Gdk.EventMask.KEY_PRESS_MASK |
                        Gdk.EventMask.KEY_RELEASE_MASK |
                        Gdk.EventMask.POINTER_MOTION_HINT_MASK |
                        Gdk.EventMask.POINTER_MOTION_MASK |
                        Gdk.EventMask.SCROLL_MASK)

        self.set_can_focus(True)
        self.grab_focus()

    def graph_is_not_empty(function):
        """
        Decorator function to prevent the execution when graph not is set
        @type  function: function
        @param function: Protected function
        """
        def check_graph_status(*args):
            if args[0].__graph is None:
                return False
            return function(*args)

        return check_graph_status

    def not_is_in_animation(function):
        """
        Decorator function to prevent the execution when graph is animating
        @type  function: function
        @param function: Protected function
        """
        def check_animation_status(*args):
            if args[0].__animating:
                return False
            return function(*args)

        return check_animation_status

    def save_drawing_to_file(self, file, type=FILE_TYPE_PNG):
        """
        """
        allocation = self.get_allocation()

        if type == FILE_TYPE_PDF:
            self.surface = cairo.PDFSurface(file,
                    allocation.width,
                    allocation.height)
        elif type == FILE_TYPE_PNG:
            self.surface = cairo.ImageSurface(cairo.FORMAT_ARGB32,
                    allocation.width,
                    allocation.height)
        elif type == FILE_TYPE_PS:
            self.surface = cairo.PSSurface(file,
                    allocation.width,
                    allocation.height)
        elif type == FILE_TYPE_SVG:
            self.surface = cairo.SVGSurface(file,
                    allocation.width,
                    allocation.height)
        else:
            raise TypeError('unknown surface type')

        context = cairo.Context(self.surface)

        context.rectangle(0, 0, allocation.width, allocation.height)
        context.set_source_rgb(1.0, 1.0, 1.0)
        context.fill()

        self.__draw(context)

        if type == FILE_TYPE_PNG:
            self.surface.write_to_png(file)

        self.surface.flush()
        self.surface.finish()

        return True

    def get_slow_inout(self):
        """
        """
        return self.__interpolation_slow_in_out

    def set_slow_inout(self, value):
        """
        """
        self.__interpolation_slow_in_out = value

    def get_region_color(self):
        """
        """
        return self.__region_color

    def set_region_color(self, value):
        """
        """
        self.__region_color = value

    def get_show_region(self):
        """
        """
        return self.__show_region

    def set_show_region(self, value):
        """
        """
        self.__show_region = value
        self.queue_draw()

    def get_pointer_status(self):
        """
        """
        return self.__pointer_status

    def set_pointer_status(self, pointer_status):
        """
        """
        self.__pointer_status = pointer_status

    def get_show_address(self):
        """
        """
        return self.__show_address

    def get_show_hostname(self):
        """
        """
        return self.__show_hostname

    def get_show_ring(self):
        """
        """
        return self.__show_ring

    def set_show_address(self, value):
        """
        """
        self.__show_address = value
        self.queue_draw()

    def set_show_hostname(self, value):
        """
        """
        self.__show_hostname = value
        self.queue_draw()

    def set_show_ring(self, value):
        """
        """
        self.__show_ring = value
        self.queue_draw()

    def get_min_ring_gap(self):
        """
        """
        return self.__min_ring_gap

    @graph_is_not_empty
    @not_is_in_animation
    def set_min_ring_gap(self, value):
        """
        """
        self.__min_ring_gap = int(value)

        if self.__ring_gap < self.__min_ring_gap:
            self.__ring_gap = self.__min_ring_gap

        self.__update_nodes_positions()
        self.queue_draw()

        return True

    def get_number_of_frames(self):
        """
        """
        return self.__number_of_frames

    @not_is_in_animation
    def set_number_of_frames(self, number_of_frames):
        """
        """
        if number_of_frames > 2:

            self.__number_of_frames = int(number_of_frames)
            return True

        self.__number_of_frames = 3
        return False

    @not_is_in_animation
    def update_layout(self):
        """
        """
        if self.__graph is None:
            return
        self.__animating = True
        self.__calc_interpolation(self.__graph.get_main_node())
        self.__livens_up()

    @not_is_in_animation
    def set_layout(self, layout):
        """
        """
        if self.__layout != layout:

            self.__layout = layout

            if self.__graph is not None:

                self.__animating = True
                self.__calc_interpolation(self.__graph.get_main_node())
                self.__livens_up()

            return True

        return False

    def get_layout(self):
        """
        """
        return self.__layout

    @not_is_in_animation
    def set_interpolation(self, interpolation):
        """
        """
        self.__interpolation = interpolation

        return True

    def get_interpolation(self):
        """
        """
        return self.__interpolation

    def get_number_of_rings(self):
        """
        """
        return self.__number_of_rings

    def get_fisheye_ring(self):
        """
        """
        return self.__fisheye_ring

    def get_fisheye_interest(self):
        """
        """
        return self.__fisheye_interest

    def get_fisheye_spread(self):
        """
        """
        return self.__fisheye_spread

    def get_fisheye(self):
        """
        """
        return self.__fisheye

    def set_fisheye(self, enable):
        """
        """
        self.__fisheye = enable

        self.__update_nodes_positions()
        self.queue_draw()

    def set_fisheye_ring(self, value):
        """
        """
        self.__fisheye_ring = value
        self.__check_fisheye_ring()

        self.__update_nodes_positions()
        self.queue_draw()

    def set_fisheye_interest(self, value):
        """
        """
        self.__fisheye_interest = value

        self.__update_nodes_positions()
        self.queue_draw()

    def set_fisheye_spread(self, value):
        """
        """
        self.__fisheye_spread = value

        self.__update_nodes_positions()
        self.queue_draw()

    def get_show_icon(self):
        """
        """
        return self.__show_icon

    def set_show_icon(self, value):
        """
        """
        self.__show_icon = value
        self.queue_draw()

    def get_show_latency(self):
        """
        """
        return self.__show_latency

    def set_show_latency(self, value):
        """
        """
        self.__show_latency = value
        self.queue_draw()

    def get_scale(self):
        """
        """
        return self.__scale

    def get_zoom(self):
        """
        """
        return int(round(self.__scale * 100))

    def set_scale(self, scale):
        """
        """
        if scale >= 0.01:

            self.__scale = scale
            self.queue_draw()

    def set_zoom(self, zoom):
        """
        """
        if float(zoom) >= 1:

            self.set_scale(float(zoom) / 100.0)
            self.queue_draw()

    def get_ring_gap(self):
        """
        """
        return self.__ring_gap

    @not_is_in_animation
    def set_ring_gap(self, ring_gap):
        """
        """
        if ring_gap >= self.__min_ring_gap:

            self.__ring_gap = ring_gap
            self.__update_nodes_positions()
            self.queue_draw()

    def scroll_event(self, widget, event):
        """
        """
        if event.direction == Gdk.ScrollDirection.UP:
            self.set_scale(self.__scale + 0.01)

        if event.direction == Gdk.ScrollDirection.DOWN:
            self.set_scale(self.__scale - 0.01)

        self.queue_draw()

    @graph_is_not_empty
    @not_is_in_animation
    def key_press(self, widget, event):
        """
        """
        key = Gdk.keyval_name(event.keyval)

        if key == 'KP_Add':
            self.set_ring_gap(self.__ring_gap + 1)

        elif key == 'KP_Subtract':
            self.set_ring_gap(self.__ring_gap - 1)

        elif key == 'Page_Up':
            self.set_scale(self.__scale + 0.01)

        elif key == 'Page_Down':
            self.set_scale(self.__scale - 0.01)

        self.queue_draw()

        return True

    @graph_is_not_empty
    def key_release(self, widget, event):
        """
        """
        key = Gdk.keyval_name(event.keyval)

        if key == 'c':
            self.__translation = (0, 0)

        elif key == 'r':
            self.__show_ring = not self.__show_ring

        elif key == 'a':
            self.__show_address = not self.__show_address

        elif key == 'h':
            self.__show_hostname = not self.__show_hostname

        elif key == 'i':
            self.__show_icon = not self.__show_icon

        elif key == 'l':
            self.__show_latency = not self.__show_latency

        self.queue_draw()

        return True

    @graph_is_not_empty
    @not_is_in_animation
    def enter_notify(self, widget, event):
        """
        """
        self.grab_focus()
        return False

    @graph_is_not_empty
    @not_is_in_animation
    def leave_notify(self, widget, event):
        """
        """
        for node in self.__graph.get_nodes():
            node.set_draw_info({'over': False})

        self.queue_draw()

        return False

    @graph_is_not_empty
    def button_press(self, widget, event):
        """
        Drawing callback
        @type  widget: GtkWidget
        @param widget: Gtk widget superclass
        @type  event: GtkEvent
        @param event: Gtk event of widget
        @rtype: boolean
        @return: Indicator of the event propagation
        """
        result = self.__get_node_by_coordinate(self.get_pointer())

        if event.button == 1:
            self.__button1_press = True

        # animate if node is pressed
        if self.__pointer_status == POINTER_JUMP_TO and event.button == 1:

            # prevent double animation
            if self.__animating:
                return False

            if result is not None:

                node, point = result
                main_node = self.__graph.get_main_node()

                if node != main_node:

                    if node.get_draw_info('group'):

                        node.set_draw_info({'group': False})
                        node.set_subtree_info({'grouped': False,
                                               'group_node': None})

                    self.__animating = True
                    self.__calc_interpolation(node)
                    self.__livens_up()

        # group node if it's pressed
        elif self.__pointer_status == POINTER_GROUP and event.button == 1:

            # prevent group on animation
            if self.__animating:
                return False

            if result is not None:

                node, point = result
                main_node = self.__graph.get_main_node()

                if node != main_node:

                    if node.get_draw_info('group'):

                        node.set_draw_info({'group': False})
                        node.set_subtree_info({'grouped': False,
                                               'group_node': None})

                    else:

                        self.__last_group_node = node

                        node.set_draw_info({'group': True})
                        node.set_subtree_info({'grouped': True,
                                               'group_node': node})

                self.__animating = True
                self.__calc_interpolation(self.__graph.get_main_node())
                self.__livens_up()

        # setting to show node's region
        elif self.__pointer_status == POINTER_FILL and event.button == 1:

            if result is not None:

                node, point = result

                if node.get_draw_info('region') == self.__region_color:
                    node.set_draw_info({'region': None})

                else:
                    node.set_draw_info({'region': self.__region_color})

                self.queue_draw()

        # show node details
        elif event.button == 3 or self.__pointer_status == POINTER_INFO:

            if event.button == 3:
                self.__button3_press = True

            if result is not None:

                # first returned value is not meaningful and should be ignored
                _, xw, yw = self.get_window().get_origin()
                node, point = result
                x, y = point

                if node in self.__node_views.keys():

                    self.__node_views[node].present()

                elif node.get_draw_info('scanned'):

                    view = NodeWindow(node, (int(xw + x), int(yw + y)))

                    def close_view(view, event, node):
                        view.destroy()
                        del self.__node_views[node]

                    view.connect("delete-event", close_view, node)
                    view.show_all()
                    self.__node_views[node] = view

        return False

    @graph_is_not_empty
    def button_release(self, widget, event):
        """
        Drawing callback
        @type  widget: GtkWidget
        @param widget: Gtk widget superclass
        @type  event: GtkEvent
        @param event: Gtk event of widget
        @rtype: boolean
        @return: Indicator of the event propagation
        """
        if event.button == 1:
            self.__button1_press = False

        if event.button == 2:
            self.__button2_press = False

        if event.button == 3:
            self.__button3_press = False

        self.grab_focus()

        return False

    @graph_is_not_empty
    def motion_notify(self, widget, event):
        """
        Drawing callback
        @type  widget: GtkWidget
        @param widget: Gtk widget superclass
        @type  event: GtkEvent
        @param event: Gtk event of widget
        @rtype: boolean
        @return: Indicator of the event propagation
        """
        pointer = self.get_pointer()

        for node in self.__graph.get_nodes():
            node.set_draw_info({'over': False})

        result = self.__get_node_by_coordinate(self.get_pointer())

        if result is not None:
            result[0].set_draw_info({'over': True})

        elif self.__button1_press and self.__last_motion_point is not None:

            ax, ay = pointer
            ox, oy = self.__last_motion_point
            tx, ty = self.__translation

            self.__translation = (tx + ax - ox, ty - ay + oy)

        self.__last_motion_point = pointer

        self.grab_focus()
        self.queue_draw()

        return False

    def draw(self, widget, context):
        """
        Drawing callback
        @type  widget: GtkWidget
        @param widget: Gtk widget superclass
        @type  context: cairo.Context
        @param context: cairo context class
        @rtype: boolean
        @return: Indicator of the event propagation
        """
        context.set_source_rgb(1.0, 1.0, 1.0)
        context.fill()

        self.__draw(context)

        return False

    @graph_is_not_empty
    def __draw(self, context):
        """
        Drawing method
        """
        # getting allocation reference
        allocation = self.get_allocation()

        self.__center_of_widget = (allocation.width // 2,
                                   allocation.height // 2)

        xc, yc = self.__center_of_widget

        ax, ay = self.__translation

        # xc = 320 yc = 240

        # -1.5 | -0.5 ( 480,  360)
        # -1.0 |  0.0 ( 320,  240)
        # -0.5 |  0.5 ( 160,  120)
        #  0.0 |  1.0 (   0,    0)
        #  0.5 |  1.5 (-160, -120)
        #  1.0 |  2.0 (-320, -240)
        #  1.5 |  2.5 (-480, -360)

        # scaling and translate
        factor = -(self.__scale - 1)

        context.translate(xc * factor + ax, yc * factor - ay)

        if self.__scale != 1.0:
            context.scale(self.__scale, self.__scale)

        # drawing over node's region
        if self.__show_region and not self.__animating:

            for node in self.__sorted_nodes:

                not_grouped = not node.get_draw_info('grouped')

                if node.get_draw_info('region') is not None and not_grouped:

                    xc, yc = self.__center_of_widget
                    r, g, b = REGION_COLORS[node.get_draw_info('region')]

                    start, final = node.get_draw_info('range')

                    i_radius = node.get_coordinate_radius()
                    f_radius = self.__calc_radius(self.__number_of_rings - 1)

                    is_fill_all = abs(final - start) == 360

                    final = math.radians(final + self.__rotate)
                    start = math.radians(start + self.__rotate)

                    context.move_to(xc, yc)
                    context.set_source_rgba(r, g, b, 0.1)
                    context.new_path()
                    context.arc(xc, yc, i_radius, -final, -start)
                    context.arc_negative(xc, yc, f_radius, -start, -final)
                    context.close_path()
                    context.fill()
                    context.stroke()

                    if not is_fill_all:

                        context.set_source_rgb(r, g, b)
                        context.set_line_width(1)

                        xa, ya = PolarCoordinate(
                                i_radius, final).to_cartesian()
                        xb, yb = PolarCoordinate(
                                f_radius, final).to_cartesian()

                        context.move_to(xc + xa, yc - ya)
                        context.line_to(xc + xb, yc - yb)
                        context.stroke()

                        xa, ya = PolarCoordinate(
                                i_radius, start).to_cartesian()
                        xb, yb = PolarCoordinate(
                                f_radius, start).to_cartesian()

                        context.move_to(xc + xa, yc - ya)
                        context.line_to(xc + xb, yc - yb)
                        context.stroke()

        # drawing network rings
        if self.__show_ring and not self.__animating:

            for i in range(1, self.__number_of_rings):

                radius = self.__calc_radius(i)

                context.arc(xc, yc, radius, 0, 2 * math.pi)
                context.set_source_rgb(0.8, 0.8, 0.8)
                context.set_line_width(1)
                context.stroke()

        # drawing nodes and your connections
        for edge in self.__graph.get_edges():

            # check group constraints for edges
            a, b = edge.get_nodes()

            a_is_grouped = a.get_draw_info('grouped')
            b_is_grouped = b.get_draw_info('grouped')

            a_is_group = a.get_draw_info('group')
            b_is_group = b.get_draw_info('group')

            a_group = a.get_draw_info('group_node')
            b_group = b.get_draw_info('group_node')

            a_is_child = a in b.get_draw_info('children')
            b_is_child = b in a.get_draw_info('children')

            last_group = self.__last_group_node
            groups = [a_group, b_group]

            if last_group in groups and last_group is not None:
                self.__draw_edge(context, edge)

            elif not a_is_grouped or not b_is_grouped:

                if not (a_is_group and b_is_child or
                        b_is_group and a_is_child):
                    self.__draw_edge(context, edge)

            elif a_group != b_group:
                self.__draw_edge(context, edge)

        for node in reversed(self.__sorted_nodes):

            # check group constraints for nodes
            group = node.get_draw_info('group_node')
            grouped = node.get_draw_info('grouped')

            if group == self.__last_group_node or not grouped:
                self.__draw_node(context, node)

    def __draw_edge(self, context, edge):
        """
        Draw the connection between two nodes
        @type  : Edge
        @param : The second node that will be connected
        """
        a, b = edge.get_nodes()

        xa, ya = a.get_cartesian_coordinate()
        xb, yb = b.get_cartesian_coordinate()
        xc, yc = self.__center_of_widget

        a_children = a.get_draw_info('children')
        b_children = b.get_draw_info('children')

        latency = edge.get_weights_mean()

        # check if isn't an hierarchy connection
        if a not in b_children and b not in a_children:
            context.set_source_rgba(1.0, 0.6, 0.1, 0.8)

        elif a.get_draw_info('no_route') or b.get_draw_info('no_route'):
            context.set_source_rgba(0.0, 0.0, 0.0, 0.8)

        else:
            context.set_source_rgba(0.1, 0.5, 1.0, 0.8)

        # calculating line thickness by latency
        if latency is not None:

            min = self.__graph.get_min_edge_mean_weight()
            max = self.__graph.get_max_edge_mean_weight()

            if max != min:
                thickness = (latency - min) * 4 / (max - min) + 1

            else:
                thickness = 1

            context.set_line_width(thickness)

        else:

            context.set_dash([2, 2])
            context.set_line_width(1)

        context.move_to(xc + xa, yc - ya)
        context.line_to(xc + xb, yc - yb)
        context.stroke()

        context.set_dash([1, 0])

        if not self.__animating and self.__show_latency:

            if latency is not None:

                context.set_font_size(8)
                context.set_line_width(1)
                context.move_to(xc + (xa + xb) / 2 + 1,
                                     yc - (ya + yb) / 2 + 4)
                context.show_text(str(round(latency, 2)))
                context.stroke()

    def __draw_node(self, context, node):
        """
        Draw nodes and your information
        @type  : NetNode
        @param : The node to be drawn
        """
        x, y = node.get_cartesian_coordinate()
        xc, yc = self.__center_of_widget
        r, g, b = node.get_draw_info('color')
        radius = node.get_draw_info('radius')

        type = node.get_info('device_type')

        x_gap = radius + 2
        y_gap = 0

        # draw group indication
        if node.get_draw_info('group'):

            x_gap += 5

            if type in SQUARE_TYPES:
                context.rectangle(xc + x - radius - 5,
                                       yc - y - radius - 5,
                                       2 * radius + 10,
                                       2 * radius + 10)

            else:
                context.arc(xc + x, yc - y, radius + 5, 0, 2 * math.pi)

            context.set_source_rgb(1.0, 1.0, 1.0)
            context.fill_preserve()

            if node.deep_search_child(self.__graph.get_main_node()):
                context.set_source_rgb(0.0, 0.0, 0.0)

            else:
                context.set_source_rgb(0.1, 0.5, 1.0)

            context.set_line_width(2)
            context.stroke()

        # draw over node
        if node.get_draw_info('over'):

            context.set_line_width(0)

            if type in SQUARE_TYPES:
                context.rectangle(xc + x - radius - 5,
                                       yc - y - radius - 5,
                                       2 * radius + 10,
                                       2 * radius + 10)

            else:
                context.arc(xc + x, yc - y, radius + 5, 0, 2 * math.pi)

            context.set_source_rgb(0.1, 0.5, 1.0)
            context.fill_preserve()
            context.stroke()

        # draw node
        if type in SQUARE_TYPES:
            context.rectangle(xc + x - radius,
                                   yc - y - radius,
                                   2 * radius,
                                   2 * radius)

        else:
            context.arc(xc + x, yc - y, radius, 0, 2 * math.pi)

        # draw icons
        if not self.__animating and self.__show_icon:

            icons = list()

            if type in ICON_DICT.keys():
                icons.append(self.__icon.get_pixbuf(ICON_DICT[type]))

            if node.get_info('filtered'):
                icons.append(self.__icon.get_pixbuf('padlock'))

            for icon in icons:

                stride, data = get_pixels_for_cairo_image_surface(icon)

                # Cairo documentation says that the correct way to obtain a
                # legal stride value is using the function
                # cairo.ImageSurface.format_stride_for_width().
                # But this method is only available since cairo 1.6. So we are
                # using the stride returned by
                # get_pixels_for_cairo_image_surface() function.
                surface = cairo.ImageSurface.create_for_data(data,
                        cairo.FORMAT_ARGB32,
                        icon.get_width(),
                        icon.get_height(),
                        stride)

                context.set_source_surface(surface,
                        round(xc + x + x_gap),
                        round(yc - y + y_gap - 6))
                context.paint()

                x_gap += 13

        # draw node text
        context.set_source_rgb(r, g, b)
        context.fill_preserve()

        if node.get_draw_info('valid'):
            context.set_source_rgb(0.0, 0.0, 0.0)

        else:
            context.set_source_rgb(0.1, 0.5, 1.0)

        if not self.__animating and self.__show_address:

            context.set_font_size(8)
            context.move_to(round(xc + x + x_gap),
                                 round(yc - y + y_gap + 4))

            hostname = node.get_info('hostname')

            if hostname is not None and self.__show_hostname:
                context.show_text(hostname)

            elif node.get_info('ip') is not None:
                context.show_text(node.get_info('ip'))

        context.set_line_width(1)
        context.stroke()

    def __check_fisheye_ring(self):
        """
        """
        if self.__fisheye_ring >= self.__number_of_rings:
            self.__fisheye_ring = self.__number_of_rings - 1

    def __set_number_of_rings(self, value):
        """
        """
        self.__number_of_rings = value
        self.__check_fisheye_ring()

    def __fisheye_function(self, ring):
        """
        """
        distance = abs(self.__fisheye_ring - ring)
        level_of_detail = self.__ring_gap * self.__fisheye_interest
        spread_distance = distance - distance * self.__fisheye_spread

        value = level_of_detail / (spread_distance + 1)

        if value < self.__min_ring_gap:
            value = self.__min_ring_gap

        return value

    @graph_is_not_empty
    @not_is_in_animation
    def __update_nodes_positions(self):
        """
        """
        for node in self.__sorted_nodes:

            if node.get_draw_info('grouped'):

                # deep group check
                group = node.get_draw_info('group_node')

                while group.get_draw_info('group_node') is not None:
                    group = group.get_draw_info('group_node')

                ring = group.get_draw_info('ring')
                node.set_coordinate_radius(self.__calc_radius(ring))

            else:
                ring = node.get_draw_info('ring')
                node.set_coordinate_radius(self.__calc_radius(ring))

    @graph_is_not_empty
    def __get_node_by_coordinate(self, point):
        """
        """
        xc, yc = self.__center_of_widget

        for node in self.__graph.get_nodes():

            if node.get_draw_info('grouped'):
                continue

            ax, ay = self.__translation

            xn, yn = node.get_cartesian_coordinate()
            center = (xc + xn * self.__scale + ax, yc - yn * self.__scale - ay)
            radius = node.get_draw_info('radius') * self.__scale

            type = node.get_info('device_type')

            if type in SQUARE_TYPES:
                if geometry.is_in_square(point, radius, center):
                    return node, center

            else:
                if geometry.is_in_circle(point, radius, center):
                    return node, center

        return None

    def __calc_radius(self, ring):
        """
        """
        if self.__fisheye:

            radius = 0

            while ring > 0:

                radius += self.__fisheye_function(ring)
                ring -= 1

        else:
            radius = ring * self.__ring_gap

        return radius

    @graph_is_not_empty
    def __arrange_nodes(self):
        """
        """
        new_nodes = set([self.__graph.get_main_node()])
        old_nodes = set()

        number_of_needed_rings = 1
        ring = 0

        # while new nodes were found
        while len(new_nodes) > 0:

            tmp_nodes = set()

            # for each new nodes
            for node in new_nodes:

                old_nodes.add(node)

                # set ring location
                node.set_draw_info({'ring': ring})

                # check group constraints
                if (node.get_draw_info('group') or
                        node.get_draw_info('grouped')):
                    children = node.get_draw_info('children')

                else:

                    # getting connections and fixing multiple fathers
                    children = set()
                    for child in self.__graph.get_node_connections(node):
                        if child in old_nodes or child in new_nodes:
                            continue
                        if child.get_draw_info('grouped'):
                            continue
                        children.add(child)

                # setting father foreign
                for child in children:
                    child.set_draw_info({'father': node})

                node.set_draw_info(
                        {'children': misc.sort_children(children, node)})
                tmp_nodes.update(children)

            # check group influence in number of rings
            for node in tmp_nodes:

                if not node.get_draw_info('grouped'):

                    number_of_needed_rings += 1
                    break

            # update new nodes set
            new_nodes.update(tmp_nodes)
            new_nodes.difference_update(old_nodes)

            ring += 1

        self.__set_number_of_rings(number_of_needed_rings)

    def __weighted_layout(self):
        """
        """
        # calculating the space needed by each node
        self.__graph.get_main_node().set_draw_info({'range': (0, 360)})
        new_nodes = set([self.__graph.get_main_node()])

        self.__graph.get_main_node().calc_needed_space()

        while len(new_nodes) > 0:

            node = new_nodes.pop()

            # add only no grouped nodes
            children = set()
            for child in node.get_draw_info('children'):

                if not child.get_draw_info('grouped'):
                    children.add(child)
                    new_nodes.add(child)

            if len(children) > 0:

                min, max = node.get_draw_info('range')

                node_total = max - min
                children_need = node.get_draw_info('children_need')

                for child in children:

                    child_need = child.get_draw_info('space_need')
                    child_total = node_total * child_need / children_need

                    theta = child_total / 2 + min + self.__rotate

                    child.set_coordinate_theta(theta)
                    child.set_draw_info({'range': (min, min + child_total)})

                    min += child_total

    def __symmetric_layout(self):
        """
        """
        self.__graph.get_main_node().set_draw_info({'range': (0, 360)})
        new_nodes = set([self.__graph.get_main_node()])

        while len(new_nodes) > 0:

            node = new_nodes.pop()

            # add only no grouped nodes
            children = set()
            for child in node.get_draw_info('children'):

                if not child.get_draw_info('grouped'):
                    children.add(child)
                    new_nodes.add(child)

            if len(children) > 0:

                min, max = node.get_draw_info('range')
                factor = float(max - min) / len(children)

                for child in children:

                    theta = factor / 2 + min + self.__rotate

                    child.set_coordinate_theta(theta)
                    child.set_draw_info({'range': (min, min + factor)})

                    min += factor

    @graph_is_not_empty
    def __calc_layout(self, reference):
        """
        """
        # selecting layout algorithm
        if self.__layout == LAYOUT_SYMMETRIC:
            self.__symmetric_layout()

        elif self.__layout == LAYOUT_WEIGHTED:
            self.__weighted_layout()

        # rotating focus' children to keep orientation
        if reference is not None:

            father, angle = reference
            theta = father.get_coordinate_theta()
            factor = theta - angle

            for node in self.__graph.get_nodes():

                theta = node.get_coordinate_theta()
                node.set_coordinate_theta(theta - factor)

                a, b = node.get_draw_info('range')
                node.set_draw_info({'range': (a - factor, b - factor)})

    @graph_is_not_empty
    def __calc_node_positions(self, reference=None):
        """
        """
        # set nodes' hierarchy
        self.__arrange_nodes()
        self.calc_sorted_nodes()

        # set nodes' coordinate radius
        for node in self.__graph.get_nodes():

            ring = node.get_draw_info('ring')
            node.set_coordinate_radius(self.__calc_radius(ring))

        # set nodes' coordinate theta
        self.__calc_layout(reference)

    def __calc_interpolation(self, focus):
        """
        """
        old_main_node = self.__graph.get_main_node()
        self.__graph.set_main_node(focus)

        # getting initial coordinates
        for node in self.__graph.get_nodes():

            if self.__interpolation == INTERPOLATION_POLAR:
                coordinate = node.get_polar_coordinate()

            elif self.__interpolation == INTERPOLATION_CARTESIAN:
                coordinate = node.get_cartesian_coordinate()

            node.set_draw_info({'start_coordinate': coordinate})

        father = focus.get_draw_info('father')

        # calculate nodes positions (and father orientation)?
        if father is not None:

            xa, ya = father.get_cartesian_coordinate()
            xb, yb = focus.get_cartesian_coordinate()

            angle = math.atan2(yb - ya, xb - xa)
            angle = math.degrees(angle)

            self.__calc_node_positions((father, 180 + angle))

        else:
            self.__calc_node_positions()

        # steps for slow-in/slow-out animation
        steps = list(range(self.__number_of_frames))

        for i in range(len(steps) // 2):
            steps[self.__number_of_frames - 1 - i] = steps[i]

        # normalize angles and calculate interpolated points
        for node in self.__sorted_nodes:

            l2di = Linear2DInterpolator()

            # change grouped nodes coordinate
            if node.get_draw_info('grouped'):

                group_node = node.get_draw_info('group_node')
                a, b = group_node.get_draw_info('final_coordinate')

                if self.__interpolation == INTERPOLATION_POLAR:
                    node.set_polar_coordinate(a, b)

                elif self.__interpolation == INTERPOLATION_CARTESIAN:
                    node.set_cartesian_coordinate(a, b)

            # change interpolation method
            if self.__interpolation == INTERPOLATION_POLAR:

                coordinate = node.get_polar_coordinate()
                node.set_draw_info({'final_coordinate': coordinate})

                # adjusting polar coordinates
                ri, ti = node.get_draw_info('start_coordinate')
                rf, tf = node.get_draw_info('final_coordinate')

                # normalization [0, 360]
                ti = geometry.normalize_angle(ti)
                tf = geometry.normalize_angle(tf)

                # against longest path
                ti, tf = geometry.calculate_short_path(ti, tf)

                # main node goes direct to center (no arc)
                if node == self.__graph.get_main_node():
                    tf = ti

                # old main node goes direct to new position (no arc)
                if node == old_main_node:
                    ti = tf

                node.set_draw_info({'start_coordinate': (ri, ti)})
                node.set_draw_info({'final_coordinate': (rf, tf)})

            elif self.__interpolation == INTERPOLATION_CARTESIAN:

                coordinate = node.get_cartesian_coordinate()
                node.set_draw_info({'final_coordinate': coordinate})

            # calculate interpolated points
            ai, bi = node.get_draw_info('start_coordinate')
            af, bf = node.get_draw_info('final_coordinate')

            l2di.set_start_point(ai, bi)
            l2di.set_final_point(af, bf)

            if self.__interpolation_slow_in_out:
                points = l2di.get_weighed_points(
                        self.__number_of_frames, steps)

            else:
                points = l2di.get_points(self.__number_of_frames)

            node.set_draw_info({'interpolated_coordinate': points})

        return True

    def __livens_up(self, index=0):
        """
        """
        if self.__graph is None:
            # Bail out if the graph became empty during an animation.
            self.__last_group_node = None
            self.__animating = False
            return False

        # prepare interpolated points
        if index == 0:

            # prevent unnecessary animation
            no_need_to_move = True

            for node in self.__graph.get_nodes():

                ai, bi = node.get_draw_info('start_coordinate')
                af, bf = node.get_draw_info('final_coordinate')

                start_c = round(ai), round(bi)
                final_c = round(af), round(bf)

                if start_c != final_c:
                    no_need_to_move = False

            if no_need_to_move:

                self.__animating = False
                return False

        # move all nodes for pass 'index'
        for node in self.__graph.get_nodes():

            a, b = node.get_draw_info('interpolated_coordinate')[index]

            if self.__interpolation == INTERPOLATION_POLAR:
                node.set_polar_coordinate(a, b)

            elif self.__interpolation == INTERPOLATION_CARTESIAN:
                node.set_cartesian_coordinate(a, b)

        self.queue_draw()

        # animation continue condition
        if index < self.__number_of_frames - 1:
            GLib.timeout_add(self.__animation_rate,  # time to recall
                                self.__livens_up,       # recursive call
                                index + 1)              # next iteration
        else:
            self.__last_group_node = None
            self.__animating = False

        return False

    @not_is_in_animation
    def set_graph(self, graph):
        """
        Set graph to be displayed in layout
        @type  : Graph
        @param : Set the graph used in visualization
        """
        if graph.get_number_of_nodes() > 0:

            self.__graph = graph

            self.__calc_node_positions()
            self.queue_draw()

        else:
            self.__graph = None

    def get_scanned_nodes(self):
        """
        """
        nodes = list()
        if self.__graph is None:
            return nodes

        for node in self.__graph.get_nodes():

            if node.get_draw_info('scanned'):
                nodes.append(node)

        return nodes

    def get_graph(self):
        """
        """
        return self.__graph

    def set_empty(self):
        """
        """
        del(self.__graph)
        self.__graph = None

        self.queue_draw()

    def get_rotation(self):
        """
        """
        return self.__rotate

    @graph_is_not_empty
    def set_rotation(self, angle):
        """
        """
        delta = angle - self.__rotate
        self.__rotate = angle

        for node in self.__graph.get_nodes():

            theta = node.get_coordinate_theta()
            node.set_coordinate_theta(theta + delta)

        self.queue_draw()

    def get_translation(self):
        """
        """
        return self.__translation

    @graph_is_not_empty
    def set_translation(self, translation):
        """
        """
        self.__translation = translation
        self.queue_draw()

    def is_empty(self):
        """
        """
        return self.__graph is None

    def is_in_animation(self):
        """
        """
        return self.__animating

    def calc_sorted_nodes(self):
        """
        """
        self.__sorted_nodes = list(self.__graph.get_nodes())
        self.__sorted_nodes.sort(key=lambda n: n.get_draw_info('ring'))


class NetNode(Node):
    """
    Node class for radial network widget
    """
    def __init__(self):
        """
        """
        self.__draw_info = dict()
        """Hash with draw information"""
        self.__coordinate = PolarCoordinate()

        super(NetNode, self).__init__()

    def get_host(self):
        """
        Set the HostInfo that this node represents
        """
        return self.get_data()

    def set_host(self, host):
        """
        Set the HostInfo that this node represents
        """
        self.set_data(host)

    def get_info(self, info):
        """Return various information extracted from the host set with
        set_host."""
        host = self.get_data()
        if host is not None:
            if info == "number_of_open_ports":
                return host.get_port_count_by_states(["open"])
            elif info == "vulnerability_score":
                num_open_ports = host.get_port_count_by_states(["open"])
                if num_open_ports < 3:
                    return 0
                elif num_open_ports < 7:
                    return 1
                else:
                    return 2
            elif info == "addresses":
                addresses = []
                if host.ip is not None:
                    addresses.append(host.ip)
                if host.ipv6 is not None:
                    addresses.append(host.ipv6)
                if host.mac is not None:
                    addresses.append(host.mac)
                return addresses
            elif info == "ip":
                for addr in (host.ip, host.ipv6, host.mac):
                    if addr:
                        return addr.get("addr")
            elif info == "hostnames":
                hostnames = []
                for hostname in host.hostnames:
                    copy = {}
                    copy["name"] = hostname.get("hostname", "")
                    copy["type"] = hostname.get("hostname_type", "")
                    hostnames.append(copy)
                return hostnames
            elif info == "hostname":
                return host.get_hostname()
            elif info == "uptime":
                if host.uptime.get("seconds") or host.uptime.get("lastboot"):
                    return host.uptime
            elif info == "device_type":
                osmatch = host.get_best_osmatch()
                if osmatch is None:
                    return None
                osclasses = osmatch['osclasses']
                if len(osclasses) == 0:
                    return None
                types = ["router", "wap", "switch", "firewall"]
                for type in types:
                    if type in osclasses[0].get("type", "").lower():
                        return type
            elif info == "os":
                os = {}

                # osmatches
                if len(host.osmatches) > 0 and \
                   host.osmatches[0]["accuracy"] != "" and \
                   host.osmatches[0]["name"] != "":
                    if os is None:
                        os = {}
                    os["matches"] = host.osmatches
                    os["matches"][0]["db_line"] = 0     # not supported

                    os_classes = []
                    for osclass in host.osmatches[0]["osclasses"]:
                        os_class = {}

                        os_class["type"] = osclass.get("type", "")
                        os_class["vendor"] = osclass.get("vendor", "")
                        os_class["accuracy"] = osclass.get("accuracy", "")
                        os_class["os_family"] = osclass.get("osfamily", "")
                        os_class["os_gen"] = osclass.get("osgen", "")

                        os_classes.append(os_class)
                    os["classes"] = os_classes

                # ports_used
                if len(host.ports_used) > 0:
                    if os is None:
                        os = {}
                    os_portsused = []

                    for portused in host.ports_used:
                        os_portused = {}

                        os_portused["state"] = portused.get("state", "")
                        os_portused["protocol"] = portused.get("proto", "")
                        os_portused["id"] = int(portused.get("portid", "0"))

                        os_portsused.append(os_portused)

                    os["used_ports"] = os_portsused

                if len(os) > 0:
                    os["fingerprint"] = ""
                    return os
            elif info == "sequences":
                # getting sequences information
                sequences = {}
                # If all fields are empty, we don't put it into the sequences
                # list
                if reduce(lambda x, y: x + y,
                        host.tcpsequence.values(), "") != "":
                    tcp = {}
                    if host.tcpsequence.get("index", "") != "":
                        tcp["index"] = int(host.tcpsequence["index"])
                    else:
                        tcp["index"] = 0
                    tcp["class"] = ""   # not supported
                    tcp["values"] = host.tcpsequence.get(
                            "values", "").split(",")
                    tcp["difficulty"] = host.tcpsequence.get("difficulty", "")
                    sequences["tcp"] = tcp
                if reduce(lambda x, y: x + y,
                        host.ipidsequence.values(), "") != "":
                    ip_id = {}
                    ip_id["class"] = host.ipidsequence.get("class", "")
                    ip_id["values"] = host.ipidsequence.get(
                            "values", "").split(",")
                    sequences["ip_id"] = ip_id
                if reduce(lambda x, y: x + y,
                        host.tcptssequence.values(), "") != "":
                    tcp_ts = {}
                    tcp_ts["class"] = host.tcptssequence.get("class", "")
                    tcp_ts["values"] = host.tcptssequence.get(
                            "values", "").split(",")
                    sequences["tcp_ts"] = tcp_ts
                return sequences
            elif info == "filtered":
                if (len(host.extraports) > 0 and
                        host.extraports[0]["state"] == "filtered"):
                    return True
                else:
                    for port in host.ports:
                        if port["port_state"] == "filtered":
                            return True
                return False
            elif info == "ports":
                ports = list()
                for host_port in host.ports:
                    port = dict()
                    state = dict()
                    service = dict()

                    port["id"] = int(host_port.get("portid", ""))
                    port["protocol"] = host_port.get("protocol", "")

                    state["state"] = host_port.get("port_state", "")
                    state["reason"] = ""        # not supported
                    state["reason_ttl"] = ""    # not supported
                    state["reason_ip"] = ""     # not supported

                    service["name"] = host_port.get("service_name", "")
                    service["conf"] = host_port.get("service_conf", "")
                    service["method"] = host_port.get("service_method", "")
                    service["version"] = host_port.get("service_version", "")
                    service["product"] = host_port.get("service_product", "")
                    service["extrainfo"] = host_port.get(
                            "service_extrainfo", "")

                    port["state"] = state
                    port["scripts"] = None      # not supported
                    port["service"] = service

                    ports.append(port)
                return ports
            elif info == "extraports":
                # extraports
                all_extraports = list()
                for extraport in host.extraports:
                    extraports = dict()
                    extraports["count"] = int(extraport.get("count", ""))
                    extraports["state"] = extraport.get("state", "")
                    extraports["reason"] = list()       # not supported
                    extraports["all_reason"] = list()   # not supported

                    all_extraports.append(extraports)
                return all_extraports
            elif info == "trace":
                # getting traceroute information
                if len(host.trace) > 0:
                    trace = {}
                    hops = []

                    for host_hop in host.trace.get("hops", []):
                        hop = {}
                        hop["ip"] = host_hop.get("ipaddr", "")
                        hop["ttl"] = int(host_hop.get("ttl", ""))
                        hop["rtt"] = host_hop.get("rtt", "")
                        hop["hostname"] = host_hop.get("host", "")

                        hops.append(hop)

                    trace["hops"] = hops
                    trace["port"] = host.trace.get("port", "")
                    trace["protocol"] = host.trace.get("proto", "")

                    return trace
        else:  # host is None
            pass

        return None

    def get_coordinate_theta(self):
        """
        """
        return self.__coordinate.get_theta()

    def get_coordinate_radius(self):
        """
        """
        return self.__coordinate.get_radius()

    def set_coordinate_theta(self, value):
        """
        """
        self.__coordinate.set_theta(value)

    def set_coordinate_radius(self, value):
        """
        """
        self.__coordinate.set_radius(value)

    def set_polar_coordinate(self, r, t):
        """
        Set polar coordinate
        @type  r: number
        @param r: The radius of coordinate
        @type  t: number
        @param t: The angle (theta) of coordinate in radians
        """
        self.__coordinate.set_coordinate(r, t)

    def get_polar_coordinate(self):
        """
        Get cartesian coordinate
        @rtype: tuple
        @return: Cartesian coordinates (x, y)
        """
        return self.__coordinate.get_coordinate()

    def set_cartesian_coordinate(self, x, y):
        """
        Set cartesian coordinate
        """
        cartesian = CartesianCoordinate(x, y)
        r, t = cartesian.to_polar()

        self.set_polar_coordinate(r, math.degrees(t))

    def get_cartesian_coordinate(self):
        """
        Get cartesian coordinate
        @rtype: tuple
        @return: Cartesian coordinates (x, y)
        """
        return self.__coordinate.to_cartesian()

    def get_draw_info(self, info=None):
        """
        Get draw information about node
        @type  : string
        @param : Information name
        @rtype: mixed
        @return: The requested information
        """
        if info is None:
            return self.__draw_info

        return self.__draw_info.get(info)

    def set_draw_info(self, info):
        """
        Set draw information
        @type  : dict
        @param : Draw information dictionary
        """
        for key in info:
            self.__draw_info[key] = info[key]

    def deep_search_child(self, node):
        """
        """
        for child in self.get_draw_info('children'):

            if child == node:
                return True

            elif child.deep_search_child(node):
                return True

        return False

    def set_subtree_info(self, info):
        """
        """
        for child in self.get_draw_info('children'):

            child.set_draw_info(info)

            if not child.get_draw_info('group'):
                child.set_subtree_info(info)

    def calc_needed_space(self):
        """
        """
        number_of_children = len(self.get_draw_info('children'))

        sum_angle = 0
        own_angle = 0

        if number_of_children > 0 and not self.get_draw_info('group'):

            for child in self.get_draw_info('children'):

                child.calc_needed_space()
                sum_angle += child.get_draw_info('space_need')

        distance = self.get_coordinate_radius()
        size = self.get_draw_info('radius') * 2
        own_angle = geometry.angle_from_object(distance, size)

        self.set_draw_info({'children_need': sum_angle})
        self.set_draw_info({'space_need': max(sum_angle, own_angle)})
