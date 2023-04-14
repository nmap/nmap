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

import math


class PolarCoordinate:
    """
    Class to implement a polar coordinate object
    """

    def __init__(self, r=0, t=0):
        """
        Constructor method of PolarCoordinate class
        @type  r: number
        @param r: The radius of coordinate
        @type  t: number
        @param t: The angle (theta) of coordinate in radians
        """

        self.__r = r
        """Radius of polar coordinate"""
        self.__t = t
        """Angle (theta) of polar coordinate in radians"""

    def get_theta(self):
        """
        """
        return math.degrees(self.__t)

    def get_radius(self):
        """
        """
        return self.__r

    def set_theta(self, t):
        """
        """
        self.__t = math.radians(t)

    def set_radius(self, r):
        """
        """
        self.__r = r

    def get_coordinate(self):
        """
        Set polar coordinate
        @rtype: tuple
        @return: Polar coordinates (r, t)
        """
        return (self.__r, math.degrees(self.__t))

    def set_coordinate(self, r, t):
        """
        Set polar coordinate
        @type  r: number
        @param r: The radius of coordinate
        @type  t: number
        @param t: The angle (theta) of coordinate
        """
        self.__r = r
        self.__t = math.radians(t)

    def to_cartesian(self):
        """
        Convert polar in cartesian coordinate
        @rtype: tuple
        @return: cartesian coordinates (x, y)
        """
        x = self.__r * math.cos(self.__t)
        y = self.__r * math.sin(self.__t)

        return (x, y)


class CartesianCoordinate:
    """
    Class to implement a cartesian coordinate object
    """
    def __init__(self, x=0, y=0):
        """
        Constructor method of CartesianCoordinate class
        @type  x: number
        @param x: The x component of coordinate
        @type  y: number
        @param y: The y component of coordinate
        """
        self.__x = x
        """X component of cartesian coordinate"""
        self.__y = y
        """Y component of cartesian coordinate"""

    def get_coordinate(self):
        """
        Get cartesian coordinate
        @rtype: tuple
        @return: Cartesian coordinates (x, y)
        """
        return (self.__x, self.__y)

    def set_coordinate(self, x, y):
        """
        Set cartesian coordinate
        @type  x: number
        @param x: The x component of coordinate
        @type  y: number
        @param y: The y component of coordinate
        """
        self.__x = x
        self.__y = y

    def to_polar(self):
        """
        Convert cartesian in polar coordinate
        @rtype: tuple
        @return: polar coordinates (r, t)
        """
        r = math.sqrt(self.__x ** 2 + self.__y ** 2)

        if self.__x > 0:

            if self.__y >= 0:
                t = math.atan(self.__y / self.__x)

            else:
                t = math.atan(self.__y / self.__x) + 2 * math.pi

        elif self.__x < 0:
            t = math.atan(self.__y / self.__x) + math.pi

        elif self.__x == 0:

            if self.__y == 0:
                t = 0

            if self.__y > 0:
                t = math.pi / 2

            else:
                t = -math.pi / 2

        return (r, t)


if __name__ == "__main__":

    # Testing application

    polar = PolarCoordinate(1, math.pi)
    cartesian = CartesianCoordinate(-1, 0)

    print(polar.to_cartesian())
    print(cartesian.to_polar())
