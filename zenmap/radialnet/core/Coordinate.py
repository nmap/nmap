# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
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
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
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
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
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
        r = math.sqrt(self.__x**2 + self.__y**2)

        if self.__x > 0:

            if self.__y >= 0:
                t = math.atan( self.__y / self.__x )

            else:
                t = math.atan( self.__y / self.__x ) + 2 * math.pi

        elif self.__x < 0:
            t = math.atan( self.__y / self.__x ) + math.pi

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

    polar     = PolarCoordinate(1, math.pi)
    cartesian = CartesianCoordinate(-1,  0)

    print polar.to_cartesian()
    print cartesian.to_polar()
