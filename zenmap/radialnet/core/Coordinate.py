# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
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
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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

    print polar.to_cartesian()
    print cartesian.to_polar()
