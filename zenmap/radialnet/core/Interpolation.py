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


class Linear2DInterpolator:
    """
    Implements a bidimensional linear interpolator.
    """

    def __init__(self):
        """
        Constructor method of Linear2DInterpolator class
        """
        self.__start_point = (0, 0)
        """Initial point of interpolation"""
        self.__final_point = (0, 0)
        """Final point of interpolation"""
        self.__interpolated_points = []
        """Interpolated points vector"""

    def set_start_point(self, a, b):
        """
        Set initial coordinate
        Set final coordinate
        @type  a: number
        @param a: The first component of final point
        @type  b: number
        @param b: The second component of final point
        """
        self.__start_point = (a, b)

    def set_final_point(self, a, b):
        """
        Set final coordinate
        @type  a: number
        @param a: The first component of final point
        @type  b: number
        @param b: The second component of final point
        """
        self.__final_point = (a, b)

    def get_weighed_points(self, number_of_pass, pass_vector):
        """
        Return the vector of coordinates between the initial and final
        coordinates with the specified size
        @type  number_of_pass: number
        @param number_of_pass: The number of pass of interpolation
        @rtype: list
        @return: A list of tuples with interpolated points
        """
        (ai, bi) = self.__start_point
        (af, bf) = self.__final_point

        a_conversion_factor = float(af - ai) / sum(pass_vector)
        b_conversion_factor = float(bf - bi) / sum(pass_vector)

        a_pass = 0
        b_pass = 0

        self.__interpolated_points = list(range(number_of_pass))

        for i in range(0, number_of_pass):

            a_pass += pass_vector[i] * a_conversion_factor
            b_pass += pass_vector[i] * b_conversion_factor
            self.__interpolated_points[i] = (ai + a_pass, bi + b_pass)

        return self.__interpolated_points

    def get_points(self, number_of_pass):
        """
        Return the vector of coordinates between the initial and final
        coordinates with the specified size
        @type  number_of_pass: number
        @param number_of_pass: The number of pass of interpolation
        @rtype: list
        @return: A list of tuples with interpolated points
        """
        (ai, bi) = self.__start_point
        (af, bf) = self.__final_point

        a_pass = float(af - ai) / number_of_pass
        b_pass = float(bf - bi) / number_of_pass

        self.__interpolated_points = list(range(number_of_pass))

        for i in range(1, number_of_pass + 1):
            self.__interpolated_points[i - 1] = (ai + a_pass * i,
                                                 bi + b_pass * i)

        return self.__interpolated_points


if __name__ == "__main__":

    # Testing application

    i = Linear2DInterpolator()

    i.set_start_point(0, 0)
    i.set_final_point(1, 1)

    print(len(i.get_points(10)), i.get_points(10))
