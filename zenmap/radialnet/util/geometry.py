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


def is_in_square(point, half_side, center=(0, 0)):
    """
    """
    x, y = point
    a, b = center

    if a + half_side >= x >= a - half_side:
        if b + half_side >= y >= b - half_side:
            return True

    return False


def is_in_circle(point, radius=1, center=(0, 0)):
    """
    """
    x, y = point
    a, b = center

    if ((x - a) ** 2 + (y - b) ** 2) <= (radius ** 2):
        return True

    return False


def atan_scale(point, scale_ceil):
    """
    """
    new_point = float(10.0 * point / scale_ceil) - 5
    return math.atan(abs(new_point))


def normalize_angle(angle):
    """
    """
    new_angle = 360.0 * (float(angle / 360) - int(angle / 360))

    if new_angle < 0:
        return 360 + new_angle

    return new_angle


def is_between_angles(a, b, c):
    """
    """
    a = normalize_angle(a)
    b = normalize_angle(b)
    c = normalize_angle(c)

    if a > b:

        if c >= a and c <= 360 or c <= b:
            return True

        return False

    else:

        if c >= a and c <= b:
            return True

        return False


def angle_distance(a, b):
    """
    """
    distance = abs(normalize_angle(a) - normalize_angle(b))

    if distance > 180:
        return 360 - distance

    return distance


def calculate_short_path(iangle, fangle):
    """
    """
    if iangle - fangle > 180:
        fangle += 360

    if iangle - fangle < -180:
        fangle -= 360

    return iangle, fangle


def angle_from_object(distance, size):
    """
    """
    return math.degrees(math.atan2(size / 2.0, distance))
