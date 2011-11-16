#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

from os.path import join, dirname

import errno
import os
import os.path
import sys
import shutil

from zenmapCore.BasePaths import base_paths, fs_dec
from zenmapCore.Version import VERSION
from zenmapCore.Name import APP_NAME
from zenmapCore.UmitOptionParser import option_parser

# Find out the prefix under which data files (interface definition XML,
# pixmaps, etc.) are stored. This can vary depending on whether we are running
# in an executable package and what type of package it is, which we check using
# the sys.frozen attribute. See
# http://mail.python.org/pipermail/pythonmac-sig/2004-November/012121.html.
def get_prefix():
    frozen = getattr(sys, "frozen", None)
    if frozen == "macosx_app":
        # A py2app .app bundle.
        return os.path.join(dirname(fs_dec(sys.executable)), "..", "Resources")
    elif frozen is not None:
        # Assume a py2exe executable.
        return dirname(fs_dec(sys.executable))
    else:
        # Normal script execution. Look in the current directory to allow
        # running from the distribution.
        return os.path.abspath(os.path.dirname(fs_dec(sys.argv[0])))

prefix = get_prefix()

# These lines are overwritten by the installer to hard-code the installed
# locations.
CONFIG_DIR = join(prefix, "share", APP_NAME, "config")
LOCALE_DIR = join(prefix, "share", APP_NAME, "locale")
MISC_DIR = join(prefix, "share", APP_NAME, "misc")
PIXMAPS_DIR = join(prefix, "share", "zenmap", "pixmaps")
DOCS_DIR = join(prefix, "share", APP_NAME, "docs")
NMAPDATADIR = join(prefix, "..")
def get_extra_executable_search_paths():
    """Return a list of additional executable search paths as a convenience for
    platforms where the default PATH is inadequate."""
    if sys.platform == 'darwin':
        return ["/usr/local/bin"]
    elif sys.platform == 'win32':
        return [dirname(sys.executable)]
    return []

#######
# Paths
class Paths(object):
    """Paths
    """
    hardcoded = ["config_dir",
                 "locale_dir",
                 "pixmaps_dir",
                 "misc_dir",
                 "docs_dir"]

    config_files_list = ["config_file",
                         "scan_profile",
                         "version"]

    empty_config_files_list = ["target_list",
                               "recent_scans",
                               "db"]

    misc_files_list = ["options",
                       "profile_editor"]

    def __init__(self):
        self.user_config_dir = option_parser.get_confdir()
        self.user_config_file = os.path.join(self.user_config_dir, base_paths['user_config_file'])
        self.config_dir = CONFIG_DIR
        self.locale_dir = LOCALE_DIR
        self.pixmaps_dir = PIXMAPS_DIR
        self.misc_dir = MISC_DIR
        self.docs_dir = DOCS_DIR
        self.nmap_dir = NMAPDATADIR

    def __getattr__(self, name):
        if name in self.hardcoded:
            return self.__dict__[name]

        elif name in self.config_files_list:
            return return_if_exists(join(self.user_config_dir, base_paths[name]))

        elif name in self.empty_config_files_list:
            return return_if_exists(join(self.user_config_dir, base_paths[name]), True)

        elif name in self.misc_files_list:
            return return_if_exists(join(self.misc_dir, base_paths[name]))

        try:
            return self.__dict__[name]
        except:
            raise NameError(name)

    def __setattr__(self, name, value):
        self.__dict__[name] = value

def create_dir(path):
    """Create a directory with os.makedirs without raising an error if the
        directory already exists."""
    try:
        os.makedirs(path)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

def create_user_config_dir(user_dir, template_dir):
    """Create a user configuration directory by creating the directory if
    necessary, then copying all the files from the given template directory,
    skipping any that already exist."""
    from zenmapCore.UmitLogging import log
    log.debug(">>> Create user dir at %s" % user_dir)
    create_dir(user_dir)

    for filename in os.listdir(template_dir):
        template_filename = os.path.join(template_dir, filename)
        user_filename = os.path.join(user_dir, filename)
        # Only copy regular files.
        if not os.path.isfile(template_filename):
            continue
        # Don't overwrite existing files.
        if os.path.exists(user_filename):
            log.debug(">>> %s already exists." % user_filename)
            continue
        shutil.copyfile(template_filename, user_filename)
        log.debug(">>> Copy %s to %s." % (template_filename, user_filename))

def return_if_exists(path, create=False):
    path = os.path.abspath(path)
    if os.path.exists(path):
        return path
    elif create:
        f = open(path, "w")
        f.close()
        return path
    raise Exception("File '%s' does not exist or could not be found!" % path)

############
# Singleton!
Path = Paths()

if __name__ == '__main__':
    print ">>> SAVED DIRECTORIES:"
    print ">>> LOCALE DIR:", Path.locale_dir
    print ">>> PIXMAPS DIR:", Path.pixmaps_dir
    print ">>> CONFIG DIR:", Path.config_dir
    print
    print ">>> FILES:"
    print ">>> USER CONFIG FILE:", Path.user_config_file
    print ">>> CONFIG FILE:", Path.user_config_file
    print ">>> TARGET_LIST:", Path.target_list
    print ">>> PROFILE_EDITOR:", Path.profile_editor
    print ">>> SCAN_PROFILE:", Path.scan_profile
    print ">>> RECENT_SCANS:", Path.recent_scans
    print ">>> OPTIONS:", Path.options
    print
    print ">>> DB:", Path.db
    print ">>> VERSION:", Path.version
