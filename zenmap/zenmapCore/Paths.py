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

from os.path import join, dirname

import errno
import os
import os.path
import sys
import shutil

from zenmapCore.BasePaths import base_paths
from zenmapCore.Name import APP_NAME


# Find out the prefix under which data files (interface definition XML,
# pixmaps, etc.) are stored. This can vary depending on whether we are running
# in an executable package and what type of package it is, which we check using
# the sys.frozen attribute. See
# http://mail.python.org/pipermail/pythonmac-sig/2004-November/012121.html.
def get_prefix():
    from site import getsitepackages
    frozen = getattr(sys, "frozen", None)
    if frozen == "macosx_app" or "Zenmap.app" in sys.executable:
        # A py2app .app bundle.
        return os.path.join(dirname(sys.executable), "..", "Resources")
    elif frozen is not None:
        # Assume a py2exe executable.
        return dirname(sys.executable)
    elif any(__file__.startswith(pdir) for pdir in getsitepackages()):
        # Installed in site-packages; use configured prefix.
        return sys.prefix
    else:
        # Normal script execution. Look in the current directory to allow
        # running from the distribution.
        return os.path.abspath(os.path.dirname(sys.argv[0]))

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
        self.config_dir = CONFIG_DIR
        self.locale_dir = LOCALE_DIR
        self.pixmaps_dir = PIXMAPS_DIR
        self.misc_dir = MISC_DIR
        self.docs_dir = DOCS_DIR
        self.nmap_dir = NMAPDATADIR
        self._delayed_incomplete = True

    # Delay initializing these paths so that
    # zenmapCore.I18N.install_gettext can install _() before modules that
    # need it get imported
    def _delayed_init(self):
        if self._delayed_incomplete:
            from zenmapCore.UmitOptionParser import option_parser
            self.user_config_dir = option_parser.get_confdir()
            self.user_config_file = os.path.join(
                    self.user_config_dir, base_paths['user_config_file'])
            self._delayed_incomplete = False

    def __getattr__(self, name):
        if name in self.hardcoded:
            return self.__dict__[name]

        self._delayed_init()
        if name in self.config_files_list:
            return return_if_exists(
                    join(self.user_config_dir, base_paths[name]))

        if name in self.empty_config_files_list:
            return return_if_exists(
                    join(self.user_config_dir, base_paths[name]), True)

        if name in self.misc_files_list:
            return return_if_exists(join(self.misc_dir, base_paths[name]))

        try:
            return self.__dict__[name]
        except Exception:
            raise NameError(name)

    def __setattr__(self, name, value):
        self.__dict__[name] = value


def create_dir(path):
    """Create a directory with os.makedirs without raising an error if the
    directory already exists."""
    try:
        os.makedirs(path)
    except OSError as e:
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
    print(">>> SAVED DIRECTORIES:")
    print(">>> LOCALE DIR:", Path.locale_dir)
    print(">>> PIXMAPS DIR:", Path.pixmaps_dir)
    print(">>> CONFIG DIR:", Path.config_dir)
    print()
    print(">>> FILES:")
    print(">>> USER CONFIG FILE:", Path.user_config_file)
    print(">>> CONFIG FILE:", Path.user_config_file)
    print(">>> TARGET_LIST:", Path.target_list)
    print(">>> PROFILE_EDITOR:", Path.profile_editor)
    print(">>> SCAN_PROFILE:", Path.scan_profile)
    print(">>> RECENT_SCANS:", Path.recent_scans)
    print(">>> OPTIONS:", Path.options)
    print()
    print(">>> DB:", Path.db)
    print(">>> VERSION:", Path.version)
