#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
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
import sys

if sys.version_info[0] != 2:
    sys.exit("Sorry, Zenmap requires Python 2")

import errno
import os
import os.path
import re

import distutils.sysconfig
from distutils import log
from distutils.core import setup, Command
from distutils.command.install import install

from glob import glob
from stat import *

from zenmapCore.Version import VERSION
from zenmapCore.Name import APP_NAME, APP_DISPLAY_NAME, APP_WEB_SITE,\
        APP_DOWNLOAD_SITE, NMAP_DISPLAY_NAME

# The name of the file used to record the list of installed files, so that the
# uninstall command can remove them.
INSTALLED_FILES_NAME = "INSTALLED_FILES"

# Directories for POSIX operating systems
# These are created after a "install" or "py2exe" command
# These directories are relative to the installation or dist directory
data_dir = os.path.join('share', APP_NAME)
pixmaps_dir = os.path.join(data_dir, 'pixmaps')
locale_dir = os.path.join(data_dir, 'locale')
config_dir = os.path.join(data_dir, 'config')
docs_dir = os.path.join(data_dir, 'docs')
misc_dir = os.path.join(data_dir, 'misc')

# Where to install .desktop files.
desktop_dir = os.path.join('share', 'applications')


def mo_find(result, dirname, fnames):
    files = []
    for f in fnames:
        p = os.path.join(dirname, f)
        if os.path.isfile(p) and f.endswith(".mo"):
            files.append(p)

    if files:
        result.append((dirname, files))

###############################################################################
# Installation variables

data_files = [
        (pixmaps_dir, glob(os.path.join(pixmaps_dir, '*.gif')) +
            glob(os.path.join(pixmaps_dir, '*.png'))),

        (os.path.join(pixmaps_dir, "radialnet"),
            glob(os.path.join(pixmaps_dir, "radialnet", '*.png'))),

        (config_dir, [os.path.join(config_dir, APP_NAME + '.conf'),
            os.path.join(config_dir, 'scan_profile.usp'),
            os.path.join(config_dir, APP_NAME + '_version')]),

        (misc_dir, glob(os.path.join(misc_dir, '*.xml'))),

        (docs_dir, [os.path.join(docs_dir, 'help.html')])
        ]

# Add i18n files to data_files list
os.path.walk(locale_dir, mo_find, data_files)


# path_startswith and path_strip_prefix are used to deal with the installation
# root (--root option, also known as DESTDIR).
def path_startswith(path, prefix):
    """Returns True if path starts with prefix. It's a little more intelligent
    than str.startswith because it normalizes the paths to remove multiple
    directory separators and down-up traversals."""
    path = os.path.normpath(path)
    prefix = os.path.normpath(prefix)
    return path.startswith(prefix)


def path_strip_prefix(path, prefix):
    """Return path stripped of its directory prefix if it starts with prefix,
    otherwise return path unmodified. This only works correctly with Unix
    paths; for example it will not replace the drive letter on a Windows path.
    Examples:
    >>> path_strip_prefix('/tmp/destdir/usr/bin', '/tmp/destdir')
    '/usr/bin'
    >>> path_strip_prefix('/tmp/../tmp/destdir/usr/bin', '/tmp///destdir')
    '/usr/bin'
    >>> path_strip_prefix('/etc', '/tmp/destdir')
    '/etc'
    >>> path_strip_prefix('/etc', '/')
    '/etc'
    >>> path_strip_prefix('/etc', '')
    '/etc'
    """
    absolute = os.path.isabs(path)
    path = os.path.normpath(path)
    prefix = os.path.normpath(prefix)
    if path.startswith(prefix) and prefix != os.sep:
        path = path[len(prefix):]
    # Absolute paths must remain absolute and relative paths must remain
    # relative.
    assert os.path.isabs(path) == absolute
    return path

###############################################################################
# Distutils subclasses


class my_install(install):
    def finalize_options(self):
        # Ubuntu's python2.6-2.6.4-0ubuntu3 package changes sys.prefix in
        # install.finalize_options when sys.prefix is "/usr/local" (our
        # default). Because we need the unchanged value later, remember it
        # here.
        self.saved_prefix = self.prefix
        install.finalize_options(self)

    def run(self):
        install.run(self)

        self.set_perms()
        self.set_modules_path()
        self.fix_paths()
        self.create_uninstaller()
        self.write_installed_files()

    def get_installed_files(self):
        """Return a list of installed files and directories, each prefixed with
        the installation root if given. The list of installed directories
        doesn't come from distutils so it may be incomplete."""
        installed_files = self.get_outputs()
        for package in self.distribution.packages:
            dir = package.replace(".", "/")
            installed_files.append(os.path.join(self.install_lib, dir))
        # Recursively include all the directories in data_dir (share/zenmap).
        # This is mainly for convenience in listing locale directories.
        installed_files.append(os.path.join(self.install_data, data_dir))
        for dirpath, dirs, files in os.walk(
                os.path.join(self.install_data, data_dir)):
            for dir in dirs:
                installed_files.append(os.path.join(dirpath, dir))
        installed_files.append(
                os.path.join(self.install_scripts, "uninstall_" + APP_NAME))
        return installed_files

    def create_uninstaller(self):
        uninstaller_filename = os.path.join(
                self.install_scripts, "uninstall_" + APP_NAME)

        uninstaller = """\
#!/usr/bin/env python
import errno, os, os.path, sys

print 'Uninstall %(name)s %(version)s'

answer = raw_input('Are you sure that you want to uninstall '
    '%(name)s %(version)s? (yes/no) ')

if answer != 'yes' and answer != 'y':
    print 'Not uninstalling.'
    sys.exit(0)

""" % {'name': APP_DISPLAY_NAME, 'version': VERSION}

        installed_files = []
        for output in self.get_installed_files():
            if self.root is not None:
                # If we have a root (DESTDIR), we need to strip it off the
                # front of paths so the uninstaller runs on the target host.
                # The path manipulations are tricky, but made easier because
                # the uninstaller only has to run on Unix.
                if not path_startswith(output, self.root):
                    # This should never happen (everything gets installed
                    # inside the root), but if it does, be safe and don't
                    # delete anything.
                    uninstaller += ("print '%s was not installed inside "
                        "the root %s; skipping.'\n" % (output, self.root))
                    continue
                output = path_strip_prefix(output, self.root)
                assert os.path.isabs(output)
            installed_files.append(output)

        uninstaller += """\
INSTALLED_FILES = (
"""
        for file in installed_files:
            uninstaller += "    %s,\n" % repr(file)
        uninstaller += """\
)

# Split the list into lists of files and directories.
files = []
dirs = []
for path in INSTALLED_FILES:
    if os.path.isfile(path) or os.path.islink(path):
        files.append(path)
    elif os.path.isdir(path):
        dirs.append(path)
# Delete the files.
for file in files:
    print "Removing '%s'." % file
    try:
        os.remove(file)
    except OSError, e:
        print >> sys.stderr, '  Error: %s.' % str(e)
# Delete the directories. First reverse-sort the normalized paths by
# length so that child directories are deleted before their parents.
dirs = [os.path.normpath(dir) for dir in dirs]
dirs.sort(key = len, reverse = True)
for dir in dirs:
    try:
        print "Removing the directory '%s'." % dir
        os.rmdir(dir)
    except OSError, e:
        if e.errno == errno.ENOTEMPTY:
            print "Directory '%s' not empty; not removing." % dir
        else:
            print >> sys.stderr, str(e)
"""

        uninstaller_file = open(uninstaller_filename, 'w')
        uninstaller_file.write(uninstaller)
        uninstaller_file.close()

        # Set exec bit for uninstaller
        mode = ((os.stat(uninstaller_filename)[ST_MODE]) | 0555) & 07777
        os.chmod(uninstaller_filename, mode)

    def set_modules_path(self):
        app_file_name = os.path.join(self.install_scripts, APP_NAME)
        # Find where the modules are installed. distutils will put them in
        # self.install_lib, but that path can contain the root (DESTDIR), so we
        # must strip it off if necessary.
        modules_dir = self.install_lib
        if self.root is not None:
            modules_dir = path_strip_prefix(modules_dir, self.root)

        app_file = open(app_file_name, "r")
        lines = app_file.readlines()
        app_file.close()

        for i in range(len(lines)):
            if re.match(r'^INSTALL_LIB =', lines[i]):
                lines[i] = "INSTALL_LIB = %s\n" % repr(modules_dir)
                break
        else:
            raise ValueError(
                    "INSTALL_LIB replacement not found in %s" % app_file_name)

        app_file = open(app_file_name, "w")
        app_file.writelines(lines)
        app_file.close()

    def set_perms(self):
        re_bin = re.compile("(bin|\.sh)")
        for output in self.get_installed_files():
            if re_bin.findall(output):
                continue

            if os.path.isdir(output):
                os.chmod(output, S_IRWXU |
                                 S_IRGRP |
                                 S_IXGRP |
                                 S_IROTH |
                                 S_IXOTH)
            else:
                os.chmod(output, S_IRUSR |
                                 S_IWUSR |
                                 S_IRGRP |
                                 S_IROTH)

    def fix_paths(self):
        """Replace some hardcoded paths to match where files were installed."""
        interesting_paths = {
                "CONFIG_DIR": os.path.join(self.saved_prefix, config_dir),
                "DOCS_DIR": os.path.join(self.saved_prefix, docs_dir),
                "LOCALE_DIR": os.path.join(self.saved_prefix, locale_dir),
                "MISC_DIR": os.path.join(self.saved_prefix, misc_dir),
                "PIXMAPS_DIR": os.path.join(self.saved_prefix, pixmaps_dir),
                # See $(nmapdatadir) in nmap/Makefile.in.
                "NMAPDATADIR": os.path.join(self.saved_prefix, "share", "nmap")
                }

        # Find and read the Paths.py file.
        pcontent = ""
        paths_file = os.path.join("zenmapCore", "Paths.py")
        installed_files = self.get_outputs()
        for f in installed_files:
            if re.findall("(%s)" % re.escape(paths_file), f):
                paths_file = f
                pf = open(paths_file)
                pcontent = pf.read()
                pf.close()
                break

        # Replace the path definitions.
        for path, replacement in interesting_paths.items():
            pcontent = re.sub("%s\s+=\s+.+" % path,
                              "%s = %s" % (path, repr(replacement)),
                              pcontent)

        # Write the modified file.
        pf = open(paths_file, "w")
        pf.write(pcontent)
        pf.close()

        # Rewrite the zenmap.desktop and zenmap-root.desktop files to point to
        # the installed locations of the su-to-zenmap.sh script and application
        # icon.
        su_filename = os.path.join(
                self.saved_prefix, data_dir, "su-to-zenmap.sh")
        icon_filename = os.path.join(
                self.saved_prefix, pixmaps_dir, "zenmap.png")

        desktop_filename = None
        root_desktop_filename = None
        for f in installed_files:
            if re.search("%s$" % re.escape("zenmap-root.desktop"), f):
                root_desktop_filename = f
            elif re.search("%s$" % re.escape("zenmap.desktop"), f):
                desktop_filename = f

        if desktop_filename is not None:
            df = open(desktop_filename, "r")
            dcontent = df.read()
            df.close()
            regex = re.compile("^(Icon *= *).*$", re.MULTILINE)
            dcontent = regex.sub("\\1%s" % icon_filename, dcontent)
            df = open(desktop_filename, "w")
            df.write(dcontent)
            df.close()

        if root_desktop_filename is not None:
            df = open(root_desktop_filename, "r")
            dcontent = df.read()
            df.close()
            regex = re.compile(
                    "^((?:Exec|TryExec) *= *).*su-to-zenmap.sh(.*)$",
                    re.MULTILINE)
            dcontent = regex.sub("\\1%s\\2" % su_filename, dcontent)
            regex = re.compile("^(Icon *= *).*$", re.MULTILINE)
            dcontent = regex.sub("\\1%s" % icon_filename, dcontent)
            df = open(root_desktop_filename, "w")
            df.write(dcontent)
            df.close()

    def write_installed_files(self):
        """Write a list of installed files for use by the uninstall command.
        This is similar to what happens with the --record option except that it
        doesn't strip off the installation root, if any. File names containing
        newline characters are not handled."""
        if INSTALLED_FILES_NAME == self.record:
            distutils.log.warn("warning: installation record is overwriting "
                "--record file '%s'." % self.record)
        f = open(INSTALLED_FILES_NAME, "w")
        try:
            for output in self.get_installed_files():
                assert "\n" not in output
                print >> f, output
        finally:
            f.close()


class my_uninstall(Command):
    """A distutils command that performs uninstallation. It reads the list of
    installed files written by the install command."""

    command_name = "uninstall"
    description = "uninstall installed files recorded in '%s'" % (
            INSTALLED_FILES_NAME)
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # Read the list of installed files.
        try:
            f = open(INSTALLED_FILES_NAME, "r")
        except IOError, e:
            if e.errno == errno.ENOENT:
                log.error("Couldn't open the installation record '%s'. "
                        "Have you installed yet?" % INSTALLED_FILES_NAME)
                return
        installed_files = [file.rstrip("\n") for file in f.readlines()]
        f.close()
        # Delete the installation record too.
        installed_files.append(INSTALLED_FILES_NAME)
        # Split the list into lists of files and directories.
        files = []
        dirs = []
        for path in installed_files:
            if os.path.isfile(path) or os.path.islink(path):
                files.append(path)
            elif os.path.isdir(path):
                dirs.append(path)
        # Delete the files.
        for file in files:
            log.info("Removing '%s'." % file)
            try:
                if not self.dry_run:
                    os.remove(file)
            except OSError, e:
                log.error(str(e))
        # Delete the directories. First reverse-sort the normalized paths by
        # length so that child directories are deleted before their parents.
        dirs = [os.path.normpath(dir) for dir in dirs]
        dirs.sort(key=len, reverse=True)
        for dir in dirs:
            try:
                log.info("Removing the directory '%s'." % dir)
                if not self.dry_run:
                    os.rmdir(dir)
            except OSError, e:
                if e.errno == errno.ENOTEMPTY:
                    log.info("Directory '%s' not empty; not removing." % dir)
                else:
                    log.error(str(e))

# setup can be called in different ways depending on what we're doing. (For
# example py2exe needs special handling.) These arguments are common between
# all the operations.
COMMON_SETUP_ARGS = {
    'name': APP_NAME,
    'license': 'Nmap License (https://nmap.org/book/man-legal.html)',
    'url': APP_WEB_SITE,
    'download_url': APP_DOWNLOAD_SITE,
    'author': 'Nmap Project',
    'maintainer': 'Nmap Project',
    'description': "%s frontend and results viewer" % NMAP_DISPLAY_NAME,
    'long_description': "%s is an %s frontend that is really useful"
        "for advanced users and easy to be used by newbies." % (
            APP_DISPLAY_NAME, NMAP_DISPLAY_NAME),
    'version': VERSION,
    'scripts': [APP_NAME],
    'packages': ['zenmapCore', 'zenmapGUI', 'zenmapGUI.higwidgets',
                 'radialnet', 'radialnet.bestwidgets', 'radialnet.core',
                 'radialnet.gui', 'radialnet.util'],
    'data_files': data_files,
}

# All of the arguments to setup are collected in setup_args.
setup_args = {}
setup_args.update(COMMON_SETUP_ARGS)

if 'py2exe' in sys.argv:
    # Windows- and py2exe-specific args.
    import py2exe

    WINDOWS_SETUP_ARGS = {
        'zipfile': 'py2exe/library.zip',
        'name': APP_NAME,
        'windows': [{
            "script": APP_NAME,
            "icon_resources": [(1, "install_scripts/windows/nmap-eye.ico")]
            }],
        # On Windows we build Ndiff here in Zenmap's setup.py so the two Python
        # programs will share a common runtime.
        'py_modules': ["ndiff"],
        # override the package search path to let Ndiff be found
        'package_dir': {
            'zenmapCore': 'zenmapCore',
            'zenmapGUI': 'zenmapGUI',
            'radialnet': 'radialnet',
            '': '../ndiff'
            },
        'console': [{
            "script": "../ndiff/scripts/ndiff",
            "description": "Nmap scan comparison tool"
            }],
        'options': {"py2exe": {
            "compressed": 1,
            "optimize": 2,
            "packages": ["encodings"],
            "includes": ["pango", "atk", "gobject", "gio", "pickle", "bz2",
                "encodings", "encodings.*", "cairo", "pangocairo"],
            "dll_excludes": ["USP10.dll", "NSI.dll", "MSIMG32.dll",
                "DNSAPI.dll"]
            }
        }
    }

    setup_args.update(WINDOWS_SETUP_ARGS)
elif 'py2app' in sys.argv:
    # Args for Mac OS X and py2app.
    import py2app
    import shutil

    # py2app requires a ".py" suffix.
    extended_app_name = APP_NAME + ".py"
    shutil.copyfile(APP_NAME, extended_app_name)

    MACOSX_SETUP_ARGS = {
        'app': [extended_app_name],
        'options': {"py2app": {
            "packages": ["gio", "gobject", "gtk", "cairo"],
            "includes": ["atk", "pango", "pangocairo"],
            "argv_emulation": True,
            "compressed": True,
            "plist": "install_scripts/macosx/Info.plist",
            "iconfile": "install_scripts/macosx/zenmap.icns"
        }}
    }

    setup_args.update(MACOSX_SETUP_ARGS)
elif 'vanilla' in sys.argv:
    # Don't create uninstaller, don't fix paths. Used for bundling on OS X
    sys.argv.remove('vanilla')
else:
    # Default args.
    DEFAULT_SETUP_ARGS = {
        'cmdclass': {'install': my_install, 'uninstall': my_uninstall},
    }
    setup_args.update(DEFAULT_SETUP_ARGS)

    data_files = [
        (desktop_dir, glob('install_scripts/unix/*.desktop')),
        (data_dir, ['install_scripts/unix/su-to-zenmap.sh'])
    ]
    setup_args["data_files"].extend(data_files)

setup(**setup_args)
