#!/usr/bin/env python

import errno
import sys
import os
import os.path
import re

import distutils.command
import distutils.command.install
import distutils.core
import distutils.cmd
import distutils.errors
from distutils.command.install import install

APP_NAME = "ndiff"

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
       
class null_command(distutils.cmd.Command):
    """This is a dummy distutils command that does nothing. We use it to
    replace the install_egg_info and avoid installing a .egg-info file, because
    there's no option to disable that."""
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        pass


class checked_install(distutils.command.install.install):
    """This is a wrapper around the install command that checks for an error
    caused by not having the python-dev package installed. By default,
    distutils gives a misleading error message: "invalid Python installation."
    """

    def finalize_options(self):
        try:
            distutils.command.install.install.finalize_options(self)
        except distutils.errors.DistutilsPlatformError, e:
            raise distutils.errors.DistutilsPlatformError(str(e) + """
Installing your distribution's python-dev package may solve this problem.""")

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


    def run(self):
        install.run(self)

# These below are from Zenmap. We're only using set_modules_path right now, but we might consider whether the others would be useful (or, if not, whether we should remove them from Zenmap).
#        self.set_perms()
        self.set_modules_path()
#        self.fix_paths()
#        self.create_uninstaller()
#        self.write_installed_files()


distutils.core.setup(name=u"ndiff", scripts=[u"scripts/ndiff"],
    py_modules=[u"ndiff"],
    data_files=[(u"share/man/man1", [u"docs/ndiff.1"])],
    cmdclass={"install_egg_info": null_command, "install": checked_install})
