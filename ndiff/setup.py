#!/usr/bin/env python3

import errno
import sys
import os
import os.path
import re

from stat import ST_MODE

import setuptools.command.install
from setuptools import setup, Command
import logging

APP_NAME = "ndiff"
# The name of the file used to record the list of installed files, so that the
# uninstall command can remove them.
INSTALLED_FILES_NAME = "INSTALLED_FILES"


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
# setuptools subclasses

class null_command(Command):
    """This is a dummy setuptools command that does nothing. We use it to
    replace the install_egg_info and avoid installing a .egg-info file, because
    there's no option to disable that."""
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def get_outputs(self):
        return ()

    def run(self):
        pass


class checked_install(setuptools.command.install.install):

    def finalize_options(self):
        # Ubuntu's python2.6-2.6.4-0ubuntu3 package changes sys.prefix in
        # install.finalize_options when sys.prefix is "/usr/local" (our
        # default). Because we need the unchanged value later, remember it
        # here.
        self.saved_prefix = sys.prefix
        super().finalize_options()

    def set_modules_path(self):
        app_file_name = os.path.join(self.install_scripts, APP_NAME)
        # Find where the modules are installed. setuptools will put them in
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
        super().run()

# These below are from Zenmap. We're only using set_modules_path right now, but
# we might consider whether the others would be useful (or, if not, whether we
# should remove them from Zenmap).
#        self.set_perms()
        self.set_modules_path()
#        self.fix_paths()
        self.create_uninstaller()
        self.write_installed_files()

    def get_installed_files(self):
        """Return a list of installed files and directories, each prefixed with
        the installation root if given. The list of installed directories
        doesn't come from setuptools so it may be incomplete."""
        installed_files = self.get_outputs()
        for package in self.distribution.py_modules:
            dir = package.replace(".", "/")
            installed_files.append(os.path.join(self.install_lib, dir))
        installed_files.append(
                os.path.join(self.install_scripts, "uninstall_" + APP_NAME))
        return installed_files

    def create_uninstaller(self):
        uninstaller_filename = os.path.join(
                self.install_scripts, "uninstall_" + APP_NAME)

        uninstaller = """\
#!/usr/bin/env python
import errno, os, os.path, sys

print('Uninstall %(name)s')

answer = raw_input('Are you sure that you want to uninstall '
    '%(name)s (yes/no) ')

if answer != 'yes' and answer != 'y':
    print('Not uninstalling.')
    sys.exit(0)

""" % {'name': APP_NAME}

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
                    uninstaller += ("print('%s was not installed inside "
                        "the root %s; skipping.')\n" % (output, self.root))
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
    print("Removing '%s'." % file)
    try:
        os.remove(file)
    except OSError, e:
        print('  Error: %s.' % str(e), file=sys.stderr)
# Delete the directories. First reverse-sort the normalized paths by
# length so that child directories are deleted before their parents.
dirs = [os.path.normpath(dir) for dir in dirs]
dirs.sort(key = len, reverse = True)
for dir in dirs:
    try:
        print("Removing the directory '%s'." % dir)
        os.rmdir(dir)
    except OSError, e:
        if e.errno == errno.ENOTEMPTY:
            print("Directory '%s' not empty; not removing." % dir)
        else:
            print(str(e), file=sys.stderr)
"""

        uninstaller_file = open(uninstaller_filename, 'w')
        uninstaller_file.write(uninstaller)
        uninstaller_file.close()

        # Set exec bit for uninstaller
        mode = ((os.stat(uninstaller_filename)[ST_MODE]) | 0o555) & 0o7777
        os.chmod(uninstaller_filename, mode)

    def write_installed_files(self):
        """Write a list of installed files for use by the uninstall command.
        This is similar to what happens with the --record option except that it
        doesn't strip off the installation root, if any. File names containing
        newline characters are not handled."""
        if INSTALLED_FILES_NAME == self.record:
            logging.warning("warning: installation record is overwriting "
                "--record file '%s'." % self.record)
        with open(INSTALLED_FILES_NAME, "w") as f:
            for output in self.get_installed_files():
                assert "\n" not in output
                print(output, file=f)


class my_uninstall(Command):
    """A setuptools command that performs uninstallation. It reads the list of
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
        except IOError as e:
            if e.errno == errno.ENOENT:
                logging.error("Couldn't open the installation record '%s'. "
                        "Have you installed yet?", INSTALLED_FILES_NAME)
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
            logging.info("Removing '%s'.", file)
            try:
                if not self.dry_run:
                    os.remove(file)
            except OSError as e:
                logging.error(str(e))
        # Delete the directories. First reverse-sort the normalized paths by
        # length so that child directories are deleted before their parents.
        dirs = [os.path.normpath(dir) for dir in dirs]
        dirs.sort(key=len, reverse=True)
        for dir in dirs:
            try:
                logging.info("Removing the directory '%s'.", dir)
                if not self.dry_run:
                    os.rmdir(dir)
            except OSError as e:
                if e.errno == errno.ENOTEMPTY:
                    logging.info("Directory '%s' not empty; not removing.",
                            dir)
                else:
                    logging.error(str(e))


setup(name="ndiff", scripts=["scripts/ndiff"],
    py_modules=["ndiff"],
    data_files=[("share/man/man1", ["docs/ndiff.1"])],
    cmdclass={
        "install_egg_info": null_command,
        "install": checked_install,
        "uninstall": my_uninstall
        })
