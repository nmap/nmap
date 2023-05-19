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

import re

from configparser import DuplicateSectionError, NoSectionError, NoOptionError
from configparser import Error as ConfigParser_Error

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConfigParser import UmitConfigParser
import zenmapCore.I18N  # lgtm[py/unused-import]

# This is the global configuration parser object that represents the contents
# of zenmap.conf. It should be initialized once by the application. Most
# interaction with the global parser is done by other classes in this file,
# like SearchConfig, that wrap specific configuration sections.
config_parser = UmitConfigParser()

# Check if running on Maemo
MAEMO = False
try:
    import hildon
    MAEMO = True
except ImportError:
    pass


def is_maemo():
    return MAEMO


class SearchConfig(UmitConfigParser, object):
    section_name = "search"

    def __init__(self):
        if not config_parser.has_section(self.section_name):
            self.create_section()

    def save_changes(self):
        config_parser.save_changes()

    def create_section(self):
        config_parser.add_section(self.section_name)
        self.directory = ""
        self.file_extension = "xml"
        self.save_time = "60;days"
        self.store_results = True
        self.search_db = True

    def _get_it(self, p_name, default):
        return config_parser.get(self.section_name, p_name, fallback=default)

    def _set_it(self, p_name, value):
        config_parser.set(self.section_name, p_name, value)

    def boolean_sanity(self, attr):
        if attr is True or \
           attr == "True" or \
           attr == "true" or \
           attr == "1":
            return "True"
        return "False"

    def get_directory(self):
        return self._get_it("directory", "")

    def set_directory(self, directory):
        self._set_it("directory", directory)

    def get_file_extension(self):
        return self._get_it("file_extension", "xml").split(";")

    def set_file_extension(self, file_extension):
        if isinstance(file_extension, list):
            self._set_it("file_extension", ";".join(file_extension))
        elif isinstance(file_extension, str):
            self._set_it("file_extension", file_extension)

    def get_save_time(self):
        return self._get_it("save_time", "60;days").split(";")

    def set_save_time(self, save_time):
        if isinstance(save_time, list):
            self._set_it("save_time", ";".join(save_time))
        elif isinstance(save_time, str):
            self._set_it("save_time", save_time)

    def get_store_results(self):
        return self.boolean_sanity(self._get_it("store_results", True))

    def set_store_results(self, store_results):
        self._set_it("store_results", self.boolean_sanity(store_results))

    def get_search_db(self):
        return self.boolean_sanity(self._get_it("search_db", True))

    def set_search_db(self, search_db):
        self._set_it("search_db", self.boolean_sanity(search_db))

    def get_converted_save_time(self):
        try:
            return int(self.save_time[0]) * self.time_list[self.save_time[1]]
        except Exception:
            # If something goes wrong, return a save time of 60 days
            return 60 * 60 * 24 * 60

    def get_time_list(self):
        # Time as key, seconds a value
        return {"hours": 60 * 60,
                "days": 60 * 60 * 24,
                "weeks": 60 * 60 * 24 * 7,
                "months": 60 * 60 * 24 * 7 * 30,
                "years": 60 * 60 * 24 * 7 * 30 * 12,
                "minutes": 60,
                "seconds": 1}

    directory = property(get_directory, set_directory)
    file_extension = property(get_file_extension, set_file_extension)
    save_time = property(get_save_time, set_save_time)
    store_results = property(get_store_results, set_store_results)
    search_db = property(get_search_db, set_search_db)
    converted_save_time = property(get_converted_save_time)
    time_list = property(get_time_list)


class Profile(UmitConfigParser, object):
    """This class represents not just one profile, but a whole collection of
    them found in a config file such as scan_profiles.usp. The methods
    therefore all take an argument that is the name of the profile to work
    on."""

    def __init__(self, user_profile=None, *args):
        UmitConfigParser.__init__(self, *args)

        try:
            if not user_profile:
                user_profile = Path.scan_profile

            self.read(user_profile)
        except ConfigParser_Error as e:
            # No scan profiles found is not a reason to crash.
            self.add_profile(_("Profiles not found"),
                    command="nmap",
                    description=_("The {} file is missing or corrupted"
                        ).format(user_profile))

        self.attributes = {}

    def _get_it(self, profile, attribute):
        if self._verify_profile(profile):
            return self.get(profile, attribute)
        return ""

    def _set_it(self, profile, attribute, value=''):
        if self._verify_profile(profile):
            return self.set(profile, attribute, value)

    def add_profile(self, profile_name, **attributes):
        """Add a profile with the given name and attributes to the collection
        of profiles. If a profile with the same name exists, it is not
        overwritten, and the method returns immediately. The backing file for
        the profiles is automatically updated."""

        log.debug(">>> Add Profile '%s': %s" % (profile_name, attributes))

        try:
            self.add_section(profile_name)
        except DuplicateSectionError:
            return None

        # Set each of the attributes ("command", "description") in the
        # ConfigParser.
        for attr in attributes:
            self._set_it(profile_name, attr, attributes[attr])

        self.save_changes()

    def remove_profile(self, profile_name):
        try:
            self.remove_section(profile_name)
        except Exception:
            pass
        self.save_changes()

    def _verify_profile(self, profile_name):
        if profile_name not in self.sections():
            return False
        return True


class WindowConfig(UmitConfigParser, object):
    section_name = "window"

    default_x = 0
    default_y = 0
    default_width = -1
    default_height = 650

    def __init__(self):
        if not config_parser.has_section(self.section_name):
            self.create_section()

    def save_changes(self):
        config_parser.save_changes()

    def create_section(self):
        config_parser.add_section(self.section_name)
        self.x = self.default_x
        self.y = self.default_y
        self.width = self.default_width
        self.height = self.default_height

    def _get_it(self, p_name, default):
        return config_parser.get(self.section_name, p_name, fallback=default)

    def _set_it(self, p_name, value):
        config_parser.set(self.section_name, p_name, value)

    def get_x(self):
        try:
            value = int(self._get_it("x", self.default_x))
        except (ValueError, NoOptionError):
            value = self.default_x
        except TypeError as e:
            v = self._get_it("x", self.default_x)
            log.exception("Trouble parsing x value as int: %s",
                    repr(v), exc_info=e)
            value = self.default_x
        return value

    def set_x(self, x):
        self._set_it("x", "%d" % x)

    def get_y(self):
        try:
            value = int(self._get_it("y", self.default_y))
        except (ValueError, NoOptionError):
            value = self.default_y
        except TypeError as e:
            v = self._get_it("y", self.default_y)
            log.exception("Trouble parsing y value as int: %s",
                    repr(v), exc_info=e)
            value = self.default_y
        return value

    def set_y(self, y):
        self._set_it("y", "%d" % y)

    def get_width(self):
        try:
            value = int(self._get_it("width", self.default_width))
        except (ValueError, NoOptionError):
            value = self.default_width
        except TypeError as e:
            v = self._get_it("width", self.default_width)
            log.exception("Trouble parsing width value as int: %s",
                    repr(v), exc_info=e)
            value = self.default_width

        if not (value >= -1):
            value = self.default_width

        return value

    def set_width(self, width):
        self._set_it("width", "%d" % width)

    def get_height(self):
        try:
            value = int(self._get_it("height", self.default_height))
        except (ValueError, NoOptionError):
            value = self.default_height
        except TypeError as e:
            v = self._get_it("height", self.default_height)
            log.exception("Trouble parsing y value as int: %s",
                    repr(v), exc_info=e)
            value = self.default_height

        if not (value >= -1):
            value = self.default_height

        return value

    def set_height(self, height):
        self._set_it("height", "%d" % height)

    x = property(get_x, set_x)
    y = property(get_y, set_y)
    width = property(get_width, set_width)
    height = property(get_height, set_height)


class CommandProfile (Profile, object):
    """This class is a wrapper around Profile that provides accessors for the
    attributes of a profile: command and description"""
    def __init__(self, user_profile=None):
        Profile.__init__(self, user_profile)

    def get_command(self, profile):
        command_string = self._get_it(profile, 'command')
        # Corrupted config file can include multiple commands.
        # Take the first one.
        if isinstance(command_string, list):
            command_string = command_string[0]
        if not hasattr(command_string, "endswith"):
            return "nmap"
        # Old versions of Zenmap used to append "%s" to commands and use that
        # to substitute the target. Ignore it if present.
        if command_string.endswith("%s"):
            command_string = command_string[:-len("%s")]
        return command_string

    def get_description(self, profile):
        desc = self._get_it(profile, 'description')
        if isinstance(desc, list):
            desc = " ".join(desc)
        return desc

    def set_command(self, profile, command=''):
        self._set_it(profile, 'command', command)

    def set_description(self, profile, description=''):
        self._set_it(profile, 'description', description)

    def get_profile(self, profile_name):
        return {'profile': profile_name,
                'command': self.get_command(profile_name),
                'description': self.get_description(profile_name)}


class NmapOutputHighlight(object):
    setts = ["bold", "italic", "underline", "text", "highlight", "regex"]

    def save_changes(self):
        config_parser.save_changes()

    def __get_it(self, p_name):
        property_name = "%s_highlight" % p_name

        try:
            return self.sanity_settings([
                config_parser.get(
                    property_name, prop, raw=True) for prop in self.setts])
        except Exception:
            settings = []
            prop_settings = self.default_highlights[p_name]
            settings.append(prop_settings["bold"])
            settings.append(prop_settings["italic"])
            settings.append(prop_settings["underline"])
            settings.append(prop_settings["text"])
            settings.append(prop_settings["highlight"])
            settings.append(prop_settings["regex"])

            self.__set_it(p_name, settings)

            return settings

    def __set_it(self, property_name, settings):
        property_name = "%s_highlight" % property_name
        settings = self.sanity_settings(list(settings))

        for pos in range(len(settings)):
            config_parser.set(property_name, self.setts[pos], settings[pos])

    def sanity_settings(self, settings):
        """This method tries to convert insane settings to sanity ones ;-)
        If user send a True, "True" or "true" value, for example, it tries to
        convert then to the integer 1.
        Same to False, "False", etc.

        Sequence: [bold, italic, underline, text, highlight, regex]
        """
        # log.debug(">>> Sanitize %s" % str(settings))

        settings[0] = self.boolean_sanity(settings[0])
        settings[1] = self.boolean_sanity(settings[1])
        settings[2] = self.boolean_sanity(settings[2])

        tuple_regex = r"[\(\[]\s?(\d+)\s?,\s?(\d+)\s?,\s?(\d+)\s?[\)\]]"
        if isinstance(settings[3], str):
            settings[3] = [
                    int(t) for t in re.findall(tuple_regex, settings[3])[0]
                    ]

        if isinstance(settings[4], str):
            settings[4] = [
                    int(h) for h in re.findall(tuple_regex, settings[4])[0]
                    ]

        return settings

    def boolean_sanity(self, attr):
        if attr is True or attr == "True" or attr == "true" or attr == "1":
            return 1
        return 0

    def get_date(self):
        return self.__get_it("date")

    def set_date(self, settings):
        self.__set_it("date", settings)

    def get_hostname(self):
        return self.__get_it("hostname")

    def set_hostname(self, settings):
        self.__set_it("hostname", settings)

    def get_ip(self):
        return self.__get_it("ip")

    def set_ip(self, settings):
        self.__set_it("ip", settings)

    def get_port_list(self):
        return self.__get_it("port_list")

    def set_port_list(self, settings):
        self.__set_it("port_list", settings)

    def get_open_port(self):
        return self.__get_it("open_port")

    def set_open_port(self, settings):
        self.__set_it("open_port", settings)

    def get_closed_port(self):
        return self.__get_it("closed_port")

    def set_closed_port(self, settings):
        self.__set_it("closed_port", settings)

    def get_filtered_port(self):
        return self.__get_it("filtered_port")

    def set_filtered_port(self, settings):
        self.__set_it("filtered_port", settings)

    def get_details(self):
        return self.__get_it("details")

    def set_details(self, settings):
        self.__set_it("details", settings)

    def get_enable(self):
        enable = True
        try:
            enable = config_parser.get("output_highlight", "enable_highlight")
        except NoSectionError:
            config_parser.set(
                    "output_highlight", "enable_highlight", str(True))

        if enable == "False" or enable == "0" or enable == "":
            return False
        return True

    def set_enable(self, enable):
        if enable is False or enable == "0" or enable is None or enable == "":
            config_parser.set(
                    "output_highlight", "enable_highlight", str(False))
        else:
            config_parser.set(
                    "output_highlight", "enable_highlight", str(True))

    date = property(get_date, set_date)
    hostname = property(get_hostname, set_hostname)
    ip = property(get_ip, set_ip)
    port_list = property(get_port_list, set_port_list)
    open_port = property(get_open_port, set_open_port)
    closed_port = property(get_closed_port, set_closed_port)
    filtered_port = property(get_filtered_port, set_filtered_port)
    details = property(get_details, set_details)
    enable = property(get_enable, set_enable)

    # These settings are made when there is nothing set yet. They set the
    # "factory" default to highlight colors
    default_highlights = {
            "date": {
                "bold": str(True),
                "italic": str(False),
                "underline": str(False),
                "text": [0, 0, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\s.{1,4}"},
            "hostname": {
                "bold": str(True),
                "italic": str(True),
                "underline": str(True),
                "text": [0, 111, 65535],
                "highlight": [65535, 65535, 65535],
                "regex": r"(\w{2,}://)*[\w-]{2,}\.[\w-]{2,}"
                         r"(\.[\w-]{2,})*(/[[\w-]{2,}]*)*"},
            "ip": {
                "bold": str(True),
                "italic": str(False),
                "underline": str(False),
                "text": [0, 0, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
            "port_list": {
                "bold": str(True),
                "italic": str(False),
                "underline": str(False),
                "text": [0, 1272, 28362],
                "highlight": [65535, 65535, 65535],
                "regex": r"PORT\s+STATE\s+SERVICE(\s+VERSION)?[^\n]*"},
            "open_port": {
                "bold": str(True),
                "italic": str(False),
                "underline": str(False),
                "text": [0, 41036, 2396],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{1,5}/.{1,5}\s+open\s+.*"},
            "closed_port": {
                "bold": str(False),
                "italic": str(False),
                "underline": str(False),
                "text": [65535, 0, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{1,5}/.{1,5}\s+closed\s+.*"},
            "filtered_port": {
                "bold": str(False),
                "italic": str(False),
                "underline": str(False),
                "text": [38502, 39119, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{1,5}/.{1,5}\s+filtered\s+.*"},
            "details": {
                "bold": str(True),
                "italic": str(False),
                "underline": str(True),
                "text": [0, 0, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"^(\w{2,}[\s]{,3}){,4}:"}
            }


# Retrieve details from zenmap.conf regarding paths subsection
# (e.g. nmap_command_path) - jurand
class PathsConfig(object):
    section_name = "paths"

    # This accounts for missing entries conf file.
    # Defaults to "nmap" if these errors occur.
    # NoOptionError, NoSectionError
    def __get_it(self, p_name, default):
        try:
            return config_parser.get(self.section_name, p_name)
        except (NoOptionError, NoSectionError):
            log.debug(
                    ">>> Using default \"%s\" for \"%s\"." % (default, p_name))
            return default

    def __set_it(self, property_name, settings):
        config_parser.set(self.section_name, property_name, settings)

    def get_nmap_command_path(self):
        return self.__get_it("nmap_command_path", "nmap")

    def set_nmap_command_path(self, settings):
        self.__set_it("nmap_command_path", settings)

    def get_ndiff_command_path(self):
        return self.__get_it("ndiff_command_path", "ndiff")

    def set_ndiff_command_path(self, settings):
        self.__set_it("ndiff_command_path", settings)

    nmap_command_path = property(get_nmap_command_path, set_nmap_command_path)
    ndiff_command_path = property(
            get_ndiff_command_path, set_ndiff_command_path)


# Exceptions
class ProfileNotFound:
    def __init__(self, profile):
        self.profile = profile

    def __str__(self):
        return "No profile named '" + self.profile + "' found!"


class ProfileCouldNotBeSaved:
    def __init__(self, profile):
        self.profile = profile

    def __str__(self):
        return "Profile named '" + self.profile + "' could not be saved!"
