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

import re

from types import StringTypes
from ConfigParser import DuplicateSectionError, NoSectionError, NoOptionError

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConfigParser import UmitConfigParser
import zenmapCore.I18N

# This is the global configuration parser object that represents the contents of
# zenmap.conf. It should be initialized once by the application. Most
# interaction with the global parser is done by other classes in this file, like
# SearchConfig, that wrap specific configuration sections.
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
        return config_parser.get(self.section_name, p_name, default)

    def _set_it(self, p_name, value):
        config_parser.set(self.section_name, p_name, value)

    def boolean_sanity(self, attr):
        if attr == True or \
           attr == "True" or \
           attr == "true" or \
           attr == "1":

            return 1

        return 0

    def get_directory(self):
        return self._get_it("directory", "")

    def set_directory(self, directory):
        self._set_it("directory", directory)

    def get_file_extension(self):
        return self._get_it("file_extension", "xml").split(";")

    def set_file_extension(self, file_extension):
        if type(file_extension) == type([]):
            self._set_it("file_extension", ";".join(file_extension))
        elif type(file_extension) in StringTypes:
            self._set_it("file_extension", file_extension)

    def get_save_time(self):
        return self._get_it("save_time", "60;days").split(";")

    def set_save_time(self, save_time):
        if type(save_time) == type([]):
            self._set_it("save_time", ";".join(save_time))
        elif type(save_time) in StringTypes:
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
        except:
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
    them found in a config file such as scan_profiles.usp. The methods therefore
    all take an argument that is the name of the profile to work on."""

    def __init__(self, user_profile = None, *args):
        UmitConfigParser.__init__(self, *args)

        if not user_profile:
            user_profile = Path.scan_profile

        fconf = open(user_profile, 'r')
        self.readfp(fconf, user_profile)

        fconf.close()
        del(fconf)

        self.attributes = {}

    def _get_it(self, profile, attribute):
        if self._verify_profile(profile):
            return self.get(profile, attribute)
        return ""

    def _set_it(self, profile, attribute, value=''):
        if self._verify_profile(profile):
            return self.set(profile, attribute, value)

    def add_profile(self, profile_name, **attributes):
        """Add a profile with the given name and attributes to the collection of
        profiles. If a profile with the same name exists, it is not overwritten,
        and the method returns immediately. The backing file for the profiles is
        automatically updated."""

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
        try: self.remove_section(profile_name)
        except: pass
        self.save_changes()

    def _verify_profile(self, profile_name):
        if profile_name not in self.sections():
            return False
        return True

class CommandProfile (Profile, object):
    """This class is a wrapper around Profile that provides accessors for the
    attributes of a profile: command and description"""
    def __init__(self, user_profile = None):
        Profile.__init__(self, user_profile)

    def get_command(self, profile):
        command_string = self._get_it(profile, 'command')
        # Old versions of Zenmap used to append "%s" to commands and use that to
        # substitute the target. Ignore it if present.
        if command_string.endswith("%s"):
            command_string = command_string[:-len("%s")]
        return command_string

    def get_description(self, profile):
        return self._get_it(profile, 'description')

    def set_command(self, profile, command=''):
        self._set_it(profile, 'command', command)

    def set_description(self, profile, description=''):
        self._set_it(profile, 'description', description)

    def get_profile(self, profile_name):
        return {'profile':profile_name, \
                'command':self.get_command(profile_name), \
                'description':self.get_description(profile_name)}


class NmapOutputHighlight(object):
    setts = ["bold", "italic", "underline", "text", "highlight", "regex"]

    def save_changes(self):
        config_parser.save_changes()

    def __get_it(self, p_name):
        property_name = "%s_highlight" % p_name

        try:
            return self.sanity_settings([config_parser.get(property_name,
                                                         prop,
                                                         True) \
                                         for prop in self.setts])
        except:
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

        [config_parser.set(property_name, self.setts[pos], settings[pos]) \
         for pos in xrange(len(settings))]

    def sanity_settings(self, settings):
        """This method tries to convert insane settings to sanity ones ;-)
        If user send a True, "True" or "true" value, for example, it tries to
        convert then to the integer 1.
        Same to False, "False", etc.

        Sequence: [bold, italic, underline, text, highlight, regex]
        """
        #log.debug(">>> Sanitize %s" % str(settings))

        settings[0] = self.boolean_sanity(settings[0])
        settings[1] = self.boolean_sanity(settings[1])
        settings[2] = self.boolean_sanity(settings[2])

        tuple_regex = "[\(\[]\s?(\d+)\s?,\s?(\d+)\s?,\s?(\d+)\s?[\)\]]"
        if isinstance(settings[3], basestring):
            settings[3] = [int(t) for t in re.findall(tuple_regex, settings[3])[0]]

        if isinstance(settings[4], basestring):
            settings[4]= [int(h) for h in re.findall(tuple_regex, settings[4])[0]]

        return settings

    def boolean_sanity(self, attr):
        if attr == True or attr == "True" or attr == "true" or attr == "1":
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
            config_parser.set("output_highlight", "enable_highlight", str(True))

        if enable == "False" or enable == "0" or enable == "":
            return False
        return True

    def set_enable(self, enable):
        if enable == False or enable == "0" or enable == None or enable == "":
            config_parser.set("output_highlight", "enable_highlight", str(False))
        else:
            config_parser.set("output_highlight", "enable_highlight", str(True))

    date = property(get_date, set_date)
    hostname = property(get_hostname, set_hostname)
    ip = property(get_ip, set_ip)
    port_list = property(get_port_list, set_port_list)
    open_port = property(get_open_port, set_open_port)
    closed_port = property(get_closed_port, set_closed_port)
    filtered_port = property(get_filtered_port, set_filtered_port)
    details = property(get_details, set_details)
    enable = property(get_enable, set_enable)

    # These settings are made when there is nothing set yet. They set the "factory" \
    # default to highlight colors
    default_highlights = {"date":{"bold":str(True),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[0, 0, 0],
                            "highlight":[65535, 65535, 65535],
                            "regex":"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\s.{1,4}"},
                          "hostname":{"bold":str(True),
                            "italic":str(True),
                            "underline":str(True),
                            "text":[0, 111, 65535],
                            "highlight":[65535, 65535, 65535],
                            "regex":"(\w{2,}://)*[\w-]{2,}\.[\w-]{2,}(\.[\w-]{2,})*(/[[\w-]{2,}]*)*"},
                          "ip":{"bold":str(True),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[0, 0, 0],
                            "highlight":[65535, 65535, 65535],
                            "regex":"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
                          "port_list":{"bold":str(True),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[0, 1272, 28362],
                            "highlight":[65535, 65535, 65535],
                            "regex":"PORT\s+STATE\s+SERVICE(\s+VERSION)?[^\n]*"},
                          "open_port":{"bold":str(True),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[0, 41036, 2396],
                            "highlight":[65535, 65535, 65535],
                            "regex":"\d{1,5}/.{1,5}\s+open\s+.*"},
                          "closed_port":{"bold":str(False),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[65535, 0, 0],
                            "highlight":[65535, 65535, 65535],
                            "regex":"\d{1,5}/.{1,5}\s+closed\s+.*"},
                          "filtered_port":{"bold":str(False),
                            "italic":str(False),
                            "underline":str(False),
                            "text":[38502, 39119, 0],
                            "highlight":[65535, 65535, 65535],
                            "regex":"\d{1,5}/.{1,5}\s+filtered\s+.*"},
                          "details":{"bold":str(True),
                            "italic":str(False),
                            "underline":str(True),
                            "text":[0, 0, 0],
                            "highlight":[65535, 65535, 65535],
                            "regex":"^(\w{2,}[\s]{,3}){,4}:"}}

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
        except (NoOptionError,NoSectionError):
            log.debug(">>> Using default \"%s\" for \"%s\"." % (default, p_name))
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
    ndiff_command_path = property(get_ndiff_command_path, set_ndiff_command_path)

# Exceptions
class ProfileNotFound:
    def __init__ (self, profile):
        self.profile = profile
    def __str__ (self):
        return "No profile named '"+self.profile+"' found!"

class ProfileCouldNotBeSaved:
    def __init__ (self, profile):
        self.profile = profile
    def __str__ (self):
        return "Profile named '"+self.profile+"' could not be saved!"
