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

import os
import os.path
import re
import io
import unittest

from glob import glob

from zenmapCore.Name import APP_NAME
from zenmapCore.NmapOptions import NmapOptions
from zenmapCore.NmapParser import NmapParser
from zenmapCore.UmitLogging import log


class HostSearch(object):
    @staticmethod
    def match_target(host, name):
        name = name.lower()
        mac = host.get_mac()
        ip = host.get_ip()
        ipv6 = host.get_ipv6()

        if mac and 'addr' in mac:
            if name in mac['addr'].lower():
                return True
        if ip and 'addr' in ip:
            if name in ip['addr'].lower():
                return True
        if ipv6 and 'addr' in ipv6:
            if name in ipv6['addr'].lower():
                return True

        if HostSearch.match_hostname(host, name):
            return True
        return False

    @staticmethod
    def match_hostname(host, hostname):
        hostname = hostname.lower()
        hostnames = host.get_hostnames()
        for hn in hostnames:
            if hostname in hn['hostname'].lower():
                return True
        else:
            return False

    @staticmethod
    def match_service(host, service):
        for port in host.get_ports():
            # We concatenate all useful fields and add them to the list
            if port['port_state'] not in ['open', 'open|filtered']:
                continue
            version = " ".join(
                    port.get(x, "") for x in (
                        "service_name",
                        "service_product",
                        "service_version",
                        "service_extrainfo"
                        )
                    )

            if service in version.lower():
                return True
        else:
            return False

    @staticmethod
    def match_os(host, os):
        os = os.lower()

        osmatches = host.get_osmatches()

        for osmatch in osmatches:
            os_str = osmatch['name'].lower()
            for osclass in osmatch['osclasses']:
                os_str += " " + osclass['vendor'].lower() + " " +\
                          osclass['osfamily'].lower() + " " +\
                          osclass['type'].lower()
            if os in os_str:
                return True

        return False

    @staticmethod
    def match_port(host_ports, port, port_state):
        # Check if the port is parsable, if not return False silently
        if re.match(r"^\d+$", port) is None:
            return False

        for hp in host_ports:
            if hp['portid'] == port and hp['port_state'] == port_state:
                return True

        return False


class SearchResult(object):
    def __init__(self):
        """This constructor is always called by SearchResult subclasses."""
        pass

    def search(self, **kargs):
        """Performs a search on each parsed scan. Since the 'and' operator is
        implicit, the search fails as soon as one of the tests fails. The
        kargs argument is a map having operators as keys and argument lists as
        values."""

        for scan_result in self.get_scan_results():
            self.parsed_scan = scan_result

            # Test each given operator against the current parsed result
            for operator, args in kargs.items():
                if not self._match_all_args(operator, args):
                    # No match => we discard this scan_result
                    break
            else:
                # All operator-matching functions have returned True, so this
                # scan_result satisfies all conditions
                yield self.parsed_scan

    def _match_all_args(self, operator, args):
        """A helper function that calls the matching function for the given
        operator and each of its arguments."""
        for arg in args:
            positive = True
            if arg != "" and arg[0] == "!":
                arg = arg[1:]
                positive = False
            if positive != self.__getattribute__("match_%s" % operator)(arg):
                # No match for this operator
                return False
        else:
            # All arguments for this operator produced a match
            return True

    def get_scan_results(self):
        # To be implemented by classes that are going to inherit this one
        pass

    def basic_match(self, keyword, property):
        if keyword == "*" or keyword == "":
            return True

        return keyword.lower() in str(
                self.parsed_scan.__getattribute__(property)).lower()

    def match_keyword(self, keyword):
        log.debug("Match keyword: %s" % keyword)

        return self.basic_match(keyword, "nmap_output") or \
               self.match_profile(keyword) or \
               self.match_target(keyword)

    def match_profile(self, profile):
        log.debug("Match profile: %s" % profile)
        log.debug("Comparing: %s == %s ??" % (
            str(self.parsed_scan.profile_name).lower(),
            "*%s*" % profile.lower()))
        return (profile == "*" or profile == "" or
                profile.lower() in str(self.parsed_scan.profile_name).lower())

    def match_option(self, option):
        log.debug("Match option: %s" % option)

        if option == "*" or option == "":
            return True

        ops = NmapOptions()
        ops.parse_string(self.parsed_scan.get_nmap_command())

        if "(" in option and ")" in option:
            # The syntax allows matching option arguments as
            # "opt:option_name(value)".  Since we've received only the
            # "option_name(value)" part, we need to parse it.
            optname = option[:option.find("(")]
            optval = option[option.find("(") + 1:option.find(")")]

            val = ops["--" + optname]
            if val is None:
                val = ops["-" + optname]
            if val is None:
                return False
            return str(val) == optval or str(val) == optval
        else:
            return (ops["--" + option] is not None or
                    ops["-" + option] is not None)

    def match_date(self, date_arg, operator="date"):
        # The parsed scan's get_date() returns a time.struct_time, so we
        # need to convert it to a date object
        from datetime import date, datetime
        scd = self.parsed_scan.get_date()
        scan_date = date(scd.tm_year, scd.tm_mon, scd.tm_mday)

        # Check if we have any fuzzy operators ("~") in our string
        fuzz = 0
        if "~" in date_arg:
            # Count 'em, and strip 'em
            fuzz = date_arg.count("~")
            date_arg = date_arg.replace("~", "")

        if re.match(r"\d\d\d\d-\d\d-\d\d$", date_arg) is not None:
            year, month, day = date_arg.split("-")
            parsed_date = date(int(year), int(month), int(day))
        elif re.match(r"[-|\+]\d+$", date_arg):
            # We need to convert from the "-n" format (n days ago) to a date
            # object (I found this in some old code, don't ask :) )
            parsed_date = date.fromordinal(
                    date.today().toordinal() + int(date_arg))
        else:
            # Fail silently
            return False

        # Now that we have both the scan date and the user date converted to
        # date objects, we need to make a comparison based on the operator
        # (date, after, before).
        if operator == "date":
            return abs((scan_date - parsed_date).days) <= fuzz
        # We ignore fuzziness for after: and before:
        elif operator == "after":
            return (scan_date - parsed_date).days >= 0
        elif operator == "before":
            return (parsed_date - scan_date).days >= 0

    def match_after(self, date_arg):
        return self.match_date(date_arg, operator="after")

    def match_before(self, date_arg):
        return self.match_date(date_arg, operator="before")

    def match_target(self, target):
        log.debug("Match target: %s" % target)

        for spec in self.parsed_scan.get_targets():
            if target in spec:
                return True
        else:
            # We search the (rDNS) hostnames list
            for host in self.parsed_scan.get_hosts():
                if HostSearch.match_target(host, target):
                    return True
        return False

    def match_os(self, os):
        # If you have lots of big scans in your DB (with a lot of hosts
        # scanned), you're probably better off using the keyword (freetext)
        # search. Keyword search just greps through the nmap output, while this
        # function iterates through all parsed OS-related values for every host
        # in every scan!
        hosts = self.parsed_scan.get_hosts()
        for host in hosts:
            if HostSearch.match_os(host, os):
                return True
        return False

    def match_scanned(self, ports):
        if ports == "":
            return True

        # Transform a comma-delimited string containing ports into a list
        ports = [not_empty for not_empty in ports.split(",") if not_empty]

        # Check if they're parsable, if not return False silently
        for port in ports:
            if re.match(r"^\d+$", port) is None:
                return False

        # Make a list of all scanned ports
        services = []
        for scaninfo in self.parsed_scan.get_scaninfo():
            services.append(scaninfo["services"].split(","))

        # These two loops iterate over search ports and over scanned ports. As
        # soon as the search finds a given port among the scanned ports, it
        # breaks from the services loop and continues with the next port in the
        # ports list. If a port isn't found in the services list, the function
        # immediately returns False.
        for port in ports:
            for service in services:
                if "-" in service and \
                   int(port) >= int(service.split("-")[0]) and \
                   int(port) <= int(service.split("-")[1]):
                    # Port range, and our port was inside
                    break
                elif port == service:
                    break
            else:
                return False
        else:
            # The ports loop finished for all ports, which means the search was
            # successful.
            return True

    def match_port(self, ports, port_state):
        log.debug("Match port:%s" % ports)

        # Transform a comma-delimited string containing ports into a list
        ports = [not_empty for not_empty in ports.split(",") if not_empty]

        for host in self.parsed_scan.get_hosts():
            for port in ports:
                if not HostSearch.match_port(
                        host.get_ports(), port, port_state):
                    break
            else:
                return True
        else:
            return False

    def match_open(self, port):
        return self.match_port(port, "open")

    def match_filtered(self, port):
        return self.match_port(port, "filtered")

    def match_closed(self, port):
        return self.match_port(port, "closed")

    def match_unfiltered(self, port):
        return self.match_port(port, "unfiltered")

    def match_open_filtered(self, port):
        return self.match_port(port, "open|filtered")

    def match_closed_filtered(self, port):
        return self.match_port(port, "closed|filtered")

    def match_service(self, sversion):
        if sversion == "" or sversion == "*":
            return True

        for host in self.parsed_scan.get_hosts():
            if HostSearch.match_service(host, sversion):
                return True
        else:
            return False

    def match_in_route(self, host):
        if host == "" or host == "*":
            return True
        host = host.lower()

        # Since the parser doesn't parse traceroute output, we need to cheat
        # and look the host up in the Nmap output, in the Traceroute section of
        # the scan.
        nmap_out = self.parsed_scan.get_nmap_output()
        tr_pos = 0
        traceroutes = []        # A scan holds one traceroute section per host
        while tr_pos != -1:
            # Find the beginning and the end of the traceroute section, and
            # append the substring to the traceroutes list
            tr_pos = nmap_out.find("TRACEROUTE", tr_pos + 1)
            tr_end_pos = nmap_out.find("\n\n", tr_pos)
            if tr_pos != -1:
                traceroutes.append(nmap_out[tr_pos:tr_end_pos])

        for tr in traceroutes:
            if host in tr.lower():
                return True
        else:
            return False


class SearchDummy(SearchResult):
    """A dummy search class that returns no results. It is used as a
    placeholder when SearchDB can't be used."""
    def get_scan_results(self):
        return []


class SearchDB(SearchResult, object):
    def __init__(self):
        SearchResult.__init__(self)
        log.debug(">>> Getting scan results stored in data base")
        self.scan_results = []
        from zenmapCore.UmitDB import UmitDB
        u = UmitDB()

        for scan in u.get_scans():
            log.debug(">>> Retrieving result of scans_id %s" % scan.scans_id)
            log.debug(">>> Nmap xml output: %s" % scan.nmap_xml_output)

            try:
                buffer = io.StringIO(scan.nmap_xml_output)
                parsed = NmapParser()
                parsed.parse(buffer)
                buffer.close()
            except Exception as e:
                log.warning(">>> Error loading scan with ID %u from database: "
                        "%s" % (scan.scans_id, str(e)))
            else:
                self.scan_results.append(parsed)

    def get_scan_results(self):
        return self.scan_results


class SearchDir(SearchResult, object):
    def __init__(self, search_directory, file_extensions=["usr"]):
        SearchResult.__init__(self)
        log.debug(">>> SearchDir initialized")
        self.search_directory = search_directory

        if isinstance(file_extensions, str):
            self.file_extensions = file_extensions.split(";")
        elif isinstance(file_extensions, list):
            self.file_extensions = file_extensions
        else:
            raise Exception(
                    "Wrong file extension format! '%s'" % file_extensions)

        log.debug(">>> Getting directory's scan results")
        self.scan_results = []
        files = []
        for ext in self.file_extensions:
            files += glob(os.path.join(self.search_directory, "*.%s" % ext))

        log.debug(">>> Scan results at selected directory: %s" % files)
        for scan_file in files:
            log.debug(">>> Retrieving scan result %s" % scan_file)
            if os.access(scan_file, os.R_OK) and os.path.isfile(scan_file):

                try:
                    parsed = NmapParser()
                    parsed.parse_file(scan_file)
                except Exception:
                    pass
                else:
                    self.scan_results.append(parsed)

    def get_scan_results(self):
        return self.scan_results


class SearchResultTest(unittest.TestCase):
    class SearchClass(SearchResult):
        """This class is for use by the unit testing code"""
        def __init__(self, filenames):
            SearchResult.__init__(self)
            self.scan_results = []
            for filename in filenames:
                scan = NmapParser()
                scan.parse_file(filename)
                self.scan_results.append(scan)

        def get_scan_results(self):
            return self.scan_results

    def setUp(self):
        files = ["test/xml_test%d.xml" % no for no in range(1, 13)]
        self.search_result = self.SearchClass(files)

    def _test_skeleton(self, key, val):
        results = []
        search = {key: [val]}
        for scan in self.search_result.search(**search):
            results.append(scan)
        return len(results)

    def test_match_os(self):
        """Test that checks if the match_os predicate works"""
        assert(self._test_skeleton('os', 'linux') == 2)

    def test_match_target(self):
        """Test that checks if the match_target predicate works"""
        assert(self._test_skeleton('target', 'localhost') == 4)

    def test_match_port_open(self):
        """Test that checks if the match_open predicate works"""
        assert(self._test_skeleton('open', '22') == 7)

    def test_match_port_closed(self):
        """Test that checks if the match_closed predicate works"""
        assert(self._test_skeleton('open', '22') == 7)
        assert(self._test_skeleton('closed', '22') == 9)

    def test_match_service(self):
        """Test that checks if the match_service predicate works"""
        assert(self._test_skeleton('service', 'apache') == 9)
        assert(self._test_skeleton('service', 'openssh') == 7)

    def test_match_service_version(self):
        """Test that checks if the match_service predicate works when """
        """checking version"""
        assert(self._test_skeleton('service', '2.0.52') == 7)


if __name__ == "__main__":
    unittest.main()
