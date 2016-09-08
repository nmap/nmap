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

import os
import unittest
import zenmapCore
import zenmapCore.NmapParser
from zenmapGUI.SearchGUI import SearchParser
from SearchResult import HostSearch


class NetworkInventory(object):
    """This class acts as a container for aggregated scans. It is also
    responsible for opening/saving the aggregation from/to persistent
    storage."""
    def __init__(self, filename=None):
        # A list of all scans that make up this inventory
        self.scans = []

        # A dictionary mapping parsed scans to filenames they were loaded from
        self.filenames = {}

        # A dictionary mapping IP addresses into HostInfo objects
        self.hosts = {}

        if filename is not None:
            self.open_from_file(filename)

    def add_scan(self, scan, filename=None):
        """Adds a scan to the list of scans. The object passed as an argument
        should be a parsed nmap result."""
        from time import localtime

        for host in scan.get_hosts():
            addr = ""
            if host.ipv6 is not None:
                # This is an IPv6 host, so we add the IPv6 address to the map
                addr = host.ipv6["addr"]
            elif host.ip is not None:
                # IPv4
                addr = host.ip["addr"]

            if addr not in self.hosts:
                # Add this host to the hosts dictionary, mapped by IP address
                self.hosts[addr] = host.make_clone()
            else:
                # This host is already present in the host list, so we need to
                # update its info with the info held in the current host object
                old_host = self.hosts[addr]
                # We need to find old_host's scan date
                old_date = localtime(0)
                for old_scan in self.scans:
                    if old_host in old_scan.get_hosts():
                        old_date = old_scan.get_date()
                new_date = scan.get_date()
                self._update_host_info(
                        old_host, host, old_date, new_date, scan)

        self.scans.append(scan)

        if filename is not None:
            basename = os.path.basename(filename)

            if basename in self.filenames.values():
                # We need to generate a new filename, since this basename
                # already exists
                base = basename
                ext = "xml"
                try:
                    base, ext = basename.rsplit(".", 1)
                except ValueError:
                    pass

                counter = 2
                while basename in self.filenames.values():
                    basename = "%s %s.%s" % (base, counter, ext)
                    counter += 1

            self.filenames[scan] = basename

    def remove_scan(self, scan):
        """Removes a scan and any host information it contained from the
        inventory."""
        # Note: If a scan is passed in that isn't in the inventory then this
        # method will throw a ValueError Exception and will not finish
        # Remove the scan from our scan list
        self.scans.remove(scan)

        # Clear the host dictionary
        self.hosts = {}

        # Remember the scan list
        scans = self.scans

        # Empty it
        self.scans = []

        # Delete the filename entry, if any
        if scan in self.filenames:
            del self.filenames[scan]

        # For each scan in the remembered list, append it to the scan list and
        # update the host list accordingly
        for scan in scans:
            self.add_scan(scan)

    def _update_host_info(self, old_host, new_host,
            old_date, new_date, new_scan):
        """This function is called when a host needs to be added to the hosts
        dictionary, but another HostInfo object for that host already exists
        in the dictionary (from a previous scan). In that case, we need to
        update the original HostInfo object so that it holds information from
        both scans."""

        # Ports
        old_list = []
        old_list.extend(old_host.ports)
        for new_port in new_host.ports:
            # Check if new_port is already present in old_host's ports
            for old_port in old_host.ports:
                if (old_port["portid"] == new_port["portid"] and
                        old_port["protocol"] == new_port["protocol"]):
                    old_list.remove(old_port)
                    # We update old_host's port information to reflect the
                    # latest known port state
                    if old_date < new_date:
                        index = old_host.ports.index(old_port)
                        old_host.ports[index] = new_port
                    # Finished processing this new_port, we jump to the next
                    break
            else:
                # This new_port isn't present in old_host, so we simply append
                # it to old_host's port info
                old_host.ports.append(new_port)

        ports = new_scan.get_port_protocol_dict()

        #remove ports which are no longer up
        if old_date < new_date:
            for defunct_port in old_list:
                # Check if defunct_port is in ports
                # and that the protocol matches
                port_number = int(defunct_port['portid'])
                if port_number in ports:
                    if defunct_port['protocol'] in ports[port_number]:
                        old_host.ports.remove(defunct_port)

        # extraports, ipidsequence, state, tcpsequence, tcptssequence, uptime
        if old_date < new_date:
            old_host.extraports = new_host.extraports
            old_host.ipidsequence = new_host.ipidsequence
            old_host.state = new_host.state
            old_host.tcpsequence = new_host.tcpsequence
            old_host.tcptssequence = new_host.tcptssequence
            old_host.uptime = new_host.uptime

        # Comment
        if old_host.comment == "":
            old_host.comment = new_host.comment
        elif new_host.comment != "":
            old_host.comment = "%s\n\n%s" % (
                    old_host.comment, new_host.comment)

        # Hostnames
        # Replace old_host's hostname with new_host's if old_host has no
        # hostname or new_host's is newer.
        if len(new_host.hostnames) > 0 and \
           (len(old_host.hostnames) == 0 or old_date < new_date):
            old_host.hostnames = new_host.hostnames

        # MAC address
        # If there was no MAC address set in old_host, set it to whatever is in
        # new_host.mac. Do the same if both hosts have a MAC address set, but
        # new_host's address is newer.
        if (old_host.mac is None or
                (old_host.mac is not None and
                    new_host.mac is not None and
                    old_date < new_date)
                ):
            old_host.mac = new_host.mac

        # OS detection fields
        # Replace old_host's OS detection fields with new_host's if old_host
        # has no OS detection info or new_host's info is newer.
        if (len(new_host.osmatches) > 0 and
                (len(old_host.osmatches) == 0 or old_date < new_date)
                ):
            old_host.osmatches = new_host.osmatches
            old_host.ports_used = new_host.ports_used

        # Traceroute information
        if (len(new_host.trace) > 0 and
                (len(old_host.trace) == 0 or old_date < new_date)
                ):
            old_host.trace = new_host.trace

    def get_scans(self):
        return self.scans

    def get_hosts(self):
        return self.hosts.values()

    def get_hosts_up(self):
        return filter(lambda h: h.get_state() == 'up', self.hosts.values())

    def get_hosts_down(self):
        return filter(lambda h: h.get_state() == 'down', self.hosts.values())

    def open_from_file(self, path):
        """Loads a scan from the given file."""
        from zenmapCore.NmapParser import NmapParser

        parsed = NmapParser()
        parsed.parse_file(path)
        self.add_scan(parsed, path)

    def open_from_dir(self, path):
        """Loads all scans from the given directory into the network
        inventory."""
        from zenmapCore.NmapParser import NmapParser

        for filename in os.listdir(path):
            fullpath = os.path.join(path, filename)
            if os.path.isdir(fullpath):
                continue
            parsed = NmapParser()
            parsed.parse_file(fullpath)
            self.add_scan(parsed, filename=fullpath)

    def save_to_file(self, path, index, format="xml"):
        """Saves the scan with the given list index into a file with a given
        path. With format = "xml", saves Nmap XML; otherwise saves plain text
        output."""
        f = open(path, 'w')
        if format == "xml":
            self.get_scans()[index].write_xml(f)
            self.filenames[self.get_scans()[index]] = f
        else:
            self.get_scans()[index].write_text(f)
        f.close()

    def _generate_filenames(self, path):
        """Generates filenames for all scans that don't already have a
        filename."""
        # The directory must not contain filenames other than those in the
        # self.filenames dictionary
        for filename in os.listdir(path):
            if os.path.basename(filename) not in self.filenames.values():
                raise Exception("The destination directory contains a file"
                        "(%s) that's not a part of the current inventory."
                        "The inventory will not be saved." %
                        os.path.basename(filename))

        for scan in self.scans:
            if scan in self.filenames:
                # This scan already has a filename
                continue

            date = "%04d%02d%02d%02d%02d" % (scan.date[0], scan.date[1],
                    scan.date[2], scan.date[3], scan.date[4])
            filename = scan.get_scan_name()

            # Prepend the date
            filename = "%s %s" % (date, filename)

            # Sanitize the filename
            for char in ["\"", "'", "/", "\\", "?", "*", ":", ";"]:
                if char in filename:
                    filename = filename.replace(char, "_")

            # Filename length check
            # https://en.wikipedia.org/wiki/Comparison_of_file_systems#Limits
            if len(filename) > 250:
                filename = filename[:250]

            # TODO: Filename security checks?

            # Try to open the file in append mode. If file.tell() returns a
            # greater-than-zero value, this means that the file already exists
            # and has some data in it, so we choose another filename until we
            # successfully open a zero-length file.
            filename_full = filename + ".xml"
            counter = 2
            while filename_full in self.filenames.values():
                # There's already a scan with this filename, so we generate a
                # new name by appending the counter value before the file
                # extension.
                filename_full = "%s %s.xml" % (filename, str(counter))
                counter += 1

            # Add the filename to the list of saved filenames
            self.filenames[scan] = filename_full

    def save_to_dir(self, path):
        """Saves all scans in the inventory into a given directory and returns
        a list of (full-path) filenames that were used to save the scans."""
        self._generate_filenames(path)

        for scan, filename in self.filenames.iteritems():
            f = open(os.path.join(path, filename), "w")
            scan.write_xml(f)
            f.close()

        return self.filenames.values()

    def open_from_db(self, id):
        pass

    def save_to_db(self):
        # For now, this saves each scan making up the inventory separately in
        # the database.
        from time import time
        from cStringIO import StringIO
        from zenmapCore.UmitDB import Scans

        for parsed in self.get_scans():
            f = StringIO()
            parsed.write_xml(f)

            scan = Scans(scan_name=parsed.scan_name,
                         nmap_xml_output=f.getvalue(),
                         date=time())


class FilteredNetworkInventory(NetworkInventory):
    def __init__(self, filename=None):
        NetworkInventory.__init__(self, filename)

        # A dictionary listing host filtering criteria
        self.search_dict = {}
        self.filtered_hosts = []
        search_keywords = dict()
        search_keywords["target"] = "target"
        search_keywords["t"] = "target"
        search_keywords["inroute"] = "in_route"
        search_keywords["ir"] = "in_route"
        search_keywords["hostname"] = "hostname"
        search_keywords["service"] = "service"
        search_keywords["s"] = "service"
        search_keywords["os"] = "os"
        search_keywords["open"] = "open"
        search_keywords["op"] = "open"
        search_keywords["closed"] = "closed"
        search_keywords["cp"] = "closed"
        search_keywords["filtered"] = "filtered"
        search_keywords["fp"] = "filtered"
        search_keywords["unfiltered"] = "unfiltered"
        search_keywords["ufp"] = "unfiltered"
        search_keywords["open|filtered"] = "open_filtered"
        search_keywords["ofp"] = "open_filtered"
        search_keywords["closed|filtered"] = "closed_filtered"
        search_keywords["cfp"] = "closed_filtered"
        self.search_parser = SearchParser(self, search_keywords)

    # FIXME: This method doesn't do anything.  We just need to support
    # the type of interface that SearchParser expects in order to use it.
    # Perhaps, we will eventually refactor the SearchParser a little bit
    # more?
    def init_search_dirs(self, junk):
        pass

    def get_hosts(self):
        if len(self.search_dict) > 0:
            return self.filtered_hosts
        else:
            return NetworkInventory.get_hosts(self)

    def get_hosts_up(self):
        if len(self.search_dict) > 0:
            return filter(lambda h: h.get_state() == 'up',
                    self.filtered_hosts)
        else:
            return NetworkInventory.get_hosts_up(self)

    def get_hosts_down(self):
        if len(self.search_dict) > 0:
            return filter(lambda h: h.get_state() == 'down',
                    self.filtered_hosts)
        else:
            return NetworkInventory.get_hosts_down(self)

    def get_total_host_count(self):
        return len(self.hosts)

    def _match_all_args(self, host, operator, args):
        """A helper function that calls the matching function for the given
        operator and each of its arguments."""
        for arg in args:
            positive = True
            if arg != "" and arg[0] == "!":
                arg = arg[1:]
                positive = False
            if positive != self.__getattribute__(
                    "match_%s" % operator)(host, arg):
                # No match for this operator
                return False
        else:
            # if the operator is not supported, pretend its true
            # All arguments for this operator produced a match
            return True

    def get_host_count(self):
        return len(self.network_inventory.hosts)

    def match_keyword(self, host, keyword):
        return (self.match_os(host, keyword) or
                self.match_target(host, keyword) or
                self.match_service(host, keyword))

    def match_target(self, host, name):
        return HostSearch.match_target(host, name)

    def match_in_route(self, host, hop):
        hops = host.get_trace().get('hops', [])
        return hop in hops

    def match_hostname(self, host, hostname):
        return HostSearch.match_hostname(host, hostname)

    def match_service(self, host, service):
        return HostSearch.match_service(host, service)

    def match_os(self, host, os):
        return HostSearch.match_os(host, os)

    def match_open(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "open")

    def match_closed(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "closed")

    def match_filtered(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "filtered")

    def match_unfiltered(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "unfiltered")

    def match_open_filtered(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "open|filtered")

    def match_closed_filtered(self, host, portno):
        host_ports = host.get_ports()
        return HostSearch.match_port(host_ports, portno, "closed|filtered")

    def apply_filter(self, filter_text):
        self.filter_text = filter_text.lower()
        self.search_parser.update(self.filter_text)
        self.filtered_hosts = []
        for hostname, host in self.hosts.iteritems():
            # For each host in this scan
            # Test each given operator against the current host
            for operator, args in self.search_dict.iteritems():
                if not self._match_all_args(host, operator, args):
                    # No match => we discard this scan_result
                    break
            else:
                # All operator-matching functions have returned True, so this
                # host satisfies all conditions
                self.filtered_hosts.append(host)


class NetworkInventoryTest(unittest.TestCase):
    def test_no_external_modification(self):
        """Test that HostInfo objects passed into the inventory are not
        modified during aggregation."""
        scan_1 = zenmapCore.NmapParser.ParserBasics()
        host_a = zenmapCore.NmapParser.HostInfo()
        host_a.hostnames = ["a"]
        host_a.set_state('up')
        scan_1.start = "1000000000"
        scan_1.nmap["hosts"] = [host_a]

        scan_2 = zenmapCore.NmapParser.ParserBasics()
        host_b = zenmapCore.NmapParser.HostInfo()
        host_b.hostnames = ["b"]
        host_b.set_state('up')
        scan_2.start = "1000000001"
        scan_2.nmap["hosts"] = [host_b]

        inv = NetworkInventory()
        inv.add_scan(scan_1)
        inv.add_scan(scan_2)

        self.assertEqual(host_a.hostnames, ["a"])
        self.assertEqual(host_b.hostnames, ["b"])
        self.assertEqual(scan_1.nmap["hosts"], [host_a])
        self.assertEqual(scan_2.nmap["hosts"], [host_b])
        self.assertEqual(inv.get_hosts_up()[0].hostnames, ["b"])

    def test_cancel_and_remove_scan(self):
        """Test that canceling and removing a scan does not blow away the
        inventory hosts"""
        added_ips = ['10.0.0.1', '10.0.0.2']
        removed_ips = ['10.0.0.3']
        scan_1 = zenmapCore.NmapParser.ParserBasics()
        host_a = zenmapCore.NmapParser.HostInfo()
        host_a.hostnames = ["a"]
        host_a.set_ip({'addr': added_ips[0]})
        scan_1.start = "1000000000"
        scan_1.nmap["hosts"] = [host_a]

        scan_2 = zenmapCore.NmapParser.ParserBasics()
        host_b = zenmapCore.NmapParser.HostInfo()
        host_b.hostnames = ["b"]
        host_b.set_ip({'addr': added_ips[1]})
        scan_2.start = "1000000001"
        scan_2.nmap["hosts"] = [host_b]

        scan_3 = zenmapCore.NmapParser.ParserBasics()
        host_c = zenmapCore.NmapParser.HostInfo()
        host_c.hostnames = ["b"]
        host_c.set_ip({'addr': removed_ips[0]})
        scan_3.start = "1000000001"
        scan_3.nmap["hosts"] = [host_c]

        inv = NetworkInventory()
        inv.add_scan(scan_1)
        inv.add_scan(scan_2)
        try:
            inv.remove_scan(scan_3)
        except:
            pass
        self.assertEqual(added_ips, inv.hosts.keys())
        self.assertEqual(host_a.hostnames, ["a"])
        self.assertEqual(host_b.hostnames, ["b"])


class FilteredNetworkInventoryTest(unittest.TestCase):
    def test_filter(self):
        """Test that the filter still works after moving code to the """
        """HostSearch class"""
        from zenmapCore.NmapParser import NmapParser
        inv = FilteredNetworkInventory()
        scan = NmapParser()
        scan.parse_file("test/xml_test9.xml")
        filter_text = "open:22 os:linux service:openssh"
        inv.add_scan(scan)
        inv.apply_filter(filter_text)
        assert(len(inv.get_hosts()) == 2)


class PortChangeTest(unittest.TestCase):
    def test_port(self):
        """Verify that the port status (open/filtered/closed) is displayed
        correctly when the port status changes in newer scans"""
        from zenmapCore.NmapParser import NmapParser
        inv = NetworkInventory()
        scan1 = NmapParser()
        scan1.parse_file("test/xml_test13.xml")
        inv.add_scan(scan1)
        scan2 = NmapParser()
        scan2.parse_file("test/xml_test14.xml")
        inv.add_scan(scan2)
        assert(len(inv.get_hosts()[0].ports) == 2)
        scan3 = NmapParser()
        scan3.parse_file("test/xml_test15.xml")
        inv.add_scan(scan3)
        assert(len(inv.get_hosts()[0].ports) == 0)

        # Additional test case for when the two scans have port scan ranges
        # which do not overlap. Example nmap -F -sU versus
        # nmap -F scanme.nmap.org
        inv = NetworkInventory()
        scan4 = NmapParser()
        scan4.parse_file("test/xml_test16.xml")
        inv.add_scan(scan4)
        assert(len(inv.get_hosts()[0].ports) == 3)
        scan5 = NmapParser()
        scan5.parse_file("test/xml_test17.xml")
        inv.add_scan(scan5)
        assert(len(inv.get_hosts()[0].ports) == 7)

if __name__ == "__main__":
    unittest.main()
    if False:

        scan1 = NmapParser("/home/ndwi/scanz/neobee_1.xml")
        scan1.parse()
        scan2 = NmapParser("/home/ndwi/scanz/scanme_nmap_org.usr")
        scan2.parse()

        inventory1 = NetworkInventory()
        inventory1.add_scan(scan1)
        inventory1.add_scan(scan2)

        for host in inventory1.get_hosts():
            print "%s" % host.ip["addr"],
            #if len(host.hostnames) > 0:
            #    print "[%s]:" % host.hostnames[0]["hostname"]
            #else:
            #    print ":"
            #for port in host.ports:
            #    print "  %s: %s" % (port["portid"], port["port_state"])
            #print "  OS matches: %s" % host.osmatches
            #print "  Ports used: %s" % host.ports_used
            #print "  Trace: %s" % host.trace
            #if "hops" in host.trace:
            #    print "         (%d)" % len(host.trace["hops"])

        inventory1.remove_scan(scan2)
        print
        for host in inventory1.get_hosts():
            print "%s" % host.ip["addr"],

        inventory1.add_scan(scan2)
        print
        for host in inventory1.get_hosts():
            print "%s" % host.ip["addr"],

        dir = "/home/ndwi/scanz/top01"
        inventory1.save_to_dir(dir)

        inventory2 = NetworkInventory()
        inventory2.open_from_dir(dir)

        print
        for host in inventory2.get_hosts():
            print "%s" % host.ip["addr"],
