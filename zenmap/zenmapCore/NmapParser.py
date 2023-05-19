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

import locale
import time
import socket
import copy

from io import StringIO

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

from xml.sax import make_parser
from xml.sax import SAXException
from xml.sax.handler import ContentHandler, EntityResolver
from xml.sax.saxutils import XMLGenerator
from xml.sax.xmlreader import AttributesImpl as Attributes

import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.NmapOptions import NmapOptions, join_quoted
from zenmapCore.StringPool import unique

# The version of the Nmap DTD this file understands and emits.
XML_OUTPUT_VERSION = "1.04"


class HostInfo(object):
    def __init__(self):
        self.comment = None
        self._tcpsequence = {}
        self._osmatches = []
        self._ports = []
        self._ports_used = []
        self._extraports = []
        self._uptime = {}
        self._hostnames = []
        self._tcptssequence = {}
        self._ipidsequence = {}
        self._ip = None
        self._ipv6 = None
        self._mac = None
        self._state = ''
        self._comment = ''
        self._trace = {}

    def make_clone(self):
        clone = HostInfo()
        clone.comment = self.comment
        clone._tcpsequence = copy.deepcopy(self._tcpsequence)
        clone._osmatches = copy.deepcopy(self._osmatches)
        clone._ports = copy.deepcopy(self._ports)
        clone._ports_used = self._ports_used
        clone._extraports = self._extraports
        clone._uptime = copy.deepcopy(self._uptime)
        clone._hostnames = copy.deepcopy(self._hostnames)
        clone._tcptssequence = copy.deepcopy(self._tcptssequence)
        clone._ipidsequence = copy.deepcopy(self._ipidsequence)
        clone._ip = copy.deepcopy(self._ip)
        clone._ipv6 = copy.deepcopy(self._ipv6)
        clone._mac = copy.deepcopy(self._mac)
        clone._state = self._state
        clone._comment = self._comment
        clone._trace = copy.deepcopy(self._trace)

        return clone

    # tcpsequence is a dict of the form
    # {'index': u'203',
    #  'values': u'3637785D,35B440D1,35E9FC3B,3640DB42,355F5931,3601AE14',
    #  'difficulty': u'Good luck!'}
    def set_tcpsequence(self, sequence):
        self._tcpsequence = sequence

    def get_tcpsequence(self):
        if self._tcpsequence:
            return self._tcpsequence
        return {}

    # tcptssequence is a dict of the form
    # {'values': u'71D0483C,71D048A3,71D0490C,71D04973,71D049DB,71D04A45',
    #  'class': u'1000HZ'}
    def set_tcptssequence(self, sequence):
        self._tcptssequence = sequence

    def get_tcptssequence(self):
        if self._tcptssequence:
            return self._tcptssequence
        return {}

    # ipidsequence is a dict of the form
    # {'values': u'0,0,0,0,0,0', 'class': u'All zeros'}
    def set_ipidsequence(self, sequence):
        self._ipidsequence = sequence

    def get_ipidsequence(self):
        if self._ipidsequence:
            return self._ipidsequence
        return {}

    # osmatches is a list of dicts of the form
    # {'name': u'Linux 2.6.24', 'accuracy': u'98', 'line': u'1000',
    #  'osclasses': ...}
    # where each 'osclasses' element is a dict of the form
    # {'vendor': u'Linux', 'osfamily': u'Linux', 'type': u'general purpose',
    #  'osgen': u'2.6.X', 'accuracy': u'98'}
    def set_osmatches(self, matches):
        self._osmatches = matches

    def get_osmatches(self):
        return self._osmatches

    def get_best_osmatch(self):
        """Return the OS match with the highest accuracy."""
        if not self._osmatches:
            return None

        def osmatch_key(osmatch):
            try:
                return -float(osmatch["accuracy"])
            except ValueError:
                return 0

        return sorted(self._osmatches, key=osmatch_key)[0]

    # ports_used is a list like
    # [{'state': u'open', 'portid': u'22', 'proto': u'tcp'},
    #  {'state': u'closed', 'portid': u'25', 'proto': u'tcp'},
    #  {'state': u'closed', 'portid': u'44054', 'proto': u'udp'}]
    # but not all three elements are necessarily present.
    def set_ports_used(self, ports):
        self._ports_used = ports

    def get_ports_used(self):
        return self._ports_used

    # uptime is a dict of the form
    # {'seconds': u'1909493', 'lastboot': u'Wed Jul 2 06:48:31 2008'}
    def set_uptime(self, uptime):
        self._uptime = uptime

    def get_uptime(self):
        if self._uptime:
            return self._uptime

        # Avoid empty dict return
        return {"seconds": "", "lastboot": ""}

    # ports is an array containing dicts of the form
    # {'port_state': u'open', 'portid': u'22', 'protocol': u'tcp',
    #  'service_conf': u'10', 'service_extrainfo': u'protocol 2.0',
    #  'service_method': u'probed', 'service_name': u'ssh',
    #  'service_product': u'OpenSSH', 'service_version': u'4.3'}
    def set_ports(self, ports):
        self._ports = ports

    def get_ports(self):
        return self._ports

    # extraports is an array of dicts of the form
    # {'count': u'1709', 'state': u'filtered'}
    def set_extraports(self, port_list):
        self._extraports = port_list

    def get_extraports(self):
        return self._extraports

    # hostnames is a list containing dicts of the form
    # [{'hostname': u'scanme.nmap.org', 'hostname_type': u'PTR'}]
    def set_hostnames(self, hostname_list):
        self._hostnames = hostname_list

    def get_hostnames(self):
        return self._hostnames

    # ip, ipv6, and mac are either None or dicts of the form
    # {'vendor': u'', 'type': u'ipv4', 'addr': u'64.13.134.52'}
    def set_ip(self, addr):
        self._ip = addr

    def get_ip(self):
        return self._ip

    def set_mac(self, addr):
        self._mac = addr

    def get_mac(self):
        return self._mac

    def set_ipv6(self, addr):
        self._ipv6 = addr

    def get_ipv6(self):
        return self._ipv6

    def get_addrs_for_sort(self):
        """Return a list of addresses as opaque values sorted such that
        1) IPv4 comes before IPv6 comes before MAC, and
        2) addresses are sorted according to their binary values, not their
           string representation.
        Use this function to the the comparison key when sorting a list of
        hosts by address."""
        l = []
        if self.ip:
            l.append((1, socket.inet_aton(self.ip["addr"])))
        if self.ipv6:
            try:
                l.append((1,
                    socket.inet_pton(socket.AF_INET6, self.ipv6["addr"])))
            except AttributeError:
                # Windows doesn't have socket.inet_pton. Go alphabetical.
                # Encode to a byte string for possible comparison with binary
                # address strings (which can't be converted to unicode).
                l.append((1, self.ipv6["addr"].encode("utf-8")))
        if self.mac:
            l.append((3, "".join(
                chr(int(x, 16)) for x in self.mac["addr"].split(":"))))
        l.sort()
        return l

    # comment is a string.
    def get_comment(self):
        return self._comment

    def set_comment(self, comment):
        self._comment = comment

    # state is a string like u'up' or u'down'.
    def set_state(self, status):
        self._state = status

    def get_state(self):
        return self._state

    def get_hostname(self):
        hostname = None
        if len(self._hostnames) > 0:
            hostname = self._hostnames[0]["hostname"]

        address = self.ip or self.ipv6 or self.mac
        if address is not None:
            address = address["addr"]

        if hostname is not None:
            if address is not None:
                return "%s (%s)" % (hostname, address)
            else:
                return hostname
        else:
            if address is not None:
                return address
            else:
                return _("Unknown Host")

    def get_port_count_by_states(self, states):
        count = 0

        for p in self.ports:
            state = p.get('port_state')
            if state in states:
                count += 1

        for extra in self.get_extraports():
            if extra['state'] in states:
                count += int(extra['count'])

        return count

    def get_open_ports(self):
        return self.get_port_count_by_states(('open', 'open|filtered'))

    def get_filtered_ports(self):
        return self.get_port_count_by_states(
                ('filtered', 'open|filtered', 'closed|filtered'))

    def get_closed_ports(self):
        return self.get_port_count_by_states(('closed', 'closed|filtered'))

    def get_scanned_ports(self):
        scanned = 0

        for p in self.ports:
            scanned += 1

        for extra in self.get_extraports():
            scanned += int(extra["count"])

        return scanned

    def get_services(self):
        services = []
        for p in self.ports:
            services.append({
                "service_name": p.get("service_name", _("unknown")),
                "portid": p.get("portid", ""),
                "service_version": p.get("service_version",
                    _("Unknown version")),
                "service_product": p.get("service_product", ""),
                "service_extrainfo": p.get("service_extrainfo", ""),
                "port_state": p.get("port_state", _("unknown")),
                "protocol": p.get("protocol", "")
                })
        return services

    def get_trace(self):
        return self._trace

    def set_trace(self, trace):
        self._trace = trace

    def append_trace_hop(self, hop):
        if "hops" in self._trace:
            self._trace["hops"].append(hop)
        else:
            self._trace["hops"] = [hop]

    def set_trace_error(self, errorstr):
        self._trace["error"] = errorstr

    # Properties
    tcpsequence = property(get_tcpsequence, set_tcpsequence)
    osmatches = property(get_osmatches, set_osmatches)
    ports = property(get_ports, set_ports)
    ports_used = property(get_ports_used, set_ports_used)
    extraports = property(get_extraports, set_extraports)
    uptime = property(get_uptime, set_uptime)
    hostnames = property(get_hostnames, set_hostnames)
    tcptssequence = property(get_tcptssequence, set_tcptssequence)
    ipidsequence = property(get_ipidsequence, set_ipidsequence)
    ip = property(get_ip, set_ip)
    ipv6 = property(get_ipv6, set_ipv6)
    mac = property(get_mac, set_mac)
    state = property(get_state, set_state)
    comment = property(get_comment, set_comment)
    services = property(get_services)
    trace = property(get_trace, set_trace)


class ParserBasics(object):
    def __init__(self):
        # This flag informs us whether the XML output file is temporary (True),
        # or user specified (False). If any of them is user-specified, it
        # doesn't get stripped out of the command string in set_nmap_command.
        self.xml_is_temp = True

        self.nmap = {
                'nmaprun': {},
                'scaninfo': [],
                'verbose': '',
                'debugging': '',
                'hosts': [],
                'runstats': {}
                }

        self.ops = NmapOptions()
        self._nmap_output = StringIO()

    def set_xml_is_temp(self, xml_is_temp):
        # This flag is False if a user has specified his own -oX option - in
        # which case we not should remove the -oX option from the command
        # string. A value of True means that we're using a temporary file which
        # should be removed from the command string (see set_nmap_command).
        self.xml_is_temp = xml_is_temp

    def get_profile_name(self):
        return self.nmap['nmaprun'].get('profile_name', '')

    def set_profile_name(self, name):
        self.nmap['nmaprun']['profile_name'] = name

    def get_targets(self):
        return self.ops.target_specs

    def set_targets(self, targets):
        self.ops.target_specs = targets

    def get_nmap_output(self):
        return self._nmap_output.getvalue()

    def set_nmap_output(self, nmap_output):
        self._nmap_output.close()
        del self._nmap_output
        self._nmap_output = StringIO()
        self._nmap_output.write(nmap_output)

    def del_nmap_output(self):
        self._nmap_output.close()
        del self._nmap_output

    def get_debugging_level(self):
        return self.nmap.get('debugging', '')

    def set_debugging_level(self, level):
        self.nmap['debugging'] = level

    def get_verbose_level(self):
        return self.nmap.get('verbose', '')

    def set_verbose_level(self, level):
        self.nmap['verbose'] = level

    def get_scaninfo(self):
        return self.nmap.get('scaninfo', '')

    def set_scaninfo(self, info):
        self.nmap['scaninfo'] = info

    def get_services_scanned(self):
        if self._services_scanned is None:
            return self._services_scanned

        services = []
        for scan in self.nmap.get('scaninfo', []):
            services.append(scan['services'])

        self._services_scanned = ','.join(services)
        return self._services_scanned

    def set_services_scanned(self, services_scanned):
        self._services_scanned = services_scanned

    def get_nmap_command(self):
        return self.ops.render_string()

    def set_nmap_command(self, command):
        self.ops.parse_string(command)
        if self.xml_is_temp:
            self.ops["-oX"] = None
        self.nmap['nmaprun']['args'] = self.ops.render_string()

    def get_scan_type(self):
        types = []
        for t in self.nmap.get('scaninfo', []):
            types.append(t['type'])
        return types

    def get_protocol(self):
        protocols = []
        for proto in self.nmap.get('scaninfo', []):
            protocols.append(proto['protocol'])
        return protocols

    def get_num_services(self):
        if self._num_services is None:
            return self._num_services

        num = 0
        for n in self.nmap.get('scaninfo', []):
            num += int(n['numservices'])

        self._num_services = num
        return self._num_services

    def set_num_services(self, num_services):
        self._num_services = num_services

    def get_date(self):
        epoch = int(self.nmap['nmaprun'].get('start', '0'))
        return time.localtime(epoch)

    def get_start(self):
        return self.nmap['nmaprun'].get('start', '0')

    def set_start(self, start):
        self.nmap['nmaprun']['start'] = start

    def set_date(self, date):
        if type(date) == type(int):
            self.nmap['nmaprun']['start'] = date
        else:
            raise Exception("Wrong date format. Date should be saved \
in epoch format!")

    def get_open_ports(self):
        ports = 0

        for h in self.nmap.get('hosts', []):
            ports += h.get_open_ports()

        return ports

    def get_filtered_ports(self):
        ports = 0

        for h in self.nmap.get('hosts', []):
            ports += h.get_filtered_ports()

        return ports

    def get_closed_ports(self):
        ports = 0

        for h in self.nmap['hosts']:
            ports += h.get_closed_ports()

        return ports

    def get_formatted_date(self):
        return time.strftime("%B %d, %Y - %H:%M", self.get_date())

    def get_scanner(self):
        return self.nmap['nmaprun'].get('scanner', '')

    def set_scanner(self, scanner):
        self.nmap['nmaprun']['scanner'] = scanner

    def get_scanner_version(self):
        return self.nmap['nmaprun'].get('version', '')

    def set_scanner_version(self, version):
        self.nmap['nmaprun']['version'] = version

    # IPv4
    def get_ipv4(self):
        hosts = self.nmap.get('hosts')
        if hosts is None:
            return []
        return [host.ip for host in hosts if host.ip is not None]

    # MAC
    def get_mac(self):
        hosts = self.nmap.get('hosts')
        if hosts is None:
            return []
        return [host.mac for host in hosts if host.mac is not None]

    # IPv6
    def get_ipv6(self):
        hosts = self.nmap.get('hosts')
        if hosts is None:
            return []
        return [host.ipv6 for host in hosts if host.ipv6 is not None]

    def get_hostnames(self):
        hostnames = []
        for host in self.nmap.get('hosts', []):
            hostnames += host.get_hostnames()
        return hostnames

    def get_hosts(self):
        return self.nmap.get('hosts', None)

    def get_runstats(self):
        return self.nmap.get('runstats', None)

    def set_runstats(self, stats):
        self.nmap['runstats'] = stats

    def get_hosts_down(self):
        return int(self.nmap['runstats'].get('hosts_down', '0'))

    def set_hosts_down(self, down):
        self.nmap['runstats']['hosts_down'] = int(down)

    def get_hosts_up(self):
        return int(self.nmap['runstats'].get('hosts_up', '0'))

    def set_hosts_up(self, up):
        self.nmap['runstats']['hosts_up'] = int(up)

    def get_hosts_scanned(self):
        return int(self.nmap['runstats'].get('hosts_scanned', '0'))

    def set_hosts_scanned(self, scanned):
        self.nmap['runstats']['hosts_scanned'] = int(scanned)

    def get_finish_time(self):
        return time.localtime(int(self.nmap['runstats'].get('finished_time',
                                                            '0')))

    def set_finish_time(self, finish):
        self.nmap['runstats']['finished_time'] = int(finish)

    def get_finish_epoc_time(self):
        return int(self.nmap['runstats'].get('finished_time', '0'))

    def set_finish_epoc_time(self, time):
        self.nmap['runstats']['finished_time'] = time

    def get_scan_name(self):
        """Get a human-readable string representing this scan."""
        scan_name = self.nmap.get("scan_name")
        if scan_name:
            return scan_name
        if self.profile_name and self.get_targets():
            return _("%s on %s") % (self.profile_name,
                    join_quoted(self.get_targets()))
        return self.get_nmap_command()

    def set_scan_name(self, scan_name):
        self.nmap["scan_name"] = scan_name

    def get_formatted_finish_date(self):
        return time.strftime("%B %d, %Y - %H:%M", self.get_finish_time())

    def get_port_protocol_dict(self):
        #Create a dict of port -> protocol for all ports scanned
        ports = {}
        for scaninfo in self.scaninfo:
            services_string = scaninfo['services'].strip()
            if services_string == "":
                services_array = []
            else:
                services_array = services_string.split(',')
            for item in services_array:
                if item.find('-') == -1:
                    if int(item) not in ports:
                        ports[int(item)] = []
                    ports[int(item)].append(scaninfo['protocol'])
                else:
                    begin, end = item.split('-')
                    for port in range(int(begin), int(end) + 1):
                        if int(port) not in ports:
                            ports[int(port)] = []
                        ports[int(port)].append(scaninfo['protocol'])
        return ports

    profile_name = property(get_profile_name, set_profile_name)
    nmap_output = property(get_nmap_output, set_nmap_output, del_nmap_output)
    debugging_level = property(get_debugging_level, set_debugging_level)
    verbose_level = property(get_verbose_level, set_verbose_level)
    scaninfo = property(get_scaninfo, set_scaninfo)
    services_scanned = property(get_services_scanned, set_services_scanned)
    nmap_command = property(get_nmap_command, set_nmap_command)
    scan_type = property(get_scan_type)
    protocol = property(get_protocol)
    num_services = property(get_num_services, set_num_services)
    date = property(get_date, set_date)
    open_ports = property(get_open_ports)
    filtered_ports = property(get_filtered_ports)
    closed_ports = property(get_closed_ports)
    formatted_date = property(get_formatted_date)
    scanner = property(get_scanner, set_scanner)
    scanner_version = property(get_scanner_version, set_scanner_version)
    ipv4 = property(get_ipv4)
    mac = property(get_mac)
    ipv6 = property(get_ipv6)
    hostnames = property(get_hostnames)
    hosts = property(get_hosts)
    runstats = property(get_runstats, set_runstats)
    hosts_down = property(get_hosts_down, set_hosts_down)
    hosts_up = property(get_hosts_up, set_hosts_up)
    hosts_scanned = property(get_hosts_scanned, set_hosts_scanned)
    finish_time = property(get_finish_time, set_finish_time)
    finish_epoc_time = property(get_finish_epoc_time, set_finish_epoc_time)
    formatted_finish_date = property(get_formatted_finish_date)
    start = property(get_start, set_start)
    scan_name = property(get_scan_name, set_scan_name)

    _num_services = None
    _services_scanned = None


class NmapParserSAX(ParserBasics, ContentHandler):
    def __init__(self):
        ParserBasics.__init__(self)
        ContentHandler.__init__(self)

        # The text inside an xml-stylesheet processing instruction, like
        # 'href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"'.
        self.xml_stylesheet_data = None

        self.in_interactive_output = False
        self.in_run_stats = False
        self.in_host = False
        self.in_hostnames = False
        self.in_ports = False
        self.in_port = False
        self.in_os = False
        self.in_trace = False
        self.list_extraports = []

        self.filename = None

        self.unsaved = False

    def set_parser(self, parser):
        self.parser = parser

    def parse(self, f):
        """Parse an Nmap XML file from the file-like object f."""
        self.parser.parse(f)

    def parse_file(self, filename):
        """Parse an Nmap XML file from the named file."""
        with open(filename, "r") as f:
            self.parse(f)
            self.filename = filename

    def _parse_nmaprun(self, attrs):
        run_tag = "nmaprun"

        if self.nmap_output == "" and "nmap_output" in attrs:
            self.nmap_output = attrs["nmap_output"]
        self.nmap[run_tag]["profile_name"] = attrs.get("profile_name", "")
        self.nmap[run_tag]["start"] = attrs.get("start", "")
        self.nmap[run_tag]["args"] = attrs.get("args", "")
        self.nmap[run_tag]["scanner"] = attrs.get("scanner", "")
        self.nmap[run_tag]["version"] = attrs.get("version", "")
        self.nmap[run_tag]["xmloutputversion"] = attrs.get(
                "xmloutputversion", "")

        self.nmap_command = self.nmap[run_tag]["args"]

    def _parse_output(self, attrs):
        if attrs.get("type") != "interactive":
            return
        if self.in_interactive_output:
            raise SAXException("Unexpected nested \"output\" element.")
        self.in_interactive_output = True
        self.nmap_output = ""

    def _parse_scaninfo(self, attrs):
        dic = {}

        dic["type"] = unique(attrs.get("type", ""))
        dic["protocol"] = unique(attrs.get("protocol", ""))
        dic["numservices"] = attrs.get("numservices", "")
        dic["services"] = attrs.get("services", "")

        self.nmap["scaninfo"].append(dic)

    def _parse_verbose(self, attrs):
        self.nmap["verbose"] = attrs.get("level", "")

    def _parse_debugging(self, attrs):
        self.nmap["debugging"] = attrs.get("level", "")

    def _parse_runstats_finished(self, attrs):
        self.nmap["runstats"]["finished_time"] = attrs.get("time", "")

    def _parse_runstats_hosts(self, attrs):
        self.nmap["runstats"]["hosts_up"] = attrs.get("up", "")
        self.nmap["runstats"]["hosts_down"] = attrs.get("down", "")
        self.nmap["runstats"]["hosts_scanned"] = attrs.get("total", "")

    def _parse_host(self, attrs):
        self.host_info = HostInfo()
        self.host_info.comment = attrs.get("comment", "")

    def _parse_host_status(self, attrs):
        self.host_info.set_state(unique(attrs.get("state", "")))

    def _parse_host_address(self, attrs):
        address_attributes = {"type": unique(attrs.get("addrtype", "")),
                              "vendor": attrs.get("vendor", ""),
                              "addr": attrs.get("addr", "")}

        if address_attributes["type"] == "ipv4":
            self.host_info.set_ip(address_attributes)
        elif address_attributes["type"] == "ipv6":
            self.host_info.set_ipv6(address_attributes)
        elif address_attributes["type"] == "mac":
            self.host_info.set_mac(address_attributes)

    def _parse_host_hostname(self, attrs):
        self.list_hostnames.append({"hostname": attrs.get("name", ""),
                                    "hostname_type": attrs.get("type", "")})

    def _parse_host_extraports(self, attrs):
        self.list_extraports.append({"state": unique(attrs.get("state", "")),
                                     "count": attrs.get("count", "")})

    def _parse_host_port(self, attrs):
        self.dic_port = {"protocol": unique(attrs.get("protocol", "")),
                         "portid": unique(attrs.get("portid", ""))}

    def _parse_host_port_state(self, attrs):
        self.dic_port["port_state"] = unique(attrs.get("state", ""))
        self.dic_port["reason"] = unique(attrs.get("reason", ""))
        self.dic_port["reason_ttl"] = unique(attrs.get("reason_ttl", ""))

    def _parse_host_port_service(self, attrs):
        self.dic_port["service_name"] = attrs.get("name", "")
        self.dic_port["service_method"] = unique(attrs.get("method", ""))
        self.dic_port["service_conf"] = attrs.get("conf", "")
        self.dic_port["service_product"] = attrs.get("product", "")
        self.dic_port["service_version"] = attrs.get("version", "")
        self.dic_port["service_extrainfo"] = attrs.get("extrainfo", "")

    def _parse_host_osmatch(self, attrs):
        osmatch = self._parsing(attrs, [], ['name', 'accuracy', 'line'])
        osmatch['osclasses'] = []
        self.list_osmatch.append(osmatch)

    def _parse_host_portused(self, attrs):
        self.list_portused.append(self._parsing(
            attrs, ['state', 'proto', 'portid'], []))

    def _parse_host_osclass(self, attrs):
        self.list_osclass.append(self._parsing(
            attrs, ['type', 'vendor', 'osfamily', 'osgen'], ['accuracy']))

    def _parsing(self, attrs, unique_names, other_names):
        # Returns a dict with the attributes of a given tag with the
        # attributes names as keys and their respective values
        dic = {}
        for at in unique_names:
            dic[at] = unique(attrs.get(at, ""))
        for at in other_names:
            dic[at] = attrs.get(at, "")
        return dic

    def _parse_host_uptime(self, attrs):
        self.host_info.set_uptime(self._parsing(
            attrs, [], ["seconds", "lastboot"]))

    def _parse_host_tcpsequence(self, attrs):
        self.host_info.set_tcpsequence(self._parsing(
            attrs, ['difficulty'], ['index', 'values']))

    def _parse_host_tcptssequence(self, attrs):
        self.host_info.set_tcptssequence(self._parsing(
            attrs, ['class'], ['values']))

    def _parse_host_ipidsequence(self, attrs):
        self.host_info.set_ipidsequence(self._parsing(
            attrs, ['class'], ['values']))

    def _parse_host_trace(self, attrs):
        trace = {}
        for attr in ["proto", "port"]:
            trace[attr] = unique(attrs.get(attr, ""))
        self.host_info.set_trace(trace)

    def _parse_host_trace_hop(self, attrs):
        hop = self._parsing(attrs, [], ["ttl", "rtt", "ipaddr", "host"])
        self.host_info.append_trace_hop(hop)

    def _parse_host_trace_error(self, attrs):
        self.host_info.set_trace_error(unique(attrs.get("errorstr", "")))

    def processingInstruction(self, target, data):
        if target == "xml-stylesheet":
            self.xml_stylesheet_data = data

    def startElement(self, name, attrs):
        if name == "nmaprun":
            self._parse_nmaprun(attrs)
        if name == "output":
            self._parse_output(attrs)
        elif name == "scaninfo":
            self._parse_scaninfo(attrs)
        elif name == "verbose":
            self._parse_verbose(attrs)
        elif name == "debugging":
            self._parse_debugging(attrs)
        elif name == "runstats":
            self.in_run_stats = True
        elif self.in_run_stats and name == "finished":
            self._parse_runstats_finished(attrs)
        elif self.in_run_stats and name == "hosts":
            self._parse_runstats_hosts(attrs)
        elif name == "host":
            self.in_host = True
            self._parse_host(attrs)
            self.list_ports = []
            self.list_extraports = []
        elif self.in_host and name == "status":
            self._parse_host_status(attrs)
        elif self.in_host and name == "address":
            self._parse_host_address(attrs)
        elif self.in_host and name == "hostnames":
            self.in_hostnames = True
            self.list_hostnames = []
        elif self.in_host and self.in_hostnames and name == "hostname":
            self._parse_host_hostname(attrs)
        elif self.in_host and name == "ports":
            self.in_ports = True
        elif self.in_host and self.in_ports and name == "extraports":
            self._parse_host_extraports(attrs)
        elif self.in_host and self.in_ports and name == "port":
            self.in_port = True
            self._parse_host_port(attrs)
        elif self.in_host and self.in_ports and \
             self.in_port and name == "state":
            self._parse_host_port_state(attrs)
        elif self.in_host and self.in_ports and \
             self.in_port and name == "service":
            self._parse_host_port_service(attrs)
        elif self.in_host and name == "os":
            self.in_os = True
            self.list_portused = []
            self.list_osmatch = []
        elif self.in_host and self.in_os and name == "osmatch":
            self._parse_host_osmatch(attrs)
        elif self.in_host and self.in_os and name == "portused":
            self._parse_host_portused(attrs)
        elif self.in_host and self.in_os and name == "osclass":
            self.list_osclass = []
            self._parse_host_osclass(attrs)
        elif self.in_host and name == "uptime":
            self._parse_host_uptime(attrs)
        elif self.in_host and name == "tcpsequence":
            self._parse_host_tcpsequence(attrs)
        elif self.in_host and name == "tcptssequence":
            self._parse_host_tcptssequence(attrs)
        elif self.in_host and name == "ipidsequence":
            self._parse_host_ipidsequence(attrs)
        elif self.in_host and name == "trace":
            self.in_trace = True
            self._parse_host_trace(attrs)
        elif self.in_host and self.in_trace and name == "hop":
            self._parse_host_trace_hop(attrs)
        elif self.in_host and self.in_trace and name == "error":
            self._parse_host_trace_error(attrs)

    def endElement(self, name):
        if name == "output":
            self.in_interactive_output = False
        elif name == "runstats":
            self.in_run_stats = False
        elif name == "host":
            self.in_host = False
            self.host_info.set_extraports(self.list_extraports)
            self.host_info.set_ports(self.list_ports)
            self.nmap["hosts"].append(self.host_info)
        elif self.in_host and name == "hostnames":
            self.in_hostnames = False
            self.host_info.set_hostnames(self.list_hostnames)
        elif self.in_host and name == "ports":
            self.in_ports = False
        elif self.in_host and self.in_ports and name == "port":
            self.in_port = False
            self.list_ports.append(self.dic_port)
            del(self.dic_port)
        elif self.in_host and self.in_os and name == "osmatch":
            self.list_osmatch[-1]['osclasses'].extend(self.list_osclass)
            self.list_osclass = []
        elif self.in_host and self.in_os and name == "os":
            self.in_os = False
            self.host_info.set_ports_used(self.list_portused)
            self.host_info.set_osmatches(self.list_osmatch)

            del(self.list_portused)
            del(self.list_osmatch)
        elif self.in_host and self.in_trace and name == "trace":
            self.in_trace = False

    def characters(self, content):
        if self.in_interactive_output:
            self._nmap_output.write(content)

    def write_text(self, f):
        """Write the Nmap text output of this object to the file-like object
        f."""
        if self.nmap_output == "":
            return
        f.write(self.nmap_output)

    def write_xml(self, f):
        """Write the XML representation of this object to the file-like object
        f."""
        writer = XMLGenerator(f)
        writer.startDocument()
        if self.xml_stylesheet_data is not None:
            writer.processingInstruction(
                    "xml-stylesheet", self.xml_stylesheet_data)
        self._write_nmaprun(writer)
        self._write_scaninfo(writer)
        self._write_verbose(writer)
        self._write_debugging(writer)
        self._write_output(writer)
        self._write_hosts(writer)
        self._write_runstats(writer)
        writer.endElement("nmaprun")
        writer.endDocument()

    def get_xml(self):
        """Return a string containing the XML representation of this scan."""
        buffer = StringIO()
        self.write_xml(buffer)
        string = buffer.getvalue()
        buffer.close()
        return string

    def write_xml_to_file(self, filename):
        """Write the XML representation of this scan to the file whose name is
        given."""
        fd = open(filename, "w")
        self.write_xml(fd)
        fd.close()

    def _write_output(self, writer):
        if self.nmap_output == "":
            return
        writer.startElement("output", Attributes({"type": "interactive"}))
        writer.characters(self.nmap_output)
        writer.endElement("output")

    def _write_runstats(self, writer):
        ##################
        # Runstats element
        writer.startElement("runstats", Attributes(dict()))

        ## Finished element
        writer.startElement("finished",
                        Attributes(dict(time=str(self.finish_epoc_time),
                                        timestr=time.ctime(time.mktime(
                                            self.get_finish_time())))))
        writer.endElement("finished")

        ## Hosts element
        writer.startElement("hosts",
                            Attributes(dict(up=str(self.hosts_up),
                                            down=str(self.hosts_down),
                                            total=str(self.hosts_scanned))))
        writer.endElement("hosts")

        writer.endElement("runstats")
        # End of Runstats element
        #########################

    def _write_hosts(self, writer):
        for host in self.hosts:
            # Start host element
            writer.startElement("host",
                                Attributes(dict(comment=host.comment)))

            # Status element
            writer.startElement("status",
                                Attributes(dict(state=host.state)))
            writer.endElement("status")

            ##################
            # Address elements
            ## IPv4
            if host.ip is not None:
                writer.startElement("address",
                            Attributes(dict(addr=host.ip.get("addr", ""),
                                        vendor=host.ip.get("vendor", ""),
                                        addrtype=host.ip.get("type", ""))))
                writer.endElement("address")

            ## IPv6
            if host.ipv6 is not None:
                writer.startElement("address",
                            Attributes(dict(addr=host.ipv6.get("addr", ""),
                                        vendor=host.ipv6.get("vendor", ""),
                                        addrtype=host.ipv6.get("type", ""))))
                writer.endElement("address")

            ## MAC
            if host.mac is not None:
                writer.startElement("address",
                            Attributes(dict(addr=host.mac.get("addr", ""),
                                        vendor=host.mac.get("vendor", ""),
                                        addrtype=host.mac.get("type", ""))))
                writer.endElement("address")
            # End of Address elements
            #########################

            ###################
            # Hostnames element
            writer.startElement("hostnames", Attributes({}))

            for hname in host.hostnames:
                writer.startElement("hostname",
                        Attributes(dict(name=hname.get("hostname", ""),
                                    type=hname.get("hostname_type", ""))))

                writer.endElement("hostname")

            writer.endElement("hostnames")
            # End of Hostnames element
            ##########################

            ###############
            # Ports element
            writer.startElement("ports", Attributes({}))

            ## Extraports elements
            for ext in host.get_extraports():
                writer.startElement("extraports",
                    Attributes(dict(count=ext.get("count", ""),
                                    state=ext.get("state", ""))))
                writer.endElement("extraports")

            ## Port elements
            for p in host.ports:
                writer.startElement("port",
                    Attributes(dict(portid=p.get("portid", ""),
                                    protocol=p.get("protocol", ""))))

                ### Port state
                writer.startElement("state",
                    Attributes(dict(state=p.get("port_state", ""),
                                    reason=p.get("reason", ""),
                                    reason_ttl=p.get("reason_ttl", ""))))
                writer.endElement("state")

                ### Port service info
                d = {}
                for xml_attr, member in (("conf", "service_conf"),
                        ("method", "service_method"),
                        ("name", "service_name"),
                        ("product", "service_product"),
                        ("version", "service_version"),
                        ("extrainfo", "service_extrainfo")):
                    if p.get(member):
                        d[xml_attr] = p.get(member)
                writer.startElement("service", Attributes(d))
                writer.endElement("service")

                writer.endElement("port")

            writer.endElement("ports")
            # End of Ports element
            ######################

            ############
            # OS element
            writer.startElement("os", Attributes({}))

            ## Ports used elements
            for pu in host.ports_used:
                writer.startElement("portused",
                            Attributes(dict(state=pu.get("state", ""),
                                            proto=pu.get("proto", ""),
                                            portid=pu.get("portid", ""))))
                writer.endElement("portused")

            ## Osmatch elements
            for om in host.osmatches:
                writer.startElement("osmatch",
                    Attributes(dict(name=om.get("name", ""),
                                    accuracy=om.get("accuracy", ""),
                                    line=om.get("line", ""))))
                ## Osclass elements
                for oc in om['osclasses']:
                    writer.startElement("osclass",
                        Attributes(dict(vendor=oc.get("vendor", ""),
                                        osfamily=oc.get("osfamily", ""),
                                        type=oc.get("type", ""),
                                        osgen=oc.get("osgen", ""),
                                        accuracy=oc.get("accuracy", ""))))
                    writer.endElement("osclass")
                writer.endElement("osmatch")

            writer.endElement("os")
            # End of OS element
            ###################

            # Uptime element
            writer.startElement("uptime",
                Attributes(dict(seconds=host.uptime.get("seconds", ""),
                            lastboot=host.uptime.get("lastboot", ""))))
            writer.endElement("uptime")

            #####################
            # Sequences elements
            ## TCP Sequence element
            # Cannot use dict() here, because of the 'class' attribute.
            writer.startElement("tcpsequence",
                Attributes({"index": host.tcpsequence.get("index", ""),
                        "difficulty": host.tcpsequence.get("difficulty", ""),
                        "values": host.tcpsequence.get("values", "")}))
            writer.endElement("tcpsequence")

            ## IP ID Sequence element
            writer.startElement("ipidsequence",
                Attributes({"class": host.ipidsequence.get("class", ""),
                            "values": host.ipidsequence.get("values", "")}))
            writer.endElement("ipidsequence")

            ## TCP TS Sequence element
            writer.startElement("tcptssequence",
                Attributes({"class": host.tcptssequence.get("class", ""),
                        "values": host.tcptssequence.get("values", "")}))
            writer.endElement("tcptssequence")
            # End of sequences elements
            ###########################

            ## Trace element
            if len(host.trace) > 0:
                writer.startElement("trace",
                    Attributes({"proto": host.trace.get("proto", ""),
                                "port": host.trace.get("port", "")}))

                if "hops" in host.trace:
                    for hop in host.trace["hops"]:
                        writer.startElement("hop",
                            Attributes({"ttl": hop["ttl"],
                                        "rtt": hop["rtt"],
                                        "ipaddr": hop["ipaddr"],
                                        "host": hop["host"]}))
                        writer.endElement("hop")

                if "error" in host.trace:
                    writer.startElement("error",
                        Attributes({"errorstr": host.trace["error"]}))
                    writer.endElement("error")

                writer.endElement("trace")
            # End of trace element
            ###########################

            # End host element
            writer.endElement("host")

    def _write_debugging(self, writer):
        writer.startElement("debugging", Attributes(dict(
                                            level=str(self.debugging_level))))
        writer.endElement("debugging")

    def _write_verbose(self, writer):
        writer.startElement("verbose", Attributes(dict(
                                            level=str(self.verbose_level))))
        writer.endElement("verbose")

    def _write_scaninfo(self, writer):
        for scan in self.scaninfo:
            writer.startElement("scaninfo",
                Attributes(dict(type=scan.get("type", ""),
                                protocol=scan.get("protocol", ""),
                                numservices=scan.get("numservices", ""),
                                services=scan.get("services", ""))))
            writer.endElement("scaninfo")

    def _write_nmaprun(self, writer):
        writer.startElement("nmaprun",
                Attributes(dict(args=str(self.nmap_command),
                                profile_name=str(self.profile_name),
                                scanner=str(self.scanner),
                                start=str(self.start),
                                startstr=time.ctime(
                                    time.mktime(self.get_date())),
                                version=str(self.scanner_version),
                                xmloutputversion=str(XML_OUTPUT_VERSION))))

    def set_unsaved(self):
        self.unsaved = True

    def is_unsaved(self):
        return self.unsaved


class OverrideEntityResolver(EntityResolver):
    """This class overrides the default behavior of xml.sax to download
    remote DTDs, instead returning blank strings"""
    empty = StringIO()

    def resolveEntity(self, publicId, systemId):
        return OverrideEntityResolver.empty


def nmap_parser_sax():
    parser = make_parser()
    nmap_parser = NmapParserSAX()

    parser.setContentHandler(nmap_parser)
    parser.setEntityResolver(OverrideEntityResolver())
    nmap_parser.set_parser(parser)

    return nmap_parser

NmapParser = nmap_parser_sax


if __name__ == '__main__':
    import sys

    file_to_parse = sys.argv[1]

    np = NmapParser()
    np.parse_file(file_to_parse)

    for host in np.hosts:
        print("%s:" % host.ip["addr"])
        print("  Comment:", repr(host.comment))
        print("  TCP sequence:", repr(host.tcpsequence))
        print("  TCP TS sequence:", repr(host.tcptssequence))
        print("  IP ID sequence:", repr(host.ipidsequence))
        print("  Uptime:", repr(host.uptime))
        print("  OS Match:", repr(host.osmatches))
        print("  Ports:")
        for p in host.ports:
            print("\t%s" % repr(p))
        print("  Ports used:", repr(host.ports_used))
        print("  OS Matches:", repr(host.osmatches))
        print("  Hostnames:", repr(host.hostnames))
        print("  IP:", repr(host.ip))
        print("  IPv6:", repr(host.ipv6))
        print("  MAC:", repr(host.mac))
        print("  State:", repr(host.state))
        if "hops" in host.trace:
            print("  Trace:")
            for hop in host.trace["hops"]:
                print("    ", repr(hop))
            print()
