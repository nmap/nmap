#!/usr/bin/env python

# Unit tests for ndiff.

import unittest
import xml.dom.minidom
import StringIO

from ndiff import *

class parse_port_list_test(unittest.TestCase):
    """Test the parse_port_list function."""
    def test_empty(self):
        ports = parse_port_list(u"")
        self.assertTrue(len(ports) == 0)

    def test_single(self):
        ports = parse_port_list(u"1,10,100")
        self.assertTrue(len(ports) == 3)
        self.assertTrue(set(ports) == set([1, 10, 100]))

    def test_range(self):
        ports = parse_port_list(u"10-20")
        self.assertTrue(len(ports) == 11)
        self.assertTrue(set(ports) == set(range(10, 21)))

    def test_combo(self):
        ports = parse_port_list(u"1,10,100-102,150")
        self.assertTrue(set(ports) == set([1, 10, 100, 101, 102, 150]))

    def test_dups(self):
        ports = parse_port_list(u"5,1-10")
        self.assertTrue(len(ports) == 10)
        self.assertTrue(set(ports) == set(range(1, 11)))

    def test_invalid(self):
        self.assertRaises(ValueError, parse_port_list, u"a")
        self.assertRaises(ValueError, parse_port_list, u",1")
        self.assertRaises(ValueError, parse_port_list, u"1,,2")
        self.assertRaises(ValueError, parse_port_list, u"1,")
        self.assertRaises(ValueError, parse_port_list, u"1-2-3")
        self.assertRaises(ValueError, parse_port_list, u"10-1")

class render_port_list_test(unittest.TestCase):
    """Test the render_port_list function."""
    def test_roundtrip(self):
        TESTS = ([],
            [1],
            [1,1],
            [1,2,3,4,10,11,12],
            [1,2,3,4,5,9,8,7,6],
            [1,2,3,4,5,3]
        )

        for test in TESTS:
            s = render_port_list(test)
            result = parse_port_list(s)
            self.assertTrue(list(set(test)) == result, u"Expected %s, got %s." % (list(set(test)), result))

class partition_port_state_changes_test(unittest.TestCase):
    """Test the partition_port_state_changes function."""
    def setUp(self):
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        self.diff = scan_diff(a, b)

    def test_port_state_change_only(self):
        for host, h_diff in self.diff:
            partition = partition_port_state_changes(h_diff)
            for group in partition:
                for hunk in group:
                    self.assertTrue(isinstance(hunk, PortStateChangeHunk))

    def test_equivalence(self):
        for host, h_diff in self.diff:
            partition = partition_port_state_changes(h_diff)
            for group in partition:
                key = (group[0].spec[1], group[0].a_port.state, group[0].b_port.state)
                for hunk in group:
                    self.assertTrue(key == (hunk.spec[1], hunk.a_port.state, hunk.b_port.state))

class consolidate_port_state_changes_test(unittest.TestCase):
    """Test the consolidate_port_state_changes function."""
    def setUp(self):
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        self.diff = scan_diff(a, b)

    def test_removal(self):
        for host, h_diff in self.diff:
            consolidated = consolidate_port_state_changes(h_diff, 0)
            for hunk in h_diff:
                self.assertTrue(not isinstance(hunk, PortStateChangeHunk))

    def test_conservation(self):
        pre_length = 0
        for host, h_diff in self.diff:
            pre_length = len(h_diff)
            consolidated = consolidate_port_state_changes(h_diff, 0)
            post_length = len(h_diff) + sum(len(group) for group in consolidated)
            self.assertTrue(pre_length == post_length)

    def test_threshold(self):
        for host, h_diff in self.diff:
            for threshold in (0, 1, 2, 4, 8):
                h_diff_copy = h_diff[:]
                consolidated = consolidate_port_state_changes(h_diff_copy, threshold)
                for group in consolidated:
                    self.assertTrue(len(group) > threshold, u"Length is %d, should be > %d." % (len(group), threshold))

class port_diff_test(unittest.TestCase):
    """Test the port_diff function."""
    def test_equal(self):
        spec = (10, "tcp")
        a = Port(spec)
        b = Port(spec)
        diff = port_diff(a, b)
        self.assertTrue(len(diff) == 0)

    def test_self(self):
        p = Port((10, "tcp"))
        diff = port_diff(p, p)
        self.assertTrue(len(diff) == 0)

    def test_id_change(self):
        a = Port((10, "tcp"))
        b = Port((20, "tcp"))
        diff = port_diff(a, b)
        self.assertTrue(len(diff) == 1)
        self.assertTrue(isinstance(diff[0], PortIdChangeHunk))

    def test_state_change(self):
        spec = (10, "tcp")
        a = Port(spec)
        a.state = "open"
        b = Port(spec)
        b.state = "closed"
        diff = port_diff(a, b)
        self.assertTrue(len(diff) == 1)
        self.assertTrue(isinstance(diff[0], PortStateChangeHunk))

    def test_id_state_change(self):
        a = Port((10, "tcp"))
        a.state = "open"
        b = Port((20, "tcp"))
        b.state = "closed"
        diff = port_diff(a, b)
        self.assertTrue(len(diff) > 1)

class service_test(unittest.TestCase):
    """Test the Service class."""
    def test_to_string(self):
        serv = Service()
        self.assertTrue(serv.to_string() == u"")
        serv.name = u"ftp"
        self.assertTrue(serv.to_string() == serv.name)

    def test_version_to_string(self):
        serv = Service()
        self.assertTrue(serv.version_to_string() == u"")
        serv = Service()
        serv.product = u"FooBar"
        self.assertTrue(len(serv.version_to_string()) > 0)
        serv = Service()
        serv.version = u"1.2.3"
        self.assertTrue(len(serv.version_to_string()) > 0)
        serv = Service()
        serv.extrainfo = u"misconfigured"
        self.assertTrue(len(serv.version_to_string()) > 0)
        serv = Service()
        serv.product = u"FooBar"
        serv.version = u"1.2.3"
        # Must match Nmap output.
        self.assertTrue(serv.version_to_string() == u"%s %s" % (serv.product, serv.version))
        serv.extrainfo = u"misconfigured"
        self.assertTrue(serv.version_to_string() == u"%s %s (%s)" % (serv.product, serv.version, serv.extrainfo))

class host_test(unittest.TestCase):
    """Test the Host class."""
    def test_empty(self):
        h = Host()
        self.assertTrue(len(h.get_known_ports()) == 0)

    def test_format_name(self):
        h = Host()
        self.assertTrue(isinstance(h.format_name(), basestring))
        h.add_address("ipv4", "127.0.0.1")
        self.assertTrue(isinstance(h.format_name(), basestring))
        h.add_hostname("localhost")
        self.assertTrue(isinstance(h.format_name(), basestring))
        h.remove_address("ipv4", "127.0.0.1")

    def test_empty_get_port(self):
        h = Host()
        for num in 10, 100, 1000, 10000:
            for proto in ("tcp", "udp", "ip"):
                port = h.ports[(num, proto)]
                self.assertTrue(port.state == Port.UNKNOWN)

    def test_add_port(self):
        h = Host()
        spec = (10, "tcp")
        port = h.ports[spec]
        self.assertTrue(port.state == Port.UNKNOWN, "Port state is %s, expected %s." % (port.get_state_string(), "unknown"))
        h.add_port(Port(spec, "open"))
        self.assertTrue(len(h.get_known_ports()) == 1)
        port = h.ports[spec]
        self.assertTrue(port.state == "open", "Port state is %s, expected %s." % (port.get_state_string(), "open"))
        h.add_port(Port(spec, "closed"))
        self.assertTrue(len(h.get_known_ports()) == 1)
        port = h.ports[spec]
        self.assertTrue(port.state == "closed", "Port state is %s, expected %s." % (port.get_state_string(), "closed"))

        spec = (22, "tcp")
        port = h.ports[spec]
        self.assertTrue(port.state == Port.UNKNOWN, "Port state is %s, expected %s." % (port.get_state_string(), "unknown"))
        port = Port(spec)
        port.state = "open"
        port.service.name = "ssh"
        h.add_port(port)
        self.assertTrue(len(h.get_known_ports()) == 2)
        port = h.ports[spec]
        self.assertTrue(port.state == "open", "Port state is %s, expected %s." % (port.get_state_string(), "open"))
        self.assertTrue(port.service.name == "ssh", "Port service.name is %s, expected %s." % (port.service.name, "ssh"))

    def test_swap_ports(self):
        h = Host()
        spec_a = (10, "tcp")
        spec_b = (20, "tcp")
        h.swap_ports(spec_a, spec_b)
        self.assertTrue(h.ports[spec_a].state == Port.UNKNOWN)
        self.assertTrue(h.ports[spec_b].state == Port.UNKNOWN)
        self.assertTrue(h.ports[spec_a].spec == spec_a)
        self.assertTrue(h.ports[spec_b].spec == spec_b)
        h.add_port(Port(spec_a, "open"))
        h.swap_ports(spec_a, spec_b)
        self.assertTrue(h.ports[spec_a].state == Port.UNKNOWN)
        self.assertTrue(h.ports[spec_b].state == "open")
        self.assertTrue(h.ports[spec_a].spec == spec_a)
        self.assertTrue(h.ports[spec_b].spec == spec_b)
        h.add_port(Port(spec_a, "closed"))
        h.swap_ports(spec_a, spec_b)
        self.assertTrue(h.ports[spec_a].state == "open")
        self.assertTrue(h.ports[spec_b].state == "closed")
        self.assertTrue(h.ports[spec_a].spec == spec_a)
        self.assertTrue(h.ports[spec_b].spec == spec_b)

def host_apply_diff(host, diff):
    """Apply a host diff to the given host."""
    for hunk in diff:
        if isinstance(hunk, HostStateChangeHunk):
            assert host.state == hunk.a_state
            host.state = hunk.b_state
        elif isinstance(hunk, HostAddressAddHunk):
            host.add_address(hunk.address_type, hunk.address)
        elif isinstance(hunk, HostAddressRemoveHunk):
            host.remove_address(hunk.address_type, hunk.address)
        elif isinstance(hunk, HostHostnameAddHunk):
            host.add_hostname(hunk.hostname)
        elif isinstance(hunk, HostHostnameRemoveHunk):
            host.remove_hostname(hunk.hostname)
        elif isinstance(hunk, PortIdChangeHunk):
            host.swap_ports(hunk.a_spec, hunk.b_spec)
        elif isinstance(hunk, PortStateChangeHunk):
            port = host.ports[hunk.spec]
            assert port.state == hunk.a_port.state
            host.add_port(Port(hunk.spec, hunk.b_port.state))
            host.ports[hunk.spec].service = hunk.b_port.service
        else:
            assert False

class host_diff_test(unittest.TestCase):
    """Test the host_diff function."""
    PORT_DIFF_HUNK_TYPES = (PortIdChangeHunk, PortStateChangeHunk)
    HOST_DIFF_HUNK_TYPES = (HostStateChangeHunk,) + PORT_DIFF_HUNK_TYPES

    def test_empty(self):
        a = Host()
        b = Host()
        diff = host_diff(a, b)
        self.assertTrue(len(diff) == 0)

    def test_self(self):
        h = Host()
        h.add_port(Port((10, "tcp"), "open"))
        h.add_port(Port((22, "tcp"), "closed"))
        diff = host_diff(h, h)
        self.assertTrue(len(diff) == 0)

    def test_state_change(self):
        a = Host()
        b = Host()
        a.state = "up"
        b.state = "down"
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.HOST_DIFF_HUNK_TYPES))

    def test_state_change_unknown(self):
        a = Host()
        b = Host()
        a.state = "up"
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.HOST_DIFF_HUNK_TYPES))
        diff = host_diff(b, a)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.HOST_DIFF_HUNK_TYPES))

    def test_port_state_change(self):
        a = Host()
        b = Host()
        spec = (10, "tcp")
        a.add_port(Port(spec, "open"))
        b.add_port(Port(spec, "closed"))
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.PORT_DIFF_HUNK_TYPES))

    def test_port_state_change_unknown(self):
        a = Host()
        b = Host()
        b.add_port(Port((10, "tcp"), "open"))
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.PORT_DIFF_HUNK_TYPES))
        diff = host_diff(b, a)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.PORT_DIFF_HUNK_TYPES))

    def test_port_state_change_multi(self):
        a = Host()
        b = Host()
        a.add_port(Port((10, "tcp"), "open"))
        a.add_port(Port((20, "tcp"), "closed"))
        a.add_port(Port((30, "tcp"), "open"))
        b.add_port(Port((10, "tcp"), "open"))
        b.add_port(Port((20, "tcp"), "open"))
        b.add_port(Port((30, "tcp"), "open"))
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, self.PORT_DIFF_HUNK_TYPES))

    def test_address_add(self):
        a = Host()
        b = Host()
        a.addresses = []
        b.addresses = [("ipv4", "127.0.0.2")]
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, HostAddressAddHunk))

    def test_address_add(self):
        a = Host()
        b = Host()
        a.addresses = [("ipv4", "127.0.0.1")]
        b.addresses = []
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, HostAddressRemoveHunk))

    def test_address_add(self):
        a = Host()
        b = Host()
        a.addresses = [("ipv4", "127.0.0.1")]
        b.addresses = [("ipv4", "127.0.0.2")]
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, (HostAddressAddHunk, HostAddressRemoveHunk)))

    def test_hostname_add(self):
        a = Host()
        b = Host()
        a.hostnames = []
        b.hostnames = ["b"]
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, HostHostnameAddHunk))

    def test_hostname_remove(self):
        a = Host()
        b = Host()
        a.hostnames = ["a"]
        b.hostnames = []
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, HostHostnameRemoveHunk))

    def test_hostname_change(self):
        a = Host()
        b = Host()
        a.hostnames = ["a"]
        b.hostnames = ["b"]
        diff = host_diff(a, b)
        self.assertTrue(len(diff) > 0)
        for hunk in diff:
            self.assertTrue(isinstance(hunk, (HostHostnameAddHunk, HostHostnameRemoveHunk)))

    def test_diff_is_effective(self):
        """Test that a host diff is effective.
        This means that if the recommended changes are applied to the first host
        the hosts become the same."""
        a = Host()
        b = Host()
        a.add_port(Port((10, "tcp"), "open"))
        a.add_port(Port((20, "tcp"), "closed"))
        a.add_port(Port((40, "udp"), "open|filtered"))
        b.add_port(Port((10, "tcp"), "open"))
        b.add_port(Port((30, "tcp"), "open"))
        a.add_port(Port((40, "udp"), "open"))
        a.hostnames = ["a", "localhost"]
        a.hostnames = ["b", "localhost", "b.example.com"]
        diff = host_diff(a, b)
        host_apply_diff(a, diff)
        diff = host_diff(a, b)
        self.assertTrue(len(diff) == 0)

class scan_test(unittest.TestCase):
    """Test the Scan class."""
    def test_empty(self):
        scan = Scan()
        scan.load_from_file("test-scans/empty.xml")
        self.assertTrue(len(scan.hosts) == 0)
        self.assertTrue(scan.start_date is not None)
        self.assertTrue(scan.end_date is not None)

    def test_single(self):
        scan = Scan()
        scan.load_from_file("test-scans/single.xml")
        self.assertTrue(len(scan.hosts) == 1)

    def test_simple(self):
        """Test that the correct number of known ports is returned when there
        are no extraports."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.get_known_ports()) == 2,
            u"Expected %d known ports, got %d." % (2, len(host.get_known_ports())))

    def test_extraports(self):
        """Test that the correct number of known ports is returned when there
        are extraports in only one state."""
        scan = Scan()
        scan.load_from_file("test-scans/single.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.get_known_ports()) == 100,
            u"Expected %d known ports, got %d." % (100, len(host.get_known_ports())))

    def test_extraports_multi(self):
        """Test that the correct number of known ports is returned when there
        are extraports in more than one state."""
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.get_known_ports()) == 5,
            u"Expected %d known ports, got %d." % (5, len(host.get_known_ports())))

    def test_addresses(self):
        """Test that addresses are recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.addresses) == 1)

    def test_hostname(self):
        """Test that hostnames are recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.hostnames) == 1)
        self.assertTrue(host.hostnames[0] == u"scanme.nmap.org")

    def test_os(self):
        """Test that OS information is recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/os.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.os) > 0)

# This test is commented out because Nmap XML doesn't store any information
# about down hosts, not even the fact that they are down. Recovering the list of
# scanned hosts to infer which ones are down would involve parsing the targets
# out of the /nmaprun/@args attribute (which is non-trivial) and possibly
# looking up their addresses.
#    def test_down_state(self):
#        """Test that hosts that are not marked "up" are in the "down" state."""
#        scan = Scan()
#        scan.load_from_file("test-scans/down.xml")
#        self.assertTrue(len(scan.hosts) == 1)
#        host = scan.hosts[0]
#        self.assertTrue(host.state == "down")

def scan_apply_diff(scan, diff):
    """Apply a scan diff to the given scan."""
    for host, h_diff in diff:
        for h in scan.hosts:
            if h == host:
                break
        else:
            h = Host()
            scan.hosts.append(h)
        host_apply_diff(h, h_diff)

class scan_diff_test(unittest.TestCase):
    """Test the scan_diff function."""
    def test_self(self):
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        diff = scan_diff(scan, scan)
        self.assertTrue(len(diff) == 0)

    def test_unknown_up(self):
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        diff = scan_diff(a, b)
        for host, h_diff in diff:
            for hunk in h_diff:
                if isinstance(hunk, HostStateChangeHunk):
                    self.assertTrue(hunk.a_state == Host.UNKNOWN)
                    self.assertTrue(hunk.b_state == u"up")
                    break
            else:
                fail("No host state change found.")

    def test_up_unknown(self):
        a = Scan()
        a.load_from_file("test-scans/simple.xml")
        b = Scan()
        b.load_from_file("test-scans/empty.xml")
        diff = scan_diff(a, b)
        for host, h_diff in diff:
            for hunk in h_diff:
                if isinstance(hunk, HostStateChangeHunk):
                    self.assertTrue(hunk.a_state == u"up")
                    self.assertTrue(hunk.b_state == Port.UNKNOWN)
                    break
            else:
                fail("No host state change found.")

    def test_diff_is_effective(self):
        """Test that a scan diff is effective.
        This means that if the recommended changes are applied to the first scan
        the scans become the same."""
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        diff = scan_diff(a, b)
        self.assertTrue(len(diff) > 0)
        scan_apply_diff(a, diff)
        diff = scan_diff(a, b)
        self.assertTrue(len(diff) == 0)

class scan_diff_xml_test(unittest.TestCase):
    def setUp(self):
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        self.scan_diff = ScanDiff(a, b)
        f = StringIO.StringIO()
        self.scan_diff.print_xml(f)
        self.xml = f.getvalue()
        f.close()

    def test_well_formed(self):
        try:
            document = xml.dom.minidom.parseString(self.xml)
        except Exception, e:
            fail(u"Parsing XML diff output caused the exception: %s" % str(e))

unittest.main()
