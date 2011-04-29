#!/usr/bin/env python

# Unit tests for Ndiff.

import subprocess
import unittest
import xml.dom.minidom
import StringIO

# The ndiff.py symlink exists so we can do this.
from ndiff import *

class scan_test(unittest.TestCase):
    """Test the Scan class."""
    def test_empty(self):
        scan = Scan()
        scan.load_from_file("test-scans/empty.xml")
        self.assertEqual(len(scan.hosts), 0)
        self.assertNotEqual(scan.start_date, None)
        self.assertNotEqual(scan.end_date, None)

    def test_single(self):
        scan = Scan()
        scan.load_from_file("test-scans/single.xml")
        self.assertEqual(len(scan.hosts), 1)

    def test_simple(self):
        """Test that the correct number of known ports is returned when there
        are no extraports."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertEqual(len(host.ports), 2)

    def test_extraports(self):
        scan = Scan()
        scan.load_from_file("test-scans/single.xml")
        host = scan.hosts[0]
        self.assertEqual(len(host.ports), 5)
        self.assertEqual(host.extraports.items(), [("filtered", 95)])

    def test_extraports_multi(self):
        """Test that the correct number of known ports is returned when there
        are extraports in more than one state."""
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        host = scan.hosts[0]
        self.assertEqual(len(host.ports), 6)
        self.assertEqual(set(host.extraports.items()), set([("filtered", 95), ("open|filtered", 99)]))

    def test_nmaprun(self):
        """Test that nmaprun information is recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/empty.xml")
        self.assertEqual(scan.scanner, u"nmap")
        self.assertEqual(scan.version, u"4.90RC2")
        self.assertEqual(scan.args, u"nmap -oX empty.xml -p 1-100")

    def test_addresses(self):
        """Test that addresses are recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertEqual(host.addresses, [IPv4Address("64.13.134.52")])

    def test_hostname(self):
        """Test that hostnames are recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/simple.xml")
        host = scan.hosts[0]
        self.assertEqual(host.hostnames, [u"scanme.nmap.org"])

    def test_os(self):
        """Test that OS information is recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.os) > 0)

    def test_script(self):
        """Test that script results are recorded."""
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        host = scan.hosts[0]
        self.assertTrue(len(host.script_results) > 0)
        self.assertTrue(len(host.ports[(22, u"tcp")].script_results) > 0)

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

class host_test(unittest.TestCase):
    """Test the Host class."""
    def test_empty(self):
        h = Host()
        self.assertEqual(len(h.addresses), 0)
        self.assertEqual(len(h.hostnames), 0)
        self.assertEqual(len(h.ports), 0)
        self.assertEqual(len(h.extraports), 0)
        self.assertEqual(len(h.os), 0)

    def test_format_name(self):
        h = Host()
        self.assertTrue(isinstance(h.format_name(), basestring))
        h.add_address(IPv4Address(u"127.0.0.1"))
        self.assertTrue(u"127.0.0.1" in h.format_name())
        h.add_address(IPv6Address("::1"))
        self.assertTrue(u"127.0.0.1" in h.format_name())
        self.assertTrue(u"::1" in h.format_name())
        h.add_hostname(u"localhost")
        self.assertTrue(u"127.0.0.1" in h.format_name())
        self.assertTrue(u"::1" in h.format_name())
        self.assertTrue(u"localhost" in h.format_name())

    def test_empty_get_port(self):
        h = Host()
        for num in 10, 100, 1000, 10000:
            for proto in ("tcp", "udp", "ip"):
                port = h.ports.get((num, proto))
                self.assertEqual(port, None)

    def test_add_port(self):
        h = Host()
        spec = (10, "tcp")
        port = h.ports.get(spec)
        self.assertEqual(port, None)
        h.add_port(Port(spec, "open"))
        self.assertEqual(len(h.ports), 1)
        port = h.ports[spec]
        self.assertEqual(port.state, "open")
        h.add_port(Port(spec, "closed"))
        self.assertEqual(len(h.ports), 1)
        port = h.ports[spec]
        self.assertEqual(port.state, "closed")

        spec = (22, "tcp")
        port = h.ports.get(spec)
        self.assertEqual(port, None)
        port = Port(spec)
        port.state = "open"
        port.service.name = "ssh"
        h.add_port(port)
        self.assertEqual(len(h.ports), 2)
        port = h.ports[spec]
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service.name, "ssh")

    def test_extraports(self):
        h = Host()
        self.assertFalse(h.is_extraports("open"))
        self.assertFalse(h.is_extraports("closed"))
        self.assertFalse(h.is_extraports("filtered"))
        h.extraports["closed"] = 10
        self.assertFalse(h.is_extraports("open"))
        self.assertTrue(h.is_extraports("closed"))
        self.assertFalse(h.is_extraports("filtered"))
        h.extraports["filtered"] = 10
        self.assertFalse(h.is_extraports("open"))
        self.assertTrue(h.is_extraports("closed"))
        self.assertTrue(h.is_extraports("filtered"))
        del h.extraports["closed"]
        del h.extraports["filtered"]
        self.assertFalse(h.is_extraports("open"))
        self.assertFalse(h.is_extraports("closed"))
        self.assertFalse(h.is_extraports("filtered"))

    def test_parse(self):
        s = Scan()
        s.load_from_file("test-scans/single.xml")
        h = s.hosts[0]
        self.assertEqual(len(h.ports), 5)
        self.assertEqual(len(h.extraports), 1)
        self.assertEqual(h.extraports.keys()[0], u"filtered")
        self.assertEqual(h.extraports.values()[0], 95)
        self.assertEqual(h.state, "up")

class address_test(unittest.TestCase):
    """Test the Address class."""
    def test_ipv4_new(self):
        a = Address.new("ipv4", "127.0.0.1")
        self.assertEqual(a.type, "ipv4")

    def test_ipv6_new(self):
        a = Address.new("ipv6", "::1")
        self.assertEqual(a.type, "ipv6")

    def test_mac_new(self):
        a = Address.new("mac", "00:00:00:00:00:00")
        self.assertEqual(a.type, "mac")

    def test_unknown_new(self):
        self.assertRaises(ValueError, Address.new, "aaa", "")

    def test_compare(self):
        """Test that addresses with the same contents compare equal."""
        a = IPv4Address("127.0.0.1")
        self.assertEqual(a, a)
        b = IPv4Address("127.0.0.1")
        self.assertEqual(a, b)
        c = Address.new("ipv4", "127.0.0.1")
        self.assertEqual(a, c)
        self.assertEqual(b, c)

        d = IPv4Address("1.1.1.1")
        self.assertNotEqual(a, d)

        e = IPv6Address("::1")
        self.assertEqual(e, e)
        self.assertNotEqual(a, e)

class port_test(unittest.TestCase):
    """Test the Port class."""
    def test_spec_string(self):
        p = Port((10, "tcp"))
        self.assertEqual(p.spec_string(), u"10/tcp")
        p = Port((100, "ip"))
        self.assertEqual(p.spec_string(), u"100/ip")

    def test_state_string(self):
        p = Port((10, "tcp"))
        self.assertEqual(p.state_string(), u"unknown")

class service_test(unittest.TestCase):
    """Test the Service class."""
    def test_compare(self):
        """Test that services with the same contents compare equal."""
        a = Service()
        a.name = u"ftp"
        a.product = u"FooBar FTP"
        a.version = u"1.1.1"
        a.tunnel = u"ssl"
        self.assertEqual(a, a)
        b = Service()
        b.name = u"ftp"
        b.product = u"FooBar FTP"
        b.version = u"1.1.1"
        b.tunnel = u"ssl"
        self.assertEqual(a, b)
        b.name = u"http"
        self.assertNotEqual(a, b)
        c = Service()
        self.assertNotEqual(a, c)

    def test_tunnel(self):
        serv = Service()
        serv.name = u"http"
        serv.tunnel = u"ssl"
        self.assertEqual(serv.name_string(), u"ssl/http")

    def test_version_string(self):
        serv = Service()
        serv.product = u"FooBar"
        self.assertTrue(len(serv.version_string()) > 0)
        serv = Service()
        serv.version = u"1.2.3"
        self.assertTrue(len(serv.version_string()) > 0)
        serv = Service()
        serv.extrainfo = u"misconfigured"
        self.assertTrue(len(serv.version_string()) > 0)
        serv = Service()
        serv.product = u"FooBar"
        serv.version = u"1.2.3"
        # Must match Nmap output.
        self.assertEqual(serv.version_string(), u"%s %s" % (serv.product, serv.version))
        serv.extrainfo = u"misconfigured"
        self.assertEqual(serv.version_string(), u"%s %s (%s)" % (serv.product, serv.version, serv.extrainfo))

class scan_diff_test(unittest.TestCase):
    """Test the ScanDiff class."""
    def test_self(self):
        scan = Scan()
        scan.load_from_file("test-scans/complex.xml")
        diff = ScanDiff(scan, scan)
        self.assertEqual(len(diff.host_diffs), 0)
        self.assertEqual(set(diff.hosts), set(diff.host_diffs.keys()))

    def test_unknown_up(self):
        a = Scan()
        a.load_from_file("test-scans/empty.xml")
        b = Scan()
        b.load_from_file("test-scans/simple.xml")
        diff = ScanDiff(a, b)
        self.assertTrue(len(diff.hosts) >= 1)
        self.assertEqual(len(diff.host_diffs), 1)
        self.assertEqual(set(diff.hosts), set(diff.host_diffs.keys()))
        h_diff = diff.host_diffs.values()[0]
        self.assertEqual(h_diff.host_a.state, None)
        self.assertEqual(h_diff.host_b.state, "up")

    def test_up_unknown(self):
        a = Scan()
        a.load_from_file("test-scans/simple.xml")
        b = Scan()
        b.load_from_file("test-scans/empty.xml")
        diff = ScanDiff(a, b)
        self.assertTrue(len(diff.hosts) >= 1)
        self.assertEqual(len(diff.host_diffs), 1)
        self.assertEqual(set(diff.hosts), set(diff.host_diffs.keys()))
        h_diff = diff.host_diffs.values()[0]
        self.assertEqual(h_diff.host_a.state, "up")
        self.assertEqual(h_diff.host_b.state, None)

    def test_diff_is_effective(self):
        """Test that a scan diff is effective. This means that if the
        recommended changes are applied to the first scan the scans become the
        same."""
        PAIRS = (
            ("empty", "empty"),
            ("simple", "complex"),
            ("complex", "simple"),
            ("single", "os"),
            ("os", "single"),
            ("random-1", "simple"),
            ("simple", "random-1"),
        )
        for pair in PAIRS:
            a = Scan()
            a.load_from_file("test-scans/%s.xml" % pair[0])
            b = Scan()
            b.load_from_file("test-scans/%s.xml" % pair[1])
            diff = ScanDiff(a, b)
            scan_apply_diff(a, diff)
            diff = ScanDiff(a, b)
            self.assertEqual(diff.host_diffs, {})
            self.assertEqual(set(diff.hosts), set(diff.host_diffs.keys()))

class host_diff_test(unittest.TestCase):
    """Test the HostDiff class."""
    def test_empty(self):
        a = Host()
        b = Host()
        diff = HostDiff(a, b)
        self.assertFalse(diff.id_changed)
        self.assertFalse(diff.state_changed)
        self.assertFalse(diff.os_changed)
        self.assertFalse(diff.extraports_changed)
        self.assertEqual(diff.cost, 0)

    def test_self(self):
        h = Host()
        h.add_port(Port((10, "tcp"), "open"))
        h.add_port(Port((22, "tcp"), "closed"))
        diff = HostDiff(h, h)
        self.assertFalse(diff.id_changed)
        self.assertFalse(diff.state_changed)
        self.assertFalse(diff.os_changed)
        self.assertFalse(diff.extraports_changed)
        self.assertEqual(diff.cost, 0)

    def test_state_change(self):
        a = Host()
        b = Host()
        a.state = "up"
        b.state = "down"
        diff = HostDiff(a, b)
        self.assertTrue(diff.state_changed)
        self.assertTrue(diff.cost > 0)

    def test_state_change_unknown(self):
        a = Host()
        b = Host()
        a.state = "up"
        diff = HostDiff(a, b)
        self.assertTrue(diff.state_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.state_changed)
        self.assertTrue(diff.cost > 0)

    def test_address_change(self):
        a = Host()
        b = Host()
        b.add_address(Address.new("ipv4", "127.0.0.1"))
        diff = HostDiff(a, b)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        a.add_address(Address.new("ipv4", "1.1.1.1"))
        diff = HostDiff(a, b)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)

    def test_hostname_change(self):
        a = Host()
        b = Host()
        b.add_hostname("host-1")
        diff = HostDiff(a, b)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        a.add_address("host-2")
        diff = HostDiff(a, b)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.id_changed)
        self.assertTrue(diff.cost > 0)

    def test_port_state_change(self):
        a = Host()
        b = Host()
        spec = (10, "tcp")
        a.add_port(Port(spec, "open"))
        b.add_port(Port(spec, "closed"))
        diff = HostDiff(a, b)
        self.assertTrue(len(diff.ports) > 0)
        self.assertEqual(set(diff.ports), set(diff.port_diffs.keys()))
        self.assertTrue(diff.cost > 0)

    def test_port_state_change_unknown(self):
        a = Host()
        b = Host()
        b.add_port(Port((10, "tcp"), "open"))
        diff = HostDiff(a, b)
        self.assertTrue(len(diff.ports) > 0)
        self.assertEqual(set(diff.ports), set(diff.port_diffs.keys()))
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(len(diff.ports) > 0)
        self.assertEqual(set(diff.ports), set(diff.port_diffs.keys()))
        self.assertTrue(diff.cost > 0)

    def test_port_state_change_multi(self):
        a = Host()
        b = Host()
        a.add_port(Port((10, "tcp"), "open"))
        a.add_port(Port((20, "tcp"), "closed"))
        a.add_port(Port((30, "tcp"), "open"))
        b.add_port(Port((10, "tcp"), "open"))
        b.add_port(Port((20, "tcp"), "open"))
        b.add_port(Port((30, "tcp"), "open"))
        diff = HostDiff(a, b)
        self.assertTrue(diff.cost > 0)

    def test_os_change(self):
        a = Host()
        b = Host()
        a.os.append("os-1")
        diff = HostDiff(a, b)
        self.assertTrue(diff.os_changed)
        self.assertTrue(len(diff.os_diffs) > 0)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.os_changed)
        self.assertTrue(len(diff.os_diffs) > 0)
        self.assertTrue(diff.cost > 0)
        b.os.append("os-2")
        diff = HostDiff(a, b)
        self.assertTrue(diff.os_changed)
        self.assertTrue(len(diff.os_diffs) > 0)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.os_changed)
        self.assertTrue(len(diff.os_diffs) > 0)
        self.assertTrue(diff.cost > 0)

    def test_extraports_change(self):
        a = Host()
        b = Host()
        a.extraports = {"open": 100}
        diff = HostDiff(a, b)
        self.assertTrue(diff.extraports_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.extraports_changed)
        self.assertTrue(diff.cost > 0)
        b.extraports = {"closed": 100}
        diff = HostDiff(a, b)
        self.assertTrue(diff.extraports_changed)
        self.assertTrue(diff.cost > 0)
        diff = HostDiff(b, a)
        self.assertTrue(diff.extraports_changed)
        self.assertTrue(diff.cost > 0)

    def test_diff_is_effective(self):
        """Test that a host diff is effective.
        This means that if the recommended changes are applied to the first host
        the hosts become the same."""
        a = Host()
        b = Host()

        a.state = "up"
        b.state = "down"

        a.add_port(Port((10, "tcp"), "open"))
        a.add_port(Port((20, "tcp"), "closed"))
        a.add_port(Port((40, "udp"), "open|filtered"))
        b.add_port(Port((10, "tcp"), "open"))
        b.add_port(Port((30, "tcp"), "open"))
        a.add_port(Port((40, "udp"), "open"))

        a.add_hostname("a")
        a.add_hostname("localhost")
        b.add_hostname("b")
        b.add_hostname("localhost")
        b.add_hostname("b.example.com")

        b.add_address(Address.new("ipv4", "1.2.3.4"))

        a.os = ["os-1", "os-2"]
        b.os = ["os-2", "os-3"]

        a.extraports = {"filtered": 99}

        diff = HostDiff(a, b)
        host_apply_diff(a, diff)
        diff = HostDiff(a, b)

        self.assertFalse(diff.id_changed)
        self.assertFalse(diff.state_changed)
        self.assertFalse(diff.os_changed)
        self.assertFalse(diff.extraports_changed)
        self.assertEqual(diff.cost, 0)

class port_diff_test(unittest.TestCase):
    """Test the PortDiff class."""
    def test_equal(self):
        spec = (10, "tcp")
        a = Port(spec)
        b = Port(spec)
        diff = PortDiff(a, b)
        self.assertEqual(diff.cost, 0)

    def test_self(self):
        p = Port((10, "tcp"))
        diff = PortDiff(p, p)
        self.assertEqual(diff.cost, 0)

    def test_state_change(self):
        spec = (10, "tcp")
        a = Port(spec)
        a.state = "open"
        b = Port(spec)
        b.state = "closed"
        diff = PortDiff(a, b)
        self.assertTrue(diff.cost > 0)
        self.assertEqual(PortDiff(a, diff.port_a).cost, 0)
        self.assertEqual(PortDiff(b, diff.port_b).cost, 0)

    def test_id_change(self):
        a = Port((10, "tcp"))
        a.state = "open"
        b = Port((20, "tcp"))
        b.state = "open"
        diff = PortDiff(a, b)
        self.assertTrue(diff.cost > 0)
        self.assertEqual(PortDiff(a, diff.port_a).cost, 0)
        self.assertEqual(PortDiff(b, diff.port_b).cost, 0)

class table_test(unittest.TestCase):
    """Test the table class."""
    def test_empty(self):
        t = Table("")
        self.assertEqual(str(t), "")
        t = Table("***")
        self.assertEqual(str(t), "")
        t = Table("* * *")
        self.assertEqual(str(t), "")

    def test_none(self):
        """Test that None is treated like an empty string when it is not at the
        end of a row."""
        t = Table("* * *")
        t.append((None, "a", "b"))
        self.assertEqual(str(t), " a b")
        t = Table("* * *")
        t.append(("a", None, "b"))
        self.assertEqual(str(t), "a  b")
        t = Table("* * *")
        t.append((None, None, "a"))
        self.assertEqual(str(t), "  a")

    def test_prefix(self):
        t = Table("<<<")
        t.append(("a", "b", "c"))
        self.assertEqual(str(t), "<<<abc")

    def test_padding(self):
        t = Table("<<<*>>>*!!!")
        t.append(())
        self.assertEqual(str(t), "<<<")
        t = Table("<<<*>>>*!!!")
        t.append(("a"))
        self.assertEqual(str(t), "<<<a>>>")
        t = Table("<<<*>>>*!!!")
        t.append(("a", "b", "c", "d"))
        self.assertEqual(str(t), "<<<a>>>b!!!cd")

    def test_append_raw(self):
        """Test the append_raw method that inserts an unformatted row."""
        t = Table("<* * *>")
        t.append(("1", "2", "3"))
        t.append_raw("   row   ")
        self.assertEqual(str(t), "<1 2 3>\n   row   ")
        t.append(("4", "5", "6"))
        self.assertEqual(str(t), "<1 2 3>\n   row   \n<4 5 6>")

    def test_strip(self):
        """Test that trailing whitespace is stripped."""
        t = Table("* * * ")
        t.append(("a", "b", None))
        self.assertEqual(str(t), "a b")
        t = Table("* * *")
        t.append(("a", None, None))
        self.assertEqual(str(t), "a")
        t = Table("* * *")
        t.append(("a", "b", ""))
        self.assertEqual(str(t), "a b")
        t = Table("* * *")
        t.append(("a", "", ""))
        self.assertEqual(str(t), "a")

    def test_newline(self):
        """Test that there is no trailing newline in a table."""
        t = Table("*")
        self.assertFalse(str(t).endswith("\n"))
        t.append(("a"))
        self.assertFalse(str(t).endswith("\n"))
        t.append(("b"))
        self.assertFalse(str(t).endswith("\n"))

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
            self.fail(u"Parsing XML diff output caused the exception: %s" % str(e))

def scan_apply_diff(scan, diff):
    """Apply a scan diff to the given scan."""
    for host in diff.hosts:
        if host not in scan.hosts:
            scan.hosts.append(host)
        host_apply_diff(host, diff.host_diffs[host])

def host_apply_diff(host, diff):
    """Apply a host diff to the given host."""
    if diff.state_changed:
        host.state = diff.host_b.state

    if diff.id_changed:
        host.addresses = diff.host_b.addresses[:]
        host.hostnames = diff.host_b.hostnames[:]

    if diff.os_changed:
        host.os = diff.host_b.os[:]

    if diff.extraports_changed:
        for state in host.extraports.keys():
            for port in host.ports.values():
                if port.state == state:
                    del host.ports[port.spec]
        host.extraports = diff.host_b.extraports.copy()

    for port in diff.ports:
        port_b = diff.port_diffs[port].port_b
        if port_b.state is None:
            del host.ports[port.spec]
        else:
            host.ports[port.spec] = diff.port_diffs[port].port_b

    for sr_diff in diff.script_result_diffs:
        sr_a = sr_diff.sr_a
        sr_b = sr_diff.sr_b
        if sr_a is None:
            host.script_results.append(sr_b)
        elif sr_b is None:
            host.script_results.remove(sr_a)
        else:
            host.script_results[host.script_results.index(sr_a)] = sr_b
    host.script_results.sort()

def call_quiet(args, **kwargs):
    """Run a command with subprocess.call and hide its output."""
    return subprocess.call(args, stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT, **kwargs)

class exit_code_test(unittest.TestCase):
    NDIFF = "./ndiff"

    def test_exit_equal(self):
        """Test that the exit code is 0 when the diff is empty."""
        for format in ("--text", "--xml"):
            code = call_quiet([self.NDIFF, format, 
                "test-scans/simple.xml", "test-scans/simple.xml"])
            self.assertEqual(code, 0)
        # Should be independent of verbosity.
        for format in ("--text", "--xml"):
            code = call_quiet([self.NDIFF, "-v", format, 
                "test-scans/simple.xml", "test-scans/simple.xml"])
            self.assertEqual(code, 0)

    def test_exit_different(self):
        """Test that the exit code is 1 when the diff is not empty."""
        for format in ("--text", "--xml"):
            code = call_quiet([self.NDIFF, format, 
                "test-scans/simple.xml", "test-scans/complex.xml"])
            self.assertEqual(code, 1)

    def test_exit_error(self):
        """Test that the exit code is 2 when there is an error."""
        code = call_quiet([self.NDIFF])
        self.assertEqual(code, 2)
        code = call_quiet([self.NDIFF, "test-scans/simple.xml"])
        self.assertEqual(code, 2)
        code = call_quiet([self.NDIFF, "test-scans/simple.xml",
            "test-scans/nonexistent.xml"])
        self.assertEqual(code, 2)
        code = call_quiet([self.NDIFF, "--nothing"])
        self.assertEqual(code, 2)

unittest.main()
