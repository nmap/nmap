#!/usr/bin/env python3

# Unit tests for preservation of OS classifications in Nmap XML.

import copy
from io import StringIO
import os
import unittest
import xml.etree.ElementTree as ET

from zenmapCore.NmapParser import NmapParser


class NmapParserTest(unittest.TestCase):
    def setUp(self):
        self.xml = self.read_fixture("xml_test_osclasses.xml")

    @staticmethod
    def read_fixture(name):
        filename = os.path.join(
                os.path.dirname(__file__), os.pardir, "test", name)
        with open(filename, "r", encoding="utf-8") as source:
            return source.read()

    def set_matches(self, groups):
        root = ET.fromstring(self.xml)
        os_element = root.find("./host/os")
        template = os_element.find("./osmatch/osclass")
        for match in list(os_element):
            os_element.remove(match)
        for index, group in enumerate(groups):
            match = ET.SubElement(
                    os_element, "osmatch",
                    name="OS-%d" % index, accuracy="100", line="1")
            for label in group:
                osclass = copy.deepcopy(template)
                osclass.set("vendor", "Vendor-%s" % label)
                osclass.set("osfamily", "Family-%s" % label)
                osclass.set("osgen", label)
                match.append(osclass)
        self.xml = ET.tostring(root, encoding="unicode")

    @staticmethod
    def xml_matches(xml):
        matches = []
        for element in ET.fromstring(xml).findall("./host/os/osmatch"):
            match = dict(element.attrib)
            match["osclasses"] = [
                    dict(osclass.attrib)
                    for osclass in element.findall("osclass")]
            matches.append(match)
        return matches

    def assert_matches(self, matches, expected):
        self.assertEqual(matches, expected)
        # Each match owns its list, including empty matches.
        for index, match in enumerate(matches):
            for other in matches[index + 1:]:
                self.assertIsNot(match["osclasses"], other["osclasses"])

    def check_roundtrip(self):
        expected = self.xml_matches(self.xml)
        scan = NmapParser()
        scan.parse(StringIO(self.xml))
        self.assert_matches(scan.hosts[0].osmatches, expected)

        saved = StringIO()
        scan.write_xml(saved)
        self.assertEqual(self.xml_matches(saved.getvalue()), expected)

        reparsed = NmapParser()
        reparsed.parse(StringIO(saved.getvalue()))
        self.assert_matches(reparsed.hosts[0].osmatches, expected)

    def test_single_class(self):
        self.set_matches([["A"]])
        self.check_roundtrip()

    def test_multiple_classes(self):
        self.check_roundtrip()

    def test_consecutive_matches(self):
        self.set_matches([["A"], ["B"]])
        self.check_roundtrip()

    def test_consecutive_multiple_classes(self):
        self.set_matches([["A", "B"], ["C", "D"]])
        self.check_roundtrip()

    def test_empty_match(self):
        self.set_matches([[]])
        self.check_roundtrip()

    def test_empty_then_populated_match(self):
        self.set_matches([[], ["A"]])
        self.check_roundtrip()

    def test_populated_empty_populated_matches(self):
        self.set_matches([["A"], [], ["B"]])
        self.check_roundtrip()

    def test_no_matches(self):
        self.set_matches([])
        self.check_roundtrip()

    def test_legacy_direct_classes(self):
        scan = NmapParser()
        scan.parse(StringIO(self.read_fixture("xml_test11.xml")))
        linux_classes = [
                dict(type="general purpose", vendor="Linux",
                     osfamily="Linux", osgen=gen, accuracy="100")
                for gen in ("2.4.X", "2.5.X", "2.6.X")]
        linux_match = dict(
                name="Linux 2.4.18 - 2.6.7", accuracy="100", line="",
                osclasses=linux_classes)
        expected = [
                [linux_match],
                [dict(name="Alcatel Speed Touch *DSL modem/router",
                      accuracy="100", line="", osclasses=[
                          dict(type="broadband router", vendor="Alcatel",
                               osfamily="embedded", osgen="",
                               accuracy="100")])],
                [linux_match],
                [dict(name="Linux 2.5.25 - 2.6.3 or Gentoo 1.2 "
                           "Linux 2.4.19 rc1-rc7)",
                      accuracy="100", line="", osclasses=linux_classes),
                 dict(name="Linux 2.6.3 - 2.6.8", accuracy="100", line="",
                      osclasses=[])]]
        self.assertEqual([host.osmatches for host in scan.hosts], expected)

        saved = StringIO()
        scan.write_xml(saved)
        # Legacy direct classes are serialized inside the first match.
        root = ET.fromstring(saved.getvalue())
        self.assertEqual(root.findall("./host/os/osclass"), [])
        self.assertEqual(
                self.xml_matches(saved.getvalue()),
                [match for matches in expected for match in matches])
        reparsed = NmapParser()
        reparsed.parse(StringIO(saved.getvalue()))
        self.assertEqual(
                [host.osmatches for host in reparsed.hosts], expected)

    def test_existing_xml_fixtures_roundtrip(self):
        for number in range(1, 18):
            name = "xml_test%d.xml" % number
            with self.subTest(fixture=name):
                scan = NmapParser()
                scan.parse(StringIO(self.read_fixture(name)))
                expected = copy.deepcopy(
                        [host.osmatches for host in scan.hosts])
                saved = StringIO()
                scan.write_xml(saved)
                reparsed = NmapParser()
                reparsed.parse(StringIO(saved.getvalue()))
                self.assertEqual(
                        [host.osmatches for host in reparsed.hosts], expected)


if __name__ == "__main__":
    unittest.main()
