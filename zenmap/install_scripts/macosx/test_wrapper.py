#!/usr/bin/env python

# This is a test class for the non-trivial escaping done by zenmap_wrapper.py.

import unittest

import zenmap_wrapper

class test_key_file(unittest.TestCase):
    def test_escape(self):
        TESTS = (
            ("", ""),
            ("a", "a"),
            ("a\nb\tc\rd\\e", "a\\nb\\tc\\rd\\\\e"),
            ("a\"b", "a\"b")
        )
        for test_line, expected in TESTS:
            actual = zenmap_wrapper.escape_key_file_value(test_line)
            self.assertEqual(expected, actual)

    def test_escape_first_space(self):
        # Check first-character space escaping.
        self.assert_(zenmap_wrapper.escape_key_file_value("  abc").startswith("\\s"))

    def test_substitute(self):
        original = "abc"
        replacements = {"b": "\"\\\t\r\ndef"}
        expected = "a\"\\\\\\t\\r\\ndefc"
        actual = zenmap_wrapper.substitute_key_file_line(original, replacements)
        self.assertEqual(expected, actual)

unittest.main()
