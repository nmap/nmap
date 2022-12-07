#!/usr/bin/env python3

# This program acts like xgettext, specialized to extract strings from Zenmap's
# profile_editor.xml file.

import getopt
import os
import sys

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax

directory = None


def escape(s):
    return '"' + s.replace('"', '\\"') + '"'


def output_msgid(msgid, locator):
    print()
    print("#: %s:%d" % (locator.getSystemId(), locator.getLineNumber()))
    print("msgid", escape(msgid))
    print("msgstr", escape(""))


class Handler (xml.sax.handler.ContentHandler):
    def setDocumentLocator(self, locator):
        self.locator = locator

    def startElement(self, name, attrs):
        if name == "group":
            output_msgid(attrs["name"], self.locator)
        if attrs.get("short_desc"):
            output_msgid(attrs["short_desc"], self.locator)
        if attrs.get("label"):
            output_msgid(attrs["label"], self.locator)

opts, filenames = getopt.gnu_getopt(sys.argv[1:], "D:", ["directory="])
for o, a in opts:
    if o == "-D" or o == "--directory":
        directory = a

if directory is not None:
    os.chdir(directory)

for fn in filenames:
    with open(fn, "r") as f:
        parser = xml.sax.make_parser()
        parser.setContentHandler(Handler())
        parser.parse(f)

if len(filenames) < 2:
    parser = xml.sax.make_parser()
    parser.setContentHandler(Handler())
    parser.parse
