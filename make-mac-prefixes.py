#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
# Processes registered MAC address prefixes from IEEE MA-L Assignments (CSV)
# https://standards-oui.ieee.org/oui/oui.csv from stdin and outputs (to stdout)
# Nmap's "nmap-mac-prefixes" with a few additional unregistered OUIs.
#
# Usage: cat oui.csv | ./make-mac-prefixes.py > nmap-mac-prefixes
# Tip: curl https://standards-oui.ieee.org/oui/oui.csv | ./make-mac-prefixes.py
#
# Author : Esa Jokinen (oh2fih)
# ------------------------------------------------------------------------------

import sys, os, csv, re

# Sort the list by MAC prefix: True = sort, False = preserve original order.
SORT = False

HEADER = """\
# MAC prefix list generated with make-mac-prefixes.py by Esa Jokinen (oh2fih).
# Original data comes from IEEE's https://standards-oui.ieee.org/oui/oui.csv
# These values are known as Organizationally Unique Identifiers (OUIs) in 
# MAC Address Block Large (MA-L) including large blocks of EUI-48 and EUI-64.
# See https://standards.ieee.org/products-programs/regauth/\
"""

ADDITIONS = [
    "525400 QEMU virtual NIC",
    "B0C420 Bochs virtual NIC",
    "DEADCA PearPC virtual NIC",
    "00FFD1 Cooperative Linux virtual NIC",
    "080027 Oracle VirtualBox virtual NIC",
]


def main(csvdata):
    """Return processed (and optionally sorted) OUIs with ADDITIONS"""
    OUIs = []

    CSVReader = csv.reader(
        csvdata.readlines(), dialect="excel", delimiter=",", quotechar='"'
    )
    next(CSVReader, None)  # skip the headers
    for Row in CSVReader:
        if validatePrefix(Row[1]):
            OUIs.append(Row[1] + " " + shorten(decapitalize(Row[2])))
        else:
            print(f"# Invalid prefix '{Row[1]}' in {Row}", file=sys.stderr)

    if not OUIs:
        print(f"# Incorrect input format; oui.csv expected.", file=sys.stderr)
        exit(1)
    else:
        print(f"# Found {len(OUIs)} registed OUIs.", file=sys.stderr)

    for addition in ADDITIONS:
        OUIs.append(addition)
    print(f"# Added {len(ADDITIONS)} unregisted OUIs.", file=sys.stderr)

    if SORT:
        OUIs.sort()
        print(f"# Sorted by MAC prefix.", file=sys.stderr)
    return OUIs


def decapitalize(string):
    """Un-capitalize an all-caps company name"""
    decapitalized = ""
    words = string.split()

    for word in words:
        sumcaps = sum(1 for elem in word if elem.isupper())
        sumalpha = sum(1 for elem in word if elem.isalpha())
        if len(word) > 4 and sumcaps == sumalpha:
            word = word.lower().capitalize()

        if len(decapitalized) > 0:
            decapitalized = f"{decapitalized} {word}"
        else:
            decapitalized = f"{word}"

    return decapitalized


def shorten(string):
    """Rules to shorten the names a bit, such as eliminating Inc."""
    string = re.sub(r",.{1,6}$", "", string)
    string = re.sub(
        r" (Corporation|Inc|Ltd|Corp|S\.A|Co|llc|pty|l\.l\.c|s\.p\.a|b\.v)(\.|\b)",
        "",
        string,
        flags=re.IGNORECASE,
    )
    string = re.sub(r"\s+.$", "", string)
    return string


def validatePrefix(prefix):
    """Validates a MAC prefix: must consist of six hexadecimal characters"""
    if re.match(r"^([0-9a-fA-F]{6})$", prefix):
        return True
    else:
        return False


if __name__ == "__main__":
    """Reads oui.csv from stdin & print nmap-mac-prefixes to stdout"""
    if os.isatty(sys.stdin.fileno()):
        print(f"# Please provide oui.csv from a pipe.", file=sys.stderr)
        exit(1)
    print(f"{HEADER}")
    print(f"\n".join(main(sys.stdin)))
