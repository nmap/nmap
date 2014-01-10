#!/usr/bin/env python

# Anonymize an Nmap XML file, replacing host name and IP addresses with random
# anonymous ones. Anonymized names will be consistent between runs of the
# program. Any servicefp attributes are removed. Give a file name as an
# argument. The anonymized file is written to stdout.
#
# The anonymization is not rigorous. This program just matches regular
# expressions against things that look like address and host names. It is
# possible that it will leave some identifying information.

import hashlib
import random
import re
import sys

VERBOSE = True

r = random.Random()


def hash(s):
    digest = hashlib.sha512(s).hexdigest()
    return int(digest, 16)


def anonymize_mac_address(addr):
    r.seed(hash(addr))
    nums = (0, 0, 0) + tuple(r.randrange(256) for i in range(3))
    return u":".join(u"%02X" % x for x in nums)


def anonymize_ipv4_address(addr):
    r.seed(hash(addr))
    nums = (10,) + tuple(r.randrange(256) for i in range(3))
    return u".".join(unicode(x) for x in nums)


def anonymize_ipv6_address(addr):
    r.seed(hash(addr))
    # RFC 4193.
    nums = (0xFD00 + r.randrange(256),)
    nums = nums + tuple(r.randrange(65536) for i in range(7))
    return u":".join("%04X" % x for x in nums)

# Maps to memoize address and host name conversions.
hostname_map = {}
address_map = {}


def anonymize_hostname(name):
    if name in hostname_map:
        return hostname_map[name]
    LETTERS = "acbdefghijklmnopqrstuvwxyz"
    r.seed(hash(name))
    length = r.randrange(5, 10)
    prefix = u"".join(r.sample(LETTERS, length))
    num = r.randrange(1000)
    hostname_map[name] = u"%s-%d.example.com" % (prefix, num)
    if VERBOSE:
        print >> sys.stderr, "Replace %s with %s" % (name, hostname_map[name])
    return hostname_map[name]

mac_re = re.compile(r'\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')
ipv4_re = re.compile(r'\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
ipv6_re = re.compile(r'\b([0-9a-fA-F]{1,4}::?){3,}[0-9a-fA-F]{1,4}\b')


def anonymize_address(addr):
    if addr in address_map:
        return address_map[addr]
    if mac_re.match(addr):
        address_map[addr] = anonymize_mac_address(addr)
    elif ipv4_re.match(addr):
        address_map[addr] = anonymize_ipv4_address(addr)
    elif ipv6_re.match(addr):
        address_map[addr] = anonymize_ipv6_address(addr)
    else:
        assert False
    if VERBOSE:
        print >> sys.stderr, "Replace %s with %s" % (addr, address_map[addr])
    return address_map[addr]


def repl_addr(match):
    addr = match.group(0)
    anon_addr = anonymize_address(addr)
    return anon_addr


def repl_hostname_name(match):
    name = match.group(1)
    anon_name = anonymize_hostname(name)
    return r'<hostname name="%s"' % anon_name


def repl_hostname(match):
    name = match.group(1)
    anon_name = anonymize_hostname(name)
    return r'hostname="%s"' % anon_name


def anonymize_file(f):
    for line in f:
        repls = []
        line = re.sub(mac_re, repl_addr, line)
        line = re.sub(ipv4_re, repl_addr, line)
        line = re.sub(ipv6_re, repl_addr, line)
        line = re.sub(r'<hostname name="([^"]*)"', repl_hostname_name, line)
        line = re.sub(r'\bhostname="([^"]*)"', repl_hostname, line)
        line = re.sub(r' *\bservicefp="([^"]*)"', r'', line)
        yield line


def main():
    filename = sys.argv[1]
    f = open(filename, "r")
    for line in anonymize_file(f):
        sys.stdout.write(line)
    f.close()

if __name__ == "__main__":
    main()
