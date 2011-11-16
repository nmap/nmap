#!/usr/bin/env python

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

# This module parses the --script-args and stores in the form of key/value
# pairs. The logic is same as in nse_main.lua, except that values are not
# returned as tables but as strings.

import re
# "^%s*([^'\"%s{},=][^{},=]-)%s*[},=]"
unquoted_re = re.compile(r'\s*([^\'"\s{},=][^{},=]*?)\s*([},=]|$)')
# "^%s*(['\"])(.-[^\\])%1%s*[},=]"
quoted_re = re.compile(r'\s*(([\'"])(.*?[^\\])\2)\s*([},=]|$)')
# "^%s*(['\"])%1%s*[},=]"
empty_re = re.compile(r'\s*(([\'"])\2)\s*([},=]|$)')

def parse_string(s, start):
    """Parses a single string that is quoted, unquoted or empty. It returns the
    found string along with the next starting position """
    for pattern in unquoted_re, quoted_re, empty_re:
        m = pattern.match(s, start) or quoted_re.match(s, start)
        if m:
            return m.group(1), m.end(1)
        raise ValueError("No string found at %s." % repr(s[start:]))

def next_char(s, start):
    """Returns the next character and position in the string."""
    while start < len(s) and s[start].isspace():
        start += 1
    if start < len(s):
        return s[start], start
    else:
        return None, start

def parse_value(s, start):
    """If the string starting from start is a name-value pair, returns a
    name-value tuple. Otherwise returns a plain string."""
    nc, j = next_char(s, start)
    if nc == "{":
        j = parse_table(s, j)
        return s[start:j], j
    else:
        tmp, j = parse_string(s, j)
        nc, j = next_char(s, j)
        if nc == "=":
            # Key/value?
            j += 1
            begin = j
            nc, j = next_char(s, j)
            if nc == "{":
                j = parse_table(s, j)
            else:
                dummy, j = parse_string(s, j)
            return (tmp, s[begin:j]), j
        else:
            return s[start:j], j

def parse_table(s, start):
    """This function is responsible for parsing a table; i.e, a string that
    starts with '{'. It returns the position where the balancing pair of braces
    gets closed."""
    nc, j = next_char(s, start)
    if not nc or nc != "{":
        raise ValueError("No '{' found at %s." % repr(s[start:]))
    j += 1
    while True:
        nc, j = next_char(s, j)
        if nc == "}":
            # End of table.
            return j + 1
        else:
            # Replace this with a call to parse_value.
            v, j = parse_value(s, j)
            nc, j = next_char(s, j)
            if nc == ",":
                j += 1

def parse_script_args(s):
    """Main function responsible for parsing the script args and storing the
    name-value pairs in a list. If an invalid argument is present it stores the
    value as None."""
    args = []
    nc, j = next_char(s, 0)
    try:
        while nc is not None:
            val, j = parse_value(s, j)
            if type(val) == str:
                raise ValueError("Only name-value pairs expected in parse_script_args.")
            else:
                args.append(val)
            nc, j = next_char(s, j)
            if nc == ",":
                j += 1
                nc, j = next_char(s, j)
    except ValueError:
        return None
    return args

def parse_script_args_dict(raw_argument):
    """Wrapper function that copies the name-value pairs from a list into a
    dictionary."""
    args_dict = {}
    args = parse_script_args(raw_argument)
    if args is None:
        return None
    for item in args:
        if(len(item) == 2): # only key/value pairs are stored
            args_dict[item[0]] = item[1]
    return args_dict

if __name__ == '__main__':
    TESTS = (
        ('', []),
        ('a=b,c=d', [('a', 'b'), ('c', 'd')]),
        ('a="b=c"', [('a', '"b=c"')]),
        ('a="def\\"ghi"', [('a', '"def\\"ghi"')]),
        ('a={one,{two,{three}}}', [('a', '{one,{two,{three}}}')]),
        ('a={"quoted}quoted"}', [('a', '{"quoted}quoted"}')]),
        ('a="unterminated', None),
        ('user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},userdb=C:\\Some\\Path\\To\\File', [('user', 'foo'), ('pass', '",{}=bar"'), ('whois', '{whodb=nofollow+ripe}'), ('userdb', 'C:\\Some\\Path\\To\\File')]),
     )

    for test, expected in TESTS:
        args_dict = parse_script_args_dict(test)
        print args_dict
        args = parse_script_args(test)
        if args == expected:
            print "PASS" , test
            continue
        print "FAIL", test
        if args is None:
            print "Parsing error"
        else:
            print "%d args" % len(args)
            for a, v in args:
                print a, "=", v
        if expected is None:
            print "Expected parsing error"
        else:
            print "Expected %d args" % len(expected)
            for a, v in expected:
                print a, "=", v
