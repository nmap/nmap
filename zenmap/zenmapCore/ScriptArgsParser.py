#!/usr/bin/env python

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# * This program is free software; you may redistribute and/or modify it    *
# * under the terms of the GNU General Public License as published by the   *
# * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
# * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
# * right to use, modify, and redistribute this software under certain      *
# * conditions.  If you wish to embed Nmap technology into proprietary      *
# * software, we sell alternative licenses (contact sales@nmap.com).        *
# * Dozens of software vendors already license Nmap technology such as      *
# * host discovery, port scanning, OS detection, version detection, and     *
# * the Nmap Scripting Engine.                                              *
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
# * As another special exception to the GPL terms, the Nmap Project grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * The Nmap Project has permission to redistribute Npcap, a packet         *
# * capturing driver and library for the Microsoft Windows platform.        *
# * Npcap is a separate work with it's own license rather than this Nmap    *
# * license.  Since the Npcap license does not permit redistribution        *
# * without special permission, our Nmap Windows binary packages which      *
# * contain Npcap may not be redistributed without special permission.      *
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
# * source code repository, it is understood (unless you specify            *
# * otherwise) that you are offering the Nmap Project the unlimited,        *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because     *
# * the inability to relicense code has caused devastating problems for     *
# * other Free Software projects (such as KDE and NASM).  We also           *
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
                raise ValueError(
                        "Only name-value pairs expected in parse_script_args.")
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
        if(len(item) == 2):  # only key/value pairs are stored
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
            ('user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},'
                'userdb=C:\\Some\\Path\\To\\File',
                [('user', 'foo'), ('pass', '",{}=bar"'),
                    ('whois', '{whodb=nofollow+ripe}'),
                    ('userdb', 'C:\\Some\\Path\\To\\File')]),
                )

    for test, expected in TESTS:
        args_dict = parse_script_args_dict(test)
        print args_dict
        args = parse_script_args(test)
        if args == expected:
            print "PASS", test
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
