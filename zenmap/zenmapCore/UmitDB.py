#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import sys

try:
    import hashlib
    md5 = hashlib.md5
except ImportError:
    import md5
    md5 = md5.new

sqlite = None
try:
    from pysqlite2 import dbapi2 as sqlite
except ImportError:
    try:
        # In case this script is been running under python2.5 with sqlite3
        import sqlite3 as sqlite
    except ImportError:
        raise ImportError(_("No module named dbapi2.pysqlite2 or sqlite3"))

from time import time

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log


umitdb = ""

try:
    umitdb = Path.db
except:
    import os.path
    from BasePaths import base_paths

    umitdb = os.path.join(Path.user_config_dir, base_paths["db"])
    Path.db = umitdb


from os.path import exists, dirname
from os import access, R_OK, W_OK

using_memory = False
if not exists(umitdb) or \
   not access(umitdb, R_OK and W_OK) or \
   not access(dirname(umitdb), R_OK and W_OK):
    # Tells sqlite to use memory instead of a physics file to avoid crash
    # and still serve user with most features
    umitdb = ":memory:"
    using_memory = True

if isinstance(umitdb, str):
    fs_enc = sys.getfilesystemencoding()
    if fs_enc is None:
        fs_enc = "UTF-8"
    umitdb = umitdb.decode(fs_enc)

# pyslite 2.4.0 doesn't handle a unicode database name, though earlier and later
# versions do. Encode to UTF-8 as pysqlite would do internally anyway.
umitdb = umitdb.encode("UTF-8")

connection = sqlite.connect(umitdb)

# By default pysqlite will raise an OperationalError when trying to return a
# TEXT data type that is not UTF-8 (it always tries to decode text in order to
# return a unicdoe object). We store XML in the database, which may have a
# different encoding, so instruct pysqlite to return a plain str for TEXT data
# types, and not to attempt any decoding.
try:
    connection.text_factory = str
except AttributeError:
    # However, text_factory is available only in pysqlite 2.1.0 and later.
    pass

class Table(object):
    def __init__(self, table_name):
        self.table_name = table_name
        self.table_id = "%s_id" % table_name

        self.cursor = connection.cursor()

    def get_item(self, item_name):
        if self.__getattribute__("_%s" % item_name):
            return self.__getattribute__("_%s" % item_name)

        sql = "SELECT %s FROM %s WHERE %s_id = %s" % (item_name, self.table_name,
                                                      self.table_name,
                                                      self.__getattribute__(self.table_id))

        self.cursor.execute(sql)

        self.__setattr__("_%s" % item_name, self.cursor.fetchall()[0][0])
        return self.__getattribute__("_%s" % item_name)

    def set_item(self, item_name, item_value):
        if item_value == self.__getattribute__("_%s" % item_name):
            return None

        sql = "UPDATE %s SET %s = ? WHERE %s_id = %s" % (self.table_name, item_name,
                                                         self.table_name,
                                                         self.__getattribute__(self.table_id))
        self.cursor.execute(sql, (item_value,))
        connection.commit()
        self.__setattr__("_%s" % item_name, item_value)

    def insert(self, **kargs):
        sql = "INSERT INTO %s ("
        for k in kargs.keys():
            sql += k
            sql += ", "
        else:
            sql = sql[:][:-2]
            sql += ") VALUES ("

        for v in xrange(len(kargs.values())):
            sql += "?, "
        else:
            sql = sql[:][:-2]
            sql += ")"

        sql %= self.table_name

        self.cursor.execute(sql, tuple(kargs.values()))
        connection.commit()

        sql = "SELECT MAX(%s_id) FROM %s;" % (self.table_name, self.table_name)
        self.cursor.execute(sql)
        return self.cursor.fetchall()[0][0]

class UmitDB(object):
    def __init__(self):
        self.cursor = connection.cursor()

    def create_db(self):
        drop_string = ("DROP TABLE scans;",)

        try:
            for d in drop_string:
                self.cursor.execute(d)
        except:
            connection.rollback()
        else:
            connection.commit()


        creation_string = ("""CREATE TABLE scans (scans_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                  scan_name TEXT,
                                                  nmap_xml_output TEXT,
                                                  digest TEXT,
                                                  date INTEGER)""",)

        for c in creation_string:
            self.cursor.execute(c)
            connection.commit()

    def add_scan(self, **kargs):
        return Scans(**kargs)

    def get_scans_ids(self):
        sql = "SELECT scans_id FROM scans;"
        self.cursor.execute(sql)
        return [sid[0] for sid in self.cursor.fetchall()]

    def get_scans(self):
        scans_ids = self.get_scans_ids()
        for sid in scans_ids:
            yield Scans(scans_id=sid)

    def cleanup(self, save_time):
        log.debug(">>> Cleaning up data base.")
        log.debug(">>> Removing results olders than %s seconds" % save_time)
        self.cursor.execute("SELECT scans_id FROM scans WHERE date < ?", (time() - save_time,))

        for sid in [sid[0] for sid in self.cursor.fetchall()]:
            log.debug(">>> Removing results with scans_id %s" % sid)
            self.cursor.execute("DELETE FROM scans WHERE scans_id = ?", (sid, ))
        else:
            connection.commit()
            log.debug(">>> Data base successfully cleaned up!")


class Scans(Table, object):
    def __init__(self, **kargs):
        Table.__init__(self, "scans")
        if "scans_id" in kargs.keys():
            self.scans_id = kargs["scans_id"]
        else:
            log.debug(">>> Creating new scan result entry at data base")
            fields = ["scan_name", "nmap_xml_output", "date"]

            for k in kargs.keys():
                if k not in fields:
                    raise Exception("Wrong table field passed to creation method. '%s'" % k)

            if "nmap_xml_output" not in kargs.keys() or not kargs["nmap_xml_output"]:
                raise Exception("Can't save result without xml output")

            if not self.verify_digest(md5(kargs["nmap_xml_output"]).hexdigest()):
                raise Exception("XML output registered already!")

            self.scans_id = self.insert(**kargs)

    def verify_digest(self, digest):
        self.cursor.execute("SELECT scans_id FROM scans WHERE digest = ?", (digest, ))
        result = self.cursor.fetchall()
        if result:
            return False
        return True

    def add_host(self, **kargs):
        kargs.update({self.table_id:self.scans_id})
        return Hosts(**kargs)

    def get_hosts(self):
        sql = "SELECT hosts_id FROM hosts WHERE scans_id= %s" % self.scans_id

        self.cursor.execute(sql)
        result = self.cursor.fetchall()

        for h in result:
            yield Hosts(hosts_id=h[0])

    def get_scans_id(self):
        return self._scans_id

    def set_scans_id(self, scans_id):
        if scans_id != self._scans_id:
            self._scans_id = scans_id

    def get_scan_name(self):
        return self.get_item("scan_name")

    def set_scan_name(self, scan_name):
        self.set_item("scan_name", scan_name)

    def get_nmap_xml_output(self):
        return self.get_item("nmap_xml_output")

    def set_nmap_xml_output(self, nmap_xml_output):
        self.set_item("nmap_xml_output", nmap_xml_output)
        self.set_item("digest", md5(nmap_xml_output).hexdigest())

    def get_date(self):
        return self.get_item("date")

    def set_date(self, date):
        self.set_item("date", date)

    scans_id = property(get_scans_id, set_scans_id)
    scan_name = property(get_scan_name, set_scan_name)
    nmap_xml_output = property(get_nmap_xml_output, set_nmap_xml_output)
    date = property(get_date, set_date)

    _scans_id = None
    _scan_name = None
    _nmap_xml_output = None
    _date = None


######################################################################
# Verify if data base exists and if it does have the required tables.
# If something is wrong, re-create table
def verify_db():
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT scans_id FROM scans WHERE date = 0")
    except sqlite.OperationalError:
        u = UmitDB()
        u.create_db()
verify_db()

######################################################################

if __name__ == "__main__":
    from pprint import pprint

    u = UmitDB()

    #print "Creating Data Base"
    #u.create_db()

    #print "Creating new scan"
    #s = u.add_scan(scan_name="Fake scan", nmap_xml_output="", date="007")

    #s = Scans(scans_id=2)
    #print s.scans_id
    #print s.scan_name
    #print s.nmap_xml_output
    #print s.date

    sql = "SELECT * FROM scans;"
    u.cursor.execute(sql)
    print "Scans:",
    pprint(u.cursor.fetchall())
