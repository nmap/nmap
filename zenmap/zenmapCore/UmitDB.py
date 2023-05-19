#!/usr/bin/env python3

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
# * Project"). Nmap is also a registered trademark of the Nmap Project.
# *
# * This program is distributed under the terms of the Nmap Public Source
# * License (NPSL). The exact license text applying to a particular Nmap
# * release or source code control revision is contained in the LICENSE
# * file distributed with that version of Nmap or source code control
# * revision. More Nmap copyright/legal information is available from
# * https://nmap.org/book/man-legal.html, and further information on the
# * NPSL license itself can be found at https://nmap.org/npsl/ . This
# * header summarizes some key points from the Nmap license, but is no
# * substitute for the actual license text.
# *
# * Nmap is generally free for end users to download and use themselves,
# * including commercial use. It is available from https://nmap.org.
# *
# * The Nmap license generally prohibits companies from using and
# * redistributing Nmap in commercial products, but we sell a special Nmap
# * OEM Edition with a more permissive license and special features for
# * this purpose. See https://nmap.org/oem/
# *
# * If you have received a written Nmap license agreement or contract
# * stating terms other than these (such as an Nmap OEM license), you may
# * choose to use and redistribute Nmap under those terms instead.
# *
# * The official Nmap Windows builds include the Npcap software
# * (https://npcap.com) for packet capture and transmission. It is under
# * separate license terms which forbid redistribution without special
# * permission. So the official Nmap Windows builds may not be redistributed
# * without special permission (such as an Nmap OEM license).
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# * This also allows you to audit the software for security holes.
# *
# * Source code also allows you to port Nmap to new platforms, fix bugs, and add
# * new features. You are highly encouraged to submit your changes as a Github PR
# * or by email to the dev@nmap.org mailing list for possible incorporation into
# * the main distribution. Unless you specify otherwise, it is understood that
# * you are offering us very broad rights to use your submissions as described in
# * the Nmap Public Source License Contributor Agreement. This is important
# * because we fund the project by selling licenses with various terms, and also
# * because the inability to relicense code has caused devastating problems for
# * other Free Software projects (such as KDE and NASM).
# *
# * The free version of Nmap is distributed in the hope that it will be
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
# * indemnification and commercial support are all available through the
# * Npcap OEM program--see https://nmap.org/oem/
# *
# ***************************************************************************/

import sqlite3
import sys

from hashlib import md5
from time import time

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log


umitdb = ""

try:
    umitdb = Path.db
except Exception:
    import os.path
    from .BasePaths import base_paths

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

connection = sqlite3.connect(umitdb)


class Table(object):
    def __init__(self, table_name):
        self.table_name = table_name
        self.table_id = "%s_id" % table_name

        self.cursor = connection.cursor()

    def get_item(self, item_name):
        if self.__getattribute__("_%s" % item_name):
            return self.__getattribute__("_%s" % item_name)

        sql = "SELECT %s FROM %s WHERE %s_id = %s" % (
                item_name,
                self.table_name,
                self.table_name,
                self.__getattribute__(self.table_id))

        self.cursor.execute(sql)

        self.__setattr__("_%s" % item_name, self.cursor.fetchall()[0][0])
        return self.__getattribute__("_%s" % item_name)

    def set_item(self, item_name, item_value):
        if item_value == self.__getattribute__("_%s" % item_name):
            return None

        sql = "UPDATE %s SET %s = ? WHERE %s_id = %s" % (
                self.table_name,
                item_name,
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

        sql = sql[:][:-2]
        sql += ") VALUES ("

        for v in range(len(kargs.values())):
            sql += "?, "

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
        drop_string = "DROP TABLE scans;"

        try:
            self.cursor.execute(drop_string)
        except Exception:
            connection.rollback()
        else:
            connection.commit()

        creation_string = """CREATE TABLE scans (
            scans_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_name TEXT,
            nmap_xml_output TEXT,
            digest TEXT,
            date INTEGER)"""

        self.cursor.execute(creation_string)
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
        log.debug(">>> Removing results older than %s seconds" % save_time)
        self.cursor.execute("SELECT scans_id FROM scans WHERE date < ?",
                (time() - save_time,))

        for sid in [sid[0] for sid in self.cursor.fetchall()]:
            log.debug(">>> Removing results with scans_id %s" % sid)
            self.cursor.execute("DELETE FROM scans WHERE scans_id = ?",
                    (sid, ))

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
                    raise Exception(
                            "Wrong table field passed to creation method. "
                            "'%s'" % k)

            if ("nmap_xml_output" not in kargs.keys() or
                    not kargs["nmap_xml_output"]):
                raise Exception("Can't save result without xml output")

            if not self.verify_digest(
                    md5(kargs["nmap_xml_output"].encode("UTF-8")).hexdigest()):
                raise Exception("XML output registered already!")

            self.scans_id = self.insert(**kargs)

    def verify_digest(self, digest):
        self.cursor.execute(
                "SELECT scans_id FROM scans WHERE digest = ?", (digest, ))
        result = self.cursor.fetchall()
        if result:
            return False
        return True

    def add_host(self, **kargs):
        kargs.update({self.table_id: self.scans_id})
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
        self.set_item("digest", md5(nmap_xml_output.encode("UTF-8")).hexdigest())

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
    except sqlite3.OperationalError:
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
    print("Scans:", end=' ')
    pprint(u.cursor.fetchall())
