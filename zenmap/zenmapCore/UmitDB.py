#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
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
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
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
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
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

# pysqlite 2.4.0 doesn't handle a unicode database name, though earlier and
# later versions do. Encode to UTF-8 as pysqlite would do internally anyway.
umitdb = umitdb.encode("UTF-8")

connection = sqlite.connect(umitdb)

# By default pysqlite will raise an OperationalError when trying to return a
# TEXT data type that is not UTF-8 (it always tries to decode text in order to
# return a unicode object). We store XML in the database, which may have a
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
        drop_string = "DROP TABLE scans;"

        try:
            self.cursor.execute(drop_string)
        except:
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
                    raise Exception(
                            "Wrong table field passed to creation method. "
                            "'%s'" % k)

            if ("nmap_xml_output" not in kargs.keys() or
                    not kargs["nmap_xml_output"]):
                raise Exception("Can't save result without xml output")

            if not self.verify_digest(
                    md5(kargs["nmap_xml_output"]).hexdigest()):
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
