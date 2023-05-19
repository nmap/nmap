/***************************************************************************
 * osscan.h -- Routines used for OS detection via TCP/IP fingerprinting.   *
 * For more information on how this works in Nmap, see my paper at         *
 * https://nmap.org/osdetect/                                               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#ifndef OSSCAN_H
#define OSSCAN_H

#include <nbase.h>
#include <vector>
#include <map>

class Target;
class FingerPrintResultsIPv4;

#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2

/* We won't even consider matches with a lower accuracy than this */
#define OSSCAN_GUESS_THRESHOLD 0.85

/* The method used to calculate the Target::distance, included in OS
   fingerprints. */
enum dist_calc_method {
        DIST_METHOD_NONE,
        DIST_METHOD_LOCALHOST,
        DIST_METHOD_DIRECT,
        DIST_METHOD_ICMP,
        DIST_METHOD_TRACEROUTE
};

/**********************  STRUCTURES  ***********************************/

#define NUM_FPTESTS 13
  // T2-T7 and U1 have 11 attributes each
#define FP_MAX_TEST_ATTRS 11
  // RIPCK
#define FP_MAX_NAME_LEN 5

// Short alphanumeric strings.
template<u8 _MaxStrLen>
struct ShortStr {
  char str[_MaxStrLen+1];
  bool trunc;
  ShortStr() : trunc(false) {memset(str, 0, sizeof(str));}
  ShortStr(const char *s) { setStr(s); }
  ShortStr(const char *s, const char *e) { setStr(s, e); }
  void setStr(const char *in);
  void setStr(const char *in, const char *end);
  // Helpers for type conversion
  operator const char *() const {return this->str;}
  operator char *() {return this->str;}
  bool operator==(const char *other) const {
    return (!trunc && strncmp(str, other, _MaxStrLen) == 0);
  }
  bool operator==(const ShortStr &other) const {
    return (!trunc && !other.trunc
        && strncmp(str, other.str, _MaxStrLen) == 0);
  }
  bool operator!=(const ShortStr &other) const {
    return (trunc || other.trunc
        || strncmp(str, other.str, _MaxStrLen) != 0);
  }
  bool operator<(const ShortStr &other) const {
    return (trunc < other.trunc || strncmp(str, other.str, _MaxStrLen) < 0);
  }
};

typedef ShortStr<FP_MAX_NAME_LEN> FPstr;

struct Attr {
  FPstr name;
  int points;
  Attr() : name(), points(0) {}
  Attr(const char *n) : name(n), points(0) {}
};

struct FingerTestDef {
  FPstr name;
  u8 numAttrs;
  bool hasR;
  std::map<FPstr, u8> AttrIdx;
  std::vector<Attr> Attrs;

  FingerTestDef() : name(), numAttrs(0), hasR(false) {}
  FingerTestDef(const FPstr &n, const char *a[]);
};

#define ID2INT(_i) static_cast<int>(_i)
#define INT2ID(_i) static_cast<FingerPrintDef::TestID>(_i)
class FingerPrintDef {
  public:
  enum TestID { SEQ, OPS, WIN, ECN, T1, T2, T3, T4, T5, T6, T7, U1, IE, INVALID };
  static const char *test_attrs[NUM_FPTESTS][FP_MAX_TEST_ATTRS];
  FingerPrintDef();
  bool parseTestStr(const char *str, const char *end);
  FingerTestDef &getTestDef(TestID id) { return TestDefs[ID2INT(id)]; }
  const FingerTestDef &getTestDef(TestID id) const { return TestDefs[ID2INT(id)]; }
  int getTestIndex(const FPstr testname) const { return ID2INT(TestIdx.at(testname)); }
  TestID str2TestID(const FPstr testname) const { return TestIdx.at(testname); }

  private:
  std::map<FPstr, TestID> TestIdx;
  std::vector<FingerTestDef> TestDefs;
};

struct OS_Classification {
  const char *OS_Vendor;
  const char *OS_Family;
  const char *OS_Generation; /* Can be NULL if unclassified */
  const char *Device_Type;
  std::vector<const char *> cpe;
};

/* A description of an operating system: a human-readable name and a list of
   classifications. */
struct FingerMatch {
  int line; /* For reference prints, the line # in nmap-os-db */
  /* For IPv6 matches, the number of fingerprints that contributed to this
   * classification group */
  /* For IPv4 fingerprints, the number of points possible */
  unsigned short numprints;
  const char *OS_name;
  std::vector<OS_Classification> OS_class;

  FingerMatch() : line(-1), numprints(0), OS_name(NULL) {}
};

struct FingerPrintDB;
struct FingerTest {
  FingerPrintDef::TestID id;
  const FingerTestDef *def;
  std::vector<const char *> *results;
  FingerTest() : id(FingerPrintDef::INVALID), def(NULL), results(NULL) {}
  FingerTest(const FPstr &testname, const FingerPrintDef &Defs) {
    id = Defs.str2TestID(testname);
    def = &Defs.getTestDef(id);
    results = new std::vector<const char *>(def->numAttrs, NULL);
  }
  FingerTest(FingerPrintDef::TestID testid, const FingerPrintDef &Defs)
    : id(testid), results(NULL) {
      def = &Defs.getTestDef(id);
      results = new std::vector<const char *>(def->numAttrs, NULL);
    }
  FingerTest(const FingerTest &other) : id(other.id), def(other.def), results(other.results) {}
  ~FingerTest() {
    // results must be freed manually
    }
  void erase();
  bool str2AVal(const char *str, const char *end);
  void setAVal(const char *attr, const char *value);
  const char *getAVal(const char *attr) const;
  const char *getAValName(u8 index) const;
  const char *getTestName() const { return def->name.str; }
  int getMaxPoints() const;
};

/* Same struct used for reference prints (DB) and observations */
struct FingerPrint {
  FingerMatch match;
  FingerTest tests[NUM_FPTESTS];
  void erase();
  void setTest(const FingerTest &test) {
    tests[ID2INT(test.id)] = test;
  }
};

/* These structs are used in fingerprint-processing code outside of Nmap itself
 * {
 */
/* SCAN pseudo-test */
struct FingerPrintScan {
  enum Attribute { V, E, D, OT, CT, CU, PV, DS, DC, G, M, TM, P, MAX_ATTR };
  static const char *attr_names[static_cast<int>(MAX_ATTR)];

  const char *values[static_cast<int>(MAX_ATTR)];
  bool present;
  FingerPrintScan() : present(false) {memset(values, 0, sizeof(values));}
  bool parse(const char *str, const char *end);
  const char *scan2str() const;
};

/* An observation parsed from string representation */
struct ObservationPrint {
  FingerPrint fp;
  FingerPrintScan scan_info;
  std::vector<FingerTest> extra_tests;
  const char *getInfo(FingerPrintScan::Attribute attr) const {
    if (attr >= FingerPrintScan::MAX_ATTR)
      return NULL;
    return scan_info.values[static_cast<int>(attr)];
  }
  void mergeTest(const FingerTest &test) {
    FingerTest &ours = fp.tests[ID2INT(test.id)];
    if (ours.id == FingerPrintDef::INVALID)
      ours = test;
    else {
      extra_tests.push_back(test);
    }
  }
};
/* } */

/* This structure contains the important data from the fingerprint
   database (nmap-os-db) */
struct FingerPrintDB {
  FingerPrintDef *MatchPoints;
  std::vector<FingerPrint *> prints;

  FingerPrintDB();
  ~FingerPrintDB();
};

/**********************  PROTOTYPES  ***********************************/

const char *fp2ascii(const FingerPrint *FP);

/* Parses a single fingerprint from the memory region given.  If a
 non-null fingerprint is returned, the user is in charge of freeing it
 when done.  This function does not require the fingerprint to be 100%
 complete since it is used by scripts such as scripts/fingerwatch for
 which some partial fingerprints are OK. */
ObservationPrint *parse_single_fingerprint(const FingerPrintDB *DB, const char *fprint);

/* These functions take a file/db name and open+parse it, returning an
   (allocated) FingerPrintDB containing the results.  They exit with
   an error message in the case of error. */
FingerPrintDB *parse_fingerprint_file(const char *fname, bool points_only);
FingerPrintDB *parse_fingerprint_reference_file(const char *dbname);

void free_fingerprint_file(FingerPrintDB *DB);

/* Compares 2 fingerprints -- a referenceFP (can have expression
   attributes) with an observed fingerprint (no expressions).  If
   verbose is nonzero, differences will be printed.  The comparison
   accuracy (between 0 and 1) is returned).  MatchPoints is
   a special "fingerprints" which tells how many points each test is worth. */
double compare_fingerprints(const FingerPrint *referenceFP, const FingerPrint *observedFP,
                            const FingerPrintDef *MatchPoints, int verbose, double threshold);

/* Takes a fingerprint and looks for matches inside the passed in
   reference fingerprint DB.  The results are stored in in FPR (which
   must point to an instantiated FingerPrintResultsIPv4 class) -- results
   will be reverse-sorted by accuracy.  No results below
   accuracy_threshold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResultsIPv4 class.  */
void match_fingerprint(const FingerPrint *FP, FingerPrintResultsIPv4 *FPR,
                       const FingerPrintDB *DB, double accuracy_threshold);

/* Returns true if perfect match -- if num_subtests & num_subtests_succeeded are non_null it updates them.  if shortcircuit is zero, it does all the tests, otherwise it returns when the first one fails */

void WriteSInfo(char *ostr, int ostrlen, bool isGoodFP,
                                const char *engine_id,
                                const struct sockaddr_storage *addr, int distance,
                                enum dist_calc_method distance_calculation_method,
                                const u8 *mac, int openTcpPort,
                                int closedTcpPort, int closedUdpPort);
const char *mergeFPs(FingerPrint *FPs[], int numFPs, bool isGoodFP,
                           const struct sockaddr_storage *addr, int distance,
                           enum dist_calc_method distance_calculation_method,
                           const u8 *mac, int openTcpPort, int closedTcpPort,
                           int closedUdpPort, bool wrapit);

#endif /*OSSCAN_H*/

