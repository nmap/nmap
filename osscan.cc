
/***************************************************************************
 * osscan.cc -- Routines used for OS detection via TCP/IP fingerprinting.  *
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

#include "osscan.h"
#include "NmapOps.h"
#include "charpool.h"
#include "FingerPrintResults.h"
#include "nmap_error.h"
#include "string_pool.h"

#include <errno.h>
#include <time.h>

#include <algorithm>
#include <set>

extern NmapOps o;

template<u8 _MaxStrLen> void ShortStr<_MaxStrLen>::setStr(const char *in) {
  const char *end = in;
  while (end - in < _MaxStrLen && *++end);
  setStr(in, end);
  trunc = trunc || *end;
}
template<u8 _MaxStrLen> void ShortStr<_MaxStrLen>::setStr(const char *in, const char *end) {
  assert(end > in && in != NULL);
  int len = end - in;
  len = MIN(len, _MaxStrLen);

  int i = 0;
  for (; i < len; i++) {
    char c = in[i];
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
      str[i] = c;
    }
    else
      break;
  }
  str[i] = '\0';
  trunc = i < (end - in);
}

const char *FingerPrintScan::attr_names[static_cast<int>(MAX_ATTR)] = {
  "V", "E", "D", "OT", "CT", "CU", "PV", "DS", "DC", "G", "M", "TM", "P"
};

bool FingerPrintScan::parse(const char *str, const char *end) {
  const char *q = str, *p=str;
  int min_attr_i = 0;

  while (p < end) {
    q = strchr_p(p, end, '=');
    if (!q) {
      error("Missing '=' in SCAN line (%s)", str);
      return false;
    }
    FPstr name(p, q);
    p = q+1;
    q = strchr_p(p, end, '%');
    if (!q) {
      q = end;
    }
    for (int i = min_attr_i; i < static_cast<int>(MAX_ATTR); i++) {
      if (name == attr_names[i]) {
        values[i] = string_pool_substr(p, q);
        while (min_attr_i <= i && values[min_attr_i]) min_attr_i++;
        break;
      }
    }
    p = q + 1;
  }
  return true;
}

const char *FingerPrintScan::scan2str() const {
  static char str[2048];
  char *p = str;
  char *end = p + sizeof(str) - 1;

  if (!present)
    goto error;

  p += Snprintf(p, end - p, "SCAN(");

  for (int j = 0; j < static_cast<int>(MAX_ATTR); j++) {
    if (values[j] == NULL)
      continue;
    p += Snprintf(p, end - p, "%s=%s%%", FingerPrintScan::attr_names[j], values[j]);
    if (p > end)
      goto error;
  }

  // overwrite last '%' with ')'
  if (*(p - 1) == '%')
    *(p - 1) = ')';
  // if there were no results and there is space for it, close parenthesis
  else if (*(p - 1) == '(' && p < end)
    *p++ = ')';
  // otherwise, something went wrong.
  else
    goto error;

  *p = '\0';
  return str;

error:
  *str = '\0';
  return NULL;
}

const char *FingerPrintDef::test_attrs[NUM_FPTESTS][FP_MAX_TEST_ATTRS] = {
  /* SEQ */ {"SP", "GCD", "ISR", "TI", "CI", "II", "SS", "TS"},
  /* OPS */ {"O1", "O2", "O3", "O4", "O5", "O6"},
  /* WIN */ {"W1", "W2", "W3", "W4", "W5", "W6"},
  /* ECN */ {"R", "DF", "T", "TG", "W", "O", "CC", "Q"},
  /* T1 */ {"R", "DF", "T", "TG", "S", "A", "F", "RD", "Q"},
  /* T2 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* T3 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* T4 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* T5 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* T6 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* T7 */ {"R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"},
  /* U1 */ {"R", "DF", "T", "TG", "IPL", "UN", "RIPL", "RID", "RIPCK", "RUCK", "RUD"},
  /* IE */ {"R", "DFI", "T", "TG", "CD"}
  };

FingerPrintDef::FingerPrintDef() {
  TestDefs.reserve(NUM_FPTESTS);
  int i = 0;
  FPstr name;
#define ADD_TEST_DEF(_Name) \
  i = ID2INT(_Name); \
  name = FPstr(#_Name); \
  TestDefs.push_back(FingerTestDef(name, test_attrs[i])); \
  assert(TestDefs[i].name == name); \
  TestIdx.insert(std::make_pair(name, _Name));

  ADD_TEST_DEF(SEQ);
  ADD_TEST_DEF(OPS);
  ADD_TEST_DEF(WIN);
  ADD_TEST_DEF(ECN);
  ADD_TEST_DEF(T1);
  ADD_TEST_DEF(T2);
  ADD_TEST_DEF(T3);
  ADD_TEST_DEF(T4);
  ADD_TEST_DEF(T5);
  ADD_TEST_DEF(T6);
  ADD_TEST_DEF(T7);
  ADD_TEST_DEF(U1);
  ADD_TEST_DEF(IE);

  assert(FingerPrintDef::INVALID == INT2ID(NUM_FPTESTS));
  assert(TestDefs.size() == NUM_FPTESTS);
  assert(TestIdx.size() == NUM_FPTESTS);
};

FingerTestDef::FingerTestDef(const FPstr &n, const char *a[])
  : name(n), numAttrs(0) {
  hasR = (0 == strcmp(a[0], "R"));
  Attrs.reserve(FP_MAX_TEST_ATTRS);
  while (numAttrs < FP_MAX_TEST_ATTRS && a[numAttrs] != NULL) {
    Attr attr(a[numAttrs]);
    Attrs.push_back(attr);
    AttrIdx.insert(std::make_pair(attr.name, numAttrs));
    numAttrs++;
  }
}

FingerPrintDB::FingerPrintDB() : MatchPoints(NULL) {
}

FingerPrintDB::~FingerPrintDB() {
  std::vector<FingerPrint *>::iterator current;

  if (MatchPoints != NULL) {
    delete MatchPoints;
  }
  for (current = prints.begin(); current != prints.end(); current++) {
    (*current)->erase();
    delete *current;
  }
}

bool FingerPrintDef::parseTestStr(const char *str, const char *end) {
  const char *p = str;
  const char *q = strchr_p(p, end, '(');
  if (!q)
    return false;

  std::map<FPstr, TestID>::iterator t_i = TestIdx.find(FPstr(p, q));
  if (t_i == TestIdx.end())
    return false;

  FingerTestDef &test = getTestDef(t_i->second);
  p = q + 1;
  while ((q = strchr_p(p, end, '='))) {
    std::map<FPstr, u8>::iterator a_i = test.AttrIdx.find(FPstr(p, q));
    if (a_i == test.AttrIdx.end())
      return false;
    Attr &attr = test.Attrs[a_i->second];

    p = q + 1;
    errno = 0;
    attr.points = strtol(p, NULL, 10);
    if (errno != 0 || attr.points <= 0)
      return false;

    if (NULL == (p = strchr_p(q, end, '%')))
      break;
    p++;
  }
  return true;
}

void FingerTest::erase() {
  if (this->results) {
    delete this->results;
    this->results = NULL;
  }
}

void FingerPrint::erase() {
  for (int i=0; i < NUM_FPTESTS; i++) {
    tests[i].erase();
  }
}

/* Compare an observed value (e.g. "45") against an OS DB expression (e.g.
   "3B-47" or "8|A" or ">10"). Return true iff there's a match. The syntax uses
     < (less than)
     > (greater than)
     | (or)
     - (range)
   No parentheses are allowed. */
static bool expr_match(const char *val, const char *expr) {
  const char *p, *q, *q1;  /* OHHHH YEEEAAAAAHHHH!#!@#$!% */
  char *endptr;
  unsigned int val_num, expr_num, expr_num1;
  bool is_numeric;

  p = expr;

  val_num = strtol(val, &endptr, 16);
  is_numeric = !*endptr;
  // TODO: this could be a lot faster if we compiled fingerprints to a bytecode
  // instead of re-parsing every time.
  do {
    q = strchr(p, '|');
    if (is_numeric && (*p == '<' || *p == '>')) {
      expr_num = strtol(p + 1, &endptr, 16);
      if (endptr == q || !*endptr) {
        if ((*p == '<' && val_num < expr_num)
            || (*p == '>' && val_num > expr_num)) {
          return true;
        }
      }
    } else if (is_numeric && ((q1 = strchr(p, '-')) != NULL)) {
      expr_num = strtol(p, &endptr, 16);
      if (endptr == q1) {
        expr_num1 = strtol(q1 + 1, &endptr, 16);
        if (endptr == q || !*endptr) {
          assert(expr_num1 > expr_num);
          if (val_num >= expr_num && val_num <= expr_num1) {
            return true;
          }
        }
      }
    } else {
      if ((q && !strncmp(p, val, q - p)) || (!q && !strcmp(p, val))) {
        return true;
      }
    }
    if (q)
      p = q + 1;
  } while (q);

  return false;
}

/* Updates num_subtests and num_subtests_succeeded for a given FingerTest.
   If you want details of the match process printed, pass nonzero for 'verbose'.
   */
static void AVal_match(const FingerTest &reference, const FingerTest &fprint, const FingerTestDef &points,
                      unsigned long &num_subtests,
                      unsigned long &num_subtests_succeeded,
                      int verbose) {
  int subtests = 0, subtests_succeeded=0;
  if (!reference.results || !fprint.results)
    return;

  const std::vector<Attr> &pointsV = points.Attrs;

  const std::vector<const char *> &refV = *reference.results;
  assert(refV.size() == points.numAttrs);

  const std::vector<const char *> &fpV = *fprint.results;
  assert(refV.size() == points.numAttrs);

  for (size_t i = 0; i < points.numAttrs; i++) {
    const char *current_ref = refV[i];
    const char *current_fp = fpV[i];
    const Attr &aDef = pointsV[i];
    if (current_ref == NULL || current_fp == NULL)
      continue;
    int pointsThisTest = aDef.points;
    if (pointsThisTest < 0)
      fatal("%s: Got bogus point amount (%d) for test %s.%s", __func__, pointsThisTest, points.name.str, aDef.name.str);
    subtests += pointsThisTest;

    if (expr_match(current_fp, current_ref)) {
      subtests_succeeded += pointsThisTest;
    } else {
      if (verbose)
        log_write(LOG_PLAIN, "%s.%s: \"%s\" NOMATCH \"%s\" (%d %s)\n", points.name.str,
            aDef.name.str, current_fp,
            current_ref, pointsThisTest, (pointsThisTest == 1) ? "point" : "points");
    }
  }
  num_subtests += subtests;
  num_subtests_succeeded += subtests_succeeded;
}

/* Compares 2 fingerprints -- a referenceFP (can have expression
   attributes) with an observed fingerprint (no expressions).  If
   verbose is nonzero, differences will be printed.  The comparison
   accuracy (between 0 and 1) is returned).  If MatchPoints is not NULL, it is
   a special "fingerprints" which tells how many points each test is worth. */
double compare_fingerprints(const FingerPrint *referenceFP, const FingerPrint *observedFP,
                            const FingerPrintDef *MatchPoints, int verbose,
                            double threshold) {
  unsigned long num_subtests = 0, num_subtests_succeeded = 0;
  assert(referenceFP);
  assert(observedFP);
  // If we fall this far behind, we can't catch up
  unsigned long max_mismatch = (1.0 - threshold) * referenceFP->match.numprints;

  for (int i = 0; i < NUM_FPTESTS; i++) {
    const FingerTest &current_ref = referenceFP->tests[i];
    const FingerTest &current_fp = observedFP->tests[i];
    const FingerTestDef &points = MatchPoints->getTestDef(INT2ID(i));

    AVal_match(current_ref, current_fp, points,
        num_subtests, num_subtests_succeeded, verbose);
    if (!verbose && num_subtests - num_subtests_succeeded > max_mismatch) {
      break;
    }
  }

  assert(num_subtests_succeeded <= num_subtests);
  return (num_subtests) ? (num_subtests_succeeded / (double) num_subtests) : 0;
}

/* Takes a fingerprint and looks for matches inside the passed in
   reference fingerprint DB.  The results are stored in in FPR (which
   must point to an instantiated FingerPrintResultsIPv4 class) -- results
   will be reverse-sorted by accuracy.  No results below
   accuracy_threshold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResultsIPv4 class.  */
void match_fingerprint(const FingerPrint *FP, FingerPrintResultsIPv4 *FPR,
                       const FingerPrintDB *DB, double accuracy_threshold) {
  double FPR_entrance_requirement = accuracy_threshold; /* accuracy must be
                                                           at least this big
                                                           to be added to the
                                                           list */
  std::vector<FingerPrint *>::const_iterator current_os;
  double acc;
  int state;
  int skipfp;
  int max_prints = sizeof(FPR->matches) / sizeof(FPR->matches[0]);
  int idx;
  double tmp_acc=0.0, tmp_acc2; /* These are temp buffers for list swaps */
  FingerMatch *tmp_FP = NULL, *tmp_FP2;

  assert(FP);
  assert(FPR);
  assert(accuracy_threshold >= 0 && accuracy_threshold <= 1);

  FPR->overall_results = OSSCAN_SUCCESS;

  for (current_os = DB->prints.begin(); current_os != DB->prints.end(); current_os++) {
    skipfp = 0;

    acc = compare_fingerprints(*current_os, FP, DB->MatchPoints, 0, FPR_entrance_requirement);

    if (acc >= FPR_entrance_requirement || acc == 1.0) {

      state = 0;
      for (idx=0; idx < FPR->num_matches; idx++) {
        if (strcmp(FPR->matches[idx]->OS_name, (*current_os)->match.OS_name) == 0) {
          if (FPR->accuracy[idx] >= acc) {
            skipfp = 1; /* Skip it -- a higher version is already in list */
          } else {
            /* We must shift the list left to delete this sucker */
            memmove(FPR->matches + idx, FPR->matches + idx + 1,
                    (FPR->num_matches - 1 - idx) * sizeof(FingerPrint *));
            memmove(FPR->accuracy + idx, FPR->accuracy + idx + 1,
                    (FPR->num_matches - 1 - idx) * sizeof(double));
            FPR->num_matches--;
            FPR->accuracy[FPR->num_matches] = 0;
          }
          break; /* There can only be 1 in the list with same name */
        }
      }

      if (!skipfp) {
        /* First we check whether we have overflowed with perfect matches */
        if (acc == 1) {
          /*      error("DEBUG: Perfect match #%d/%d", FPR->num_perfect_matches + 1, max_prints); */
          if (FPR->num_perfect_matches == max_prints) {
            FPR->overall_results = OSSCAN_TOOMANYMATCHES;
            return;
          }
          FPR->num_perfect_matches++;
        }

        /* Now we add the sucker to the list */
        state = 0; /* Have not yet done the insertion */
        for (idx=-1; idx < max_prints -1; idx++) {
          if (state == 1) {
            /* Push tmp_acc and tmp_FP onto the next idx */
            tmp_acc2 = FPR->accuracy[idx+1];
            tmp_FP2 = FPR->matches[idx+1];

            FPR->accuracy[idx+1] = tmp_acc;
            FPR->matches[idx+1] = tmp_FP;

            tmp_acc = tmp_acc2;
            tmp_FP = tmp_FP2;
          } else if (FPR->accuracy[idx + 1] < acc) {
            /* OK, I insert the sucker into the next slot ... */
            tmp_acc = FPR->accuracy[idx+1];
            tmp_FP = FPR->matches[idx+1];
            FPR->matches[idx+1] = &(*current_os)->match;
            FPR->accuracy[idx+1] = acc;
            state = 1;
          }
        }
        if (state != 1) {
          fatal("Bogus list insertion state (%d) -- num_matches = %d num_perfect_matches=%d entrance_requirement=%f", state, FPR->num_matches, FPR->num_perfect_matches, FPR_entrance_requirement);
        }
        FPR->num_matches++;
        /* If we are over max_prints, one was shoved off list */
        if (FPR->num_matches > max_prints)
          FPR->num_matches = max_prints;

        /* Calculate the new min req. */
        if (FPR->num_matches == max_prints) {
          FPR_entrance_requirement = FPR->accuracy[max_prints - 1] + 0.00001;
          FPR_entrance_requirement = MIN(FPR_entrance_requirement, 1.0);
        }
      }
    }
  }

  if (FPR->num_matches == 0 && FPR->overall_results == OSSCAN_SUCCESS)
    FPR->overall_results = OSSCAN_NOMATCHES;

  return;
}

static const char *dist_method_fp_string(enum dist_calc_method method)
{
  const char *s = "";

  switch (method) {
  case DIST_METHOD_NONE:
    s = "";
    break;
  case DIST_METHOD_LOCALHOST:
    s = "L";
    break;
  case DIST_METHOD_DIRECT:
    s = "D";
    break;
  case DIST_METHOD_ICMP:
    s = "I";
    break;
  case DIST_METHOD_TRACEROUTE:
    s = "T";
    break;
  }

  return s;
}

/* Writes an informational "Test" result suitable for including at the
   top of a fingerprint.  Gives info which might be useful when the
   FPrint is submitted (eg Nmap version, etc).  Result is written (up
   to ostrlen) to the ostr var passed in */
void WriteSInfo(char *ostr, int ostrlen, bool isGoodFP,
                                const char *engine_id,
                                const struct sockaddr_storage *addr, int distance,
                                enum dist_calc_method distance_calculation_method,
                                const u8 *mac, int openTcpPort,
                                int closedTcpPort, int closedUdpPort) {
  struct tm ltime;
  int err;
  time_t timep;
  char dsbuf[10], otbuf[8], ctbuf[8], cubuf[8], dcbuf[8];
  char macbuf[16];
  timep = time(NULL);
  err = n_localtime(&timep, &ltime);
  if (err)
    error("Error in localtime: %s", strerror(err));

  otbuf[0] = '\0';
  if (openTcpPort != -1)
    Snprintf(otbuf, sizeof(otbuf), "%d", openTcpPort);
  ctbuf[0] = '\0';
  if (closedTcpPort != -1)
    Snprintf(ctbuf, sizeof(ctbuf), "%d", closedTcpPort);
  cubuf[0] = '\0';
  if (closedUdpPort != -1)
    Snprintf(cubuf, sizeof(cubuf), "%d", closedUdpPort);

  dsbuf[0] = '\0';
  if (distance != -1)
    Snprintf(dsbuf, sizeof(dsbuf), "%%DS=%d", distance);
  if (distance_calculation_method != DIST_METHOD_NONE)
    Snprintf(dcbuf, sizeof(dcbuf), "%%DC=%s", dist_method_fp_string(distance_calculation_method));
  else
    dcbuf[0] = '\0';

  macbuf[0] = '\0';
  if (mac)
    Snprintf(macbuf, sizeof(macbuf), "%%M=%02X%02X%02X", mac[0], mac[1], mac[2]);

  Snprintf(ostr, ostrlen, "SCAN(V=%s%%E=%s%%D=%d/%d%%OT=%s%%CT=%s%%CU=%s%%PV=%c%s%s%%G=%c%s%%TM=%X%%P=%s)",
                   NMAP_VERSION, engine_id, err ? 0 : ltime.tm_mon + 1, err ? 0 : ltime.tm_mday,
                   otbuf, ctbuf, cubuf, isipprivate(addr) ? 'Y' : 'N', dsbuf, dcbuf, isGoodFP ? 'Y' : 'N',
                   macbuf, (int) timep, NMAP_PLATFORM);
}

/* Puts a textual representation of the test in s.
   No more than n bytes will be written. Unless n is 0, the string is always
   null-terminated. Returns the number of bytes written, excluding the
   terminator. */
static int test2str(const FingerTest *test, char *s, const size_t n) {
  char *p;
  char *end;

  if (n == 0)
    return 0;

  p = s;
  end = s + n - 1;

  std::vector<const char *> &results = *test->results;
  p += Snprintf(p, n, "%s(", test->getTestName());
  if (p > end)
    goto error;

assert(results.size() == test->def->numAttrs);
  for (u8 i = 0; i < results.size(); i++) {
    if (results[i] == NULL)
      continue;
    p += Snprintf(p, end - p, "%s=%s%%", test->getAValName(i), results[i]);
    if (p > end)
      goto error;
  }

  // overwrite last '%' with ')'
  if (*(p - 1) == '%')
    *(p - 1) = ')';
  // if there were no results and there is space for it, close parenthesis
  else if (*(p - 1) == '(' && p < end)
    *p++ = ')';
  // otherwise, something went wrong.
  else
    goto error;

  *p = '\0';

  return p - s;

error:
  *s = '\0';

  return -1;
}

bool FingerTest::str2AVal(const char *str, const char *end) {
  assert(results);
  assert(def);
  const char *q = str, *p=str;
  u8 maxIdx = 0;
  if (!def->hasR && 0 == strncmp("R=N", str, end - str)) {
    return true;
  }
  u8 count = def->numAttrs;
  std::vector<const char *> &AVs = *results;
  for (u8 i = 0; i < count; i++) AVs[i] = NULL;

  for (u8 i = 0; i < count && p < end; i++) {
    q = strchr_p(p, end, '=');
    if (!q) {
      error("Parse error with AVal string (%s) in nmap-os-db file", str);
      return false;
    }
    std::map<FPstr, u8>::const_iterator idx = def->AttrIdx.find(FPstr(p, q));
    u8 j = idx->second;
    if (idx == def->AttrIdx.end() || AVs[j] != NULL) {
      error("Parse error with AVal string (%s) in nmap-os-db file", str);
      return false;
    }
    p = q+1;
    q = strchr_p(p, end, '%');
    if (!q) {
      q = end;
    }
    AVs[j] = string_pool_substr(p, q);
    maxIdx = MAX(maxIdx, j);
    p = q + 1;
  }
  if (p < end) {
    error("Too many values in AVal string (%s)", str);
    return false;
  }
  if (def->hasR) {
    if (maxIdx > 0) {
      assert(AVs[0] == NULL || 0 == strcmp("Y", AVs[0]));
      AVs[0] = "Y";
    }
    else {
      assert(AVs[0] == NULL || 0 == strcmp("N", AVs[0]));
      AVs[0] = "N";
    }
  }
  return true;
}

void FingerTest::setAVal(const char *attr, const char *value) {
  u8 idx = def->AttrIdx.at(attr);
  assert(idx < results->size());
  (*results)[idx] = value;
}

const char *FingerTest::getAValName(u8 index) const {
  return def->Attrs.at(index).name;
}

const char *FingerTest::getAVal(const char *attr) const {
  if (!results)
    return NULL;

  u8 idx = def->AttrIdx.at(attr);
  return results->at(idx);
}

int FingerTest::getMaxPoints() const {
  int points = 0;
  for (size_t i = 0; i < def->numAttrs; i++) {
    if ((*results)[i] != NULL)
      points += def->Attrs[i].points;
  }
  return points;
}

/* This is a less-than relation predicate that establishes the preferred order
   of tests when they are displayed. Returns true if and only if the test a
   should come before the test b. */
struct FingerTestCmp {
  bool operator()(const FingerTest* a, const FingerTest* b) const {
    if (a->id != b->id)
      return a->id < b->id;
    if (a->results == NULL) {
      return b->results != NULL;
    }
    else if (b->results == NULL) {
      return false;
    }
    const std::vector<const char *> &av_a = *a->results;
    size_t numtests = av_a.size();
    const std::vector<const char *> &av_b = *b->results;
    assert(av_b.size() == numtests);

    for (size_t i = 0; i < numtests; i++) {
      if (av_a[i] == NULL) {
        if (av_b[i] == NULL)
          continue;
        else
          return true;
      }
      else if (av_b[i] == NULL) {
        return false;
      }
      int cmp = strcmp(av_a[i], av_b[i]);
      if (cmp == 0)
        continue;
      else
        return cmp < 0;
    }
    return false;
  }
};

/* Merges the tests from several fingerprints into a character string
   representation. Tests that are identical between more than one fingerprint
   are included only once. If wrapit is true, the string is wrapped for
   submission. */
const char *mergeFPs(FingerPrint *FPs[], int numFPs, bool isGoodFP,
                           const struct sockaddr_storage *addr, int distance,
                           enum dist_calc_method distance_calculation_method,
                           const u8 *mac, int openTcpPort, int closedTcpPort,
                           int closedUdpPort, bool wrapit) {
  static char str[10240];
  static char wrapstr[10240];

  char *p;
  char *end = str + sizeof(str) - 1; /* Last byte allowed to write into */
  std::set<const FingerTest *, FingerTestCmp> tests;
  std::set<const FingerTest *, FingerTestCmp>::iterator iter;

  if (numFPs <= 0)
    return "(None)";
  else if (numFPs > 32)
    return "(Too many)";

  /* Put the tests in the proper order and ensure that tests with identical
     names are contiguous. */
  for (int i = 0; i < numFPs; i++) {
    for (int j = 0; j < NUM_FPTESTS; j++) {
      const FingerTest &ft = FPs[i]->tests[j];
      if (ft.id != FingerPrintDef::INVALID)
        tests.insert(&ft);
    }
  }

  memset(str, 0, sizeof(str));

  p = str;

  /* Lets start by writing the fake "SCAN" test for submitting fingerprints */
  WriteSInfo(p, sizeof(str), isGoodFP, "4", addr, distance, distance_calculation_method, mac, openTcpPort, closedTcpPort, closedUdpPort);
  p = p + strlen(str);
  if (!wrapit)
    *p++ = '\n';

  assert(p <= end);

  /* Append the string representation of each test to the result string. */
  for (iter = tests.begin(); iter != tests.end(); iter++) {
    int len;

    len = test2str(*iter, p, end - p + 1);
    if (len == -1)
      break;
    p += len;
    if (!wrapit) {
      if (p + 1 > end)
        break;
      *p++ = '\n';
    }
  }

  /* If we bailed out of the loop early it was because we ran out of space. */
  if (iter != tests.end())
    fatal("Merged fingerprint too long in %s.\n", __func__);

  *p = '\0';

  if (!wrapit) {
    return str;
  } else {
    /* Wrap the str. */
    int len;
    char *p1 = wrapstr;
    end = wrapstr + sizeof(wrapstr) - 1;

    p = str;

    while (*p && end-p1 >= 3) {
      len = 0;
      strcpy(p1, "OS:"); p1 += 3; len +=3;
      while (*p && len <= FP_RESULT_WRAP_LINE_LEN && end-p1 > 0) {
        *p1++ = *p++;
        len++;
      }
      if (end-p1 <= 0) {
        fatal("Wrapped result too long!\n");
        break;
      }
      *p1++ = '\n';
    }
    *p1 = '\0';

    return wrapstr;
  }
}

const char *fp2ascii(const FingerPrint *FP) {
  static char str[2048];
  char *p = str;

  if (!FP)
    return "(None)";

  for (int j = 0; j < NUM_FPTESTS; j++) {
    const FingerTest &ft = FP->tests[j];
    if (ft.id == FingerPrintDef::INVALID)
      continue;
    int len;

    len = test2str(&ft, p, sizeof(str) - (p - str));
    if (len == -1)
      break;
    p += len;
    if (p + 1 > str + sizeof(str))
      break;
    *p++ = '\n';
  }

  *p = '\0';

  return str;
}

/* Parse a 'Class' line found in the fingerprint file into the current
   FP.  Classno is the number of 'class' lines found so far in the
   current fingerprint.  The function quits if there is a parse error */
static void parse_classline(FingerPrint *FP, const char *thisline, const char *lineend, int lineno) {
  const char *begin, *end;
  struct OS_Classification os_class;

  if (!thisline || lineend - thisline < 6 || strncmp(thisline, "Class ", 6) != 0)
    fatal("Bogus line #%d (%.*s) passed to %s()", lineno, (int)(lineend - thisline), thisline, __func__);

  /* Make sure there's some content here */
  begin = thisline + 6;
  while (begin < lineend && (*begin == '|' || isspace((int) (unsigned char) *begin)))
    begin++;
  if (begin >= lineend)
    return;

  /* First let's get the vendor name. */
  begin = thisline + 6;
  end = strchr_p(begin, lineend, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  os_class.OS_Vendor = string_pool_substr_strip(begin, end);

  /* Next comes the OS family. */
  begin = end + 1;
  end = strchr_p(begin, lineend, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  os_class.OS_Family = string_pool_substr_strip(begin, end);

  /* And now the the OS generation. */
  begin = end + 1;
  end = strchr_p(begin, lineend, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  /* OS generation is handled specially: instead of an empty string it's
     supposed to be NULL. */
  while (isspace((int) (unsigned char) *begin))
    begin++;
  if (begin < end)
    os_class.OS_Generation = string_pool_substr_strip(begin, end);
  else
    os_class.OS_Generation = NULL;

  /* And finally the device type. */
  begin = end + 1;
  os_class.Device_Type = string_pool_substr_strip(begin, lineend);

  FP->match.OS_class.push_back(os_class);
}

static void parse_cpeline(FingerPrint *FP, const char *thisline, const char *lineend, int lineno) {
  const char *cpe;

  if (FP->match.OS_class.empty())
    fatal("\"CPE\" line without preceding \"Class\" at line %d", lineno);

  OS_Classification& osc = FP->match.OS_class.back();

  if (thisline == NULL || lineend - thisline < 4 || strncmp(thisline, "CPE ", 4) != 0)
    fatal("Bogus line #%d (%.*s) passed to %s()", lineno, (int)(lineend - thisline), thisline, __func__);

  /* The cpe part may be followed by whitespace-separated flags (like "auto"),
     which we ignore. */
  cpe = string_pool_strip_word(thisline + 4, lineend);
  assert(cpe != NULL);
  osc.cpe.push_back(cpe);
}

/* Parses a single fingerprint from the memory region given.  If a
   non-null fingerprint is returned, the user is in charge of freeing it
   when done.  This function does not require the fingerprint to be 100%
   complete since it is used by scripts such as scripts/fingerwatch for
   which some partial fingerpritns are OK. */
/* This function is not currently used by Nmap, but it is present here because
   it is used by fingerprint utilities that link with Nmap object files. */
ObservationPrint *parse_single_fingerprint(const FingerPrintDB *DB, const char *fprint) {
  int lineno = 0;
  const char *p, *q;
  const char *thisline, *nextline;
  const char * const end = strchr(fprint, '\0');

  ObservationPrint *ObFP = new ObservationPrint;
  FingerPrint *FP = &ObFP->fp;

  thisline = fprint;

  do /* 1 line at a time */ {
    nextline = strchr_p(thisline, end, '\n');
    if (!nextline)
      nextline = end;
    /* printf("Preparing to handle next line: %s\n", thisline); */

    while (thisline < nextline && isspace((int) (unsigned char) *thisline))
      thisline++;
    if (thisline >= nextline) {
      fatal("Parse error on line %d of fingerprint\n", lineno);
    }

    if (strncmp(thisline, "Fingerprint ", 12) == 0) {
      /* Ignore a second Fingerprint line if it appears. */
      if (FP->match.OS_name == NULL) {
        p = thisline + 12;
        while (p < nextline && isspace((int) (unsigned char) *p))
          p++;

        q = nextline;
        while (q > p && isspace((int) (unsigned char) *(q - 1)))
          q--;

        FP->match.OS_name = cp_strndup(p, q - p);
      }
    } else if (strncmp(thisline, "MatchPoints", 11) == 0) {
      p = thisline + 11;
      while (p < nextline && isspace((int) (unsigned char) *p))
        p++;
      if (p != nextline)
        fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
    } else if (strncmp(thisline, "Class ", 6) == 0) {

      parse_classline(FP, thisline, nextline, lineno);

    } else if (strncmp(thisline, "CPE ", 4) == 0) {

      parse_cpeline(FP, thisline, nextline, lineno);

    } else if (strncmp(thisline, "SCAN(", 5) == 0) {
      ObFP->scan_info.present = true;
      p = thisline + 5;
      q = strchr_p(p, nextline, ')');
      if (!q) {
        fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
      }
      if (!ObFP->scan_info.parse(p, q)) {
        fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
      }
    } else if ((q = strchr_p(thisline, nextline, '('))) {
      FingerTest test(FPstr(thisline, q), *DB->MatchPoints);
      p = q+1;
      q = strchr_p(p, nextline, ')');
      if (!q) {
        fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
      }
      if (!test.str2AVal(p, q)) {
        fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
      }
      ObFP->mergeTest(test);
    } else {
      fatal("Parse error on line %d of fingerprint: %.*s\n", lineno, (int)(nextline - thisline), thisline);
    }

    thisline = nextline + 1; /* Time to handle the next line, if there is one */
    lineno++;
  } while (thisline && thisline < end);

  return ObFP;
}


FingerPrintDB *parse_fingerprint_file(const char *fname, bool points_only) {
  FingerPrintDB *DB = NULL;
  FingerPrint *current;
  FILE *fp;
  char line[2048];
  int lineno = 0;
  bool parsingMatchPoints = false;

  DB = new FingerPrintDB;

  const char *p, *q; /* OH YEAH!!!! */

  fp = fopen(fname, "r");
  if (!fp)
    pfatal("Unable to open Nmap fingerprint file: %s", fname);

top:
  while (fgets(line, sizeof(line), fp)) {
    lineno++;
    /* Read in a record */
    if (*line == '\n' || *line == '#')
      continue;

fparse:
    if (strncmp(line, "Fingerprint", 11) == 0) {
      parsingMatchPoints = false;
      if (points_only)
        break;
      current = new FingerPrint;
    } else if (strncmp(line, "MatchPoints", 11) == 0) {
      if (DB->MatchPoints)
        fatal("Found MatchPoints directive on line %d of %s even though it has previously been seen in the file", lineno, fname);
      parsingMatchPoints = true;
    } else {
      error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
      continue;
    }

    if (parsingMatchPoints) {
      DB->MatchPoints = new FingerPrintDef();
    } else {
      DB->prints.push_back(current);
      p = line + 12;
      while (*p && isspace((int) (unsigned char) *p))
        p++;

      q = strpbrk(p, "\n#");
      if (!q)
        fatal("Parse error on line %d of fingerprint: %s", lineno, line);

      while (isspace((int) (unsigned char) *(--q)))
        ;

      if (q < p)
        fatal("Parse error on line %d of fingerprint: %s", lineno, line);

      current->match.OS_name = cp_strndup(p, q - p + 1);

      current->match.line = lineno;
    }

    /* Now we read the fingerprint itself */
    while (fgets(line, sizeof(line), fp)) {
      lineno++;
      if (*line == '#')
        continue;
      if (*line == '\n')
        break;

      q = strchr(line, '\n');

      if (0 == strncmp(line, "Fingerprint ",12)) {
        goto fparse;
      } else if (parsingMatchPoints) {
        if (!DB->MatchPoints->parseTestStr(line, q)) {
          fatal("Parse error in MatchPoints on line %d of nmap-os-db file: %s", lineno, line);
        }
      } else if (strncmp(line, "Class ", 6) == 0) {
        parse_classline(current, line, q, lineno);
      } else if (strncmp(line, "CPE ", 4) == 0) {
        parse_cpeline(current, line, q, lineno);
      } else {
        p = line;
        q = strchr(line, '(');
        if (!q) {
          error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
          goto top;
        }
        FingerTest test(FPstr(p, q), *DB->MatchPoints);
        p = q+1;
        q = strchr(p, ')');
        if (!q) {
          error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
          goto top;
        }
        if (!test.str2AVal(p, q)) {
          error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
          goto top;
        }
        current->setTest(test);
        current->match.numprints += test.getMaxPoints();
      }
    }
  }

  fclose(fp);
  return DB;
}

FingerPrintDB *parse_fingerprint_reference_file(const char *dbname) {
  char filename[256];

  if (nmap_fetchfile(filename, sizeof(filename), dbname) != 1) {
    fatal("OS scan requested but I cannot find %s file.", dbname);
  }
  /* Record where this data file was found. */
  o.loaded_data_files[dbname] = filename;

  return parse_fingerprint_file(filename, false);
}
