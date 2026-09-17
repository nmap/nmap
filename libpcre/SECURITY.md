Security policies
=================

Release security
----------------

The PCRE2 project provides source-only releases, with no binaries.

These source releases can be downloaded from the
[GitHub Releases](https://github.com/PCRE2Project/pcre2/releases) page. Each
release file is GPG-signed.

* Releases up to and including 10.44 are signed by Philip Hazel (GPG key:
  <kbd>45F68D54BBE23FB3039B46E59766E084FB0F43D8</kbd>)
* Releases from 10.45 onwards will be signed by Nicholas Wilson (GPG key:
  <kbd>A95536204A3BB489715231282A98E77EB6F24CA8</kbd>, cross-signed by Philip
  Hazel's key for release continuity)

From releases 10.45 onwards, the source code will additionally be provided via
Git checkout of the (GPG-signed) release tag.

Please contact the maintainers for any queries about release integrity or the
project's supply-chain.

Support lifecycle
-----------------

See the documentation under [SUPPORT-LIFECYCLE](./SUPPORT-LIFECYCLE.md) for
details on how to distribute versions of PCRE2 older than the latest, with
backported security and high-severity bug fixes.

Reporting vulnerabilities
-------------------------

The PCRE2 project prioritises security. We appreciate third-party testing and
security research, and would be grateful if you could responsibly disclose your
findings to us. We will make every effort to acknowledge your contributions.

To report a security issue, please use the GitHub Security Advisory
["Report a Vulnerability"](https://github.com/PCRE2Project/pcre2/security/advisories/new)
tab. (Alternatively, if you prefer you may send a GPG-encrypted email to one of
the maintainers.)

### Timeline

As a very small volunteer team, we cannot guarantee rapid response, but would
aim to respond within 1 week, or perhaps 2 during holidays.

### Response procedure

PCRE2 has in the past made rapid releases in response to security incidents.

We have never produced an embargoed release, or provided preferential
access to security fixes to any clients.

We would aim to notify security managers from trusted downstream distributors,
such as major Linux distributions, via the `pcre2-dev` mailing list, by
publicly signalling an upcoming security release before disclosing the
vulnerability publicly, where advance notification is possible.

Previous vulnerabilities
------------------------

* GHSA-2p8c-ff85-vh9x (July 2026). Affects 10.47 and earlier, and is fixed
  in 10.48.
* GHSA-3r4p-g7gg-ppmf (July 2026). Affects 10.32-10.47, and is fixed in 10.48.
* GHSA-q8g2-wprr-34m9 (May 2026). Affects 10.30-10.47, and is fixed in 10.48.
* GHSA-9qww-pwc4-77qq (May 2026). Affects 10.34-10.47, and is fixed in 10.48.
* GHSA-fmgr-6ggq-9859 (January 2026). Affects 10.47 and earlier, and is fixed
  in 10.48.
* GHSA-q7rw-r7qq-2hx6 (October 2025). Affects 10.45 and later, and is fixed in
  10.48.
* CVE-2025-58050 [GHSA-c2gv-xgf5-5cc2] (August 2025). Affects 10.45 only (not
  earlier), and is fixed in 10.46.
* CVE-2022-41409 (July 2023). Only affects test code; no expected impact. Fixed
  in 10.41.
* CVE-2022-1587 and CVE-2022-1586 (May 2020). Affect versions before 10.40, and
  fixed in 10.40.
* CVE-2019-20454 (February 2020). Affects versions 10.31 to 10.33, and is fixed
  in 10.34.
* CVE-2017-8786 (May 2017). Only affects test code. Fixed in 10.30.
* CVE-2017-8399 (May 2017). High severity. Fixed in 10.30.
* CVE-2017-7186 (March 2017). Fixed in 10.30.
* CVE-2016-3191 (March 2016). High severity. Fixed in 10.22.
* CVE-2015-8381, CVE-2015-3217 and CVE-2015-3210 (December 2015). High severity.
  Fixed in 10.20.

Common Platform Enumeration (CPE) names:
* CPE name version 2.3: `cpe:2.3:a:pcre:pcre2:-:*:*:*:*:*:*:*`
* CPE name version 2.2: `cpe:/a:pcre:pcre2:-`
