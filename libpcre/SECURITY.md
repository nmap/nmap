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

Previous vulnerabilities
------------------------

* CVE-2025-58050 (August 2025). Affects 10.45 only (not earlier), and is fixed
  in 10.46.

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

PCRE2 has in the past made at least one rapid release in response to
security incidents.

We have never produced an embargoed release, or provided preferential
access to security fixes to any clients.

We would aim to notify security managers from trusted downstream distributors,
such as major Linux distributions, via the `pcre2-dev` mailing list, by
publicly signalling an upcoming security release before disclosing the
vulnerability publicly, where advance notification is possible.
