# PCRE2 Support Lifecycle

This document outlines the support lifecycle policy for PCRE2 releases. It is
intended to provide clear guidance to distributors on the supported versions of
PCRE2, and the actions required to distribute older versions of PCRE2 securely.

## Release policy

PCRE2 releases follow a rolling version policy. There is one linear history of
releases, with each new release providing a mixture of enhancements and fixes to
the previous release.

PCRE2 is designed to have a high level of backwards-compatibility and stability.
Where possible, we recommend that consumers of the library update to the latest
version.

However, we recognise that Linux distributions in particular bundle older
versions for many years. To enable this practice, this document provides advice
on how to package and distribute older releases of PCRE2.

This document will be updated with each new PCRE2 release to reflect the current
support status and any new lifecycle recommendations.

## Actions for PCRE2 distributors and packagers

* Check this document on each release of PCRE2.
* Each version of PCRE2 that you are supporting should be listed here.
* Check for changes in that version's "backports to apply" section. Apply
  commits from the release branch according to your distribution's backporting
  criteria.

The patches are made available in two ways:

* For tarball-based workflows, I am including the dump of the commits
  containing the changes to be backported. These flat files record the
  canonical changes, but may require adaptation to an old release.

* For git-based workflows (preferable), I am publishing a release branch for
  each release - for example, `release/pcre2-10.47`. This branch will always
  be ahead of the `pcre2-10.47` release tag, and the additional commits
  consist of the cherry-picked commits, with approved and tested conflict
  resolutions applied.

  To apply all recommended commits for a release, fetch its branch and
  merge (or cherry-pick) the commits after the release tag.

## Support Policy

1. Each PCRE2 version will be supported for at least 5 years from its release
   date.
2. Selected releases older than 5 years may continue to receive support if they
   are actively distributed.
3. For supported versions, security and high-severity bug fixes will be
   backported and listed in this document.

The following distributions have been considered to determine support
requirements:

- RHEL/CentOS/Fedora: Long lifecycle. Although it's listed at 10+ years, there
  is effectively a freeze after five years of "Full Support", with presumably only
  CVE fixes being backported after that during "Maintenance Support".

  Packages: https://src.fedoraproject.org/rpms/pcre2

  Packages: https://gitlab.com/redhat/centos-stream/rpms/pcre2

- Debian: Five year lifecycle. There is a three-year period of full support. In
  practice, backports to "oldoldstable" releases are made only if absolutely
  required, such as a CVE that requires fixing for compliance reasons. The
  "stable" and "oldstable" releases actively accumulate backported fixes.

  Packages: https://tracker.debian.org/pkg/pcre2

- Ubuntu: Five year LTS. I believe most customers update fairly promptly every
  two years, and few if any non-security backports are made to LTS releases
  older than the current one.

  Packages: https://code.launchpad.net/ubuntu/+source/pcre2

- Alpine: Two year lifecycle.

  Packages: https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/main/pcre2?ref_type=heads

- SUSE: Extremely long lifecycle; PCRE2 will stop backporting fixes long before
  SUSE drops support.

  Packages: https://build.opensuse.org/package/show/openSUSE:Factory/pcre2

- Arch: Rolling release. No need for backports. However, it is a major upstream
  packaging source for the Arch-based ecosystem.

  Packages: https://gitlab.archlinux.org/archlinux/packaging/packages/pcre2

- Other notable primary packaging sources include:
  * Gentoo

    https://gitweb.gentoo.org/repo/gentoo.git/tree/dev-libs/libpcre2

  * NixOS

    https://github.com/NixOS/nixpkgs/blob/master/pkgs/development/libraries/pcre2/default.nix

Please contact us if you would like the PCRE2 maintainers to be aware of your
packages, particularly if you are a distributor of PCRE2, and provide a support
lifecycle for old (not-latest) PCRE2 releases.

## Supported Versions

Below is the list of PCRE2 versions supported by upstream distributors. For
each version, specific recommendations and backported fixes (if any) are
provided.

### PCRE2 10.23 14-February-2017

* Shipped in RHEL 7 (paid Extended Life Cycle Support ends 31 May 2029).

I am not providing a recommendation of what patches to apply. This release is
beyond PCRE2's standard five-year support period and is maintained only through
an extended-support programme.

### PCRE2 10.31 12-February-2018

* Shipped in Ubuntu 18.04 "Bionic Beaver" (Expanded Security Maintenance ends
  April 2028).
* Shipped in SUSE Linux Enterprise Server 15 SP1, SP2 and SP3 (paid LTSS
  Reactive support ends 31 January 2027, 31 December 2027 and 31 December
  2028, respectively).

I am not providing a recommendation of what patches to apply. These releases
are beyond PCRE2's standard five-year support period and are maintained only
through extended-support programmes.

### PCRE2 10.32 10-September-2018

* Shipped in RHEL 8 (Maintenance Support ends 31 May 2029; paid Extended Life
  Cycle support ends 31 May 2033).

This version is older than 5 years, but remains listed in SUPPORT-LIFECYCLE.md
potentially until May 2029 (end of "Maintenance Support" for RHEL 8), in
recognition that customer workloads may be using this version until then.

I am not providing a recommendation of what patches to apply. Distributors still
shipping this release have likely frozen their codebase at this point.

For the record, RHEL 8 used the following sets of patches:
https://src.fedoraproject.org/rpms/pcre2/tree/f28,
https://gitlab.com/redhat/centos-stream/rpms/pcre2/-/tree/c8s?ref_type=heads

The most serious of these was the backported mitigation for CVE-2019-20454 from
the fix in 10.34.

### PCRE2 10.34 21-November-2019

* Shipped in Ubuntu 20.04 "Focal Fossa" (Expanded Security Maintenance ends
  April 2030).
* Shipped in SUSE Linux Enterprise Server 12 SP5 (paid LTSS ends 31 October
  2027).

I am not providing a recommendation of what patches to apply. These releases
are beyond PCRE2's standard five-year support period and are maintained only
through extended-support programmes.

### PCRE2 10.36 04-December-2020

* Shipped in Debian 11 "Bullseye" (EOL 31 Aug 2026).

I am not providing a recommendation of what patches to apply. Distributors still
shipping this release have likely frozen their codebase at this point, since the
release of Debian 12.

### PCRE2 10.37 26-May-2021

I am not providing a recommendation of what patches to apply. I am not aware of
any Linux distributions providing extended support for 10.37. I have not tested
this release with any backported fixes applied.

Patches introduced:
* `patches/pcre2-10.37-Remove-real-POSIX.patch`: To be backported to older
  versions as required. This changes a behaviour which has been present since
  the beginning of PCRE2's libpcre2posix.so, although the behaviour was updated
  in 10.33. Versions prior to 10.33 cannot benefit from the backport; versions
  10.33-10.36 may use the backport at the distributor's discretion (that is, if
  users have requested it; but it is not needed otherwise).

### PCRE2 10.38 01-October-2021

Do not use (update to 10.39).

### PCRE2 10.39 29-October-2021

* Shipped in Ubuntu 22.04 "Jammy Jellyfish" (EOL 01 Apr 2027).
* Shipped in SUSE Linux Enterprise Server 15 SP4 and SP5 (paid LTSS ends 31
  December 2026 and 31 December 2027, respectively).

Backports to apply:
* `patches/pcre2-10.40-A-Fixed-a-unicode.patch`
* `patches/pcre2-10.40-B-Fixed-an-issue-affecting.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

Patches introduced:
* `patches/pcre2-10.39-Fix-incorrect-detection.patch`: Significant bugfix for
  JIT matching

### PCRE2 10.40 15-April-2022

* Shipped in RHEL 9 (Full Support ends 31 May 2027; Maintenance Support ends 31
  May 2032; paid Extended Life Cycle support ends 31 May 2036).
* Shipped in CentOS Stream 9 (EOL 31 May 2027).

Backports to apply:
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

For the record, RHEL/CentOS 9 ships rather more backported patches than other
distributions:
https://gitlab.com/redhat/centos-stream/rpms/pcre2/-/tree/c9s?ref_type=heads

Some of these patches may be relevant to other distributions, but I have not
tested them myself for compatibility with 10.40 or other earlier releases.

Patches introduced:
* `patches/pcre2-10.40-A-Fixed-a-unicode.patch`: Fixed CVE-2022-1586. This
  should be assumed to affect all previous versions of PCRE2 (lower bound of
  affected releases unconfirmed).
* `patches/pcre2-10.40-B-Fixed-an-issue-affecting.patch`: Fixed CVE-2022-1587.
  This should be assumed to affect all previous versions of PCRE2 (lower bound
  of affected releases unconfirmed).

### PCRE2 10.41 06-December-2022

Do not use (update to 10.42).

Introduced the fix for CVE-2022-41409. This only affects the pcre2test runner
for the test suite, so this fix is not backported.

### PCRE2 10.42 11-December-2022

* Shipped in Debian 12 "Bookworm" (EOL 30 Jun 2028).
* Shipped in Ubuntu 24.04 "Noble Numbat" (EOL 31 May 2029).
* Shipped in SUSE Linux Enterprise Server 15 SP6 and SP7 (paid LTSS ends 31
  December 2028 and general support ends 31 July 2031, respectively).

Users on RISC-V are advised to update to 10.43, or not use the JIT unless using
a backport for https://github.com/zherczeg/sljit/pull/223. Given the small
RISC-V userbase (especially on older releases), disabling the JIT for RISC-V
builds is likely acceptable.

Backports to apply:
* `patches/pcre2-10.43-Avoid-LIMIT_HEAP-integer.patch`
* `patches/pcre2-10.43-Fix-heapframe-overflow.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

### PCRE2 10.43 16-February-2024

* Shipped in Alpine 3.21 (EOL 01 Nov 2026).

Backports to apply:
* `patches/pcre2-10.44-Fix-locking-region.patch`
* `patches/pcre2-10.44-Fix-incorrect-compiling.patch`
* `patches/pcre2-10.48-Fix-JIT-STR_END.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

Patches introduced:
* `patches/pcre2-10.43-Avoid-LIMIT_HEAP-integer.patch`: Fix integer overflow in
  handling of LIMIT_HEAP. This is not a critical fix for backporting, and in
  10.41, the code for handling the heapframes changed to always using a
  heap-allocated frames vector. This patch is therefore recommended for
  backporting to 10.42 only.
* `patches/pcre2-10.43-Fix-heapframe-overflow.patch`: Fix buffer overrun in
  handling of LIMIT_HEAP. The regression was introduced in d90fb238 in PCRE2
  10.41, so the patch is for backporting to 10.41-42.

### PCRE2 10.44 07-June-2024

* Shipped in RHEL 10 (Full Support ends 31 May 2030; Maintenance Support ends
  31 May 2035; paid Extended Life Cycle support ends 31 May 2039).
* Shipped in CentOS Stream 10 (EOL 31 May 2030).

Backports to apply:
* `patches/pcre2-10.45-Memory-reports-only-compiled.patch`
* `patches/pcre2-10.48-Fix-JIT-STR_END.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

Patches introduced:
* `patches/pcre2-10.44-Fix-locking-region.patch`: To be backported to 10.43 only
  (bug introduced in 10.43). Crashes in multithreaded applications using the PCRE2
  JIT were likely in 10.43 without this patch.
* `patches/pcre2-10.44-Fix-incorrect-compiling.patch`: Fixes a bug causing
  incorrect compilation of certain patterns which could crashes, for backporting
  to 10.43. Because 10.42 and earlier required fixed-length lookbehinds, the
  patch does not require backporting to earlier versions.

### PCRE2 10.45 05-February-2025

* Shipped in openSUSE Leap 16.0 (EOL 31 October 2027).
* Shipped in SUSE Linux Enterprise Server 16.0 (general support ends 30
  November 2027).

Do not use (update to 10.46, which is is a drop-in compatible release with a
security fix).

Patches introduced:
* `patches/pcre2-10.45-Memory-reports-only-compiled.patch`: To be backported to
  10.44 only. This is a test-only fix, so is not important to backport unless
  test suite failures are observed.

### PCRE2 10.46 27-August-2025

* Shipped in Debian 13 "Trixie" (EOL 30 Jun 2030).
* Shipped in Ubuntu 26.04 "Resolute Raccoon" (EOL 30 April 2031).
* Shipped in Alpine 3.22 (EOL 01 May 2027).
* Shipped in NixOS 26.05 (EOL 31 December 2026).

Introduced the fix for CVE-2025-58050. This only affects 10.45. Do not backport
the patch (just update to 10.46).

Backports to apply:
* `patches/pcre2-10.47-Fix-for-callback.patch`
* `patches/pcre2-10.48-Write-serialization-padding.patch`
* `patches/pcre2-10.48-Fix-character-list-generator.patch`
* `patches/pcre2-10.48-Fix-scan-prefix-repeat-reset.patch`
* `patches/pcre2-10.48-Fix-JIT-STR_END.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

### PCRE2 10.47 21-October-2025

* Shipped in Fedora 43 (EOL 09 December 2026) and Fedora 44 (EOL 02 June
  2027).
* Shipped in Alpine 3.23 (EOL 01 November 2027) and Alpine 3.24 (EOL 01 June
  2028).

Backports to apply:
* `patches/pcre2-10.48-Write-serialization-padding.patch`
* `patches/pcre2-10.48-Fix-character-list-generator.patch`
* `patches/pcre2-10.48-Fix-repeated-substitute-escapes.patch`
* `patches/pcre2-10.48-Fix-scan-prefix-repeat-reset.patch`
* `patches/pcre2-10.48-Fix-JIT-STR_END.patch`
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`
* `patches/pcre2-10.48-Keep-escape-error-offset-in-pattern.patch`
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`

Patches introduced:
* `patches/pcre2-10.47-Fix-for-callback.patch`: A fix for a significant memory
  read overrun in a function rarely called by applications, to be backported to
  10.45 and 10.46 only (bug introduced in 10.45).
* There is a new and rewritten JIT implementation for the AArch64 SIMD code,
  fixing crashes and out-of-bounds memory reads in the previous, legacy AArch64
  JIT. This is probably not possible to backport.

### PCRE2 10.48 31-August-2026

Patches introduced:
* `patches/pcre2-10.48-Write-serialization-padding.patch`: Initializes
  character-list padding before serialization, preventing a two-byte
  information disclosure (GHSA-q7rw-r7qq-2hx6). The affected representation
  was introduced in 10.45; affected releases are 10.45-10.47.
* `patches/pcre2-10.48-Fix-character-list-generator.patch`: Fixes incorrect
  compilation and false-negative matches for Unicode character lists around
  U+0100 and ranges crossing U+00FF. The affected representation was
  introduced in 10.45; affected releases are 10.45-10.47.
* `patches/pcre2-10.48-Fix-repeated-substitute-escapes.patch`: Fixes incorrect
  conditional substitution output and errors after consecutive extended
  replacement escapes. This regression was introduced in 10.47 and affects
  10.47 only.
* `patches/pcre2-10.48-Fix-scan-prefix-repeat-reset.patch`: Fixes JIT false
  negatives caused by stale repeat state during prefix scanning. The affected
  scan-prefix implementation was introduced in 10.45; affected releases are
  10.45-10.47.
* `patches/pcre2-10.48-Fix-JIT-STR_END.patch`: Restores `STR_END` while JIT
  backtracks through non-atomic variable-length lookbehinds. The affected JIT
  support was introduced in 10.43; affected releases are 10.43-10.47.
* `patches/pcre2-10.48-Fix-JIT-match-context-reuse.patch`: Prevents direct
  `pcre2_jit_match()` reuse from leaking a copied subject, retaining stale
  ownership state, or freeing caller-owned memory. Copied-subject support was
  introduced in 10.33; affected releases are 10.33-10.47.
* `patches/pcre2-10.48-Check-JIT-mode-before-validation.patch`: Checks that the
  requested JIT mode exists before JIT validation and execution
  (GHSA-2p8c-ff85-vh9x). The accompanying regression test is part of the same
  backport series. The affected invalid-UTF fallback was introduced in 10.34;
  affected releases are 10.34-10.47.
* `patches/pcre2-10.48-Fix-allocation-byte-sizing.patch`: Uses byte sizes for
  two allocations and adds overflow checks (GHSA-q8g2-wprr-34m9). One affected
  allocation has been confirmed as far back as PCRE2 10.00; affected releases
  are 10.47 and earlier.
* `patches/pcre2-10.48-Keep-escape-error-offset-in-pattern.patch`: Keeps error
  offsets within malformed patterns ending in incomplete `\x{`, `\o{`, or
  `\N{U+` escapes. This regression was introduced in 10.47 and affects 10.47
  only.
* `patches/pcre2-10.48-Fix-invalid-UTF-backwards-scans.patch`: Prevents two
  out-of-bounds reads while scanning backwards through invalid UTF data
  (GHSA-9qww-pwc4-77qq). Invalid-UTF matching was introduced in 10.34; affected
  releases are 10.34-10.47.
* `patches/pcre2-10.48-Fix-compiler-integer-overflows.patch`: Adds bounds checks
  for several integer overflows while compiling patterns
  (GHSA-fmgr-6ggq-9859). The affected generic calculations have been confirmed
  in PCRE2 10.00; affected releases are 10.47 and earlier.
* `patches/pcre2-10.48-Fix-DFA-workspace-overflows.patch`: Prevents workspace
  size and offset overflows in DFA matching (GHSA-3r4p-g7gg-ppmf). The affected
  heap workspace was introduced in 10.32; affected releases are 10.32-10.47.
