/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _diag_control_h
#define _diag_control_h

#include "pcap/compiler-tests.h"

#if PCAP_IS_AT_LEAST_CLANG_VERSION(2,8) || \
    PCAP_IS_AT_LEAST_GNUC_VERSION(4,6) || \
    PCAP_IS_AT_LEAST_SUNC_VERSION(5,5)
  /*
   * All these compilers support this way of putting pragmas into #defines.
   * We use it only if we have a compiler that supports it; see below
   * for the code that uses it and the #defines that control whether
   * that code is used.
   */
  #define PCAP_DO_PRAGMA(x) _Pragma (#x)
#endif

/*
 * Suppress "enum value not explicitly handled in switch" warnings.
 * We may have to build on multiple different Windows SDKs, so we
 * may not be able to include all enum values in a switch, as they
 * won't necessarily be defined on all the SDKs, and, unlike
 * #defines, there's no easy way to test whether a given enum has
 * a given value.  It *could* be done by the configure script or
 * CMake tests.
 */
#if defined(_MSC_VER)
  #define DIAG_OFF_ENUM_SWITCH \
    __pragma(warning(push)) \
    __pragma(warning(disable:4061))
  #define DIAG_ON_ENUM_SWITCH \
    __pragma(warning(pop))
#endif

/*
 * Suppress "switch statement has only a default case" warnings.
 * There's a switch in bpf_filter.c that only has additional
 * cases on Linux.
 */
#if defined(_MSC_VER)
  #define DIAG_OFF_DEFAULT_ONLY_SWITCH \
    __pragma(warning(push)) \
    __pragma(warning(disable:4065))
  #define DIAG_ON_DEFAULT_ONLY_SWITCH \
    __pragma(warning(pop))
#endif

/*
 * Suppress Flex, narrowing, and deprecation warnings.
 */
#if PCAP_IS_AT_LEAST_CLANG_VERSION(2,8)
  /*
   * This is Clang 2.8 or later; we can use "clang diagnostic
   * ignored -Wxxx" and "clang diagnostic push/pop".
   *
   * Suppress -Wdocumentation warnings; GCC doesn't support -Wdocumentation,
   * at least according to the GCC 7.3 documentation.  Apparently, Flex
   * generates code that upsets at least some versions of Clang's
   * -Wdocumentation.
   *
   * (This could be clang-cl, which defines _MSC_VER, so test this
   * before testing _MSC_VER.)
   */
  #define DIAG_OFF_FLEX \
    PCAP_DO_PRAGMA(clang diagnostic push) \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wsign-compare") \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wdocumentation") \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wshorten-64-to-32") \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wmissing-noreturn") \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wunused-parameter") \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wunreachable-code")
  #define DIAG_ON_FLEX \
    PCAP_DO_PRAGMA(clang diagnostic pop)

  /*
   * Suppress the only narrowing warnings you get from Clang.
   */
  #define DIAG_OFF_NARROWING \
    PCAP_DO_PRAGMA(clang diagnostic push) \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wshorten-64-to-32")

  #define DIAG_ON_NARROWING \
    PCAP_DO_PRAGMA(clang diagnostic pop)

  /*
   * Suppress deprecation warnings.
   */
  #define DIAG_OFF_DEPRECATION \
    PCAP_DO_PRAGMA(clang diagnostic push) \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wdeprecated-declarations")
  #define DIAG_ON_DEPRECATION \
    PCAP_DO_PRAGMA(clang diagnostic pop)

  /*
   * When Clang correctly detects an old-style function prototype after
   * preprocessing, the warning can be irrelevant to this source tree because
   * the prototype comes from a system header macro.
   */
  #if PCAP_IS_AT_LEAST_CLANG_VERSION(5,0)
    #define DIAG_OFF_STRICT_PROTOTYPES \
      PCAP_DO_PRAGMA(clang diagnostic push) \
      PCAP_DO_PRAGMA(clang diagnostic ignored "-Wstrict-prototypes")
    #define DIAG_ON_STRICT_PROTOTYPES \
      PCAP_DO_PRAGMA(clang diagnostic pop)
  #endif

  #define DIAG_OFF_DOCUMENTATION \
    PCAP_DO_PRAGMA(clang diagnostic push) \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wdocumentation")
  #define DIAG_ON_DOCUMENTATION \
    PCAP_DO_PRAGMA(clang diagnostic pop)

  #define DIAG_OFF_SIGN_COMPARE \
    PCAP_DO_PRAGMA(clang diagnostic push) \
    PCAP_DO_PRAGMA(clang diagnostic ignored "-Wsign-compare")
  #define DIAG_ON_SIGN_COMPARE \
    PCAP_DO_PRAGMA(clang diagnostic pop)
#elif defined(_MSC_VER)
  /*
   * This is Microsoft Visual Studio; we can use __pragma(warning(disable:XXXX))
   * and __pragma(warning(push/pop)).
   *
   * Suppress signed-vs-unsigned comparison, narrowing, and unreachable
   * code warnings.
   */
  #define DIAG_OFF_FLEX \
    __pragma(warning(push)) \
    __pragma(warning(disable:4127)) \
    __pragma(warning(disable:4242)) \
    __pragma(warning(disable:4244)) \
    __pragma(warning(disable:4702))
  #define DIAG_ON_FLEX \
    __pragma(warning(pop))

  /*
   * Suppress narrowing warnings.
   */
  #define DIAG_OFF_NARROWING \
    __pragma(warning(push)) \
    __pragma(warning(disable:4242)) \
    __pragma(warning(disable:4311))
  #define DIAG_ON_NARROWING \
    __pragma(warning(pop))

  /*
   * Suppress deprecation warnings.
   */
  #define DIAG_OFF_DEPRECATION \
    __pragma(warning(push)) \
    __pragma(warning(disable:4996))
  #define DIAG_ON_DEPRECATION \
    __pragma(warning(pop))
#elif PCAP_IS_AT_LEAST_GNUC_VERSION(4,6)
  /*
   * This is GCC 4.6 or later, or a compiler claiming to be that.
   * We can use "GCC diagnostic ignored -Wxxx" (introduced in 4.2)
   * and "GCC diagnostic push/pop" (introduced in 4.6).
   */
  #define DIAG_OFF_FLEX \
    PCAP_DO_PRAGMA(GCC diagnostic push) \
    PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wsign-compare") \
    PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wunused-parameter") \
    PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wunreachable-code")
  #define DIAG_ON_FLEX \
    PCAP_DO_PRAGMA(GCC diagnostic pop)

  /*
   * GCC currently doesn't issue any narrowing warnings.
   */

  /*
   * Suppress deprecation warnings.
   */
  #define DIAG_OFF_DEPRECATION \
    PCAP_DO_PRAGMA(GCC diagnostic push) \
    PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wdeprecated-declarations")
  #define DIAG_ON_DEPRECATION \
    PCAP_DO_PRAGMA(GCC diagnostic pop)

  /*
   * Suppress format-truncation= warnings.
   * GCC 7.1 had introduced this warning option. Earlier versions (at least
   * one particular copy of GCC 4.6.4) treat the request as a warning.
   */
  #if PCAP_IS_AT_LEAST_GNUC_VERSION(7,1)
    #define DIAG_OFF_FORMAT_TRUNCATION \
      PCAP_DO_PRAGMA(GCC diagnostic push) \
      PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wformat-truncation=")
    #define DIAG_ON_FORMAT_TRUNCATION \
      PCAP_DO_PRAGMA(GCC diagnostic pop)
  #endif
#elif PCAP_IS_AT_LEAST_SUNC_VERSION(5,5)
  /*
   * Sun C compiler version 5.5 (Studio version 8) and later supports "#pragma
   * error_messages()".
   */
  #define DIAG_OFF_FLEX \
    PCAP_DO_PRAGMA(error_messages(off,E_STATEMENT_NOT_REACHED))
  #define DIAG_ON_FLEX \
    PCAP_DO_PRAGMA(error_messages(default,E_STATEMENT_NOT_REACHED))
#endif

#ifdef YYBYACC
  /*
   * Berkeley YACC.
   *
   * It generates a global declaration of yylval, or the appropriately
   * prefixed version of yylval, in grammar.h, *even though it's been
   * told to generate a pure parser, meaning it doesn't have any global
   * variables*.  Bison doesn't do this.
   *
   * That causes a warning due to the local declaration in the parser
   * shadowing the global declaration.
   *
   * So, if the compiler warns about that, we turn off -Wshadow warnings.
   *
   * In addition, the generated code may have functions with unreachable
   * code, so suppress warnings about those.
   */
  #if PCAP_IS_AT_LEAST_CLANG_VERSION(2,8)
    /*
     * This is Clang 2.8 or later (including clang-cl, so test this
     * before _MSC_VER); we can use "clang diagnostic ignored -Wxxx".
     */
    #define DIAG_OFF_BISON_BYACC \
      PCAP_DO_PRAGMA(clang diagnostic ignored "-Wshadow") \
      PCAP_DO_PRAGMA(clang diagnostic ignored "-Wunreachable-code")
  #elif defined(_MSC_VER)
    /*
     * This is Microsoft Visual Studio; we can use
     * __pragma(warning(disable:XXXX)).
     */
    #define DIAG_OFF_BISON_BYACC \
      __pragma(warning(disable:4702))
  #elif PCAP_IS_AT_LEAST_GNUC_VERSION(4,6)
    /*
     * This is GCC 4.6 or later, or a compiler claiming to be that.
     * We can use "GCC diagnostic ignored -Wxxx" (introduced in 4.2,
     * but it may not actually work very well prior to 4.6).
     */
    #define DIAG_OFF_BISON_BYACC \
      PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wshadow") \
      PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wunreachable-code")
  #endif
#else
  /*
   * Bison.
   *
   * The generated code may have functions with unreachable code and
   * switches with only a default case, so suppress warnings about those.
   */
  #if PCAP_IS_AT_LEAST_CLANG_VERSION(2,8)
    /*
     * This is Clang 2.8 or later (including clang-cl, so test this
     * before _MSC_VER); we can use "clang diagnostic ignored -Wxxx".
     */
    #define DIAG_OFF_BISON_BYACC \
      PCAP_DO_PRAGMA(clang diagnostic ignored "-Wunreachable-code")
  #elif defined(_MSC_VER)
    /*
     * This is Microsoft Visual Studio; we can use
     * __pragma(warning(disable:XXXX)).
     *
     * Suppress some /Wall warnings.
     */
    #define DIAG_OFF_BISON_BYACC \
      __pragma(warning(disable:4065)) \
      __pragma(warning(disable:4127)) \
      __pragma(warning(disable:4242)) \
      __pragma(warning(disable:4244)) \
      __pragma(warning(disable:4702))
  #elif PCAP_IS_AT_LEAST_GNUC_VERSION(4,6)
    /*
     * This is GCC 4.6 or later, or a compiler claiming to be that.
     * We can use "GCC diagnostic ignored -Wxxx" (introduced in 4.2,
     * but it may not actually work very well prior to 4.6).
     */
    #define DIAG_OFF_BISON_BYACC \
      PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wunreachable-code")
  #elif PCAP_IS_AT_LEAST_SUNC_VERSION(5,5)
    /*
     * Same as for DIAG_OFF_FLEX above.
     */
    #define DIAG_OFF_BISON_BYACC \
      PCAP_DO_PRAGMA(error_messages(off,E_STATEMENT_NOT_REACHED))
  #endif
#endif

#if PCAP_IS_AT_LEAST_CLANG_VERSION(2,8)
  /*
   * Clang appears to let you ignore a result without a warning by
   * casting the function result to void, so we don't appear to
   * need this for Clang.
   */
#elif PCAP_IS_AT_LEAST_GNUC_VERSION(4,5)
  /*
   * GCC warns about unused return values if a function is marked as
   * "warn about ignoring this function's return value".
   */
  #define DIAG_OFF_WARN_UNUSED_RESULT \
    PCAP_DO_PRAGMA(GCC diagnostic push) \
    PCAP_DO_PRAGMA(GCC diagnostic ignored "-Wunused-result")
  #define DIAG_ON_WARN_UNUSED_RESULT \
    PCAP_DO_PRAGMA(GCC diagnostic pop)

  /*
   * GCC does not currently generate any -Wstrict-prototypes warnings that
   * would need silencing as is done for Clang above.
   */
#endif

/*
 * GCC needs this on AIX for longjmp().
 */
#if PCAP_IS_AT_LEAST_GNUC_VERSION(5,1)
  /*
   * Beware that the effect of this builtin is more than just squelching the
   * warning! GCC trusts it enough for the process to segfault if the control
   * flow reaches the builtin (an infinite empty loop in the same context would
   * squelch the warning and ruin the process too, albeit in a different way).
   * So please remember to use this very carefully.
   */
  #define PCAP_UNREACHABLE __builtin_unreachable();
#endif

#ifndef DIAG_OFF_ENUM_SWITCH
#define DIAG_OFF_ENUM_SWITCH
#endif
#ifndef DIAG_ON_ENUM_SWITCH
#define DIAG_ON_ENUM_SWITCH
#endif
#ifndef DIAG_OFF_DEFAULT_ONLY_SWITCH
#define DIAG_OFF_DEFAULT_ONLY_SWITCH
#endif
#ifndef DIAG_ON_DEFAULT_ONLY_SWITCH
#define DIAG_ON_DEFAULT_ONLY_SWITCH
#endif
#ifndef DIAG_OFF_FLEX
#define DIAG_OFF_FLEX
#endif
#ifndef DIAG_ON_FLEX
#define DIAG_ON_FLEX
#endif
#ifndef DIAG_OFF_NARROWING
#define DIAG_OFF_NARROWING
#endif
#ifndef DIAG_ON_NARROWING
#define DIAG_ON_NARROWING
#endif
#ifndef DIAG_OFF_DEPRECATION
#define DIAG_OFF_DEPRECATION
#endif
#ifndef DIAG_ON_DEPRECATION
#define DIAG_ON_DEPRECATION
#endif
#ifndef DIAG_OFF_FORMAT_TRUNCATION
#define DIAG_OFF_FORMAT_TRUNCATION
#endif
#ifndef DIAG_ON_FORMAT_TRUNCATION
#define DIAG_ON_FORMAT_TRUNCATION
#endif
#ifndef DIAG_OFF_BISON_BYACC
#define DIAG_OFF_BISON_BYACC
#endif
//
// DIAG_ON_BISON_BYACC does not need to be defined.
//
#ifndef DIAG_OFF_WARN_UNUSED_RESULT
#define DIAG_OFF_WARN_UNUSED_RESULT
#endif
#ifndef DIAG_ON_WARN_UNUSED_RESULT
#define DIAG_ON_WARN_UNUSED_RESULT
#endif
#ifndef DIAG_OFF_STRICT_PROTOTYPES
#define DIAG_OFF_STRICT_PROTOTYPES
#endif
#ifndef DIAG_ON_STRICT_PROTOTYPES
#define DIAG_ON_STRICT_PROTOTYPES
#endif
#ifndef DIAG_OFF_DOCUMENTATION
#define DIAG_OFF_DOCUMENTATION
#endif
#ifndef DIAG_ON_DOCUMENTATION
#define DIAG_ON_DOCUMENTATION
#endif
#ifndef DIAG_OFF_SIGN_COMPARE
#define DIAG_OFF_SIGN_COMPARE
#endif
#ifndef DIAG_ON_SIGN_COMPARE
#define DIAG_ON_SIGN_COMPARE
#endif
#ifndef PCAP_UNREACHABLE
#define PCAP_UNREACHABLE
#endif

#endif /* _diag_control_h */
