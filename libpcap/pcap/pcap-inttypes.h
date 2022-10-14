/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2009 CACE Technologies, Inc. Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef pcap_pcap_inttypes_h
#define pcap_pcap_inttypes_h

/*
 * If we're compiling with Visual Studio, make sure we have at least
 * VS 2015 or later, so we have sufficient C99 support.
 *
 * XXX - verify that we have at least C99 support on UN*Xes?
 *
 * What about MinGW or various DOS toolchains?  We're currently assuming
 * sufficient C99 support there.
 */
#if defined(_MSC_VER)
  /*
   * Compiler is MSVC.  Make sure we have VS 2015 or later.
   */
  #if _MSC_VER < 1900
    #error "Building libpcap requires VS 2015 or later"
  #endif
#endif

/*
 * Include <inttypes.h> to get the integer types and PRi[doux]64 values
 * defined.
 *
 * If the compiler is MSVC, we require VS 2015 or newer, so we
 * have <inttypes.h> - and support for %zu in the formatted
 * printing functions.
 *
 * If the compiler is MinGW, we assume we have <inttypes.h> - and
 * support for %zu in the formatted printing functions.
 *
 * If the target is UN*X, we assume we have a C99-or-later development
 * environment, and thus have <inttypes.h> - and support for %zu in
 * the formatted printing functions.
 *
 * If the target is MS-DOS, we assume we have <inttypes.h> - and support
 * for %zu in the formatted printing functions.
 *
 * I.e., assume we have <inttypes.h> and that it suffices.
 */

/*
 * XXX - somehow make sure we have enough C99 support with other
 * compilers and support libraries?
 */

#include <inttypes.h>

#endif /* pcap/pcap-inttypes.h */
