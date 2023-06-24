/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
                    This module by Zoltan Herczeg
     Original API code Copyright (c) 1997-2012 University of Cambridge
          New API code Copyright (c) 2016-2021 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcre2_internal.h"

#ifdef SUPPORT_JIT
/* NMAP_MODIFICATIONS */
#endif

/*************************************************
*        JIT compile a Regular Expression        *
*************************************************/

/* This function used JIT to convert a previously-compiled pattern into machine
code.

Arguments:
  code          a compiled pattern
  options       JIT option bits

Returns:        0: success or (*NOJIT) was used
               <0: an error code
*/

#define PUBLIC_JIT_COMPILE_OPTIONS \
  (PCRE2_JIT_COMPLETE|PCRE2_JIT_PARTIAL_SOFT|PCRE2_JIT_PARTIAL_HARD|PCRE2_JIT_INVALID_UTF)

PCRE2_EXP_DEFN int PCRE2_CALL_CONVENTION
pcre2_jit_compile(pcre2_code *code, uint32_t options)
{
pcre2_real_code *re = (pcre2_real_code *)code;
#ifdef SUPPORT_JIT
executable_functions *functions;
static int executable_allocator_is_working = -1;
#endif

if (code == NULL)
  return PCRE2_ERROR_NULL;

if ((options & ~PUBLIC_JIT_COMPILE_OPTIONS) != 0)
  return PCRE2_ERROR_JIT_BADOPTION;

/* Support for invalid UTF was first introduced in JIT, with the option
PCRE2_JIT_INVALID_UTF. Later, support was added to the interpreter, and the
compile-time option PCRE2_MATCH_INVALID_UTF was created. This is now the
preferred feature, with the earlier option deprecated. However, for backward
compatibility, if the earlier option is set, it forces the new option so that
if JIT matching falls back to the interpreter, there is still support for
invalid UTF. However, if this function has already been successfully called
without PCRE2_JIT_INVALID_UTF and without PCRE2_MATCH_INVALID_UTF (meaning that
non-invalid-supporting JIT code was compiled), give an error.

If in the future support for PCRE2_JIT_INVALID_UTF is withdrawn, the following
actions are needed:

  1. Remove the definition from pcre2.h.in and from the list in
     PUBLIC_JIT_COMPILE_OPTIONS above.

  2. Replace PCRE2_JIT_INVALID_UTF with a local flag in this module.

  3. Replace PCRE2_JIT_INVALID_UTF in pcre2_jit_test.c.

  4. Delete the following short block of code. The setting of "re" and
     "functions" can be moved into the JIT-only block below, but if that is
     done, (void)re and (void)functions will be needed in the non-JIT case, to
     avoid compiler warnings.
*/

#ifdef SUPPORT_JIT
functions = (executable_functions *)re->executable_jit;
#endif

if ((options & PCRE2_JIT_INVALID_UTF) != 0)
  {
  if ((re->overall_options & PCRE2_MATCH_INVALID_UTF) == 0)
    {
#ifdef SUPPORT_JIT
    if (functions != NULL) return PCRE2_ERROR_JIT_BADOPTION;
#endif
    re->overall_options |= PCRE2_MATCH_INVALID_UTF;
    }
  }

/* The above tests are run with and without JIT support. This means that
PCRE2_JIT_INVALID_UTF propagates back into the regex options (ensuring
interpreter support) even in the absence of JIT. But now, if there is no JIT
support, give an error return. */

#ifndef SUPPORT_JIT
return PCRE2_ERROR_JIT_BADOPTION;
#else  /* SUPPORT_JIT */
/* NMAP_MODIFICATIONS */
#endif  /* SUPPORT_JIT */
}

/* JIT compiler uses an all-in-one approach. This improves security,
   since the code generator functions are not exported. */

#define INCLUDED_FROM_PCRE2_JIT_COMPILE

#if 0
/* NMAP_MODIFICATIONS */
#include "pcre2_jit_match.c"
#include "pcre2_jit_misc.c"
#endif

/* End of pcre2_jit_compile.c */
