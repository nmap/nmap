/*
 * Copyright (C) 2015 Patrick Monnerat, D+H <patrick.monnerat@dh.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef LIBSSH2_STDIO_H
#define LIBSSH2_STDIO_H

/*
 *  <stdio.h> wrapper.
 *  Its goal is to redefine snprintf/vsnprintf which are not supported by QADRT.
 */

#include <qadrt.h>

#if __ILEC400_TGTVRM__ >= 710
# include_next <stdio.h>
#elif __ILEC400_TGTVRM__ >= 510
# ifndef __SRCSTMF__
#  include <QADRT/h/stdio>
# else
#  include </QIBM/ProdData/qadrt/include/stdio.h>
# endif
#endif

extern int  _libssh2_os400_vsnprintf(char *dst, size_t len,
                                     const char *fmt, va_list args);
extern int  _libssh2_os400_snprintf(char *dst, size_t len,
                                    const char *fmt, ...);

#ifndef LIBSSH2_DISABLE_QADRT_EXT
# define vsnprintf(dst, len, fmt, args)                                     \
                        _libssh2_os400_vsnprintf((dst), (len), (fmt), (args))
# define snprintf       _libssh2_os400_snprintf
#endif

#endif

/* vim: set expandtab ts=4 sw=4: */
