/*
 * Copyright (c) 1994, 1995, 1996
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

#ifndef thread_local_h
#define	thread_local_h

/*
 * This defines thread_local to specify thread-local storage, if it
 * is not already defined.
 *
 * C11, if __STDC_NO_THREADS__ is not defined to be 1, defines
 * _Thread_local to indicate thread-local storage.  (You can also
 * include <threads.h> to so define it, but we don't use any of
 * the other stuff there.)
 *
 * Otherwise, we define it ourselves, based on the compiler.
 *
 * This is taken from https://stackoverflow.com/a/18298965/16139739.
 */
#ifndef thread_local
  #if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
    #define thread_local _Thread_local
  #elif defined __TINYC__
    #define thread_local
    #warning "Some libpcap calls will not be thread-safe."
  #elif defined _WIN32 && ( \
         defined _MSC_VER || \
         defined __ICL || \
         defined __DMC__ || \
         defined __BORLANDC__ )
    #define thread_local __declspec(thread)
  /* note that ICC (linux) and Clang are covered by __GNUC__ */
  #elif defined __GNUC__ || \
         defined __SUNPRO_C || \
         defined __xlC__
    #define thread_local __thread
  #else
    #error "Cannot define thread_local"
  #endif
#endif

#endif
