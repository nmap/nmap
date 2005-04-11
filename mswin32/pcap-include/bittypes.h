/*
 * Copyright (C) 1999 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _BITTYPES_H
#define _BITTYPES_H

#ifndef HAVE_U_INT8_T

#if SIZEOF_CHAR == 1
typedef unsigned char u_int8_t;
typedef signed char int8_t;
#elif SIZEOF_INT == 1
typedef unsigned int u_int8_t;
typedef signed int int8_t;
#else  /* XXX */
#error "there's no appropriate type for u_int8_t"
#endif
#define HAVE_U_INT8_T 1
#define HAVE_INT8_T 1

#endif /* HAVE_U_INT8_T */

#ifndef HAVE_U_INT16_T 

#if SIZEOF_SHORT == 2
typedef unsigned short u_int16_t;
typedef signed short int16_t;
#elif SIZEOF_INT == 2
typedef unsigned int u_int16_t;
typedef signed int int16_t;
#elif SIZEOF_CHAR == 2
typedef unsigned char u_int16_t;
typedef signed char int16_t;
#else  /* XXX */
#error "there's no appropriate type for u_int16_t"
#endif
#define HAVE_U_INT16_T 1
#define HAVE_INT16_T 1

#endif /* HAVE_U_INT16_T */

#ifndef HAVE_U_INT32_T

#if SIZEOF_INT == 4
typedef unsigned int u_int32_t;
typedef signed int int32_t;
#elif SIZEOF_LONG == 4
typedef unsigned long u_int32_t;
typedef signed long int32_t;
#elif SIZEOF_SHORT == 4
typedef unsigned short u_int32_t;
typedef signed short int32_t;
#else  /* XXX */
#error "there's no appropriate type for u_int32_t"
#endif
#define HAVE_U_INT32_T 1
#define HAVE_INT32_T 1

#endif /* HAVE_U_INT32_T */

#endif /* _BITTYPES_H */
