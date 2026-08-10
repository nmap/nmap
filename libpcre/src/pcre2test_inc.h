/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
     Original API code Copyright (c) 1997-2012 University of Cambridge
          New API code Copyright (c) 2016-2024 University of Cambridge

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


/* This module contains the mode-dependent code which is used by pcre2test.c.
It is #included in pcre2test.c at each supported code unit width, with
PCRE2_SUFFIX set appropriately, just like the functions that comprise the
library. */


/* ------- Macros for hiding the bit width of this file's members ---------- */

#define pbuffer               PCRE2_SUFFIX(pbuffer)
#define pbuffer_size          G(pbuffer,_size)

#if PCRE2_CODE_UNIT_WIDTH == 8 || PCRE2_CODE_UNIT_WIDTH == 16
#define utf_to_ord            G(G(utf,PCRE2_CODE_UNIT_WIDTH),_to_ord)
#endif

#define compiled_code         PCRE2_SUFFIX(compiled_code_)
#define general_context       PCRE2_SUFFIX(general_context_)
#define general_context_copy  PCRE2_SUFFIX(general_context_copy_)
#define pat_context           PCRE2_SUFFIX(pat_context_)
#define default_pat_context   PCRE2_SUFFIX(default_pat_context_)
#define con_context           PCRE2_SUFFIX(con_context_)
#define default_con_context   PCRE2_SUFFIX(default_con_context_)
#define dat_context           PCRE2_SUFFIX(dat_context_)
#define default_dat_context   PCRE2_SUFFIX(default_dat_context_)
#define match_data            PCRE2_SUFFIX(match_data_)
#define jit_stack             PCRE2_SUFFIX(jit_stack_)
#define jit_stack_size        PCRE2_SUFFIX(jit_stack_size_)
#define patstack              PCRE2_SUFFIX(patstack_)
#define patstacknext          PCRE2_SUFFIX(patstacknext_)
#define rep_in_buffer         PCRE2_SUFFIX(rep_in_buffer_)
#define rep_in_buffer_size    PCRE2_SUFFIX(rep_in_buffer_size_)
#define rep_out_buffer        PCRE2_SUFFIX(rep_out_buffer_)
#define rep_out_buffer_size   PCRE2_SUFFIX(rep_out_buffer_size_)

#define jit_callback                      PCRE2_SUFFIX(jit_callback_)
#define pcre2_strcmp_c8                   PCRE2_SUFFIX(pcre2_strcmp_c8_)
#define pcre2_strlen                      PCRE2_SUFFIX(pcre2_strlen_)
#define pchars                            PCRE2_SUFFIX(pchars_)
#define ptrunc                            PCRE2_SUFFIX(ptrunc_)
#define config_str                        PCRE2_SUFFIX(config_str_)
#define check_modifier                    PCRE2_SUFFIX(check_modifier_)
#define decode_modifiers                  PCRE2_SUFFIX(decode_modifiers_)
#define pattern_info                      PCRE2_SUFFIX(pattern_info_)
#define show_memory_info                  PCRE2_SUFFIX(show_memory_info_)
#define show_framesize                    PCRE2_SUFFIX(show_framesize_)
#define show_heapframes_size              PCRE2_SUFFIX(show_heapframes_size_)
#define print_error_message_file          PCRE2_SUFFIX(print_error_message_file_)
#define print_error_message               PCRE2_SUFFIX(print_error_message_)
#define callout_enumerate_function        PCRE2_SUFFIX(callout_enumerate_function_)
#define callout_enumerate_function_void   PCRE2_SUFFIX(callout_enumerate_function_void_)
#define callout_enumerate_function_fail   PCRE2_SUFFIX(callout_enumerate_function_fail_)
#define show_pattern_info                 PCRE2_SUFFIX(show_pattern_info_)
#define serial_error                      PCRE2_SUFFIX(serial_error_)
#define process_command                   PCRE2_SUFFIX(process_command_)
#define process_pattern                   PCRE2_SUFFIX(process_pattern_)
#define have_active_pattern               PCRE2_SUFFIX(have_active_pattern_)
#define free_active_pattern               PCRE2_SUFFIX(free_active_pattern_)
#define check_match_limit                 PCRE2_SUFFIX(check_match_limit_)
#define substitute_callout_function       PCRE2_SUFFIX(substitute_callout_function_)
#define substitute_case_callout_function  PCRE2_SUFFIX(substitute_case_callout_function_)
#define callout_function                  PCRE2_SUFFIX(callout_function_)
#define copy_and_get                      PCRE2_SUFFIX(copy_and_get_)
#define copy_substitute_string            PCRE2_SUFFIX(copy_substitute_string_)
#define process_data                      PCRE2_SUFFIX(process_data_)
#define init_globals                      PCRE2_SUFFIX(init_globals_)
#define free_globals                      PCRE2_SUFFIX(free_globals_)
#define unittest                          PCRE2_SUFFIX(unittest_)


/* ---------------------- Mode-dependent variables ------------------------- */

static pcre2_code             *compiled_code = NULL;
static pcre2_general_context  *general_context = NULL, *general_context_copy = NULL;
static pcre2_compile_context  *pat_context = NULL, *default_pat_context = NULL;
static pcre2_convert_context  *con_context = NULL, *default_con_context = NULL;
static pcre2_match_context    *dat_context = NULL, *default_dat_context = NULL;
static pcre2_match_data       *match_data = NULL;

static pcre2_jit_stack *jit_stack = NULL;
static size_t           jit_stack_size = 0;

static pcre2_code *patstack[PATSTACKSIZE];
static int         patstacknext = 0;

static PCRE2_UCHAR *rep_in_buffer = NULL;
static size_t       rep_in_buffer_size = REPLACE_MODSIZE;    /* Code units */
static PCRE2_UCHAR *rep_out_buffer = NULL;
static size_t       rep_out_buffer_size = REPLACE_BUFFSIZE;  /* Code units */



/*************************************************
*         JIT memory callback                    *
*************************************************/

static pcre2_jit_stack*
jit_callback(void *arg)
{
jit_was_used = TRUE;
return (pcre2_jit_stack *)arg;
}



/*************************************************
*  Compare zero-terminated PCRE2 & 8-bit strings *
*************************************************/

static int
pcre2_strcmp_c8(PCRE2_SPTR str1, const char *str2)
{
PCRE2_UCHAR c1, c2;
while (*str1 != '\0' || *str2 != '\0')
  {
  c1 = *str1++;
  c2 = *str2++;
  if (c1 != c2) return ((c1 > c2) << 1) - 1;
  }
return 0;
}



/*************************************************
*        Find the length of a PCRE2 string       *
*************************************************/

static size_t
pcre2_strlen(PCRE2_SPTR str)
{
size_t c = 0;
while (*str++ != 0) c++;
return c;
}



/*************************************************
*           Print character string               *
*************************************************/

/* Must handle Unicode strings in UTF mode. Yields number of characters printed.
For printing *MARK strings, a negative length is given, indicating that the
length is in the first code unit. If handed a NULL file, this function just
counts chars without printing (because pchar() does that). */

static int pchars(int clr, PCRE2_SPTR p, ptrdiff_t length, BOOL utf, FILE *f)
{
#if PCRE2_CODE_UNIT_WIDTH == 8 || PCRE2_CODE_UNIT_WIDTH == 16
PCRE2_SPTR end;
uint32_t c = 0;
int yield = 0;

colour_begin(clr, f);

if (length < 0) length = *p++;
end = p + length;
while (length-- > 0)
  {
  if (utf)
    {
    int rc = utf_to_ord(p, end, &c);
    if (rc > 0 && rc <= length + 1)   /* Mustn't run over the end */
      {
      length -= rc - 1;
      p += rc;
      yield += pchar(c, utf, f);
      continue;
      }
    }
  c = *p++;
  yield += pchar(c, utf, f);
  }

colour_end(f);
return yield;

#else
int yield = 0;

colour_begin(clr, f);

if (length < 0) length = *p++;
while (length-- > 0)
  {
  uint32_t c = *p++;
  yield += pchar(c, utf, f);
  }

colour_end(f);
return yield;

#endif
}



/*************************************************
*        Print truncated character string        *
*************************************************/

/* Must handle Unicode strings in UTF mode. Passed the total input string, and
the offset to print from/to. If left is true, prints up to the offset,
truncated; otherwise prints from the offset to the right, truncated. */

#if PCRE2_CODE_UNIT_WIDTH == 8
static void ptrunc_8(int clr, PCRE2_SPTR p, size_t p_len, size_t offset,
  BOOL left, BOOL utf, FILE *f)
{
PCRE2_SPTR start = p + offset;
PCRE2_SPTR end = p + offset;
size_t printed = 0;

colour_begin(clr, f);

if (left)
  {
  while (start > p && printed < 10)
    {
    printed++;
    start--;
    if (utf)
      { while(start > p && (*start & 0xc0u) == 0x80u) start--; }
    }
  }
else
  {
  while (end < p + p_len && printed < 10)
    {
    printed++;
    end++;
    if (utf)
      { while(end < p + p_len && (*end & 0xc0u) == 0x80u) end++; }
    }
  }

if (left && start > p) fprintf(f, "...");
for (; start < end; start++) fprintf(f, "%c", CHAR_OUTPUT(*start));
if (!left && end < p + p_len) fprintf(f, "...");

colour_end(f);
}

#elif PCRE2_CODE_UNIT_WIDTH == 16
static void ptrunc_16(int clr, PCRE2_SPTR p, size_t p_len, size_t offset,
  BOOL left, BOOL utf, FILE *f)
{
PCRE2_SPTR start = p + offset;
PCRE2_SPTR end = p + offset;
size_t printed = 0;

colour_begin(clr, f);

if (left)
  {
  while (start > p && printed < 10)
    {
    printed++;
    start--;
    if (utf)
      { while(start > p && (*start & 0xfc00u) == 0xdc00u) start--; }
    }
  }
else
  {
  while (end < p + p_len && printed < 10)
    {
    printed++;
    end++;
    if (utf)
      { while(end < p + p_len && (*end & 0xfc00u) == 0xdc00u) end++; }
    }
  }

if (left && start > p) fprintf(f, "...");
while (start < end)
  {
  uint32_t c;
  int rc = utf16_to_ord(start, end, &c);
  if (rc < 0) c = *start++;
  else start += rc;
  if (c > 0xff || (utf && c > 0x7f))
    {
    uint8_t u8buff[6];
    int clen = ord_to_utf8(c, u8buff);
    fprintf(f, "%.*s", clen, u8buff);
    continue;
    }
  fputc((int)c, f);
  }
if (!left && end < p + p_len) fprintf(f, "...");

colour_end(f);
}

#elif PCRE2_CODE_UNIT_WIDTH == 32
static void ptrunc_32(int clr, PCRE2_SPTR p, size_t p_len, size_t offset,
  BOOL left, BOOL utf, FILE *f)
{
PCRE2_SPTR start = p + offset;
PCRE2_SPTR end = p + offset;

colour_begin(clr, f);

if (left)
  {
  start -= (offset > 10)? 10 : offset;
  }
else
  {
  end += (p + p_len - end > 10)? 10 : p + p_len - end;
  }

if (left && start > p) fprintf(f, "...");
while (start < end)
  {
  uint32_t c = *start++;
  if (c > 0xff || (utf && c > 0x7f))
    {
    uint8_t u8buff[6];
    int clen = ord_to_utf8(c, u8buff);
    fprintf(f, "%.*s", clen, u8buff);
    continue;
    }
  fputc((int)c, f);
  }
if (!left && end < p + p_len) fprintf(f, "...");

colour_end(f);
}
#endif

#if PCRE2_CODE_UNIT_WIDTH == 16
/*************************************************
*           Convert string to 16-bit             *
*************************************************/

/* In UTF mode the input is always interpreted as a string of UTF-8 bytes using
the original UTF-8 definition of RFC 2279, which allows for up to 6 bytes, and
code values from 0 to 0x7fffffff. However, values greater than the later UTF
limit of 0x10ffff cause an error. In non-UTF mode the input is interpreted as
UTF-8 if the utf8_input modifier is set, but an error is generated for values
greater than 0xffff.

If all the input bytes are ASCII, the space needed for a 16-bit string is
exactly double the 8-bit size. Otherwise, the size needed for a 16-bit string
is no more than double, because up to 0xffff uses no more than 3 bytes in UTF-8
but possibly 4 in UTF-16. Higher values use 4 bytes in UTF-8 and up to 4 bytes
in UTF-16. The result is always left in pbuffer16. Impose a minimum size to
save repeated re-sizing.

Note that this function does not object to surrogate values. This is
deliberate; it makes it possible to construct UTF-16 strings that are invalid,
for the purpose of testing that they are correctly faulted.

Arguments:
  p          points to a byte string
  utf        true in UTF mode
  lenptr     points to number of bytes in the string (excluding trailing zero)

Returns:     0 on success, with the length updated to the number of 16-bit
               data items used (excluding the trailing zero)
             OR -1 if a UTF-8 string is malformed
             OR -2 if a value > 0x10ffff is encountered in UTF mode
             OR -3 if a value > 0xffff is encountered when not in UTF mode
*/

static int
to16(uint8_t *p, int utf, PCRE2_SIZE *lenptr)
{
uint16_t *pp;
PCRE2_SIZE len = *lenptr;

if (pbuffer16_size < 2*len + 2)
  {
  if (pbuffer16 != NULL) free(pbuffer16);
  pbuffer16_size = 2*len + 2;
  if (pbuffer16_size < 4096) pbuffer16_size = 4096;
  pbuffer16 = (uint16_t *)malloc(pbuffer16_size);
  if (pbuffer16 == NULL)
    {
    cfprintf(clr_test_error, stderr, "pcre2test: malloc(%" SIZ_FORM ") failed for pbuffer16\n",
      pbuffer16_size);
    exit(1);
    }
  }

pp = pbuffer16;
if (!utf && (pat_patctl.control & CTL_UTF8_INPUT) == 0)
  {
  for (; len > 0; len--) *pp++ = *p++;
  }

else while (len > 0)
  {
  uint32_t c;
  const uint8_t *end = p + len;
  int chlen = utf8_to_ord(p, end, &c);
  if (chlen <= 0) return -1;
  if (!utf && c > 0xffff) return -3;
  if (c > 0x10ffff) return -2;
  p += chlen;
  len -= chlen;
  if (c < 0x10000) *pp++ = c; else
    {
    c -= 0x10000;
    *pp++ = 0xd800 | (c >> 10);
    *pp++ = 0xdc00 | (c & 0x3ff);
    }
  }

*pp = 0;
*lenptr = pp - pbuffer16;
return 0;
}
#endif /* PCRE2_CODE_UNIT_WIDTH == 16 */



#if PCRE2_CODE_UNIT_WIDTH == 32
/*************************************************
*           Convert string to 32-bit             *
*************************************************/

/* In UTF mode the input is always interpreted as a string of UTF-8 bytes using
the original UTF-8 definition of RFC 2279, which allows for up to 6 bytes, and
code values from 0 to 0x7fffffff. However, values greater than the later UTF
limit of 0x10ffff cause an error.

In non-UTF mode the input is interpreted as UTF-8 if the utf8_input modifier
is set, and no limit is imposed. There is special interpretation of the 0xff
byte (which is illegal in UTF-8) in this case: it causes the top bit of the
next character to be set. This provides a way of generating 32-bit characters
greater than 0x7fffffff.

If all the input bytes are ASCII, the space needed for a 32-bit string is
exactly four times the 8-bit size. Otherwise, the size needed for a 32-bit
string is no more than four times, because the number of characters must be
less than the number of bytes. The result is always left in pbuffer32. Impose a
minimum size to save repeated re-sizing.

Note that this function does not object to surrogate values. This is
deliberate; it makes it possible to construct UTF-32 strings that are invalid,
for the purpose of testing that they are correctly faulted.

Arguments:
  p          points to a byte string
  utf        true in UTF mode
  lenptr     points to number of bytes in the string (excluding trailing zero)

Returns:     0 on success, with the length updated to the number of 32-bit
               data items used (excluding the trailing zero)
             OR -1 if a UTF-8 string is malformed
             OR -2 if a value > 0x10ffff is encountered in UTF mode
*/

static int
to32(uint8_t *p, int utf, PCRE2_SIZE *lenptr)
{
uint32_t *pp;
PCRE2_SIZE len = *lenptr;

if (pbuffer32_size < 4*len + 4)
  {
  if (pbuffer32 != NULL) free(pbuffer32);
  pbuffer32_size = 4*len + 4;
  if (pbuffer32_size < 8192) pbuffer32_size = 8192;
  pbuffer32 = (uint32_t *)malloc(pbuffer32_size);
  if (pbuffer32 == NULL)
    {
    cfprintf(clr_test_error, stderr, "pcre2test: malloc(%" SIZ_FORM ") failed for pbuffer32\n",
      pbuffer32_size);
    exit(1);
    }
  }

pp = pbuffer32;
if (!utf && (pat_patctl.control & CTL_UTF8_INPUT) == 0)
  {
  for (; len > 0; len--) *pp++ = *p++;
  }

else while (len > 0)
  {
  int chlen;
  uint32_t c;
  uint32_t topbit = 0;
  const uint8_t *end = p + len;
  if (!utf && *p == 0xff && len > 1)
    {
    topbit = 0x80000000u;
    p++;
    len--;
    }
  chlen = utf8_to_ord(p, end, &c);
  if (chlen <= 0) return -1;
  if (utf && c > 0x10ffff) return -2;
  p += chlen;
  len -= chlen;
  *pp++ = c | topbit;
  }

*pp = 0;
*lenptr = pp - pbuffer32;
return 0;
}
#endif /* PCRE2_CODE_UNIT_WIDTH == 32 */



/*************************************************
*        Read a string from pcre2_config()       *
*************************************************/

/* Read out a version string from pcre2_config(), transcoding it into an
8-bit buffer.

Arguments:
  what       the item to read
  where      the 8-bit buffer to receive the string
*/

static void
config_str(uint32_t what, char *where)
{
int r1, r2;
PCRE2_UCHAR buf[VERSION_SIZE];

r1 = pcre2_config(what, NULL);
r2 = pcre2_config(what, buf);
if (r1 < 0 || r1 != r2 || r1 >= VERSION_SIZE)
  {
  cfprintf(clr_test_error, stderr, "pcre2test: Error in pcre2_config(%d)\n", what);
  exit(1);
  }

while (r1-- > 0) where[r1] = (char)buf[r1];
}



/*************************************************
*       Check a modifier and find its field      *
*************************************************/

/* This function is called when a modifier has been identified. We check that
it is allowed here and find the field that is to be changed.

Arguments:
  m          the modifier list entry
  ctx        CTX_PAT     => pattern context
             CTX_POPPAT  => pattern context for popped pattern
             CTX_DEFPAT  => default pattern context
             CTX_DAT     => data context
             CTX_DEFDAT  => default data context
  pctl       point to pattern control block
  dctl       point to data control block
  c          a single character or 0

Returns:     a field pointer or NULL
*/

static void *
check_modifier(modstruct *m, int ctx, patctl *pctl, datctl *dctl, uint32_t c)
{
void *field = NULL;
PCRE2_SIZE offset = m->offset;

if (restrict_for_perl_test) switch(m->which)
  {
  case MOD_PNDP:
  case MOD_PATP:
  case MOD_DATP:
  case MOD_PDP:
  break;

  default:
  cfprintf(clr_test_error, outfile, "** \"%s\" is not allowed in a Perl-compatible test\n",
    m->name);
  return NULL;
  }

switch (m->which)
  {
  case MOD_CTC:  /* Compile context modifier */
  if (ctx == CTX_DEFPAT) field = default_pat_context;
    else if (ctx == CTX_PAT) field = pat_context;
  break;

  case MOD_CTM:  /* Match context modifier */
  if (ctx == CTX_DEFDAT) field = default_dat_context;
    else if (ctx == CTX_DAT) field = dat_context;
  break;

  case MOD_DAT:    /* Data line modifier */
  case MOD_DATP:   /* Allowed for Perl test */
  if (dctl != NULL) field = dctl;
  break;

  case MOD_PAT:    /* Pattern modifier */
  case MOD_PATP:   /* Allowed for Perl test */
  if (pctl != NULL) field = pctl;
  break;

  case MOD_PD:   /* Pattern or data line modifier */
  case MOD_PDP:  /* Ditto, allowed for Perl test */
  case MOD_PND:  /* Ditto, but not default pattern */
  case MOD_PNDP: /* Ditto, allowed for Perl test */
  if (dctl != NULL) field = dctl;
    else if (pctl != NULL && (m->which == MOD_PD || m->which == MOD_PDP ||
             ctx != CTX_DEFPAT))
      field = pctl;
  break;
  }

if (field == NULL)
  {
  if (c == 0)
    cfprintf(clr_test_error, outfile, "** \"%s\" is not valid here\n", m->name);
  else
    cfprintf(clr_test_error, outfile, "** /%c is not valid here\n", c);
  return NULL;
  }

return (char *)field + offset;
}



/*************************************************
*            Decode a modifier list              *
*************************************************/

/* A pointer to a control block is NULL when called in cases when that block is
not relevant. They are never all relevant in one call. At least one of patctl
and datctl is NULL. The second argument specifies which context to use for
modifiers that apply to contexts.

Arguments:
  p          point to modifier string
  ctx        CTX_PAT     => pattern context
             CTX_POPPAT  => pattern context for popped pattern
             CTX_DEFPAT  => default pattern context
             CTX_DAT     => data context
             CTX_DEFDAT  => default data context
  pctl       point to pattern control block
  dctl       point to data control block

Returns: TRUE if successful decode, FALSE otherwise
*/

static BOOL
decode_modifiers(uint8_t *p, int ctx, patctl *pctl, datctl *dctl)
{
uint8_t *ep, *pp;
long li;
unsigned long uli;
BOOL first = TRUE;

for (;;)
  {
  void *field;
  modstruct *m;
  BOOL off = FALSE;
  unsigned int i;
  size_t len;
  int index;
  char *endptr;

  /* Skip white space and commas. */

  while (isspace(*p) || *p == ',') p++;
  if (*p == 0) break;

  /* Find the end of the item; lose trailing whitespace at end of line. */

  for (ep = p; *ep != 0 && *ep != ','; ep++);
  if (*ep == 0)
    {
    while (ep > p && isspace(ep[-1])) ep--;
    *ep = 0;
    }

  /* Remember if the first character is '-'. */

  if (*p == '-')
    {
    off = TRUE;
    p++;
    }

  /* Find the length of a full-length modifier name, and scan for it. */

  pp = p;
  while (pp < ep && *pp != '=') pp++;
  index = scan_modifiers(p, pp - p);

  /* If the first modifier is unrecognized, try to interpret it as a sequence
  of single-character abbreviated modifiers. None of these modifiers have any
  associated data. They just set options or control bits. */

  if (index < 0)
    {
    uint32_t cc;
    uint8_t *mp = p;

    if (!first)
      {
      cfprintf(clr_test_error, outfile, "** Unrecognized modifier \"%.*s\"\n", (int)(ep-p), p);
      if (ep - p == 1)
        cfprintf(clr_test_error, outfile, "** Single-character modifiers must come first\n");
      return FALSE;
      }

    first = FALSE;

    for (cc = *p; cc != ',' && cc != '\n' && cc != 0; cc = *(++p))
      {
      for (i = 0; i < C1MODLISTCOUNT; i++)
        if (cc == c1modlist[i].onechar) break;

      if (i >= C1MODLISTCOUNT)
        {
        cfprintf(clr_test_error, outfile, "** Unrecognized modifier '%c' in modifier string "
          "\"%.*s\"\n", *p, (int)(ep-mp), mp);
        return FALSE;
        }

      if (c1modlist[i].index >= 0)
        {
        index = c1modlist[i].index;
        }

      else
        {
        index = scan_modifiers((const uint8_t *)(c1modlist[i].fullname),
          strlen(c1modlist[i].fullname));
        if (index < 0)
          {
          cfprintf(clr_test_error, outfile, "** Internal error: single-character equivalent "
            "modifier \"%s\" not found\n", c1modlist[i].fullname);
          return FALSE;
          }
        c1modlist[i].index = index;     /* Cache for next time */
        }

      field = check_modifier(modlist + index, ctx, pctl, dctl, *p);
      if (field == NULL) return FALSE;

      /* /x is a special case; a second appearance changes PCRE2_EXTENDED to
      PCRE2_EXTENDED_MORE. */

      if (cc == 'x' && (*((uint32_t *)field) & PCRE2_EXTENDED) != 0)
        {
        *((uint32_t *)field) &= ~PCRE2_EXTENDED;
        *((uint32_t *)field) |= PCRE2_EXTENDED_MORE;
        }
      else
        *((uint32_t *)field) |= modlist[index].value;
      }

    continue;    /* With the next (fullname) modifier */
    }

  /* We have a match on a full-name modifier. Check for the existence of data
  when needed. */

  m = modlist + index;      /* Save typing */
  if (m->type != MOD_CTL && m->type != MOD_OPT && m->type != MOD_OPTMZ &&
      (m->type != MOD_IND || *pp == '='))
    {
    if (*pp++ != '=')
      {
      cfprintf(clr_test_error, outfile, "** '=' expected after \"%s\"\n", m->name);
      return FALSE;
      }
    if (off)
      {
      cfprintf(clr_test_error, outfile, "** '-' is not valid for \"%s\"\n", m->name);
      return FALSE;
      }
    }

  /* These on/off types have no data. */

  else if (*pp != ',' && *pp != '\n' && *pp != ' ' && *pp != 0)
    {
    cfprintf(clr_test_error, outfile, "** Unrecognized modifier '%.*s'\n", (int)(ep-p), p);
    return FALSE;
    }

  /* Set the data length for those types that have data. Then find the field
  that is to be set. If check_modifier() returns NULL, it has already output an
  error message. */

  len = ep - pp;
  field = check_modifier(m, ctx, pctl, dctl, 0);
  if (field == NULL) return FALSE;

  /* Process according to data type. */

  switch (m->type)
    {
    case MOD_CTL:
    case MOD_OPT:
    if (off) *((uint32_t *)field) &= ~m->value;
      else *((uint32_t *)field) |= m->value;
    break;

    case MOD_OPTMZ:
    pcre2_set_optimize(field, m->value);
    break;

    case MOD_BSR:
    if (len == 7 && strncmpic(pp, (const uint8_t *)"default", 7) == 0)
      {
#ifdef BSR_ANYCRLF
      *((uint16_t *)field) = PCRE2_BSR_ANYCRLF;
#else
      *((uint16_t *)field) = PCRE2_BSR_UNICODE;
#endif
      if (ctx == CTX_PAT || ctx == CTX_DEFPAT) pctl->control2 &= ~CTL2_BSR_SET;
        else dctl->control2 &= ~CTL2_BSR_SET;
      }
    else
      {
      if (len == 7 && strncmpic(pp, (const uint8_t *)"anycrlf", 7) == 0)
        *((uint16_t *)field) = PCRE2_BSR_ANYCRLF;
      else if (len == 7 && strncmpic(pp, (const uint8_t *)"unicode", 7) == 0)
        *((uint16_t *)field) = PCRE2_BSR_UNICODE;
      else goto INVALID_VALUE;
      if (ctx == CTX_PAT || ctx == CTX_DEFPAT) pctl->control2 |= CTL2_BSR_SET;
        else dctl->control2 |= CTL2_BSR_SET;
      }
    pp = ep;
    break;

    case MOD_CHR:  /* A single character */
    *((uint32_t *)field) = *pp++;
    break;

    case MOD_CON:  /* A convert type/options list */
    for (;; pp++)
      {
      uint8_t *colon = (uint8_t *)strchr((const char *)pp, ':');
      len = ((colon != NULL && colon < ep)? colon:ep) - pp;
      for (i = 0; i < convertlistcount; i++)
        {
        if (strncmpic(pp, (const uint8_t *)convertlist[i].name, len) == 0)
          {
          if (*((uint32_t *)field) == CONVERT_UNSET)
            *((uint32_t *)field) = convertlist[i].option;
          else
            *((uint32_t *)field) |= convertlist[i].option;
          break;
          }
        }
      if (i >= convertlistcount) goto INVALID_VALUE;
      pp += len;
      if (*pp != ':') break;
      }
    break;

    case MOD_IN2:    /* One or two unsigned integers */
    if (!isdigit(*pp)) goto INVALID_VALUE;
    uli = strtoul((const char *)pp, &endptr, 10);
    if (U32OVERFLOW(uli)) goto INVALID_VALUE;
    ((uint32_t *)field)[0] = (uint32_t)uli;
    if (*endptr == ':')
      {
      uli = strtoul((const char *)endptr+1, &endptr, 10);
      if (U32OVERFLOW(uli)) goto INVALID_VALUE;
      ((uint32_t *)field)[1] = (uint32_t)uli;
      }
    else ((uint32_t *)field)[1] = 0;
    pp = (uint8_t *)endptr;
    break;

    /* PCRE2_SIZE_MAX is usually SIZE_MAX, which may be greater, equal to, or
    less than ULONG_MAX. So first test for overflowing the long int, and then
    test for overflowing PCRE2_SIZE_MAX if it is smaller than ULONG_MAX. */

    case MOD_SIZ:    /* PCRE2_SIZE value */
    if (!isdigit(*pp)) goto INVALID_VALUE;
    uli = strtoul((const char *)pp, &endptr, 10);
    if (uli == ULONG_MAX) goto INVALID_VALUE;
#if ULONG_MAX > PCRE2_SIZE_MAX
    if (uli > PCRE2_SIZE_MAX) goto INVALID_VALUE;
#endif
    *((PCRE2_SIZE *)field) = (PCRE2_SIZE)uli;
    pp = (uint8_t *)endptr;
    break;

    case MOD_IND:    /* Unsigned integer with default */
    if (len == 0)
      {
      *((uint32_t *)field) = (uint32_t)(m->value);
      break;
      }
    PCRE2_FALLTHROUGH /* Fall through */

    case MOD_INT:    /* Unsigned integer */
    if (!isdigit(*pp)) goto INVALID_VALUE;
    uli = strtoul((const char *)pp, &endptr, 10);
    if (U32OVERFLOW(uli)) goto INVALID_VALUE;
    *((uint32_t *)field) = (uint32_t)uli;
    pp = (uint8_t *)endptr;
    break;

    case MOD_INS:   /* Signed integer */
    if (!isdigit(*pp) && *pp != '-') goto INVALID_VALUE;
    li = strtol((const char *)pp, &endptr, 10);
    if (S32OVERFLOW(li)) goto INVALID_VALUE;
    *((int32_t *)field) = (int32_t)li;
    pp = (uint8_t *)endptr;
    break;

    case MOD_NL:
    for (i = 0; i < sizeof(newlines)/sizeof(char *); i++)
      if (len == strlen(newlines[i]) &&
        strncmpic(pp, (const uint8_t *)newlines[i], len) == 0) break;
    if (i >= sizeof(newlines)/sizeof(char *)) goto INVALID_VALUE;
    if (i == 0)
      {
      pcre2_set_newline(field, NEWLINE_DEFAULT);
      if (ctx == CTX_PAT || ctx == CTX_DEFPAT) pctl->control2 &= ~CTL2_NL_SET;
        else dctl->control2 &= ~CTL2_NL_SET;
      }
    else
      {
      pcre2_set_newline(field, i);
      if (ctx == CTX_PAT || ctx == CTX_DEFPAT) pctl->control2 |= CTL2_NL_SET;
        else dctl->control2 |= CTL2_NL_SET;
      }
    pp = ep;
    break;

    case MOD_NN:              /* Name or (signed) number; may be several */
    if (isdigit(*pp) || *pp == '-')
      {
      int ct = MAXCPYGET - 1;
      int32_t value;
      li = strtol((const char *)pp, &endptr, 10);
      if (S32OVERFLOW(li)) goto INVALID_VALUE;
      value = (int32_t)li;
      field = (char *)field - m->offset + m->value;      /* Adjust field ptr */
      if (value >= 0)                                    /* Add new number */
        {
        while (*((int32_t *)field) >= 0 && ct-- > 0)   /* Skip previous */
          field = (char *)field + sizeof(int32_t);
        if (ct <= 0)
          {
          cfprintf(clr_test_error, outfile, "** Too many numeric \"%s\" modifiers\n", m->name);
          return FALSE;
          }
        }
      *((int32_t *)field) = value;
      if (ct > 0) ((int32_t *)field)[1] = -1;
      pp = (uint8_t *)endptr;
      }

    /* Multiple strings are put end to end. */

    else
      {
      char *nn = (char *)field;
      if (len > 0)                    /* Add new name */
        {
        if (len > MAX_NAME_SIZE)
          {
          cfprintf(clr_test_error, outfile, "** Group name in \"%s\" is too long\n", m->name);
          return FALSE;
          }
        while (*nn != 0) nn += strlen(nn) + 1;
        if (nn + len + 2 - (char *)field > LENCPYGET)
          {
          cfprintf(clr_test_error, outfile, "** Too many characters in named \"%s\" modifiers\n",
            m->name);
          return FALSE;
          }
        memcpy(nn, pp, len);
        }
      nn[len] = 0 ;
      nn[len+1] = 0;
      pp = ep;
      }
    break;

    case MOD_STR:
    if (len + 1 > m->value)
      {
      cfprintf(clr_test_error, outfile, "** Overlong value for \"%s\" (max %d code units)\n",
        m->name, m->value - 1);
      return FALSE;
      }
    ((uint8_t *)field)[0] = len;
    memcpy(((uint8_t *)field)+1, pp, len);
    ((uint8_t *)field)[len+1] = 0;
    pp = ep;
    break;
    }

  if (*pp != ',' && *pp != '\n' && *pp != ' ' && *pp != 0)
    {
    cfprintf(clr_test_error, outfile, "** Comma expected after modifier item \"%s\"\n", m->name);
    return FALSE;
    }

  p = pp;

  if (ctx == CTX_POPPAT &&
     (pctl->options != 0 ||
      pctl->tables_id != 0 ||
      pctl->locale[0] != MOD_STR_UNSET ||
      (pctl->control & NOTPOP_CONTROLS) != 0))
    {
    cfprintf(clr_test_error, outfile, "** \"%s\" is not valid here\n", m->name);
    return FALSE;
    }
  }

return TRUE;

INVALID_VALUE:
cfprintf(clr_test_error, outfile, "** Invalid value in \"%.*s\"\n", (int)(ep-p), p);
return FALSE;
}



/*************************************************
*             Get info from a pattern            *
*************************************************/

/* A wrapped call to pcre2_pattern_info(), applied to the current compiled
pattern.

Arguments:
  what        code for the required information
  where       where to put the answer
  unsetok     PCRE2_ERROR_UNSET is an "expected" result

Returns:      the return from pcre2_pattern_info()
*/

static int
pattern_info(int what, void *where, BOOL unsetok)
{
int rc;
(void)pcre2_pattern_info(compiled_code, what, NULL);  /* Exercise the code */
rc = pcre2_pattern_info(compiled_code, what, where);
if (rc >= 0) return 0;
if (rc != PCRE2_ERROR_UNSET || !unsetok)
  {
  cfprintf(clr_api_error, outfile, "Error %d from "
    "pcre2_pattern_info_" STR(PCRE2_CODE_UNIT_WIDTH) "(%d)\n", rc, what);
  }
return rc;
}



/*************************************************
*      Show memory usage info for a pattern      *
*************************************************/

static void
show_memory_info(void)
{
uint32_t name_count, name_entry_size;
PCRE2_SIZE size, cblock_size, data_size;

cblock_size = sizeof(pcre2_real_code);

(void)pattern_info(PCRE2_INFO_SIZE, &size, FALSE);
(void)pattern_info(PCRE2_INFO_NAMECOUNT, &name_count, FALSE);
(void)pattern_info(PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size, FALSE);

/* The uint32_t variables are cast before multiplying to avoid potential
 integer overflow. */
data_size = CU2BYTES((PCRE2_SIZE)name_count * (PCRE2_SIZE)name_entry_size);

cfprintf(clr_profiling, outfile, "Memory allocation - code size : %" SIZ_FORM "\n", size -
  cblock_size - data_size);
if (data_size != 0)
  cfprintf(clr_profiling, outfile, "Memory allocation - data size : %" SIZ_FORM "\n", data_size);

if (pat_patctl.jit != 0)
  {
  (void)pattern_info(PCRE2_INFO_JITSIZE, &size, FALSE);
  cfprintf(clr_profiling, outfile, "Memory allocation - JIT code  : %" SIZ_FORM "\n", size);
  }
}



/*************************************************
*       Show frame size info for a pattern       *
*************************************************/

static void
show_framesize(void)
{
PCRE2_SIZE frame_size;
(void)pattern_info(PCRE2_INFO_FRAMESIZE, &frame_size, FALSE);
cfprintf(clr_profiling, outfile, "Frame size for pcre2_match(): %" SIZ_FORM "\n", frame_size);
}



/*************************************************
*   Show heapframes size info for a match_data   *
*************************************************/

static void
show_heapframes_size(void)
{
PCRE2_SIZE heapframes_size;
heapframes_size = pcre2_get_match_data_heapframes_size(match_data);
cfprintf(clr_profiling, outfile, "Heapframes size in match_data: %" SIZ_FORM "\n",
  heapframes_size);
}



/*************************************************
*         Get and output an error message        *
*************************************************/

static BOOL
print_error_message_file(FILE *file, int errorcode, const char *before,
  const char *after, BOOL badcode_ok)
{
int len;
PCRE2_UCHAR buf[128];

len = pcre2_get_error_message(errorcode, buf, sizeof(buf)/sizeof(*buf));
if (len == PCRE2_ERROR_BADDATA && badcode_ok)
  {
  cfprintf(clr_api_error, file, "%sPCRE2_ERROR_BADDATA (unknown error number)%s", before,
    after);
  }
else if (len < 0)
  {
  cfprintf(clr_test_error, file, "\n** pcre2test internal error: cannot interpret error "
    "number\n** Unexpected return (%d) from pcre2_get_error_message()\n", len);
  }
else if ((unsigned)len != pcre2_strlen(buf))
  {
  cfprintf(clr_test_error, file, "\n** pcre2test: unexpected length %d from pcre2_get_error_message()\n", len);
  return FALSE;
  }
else
  {
  cfprintf(clr_api_error, file, "%s", before);
  pchars(clr_api_error, buf, len, FALSE, file);
  cfprintf(clr_api_error, file, "%s", after);
  }
return len >= 0;
}

static BOOL
print_error_message(int errorcode, const char *before, const char *after)
{
return print_error_message_file(outfile, errorcode, before, after, FALSE);
}


/*************************************************
*     Callback function for callout enumeration  *
*************************************************/

/* Testing function to log data inside callout enumeration callbacks.

Argument:
  cb            pointer to enumerate block
  callout_data  user data

Returns:    0
*/

static int callout_enumerate_function(pcre2_callout_enumerate_block *cb,
  void *callout_data)
{
uint32_t i;
PCRE2_SPTR pattern_string = pbuffer;
BOOL utf = (compiled_code->overall_options & PCRE2_UTF) != 0;
PCRE2_SIZE next_item_length = cb->next_item_length;

(void)callout_data;  /* Not currently displayed */

fprintf(outfile, "Callout ");
if (cb->callout_string != NULL)
  {
  uint32_t delimiter = cb->callout_string[-1];
  fprintf(outfile, "%c", CHAR_OUTPUT(delimiter));
  pchars(clr_none, cb->callout_string, cb->callout_string_length, utf, outfile);
  for (i = 0; callout_start_delims[i] != 0; i++)
    if (delimiter == callout_start_delims[i])
      {
      delimiter = callout_end_delims[i];
      break;
      }
  fprintf(outfile, "%c  ", CHAR_OUTPUT(delimiter));
  }
else fprintf(outfile, "%d  ", cb->callout_number);

if (next_item_length == 0 && pattern_string[cb->pattern_position] != 0)
  next_item_length = 1;
pchars(clr_none, pattern_string+cb->pattern_position, next_item_length, utf, outfile);
fprintf(outfile, "\n");

return 0;
}

static int callout_enumerate_function_void(pcre2_callout_enumerate_block *cb,
  void *callout_data)
{
(void)cb;
(void)callout_data;
return 0;
}

static int callout_enumerate_function_fail(pcre2_callout_enumerate_block *cb,
  void *callout_data)
{
(void)cb;
return *(int *)callout_data;
}



/*************************************************
*        Show information about a pattern        *
*************************************************/

/* This function is called after a pattern has been compiled if any of the
information-requesting controls have been set.

Arguments:  none

Returns:    PR_OK     continue processing next line
            PR_SKIP   skip to a blank line
            PR_ABEND  abort the pcre2test run
*/

static int
show_pattern_info(void)
{
int rc;
uint32_t compile_options, overall_options, extra_options;
BOOL utf = (compiled_code->overall_options & PCRE2_UTF) != 0;

if ((pat_patctl.control & CTL_MEMORY) != 0)
  show_memory_info();

if ((pat_patctl.control2 & CTL2_FRAMESIZE) != 0)
  show_framesize();

if ((pat_patctl.control & (CTL_BINCODE|CTL_FULLBINCODE)) != 0)
  {
  fprintf(outfile, "------------------------------------------------------------------\n");
  pcre2_printint(compiled_code, outfile,
    (pat_patctl.control & CTL_FULLBINCODE) != 0);
  }

if ((pat_patctl.control & CTL_INFO) != 0)
  {
  PCRE2_SPTR nametable;
  uint8_t *start_bits;
  BOOL heap_limit_set, match_limit_set, depth_limit_set;
  uint32_t backrefmax, bsr_convention, capture_count, first_ctype, first_cunit,
    hasbackslashc, hascrorlf, jchanged, last_ctype, last_cunit, match_empty,
    depth_limit, heap_limit, match_limit, minlength, nameentrysize, namecount,
    newline_convention;

  /* These info requests may return PCRE2_ERROR_UNSET. */

  switch(pattern_info(PCRE2_INFO_HEAPLIMIT, &heap_limit, TRUE))
    {
    case 0:
    heap_limit_set = TRUE;
    break;

    case PCRE2_ERROR_UNSET:
    heap_limit_set = FALSE;
    break;

    default:
    return PR_ABEND;
    }

  switch(pattern_info(PCRE2_INFO_MATCHLIMIT, &match_limit, TRUE))
    {
    case 0:
    match_limit_set = TRUE;
    break;

    case PCRE2_ERROR_UNSET:
    match_limit_set = FALSE;
    break;

    default:
    return PR_ABEND;
    }

  switch(pattern_info(PCRE2_INFO_DEPTHLIMIT, &depth_limit, TRUE))
    {
    case 0:
    depth_limit_set = TRUE;
    break;

    case PCRE2_ERROR_UNSET:
    depth_limit_set = FALSE;
    break;

    default:
    return PR_ABEND;
    }

  /* These info requests should always succeed. */

  if (pattern_info(PCRE2_INFO_BACKREFMAX, &backrefmax, FALSE) +
      pattern_info(PCRE2_INFO_BSR, &bsr_convention, FALSE) +
      pattern_info(PCRE2_INFO_CAPTURECOUNT, &capture_count, FALSE) +
      pattern_info(PCRE2_INFO_FIRSTBITMAP, &start_bits, FALSE) +
      pattern_info(PCRE2_INFO_FIRSTCODEUNIT, &first_cunit, FALSE) +
      pattern_info(PCRE2_INFO_FIRSTCODETYPE, &first_ctype, FALSE) +
      pattern_info(PCRE2_INFO_HASBACKSLASHC, &hasbackslashc, FALSE) +
      pattern_info(PCRE2_INFO_HASCRORLF, &hascrorlf, FALSE) +
      pattern_info(PCRE2_INFO_JCHANGED, &jchanged, FALSE) +
      pattern_info(PCRE2_INFO_LASTCODEUNIT, &last_cunit, FALSE) +
      pattern_info(PCRE2_INFO_LASTCODETYPE, &last_ctype, FALSE) +
      pattern_info(PCRE2_INFO_MATCHEMPTY, &match_empty, FALSE) +
      pattern_info(PCRE2_INFO_MINLENGTH, &minlength, FALSE) +
      pattern_info(PCRE2_INFO_NAMECOUNT, &namecount, FALSE) +
      pattern_info(PCRE2_INFO_NAMEENTRYSIZE, &nameentrysize, FALSE) +
      pattern_info(PCRE2_INFO_NAMETABLE, &nametable, FALSE) +
      pattern_info(PCRE2_INFO_NEWLINE, &newline_convention, FALSE)
      != 0)
    return PR_ABEND;

  fprintf(outfile, "Capture group count = %d\n", capture_count);

  if (backrefmax > 0)
    fprintf(outfile, "Max back reference = %d\n", backrefmax);

  if (maxlookbehind > 0)
    fprintf(outfile, "Max lookbehind = %d\n", maxlookbehind);

  if (heap_limit_set)
    fprintf(outfile, "Heap limit = %u\n", heap_limit);

  if (match_limit_set)
    fprintf(outfile, "Match limit = %u\n", match_limit);

  if (depth_limit_set)
    fprintf(outfile, "Depth limit = %u\n", depth_limit);

  if (namecount > 0)
    {
    fprintf(outfile, "Named capture groups:\n");
    for (; namecount > 0; namecount--)
      {
      size_t length = pcre2_strlen(nametable + IMM2_SIZE);
      fprintf(outfile, "  ");

      /* In UTF mode the name may be a UTF string containing non-ASCII
      letters and digits. We must output it as a UTF-8 string. In non-UTF mode,
      use the normal string printing functions, which use escapes for all
      non-ASCII characters. */

      if (utf)
        {
#if PCRE2_CODE_UNIT_WIDTH == 32
        PCRE2_SPTR nameptr = nametable + IMM2_SIZE;
        while (*nameptr != 0)
          {
          uint8_t u8buff[6];
          int len = ord_to_utf8(*nameptr++, u8buff);
          fprintf(outfile, "%.*s", len, u8buff);
          }
#endif
#if PCRE2_CODE_UNIT_WIDTH == 16
        PCRE2_SPTR nameptr = nametable + IMM2_SIZE;
        PCRE2_SPTR nameptr_end = nameptr + pcre2_strlen(nameptr);
        while (*nameptr != 0)
          {
          int len;
          uint8_t u8buff[6];
          uint32_t c;
          int ord_rc = utf16_to_ord(nameptr, nameptr_end, &c);
          if (ord_rc > 0) nameptr += ord_rc;
          else c = *nameptr++;
          len = ord_to_utf8(c, u8buff);
          fprintf(outfile, "%.*s", len, u8buff);
          }
#endif
#if PCRE2_CODE_UNIT_WIDTH == 8
        fprintf(outfile, "%s", nametable + IMM2_SIZE);
#endif
        }
      else  /* Not UTF mode */
        {
        pchars(clr_none, nametable + IMM2_SIZE, length, FALSE, outfile);
        }

      while (length++ < nameentrysize - IMM2_SIZE) putc(' ', outfile);

      fprintf(outfile, "%3d\n", GET2(nametable, 0));

      nametable = nametable + nameentrysize;
      }
    }

  if (hascrorlf)     fprintf(outfile, "Contains explicit CR or LF match\n");
  if (hasbackslashc) fprintf(outfile, "Contains \\C\n");
  if (match_empty)   fprintf(outfile, "May match empty string\n");

  pattern_info(PCRE2_INFO_ARGOPTIONS, &compile_options, FALSE);
  pattern_info(PCRE2_INFO_ALLOPTIONS, &overall_options, FALSE);
  pattern_info(PCRE2_INFO_EXTRAOPTIONS, &extra_options, FALSE);

  /* Remove UTF/UCP if they were there only because of forbid_utf. This saves
  cluttering up the verification output of non-UTF test files. */

  if ((pat_patctl.options & PCRE2_NEVER_UTF) == 0)
    {
    compile_options &= ~PCRE2_NEVER_UTF;
    overall_options &= ~PCRE2_NEVER_UTF;
    }

  if ((pat_patctl.options & PCRE2_NEVER_UCP) == 0)
    {
    compile_options &= ~PCRE2_NEVER_UCP;
    overall_options &= ~PCRE2_NEVER_UCP;
    }

  if ((compile_options|overall_options) != 0)
    {
    if (compile_options == overall_options)
      show_compile_options(clr_none, compile_options, "Options:", "\n");
    else
      {
      show_compile_options(clr_none, compile_options, "Compile options:", "\n");
      show_compile_options(clr_none, overall_options, "Overall options:", "\n");
      }
    }

  if (extra_options != 0)
    show_compile_extra_options(clr_none, extra_options, "Extra options:", "\n");

  if (compiled_code->optimization_flags != PCRE2_OPTIMIZATION_ALL)
    show_optimize_flags(clr_none, compiled_code->optimization_flags, "Optimizations: ", "\n");

  if (jchanged) fprintf(outfile, "Duplicate name status changes\n");

  if ((pat_patctl.control2 & CTL2_BSR_SET) != 0 ||
      (compiled_code->flags & PCRE2_BSR_SET) != 0)
    fprintf(outfile, "\\R matches %s\n", (bsr_convention == PCRE2_BSR_UNICODE)?
      "any Unicode newline" : "CR, LF, or CRLF");

  if ((compiled_code->flags & PCRE2_NL_SET) != 0)
    {
    switch (newline_convention)
      {
      case PCRE2_NEWLINE_CR:
      fprintf(outfile, "Forced newline is CR\n");
      break;

      case PCRE2_NEWLINE_LF:
      fprintf(outfile, "Forced newline is LF\n");
      break;

      case PCRE2_NEWLINE_CRLF:
      fprintf(outfile, "Forced newline is CRLF\n");
      break;

      case PCRE2_NEWLINE_ANYCRLF:
      fprintf(outfile, "Forced newline is CR, LF, or CRLF\n");
      break;

      case PCRE2_NEWLINE_ANY:
      fprintf(outfile, "Forced newline is any Unicode newline\n");
      break;

      case PCRE2_NEWLINE_NUL:
      fprintf(outfile, "Forced newline is NUL\n");
      break;

      default:
      break;
      }
    }

  if (first_ctype == 2)
    {
    fprintf(outfile, "First code unit at start or follows newline\n");
    }
  else if (first_ctype == 1)
    {
    const char *caseless =
      ((compiled_code->flags & PCRE2_FIRSTCASELESS) == 0)?
      "" : " (caseless)";
    if (first_cunit != 0xff && PRINTABLE(first_cunit))
      fprintf(outfile, "First code unit = \'%c\'%s\n", CHAR_OUTPUT(first_cunit),
              caseless);
    else
      {
      fprintf(outfile, "First code unit = ");
      if (first_cunit == 0xff)
        fprintf(outfile, "\\xff");
      else
        pchar(first_cunit, FALSE, outfile);
      fprintf(outfile, "%s\n", caseless);
      }
    }
  else if (start_bits != NULL)
    {
    int input;
    int c = 24;
    fprintf(outfile, "Starting code units:");
    for (input = 0; input < 256; input++)
      {
      int i = CHAR_INPUT_HEX(input);
      if ((start_bits[i/8] & (1u << (i&7))) != 0)
        {
        if (c > 75)
          {
          fprintf(outfile, "\n ");
          c = 2;
          }
        if (PRINTABLE(i) && i != CHAR_SPACE)
          {
          fprintf(outfile, " %c", CHAR_OUTPUT(i));
          c += 2;
          }
        else
          {
          fprintf(outfile, " \\x%02x", CHAR_OUTPUT_HEX(i));
          c += 5;
          }
        }
      }
    fprintf(outfile, "\n");
    }

  if (last_ctype != 0)
    {
    const char *caseless =
      ((compiled_code->flags & PCRE2_LASTCASELESS) == 0)?
      "" : " (caseless)";
    if (PRINTABLE(last_cunit))
      fprintf(outfile, "Last code unit = \'%c\'%s\n", CHAR_OUTPUT(last_cunit),
              caseless);
    else
      {
      fprintf(outfile, "Last code unit = ");
      pchar(last_cunit, FALSE, outfile);
      fprintf(outfile, "%s\n", caseless);
      }
    }

  if ((compiled_code->optimization_flags & PCRE2_OPTIM_START_OPTIMIZE) != 0)
    fprintf(outfile, "Subject length lower bound = %d\n", minlength);

  if (pat_patctl.jit != 0 && (pat_patctl.control & CTL_JITVERIFY) != 0)
    {
#ifdef SUPPORT_JIT
    if (compiled_code->executable_jit != NULL)
      fprintf(outfile, "JIT compilation was successful\n");
    else
      {
      cfprintf(clr_api_error, outfile, "JIT compilation was not successful");
      if (jitrc != 0 && !print_error_message(jitrc, " (", ")"))
        return PR_ABEND;
      fprintf(outfile, "\n");
      }
#else
      cfprintf(clr_api_error, outfile, "JIT support is not available in this version of PCRE2\n");
#endif
    }
  }

rc = pcre2_callout_enumerate(compiled_code,
  ((pat_patctl.control & CTL_CALLOUT_INFO) != 0)? callout_enumerate_function :
  /* Exercise the callout enumeration code with a dummy callback to make sure
  it works. */
  callout_enumerate_function_void, NULL);
if (rc != 0)
  {
  cfprintf(clr_api_error, outfile, "Callout enumerate failed: error %d: ", rc);
  if (rc < 0 && !print_error_message(rc, "", "\n"))
    return PR_ABEND;
  return PR_SKIP;
  }

return PR_OK;
}



/*************************************************
*              Handle serialization error        *
*************************************************/

/* Print an error message after a serialization failure.

Arguments:
  rc         the error code
  msg        an initial message for what failed

Returns:     FALSE if print_error_message() fails
*/

static BOOL
serial_error(int rc, const char *msg)
{
cfprintf(clr_api_error, outfile, "%s failed: error %d: ", msg, rc);
return print_error_message(rc, "", "\n");
}



/*************************************************
*               Process command line             *
*************************************************/

/* This function is called for lines beginning with # and a character that is
not ! or whitespace, when encountered between tests, which means that there is
no compiled pattern (compiled_code is NULL). The line is in buffer.

Arguments:  none

Returns:    PR_OK     continue processing next line
            PR_SKIP   skip to a blank line
            PR_ABEND  abort the pcre2test run
*/

static int
process_command(void)
{
FILE *f;
PCRE2_SIZE serial_size;
size_t i;
int rc, cmd, yield;
uint16_t first_listed_newline;
const char *cmdname;
size_t cmdlen;
uint8_t *argptr, *serial;
BOOL if_inverted;

yield = PR_OK;
cmd = CMD_UNKNOWN;
cmdlen = 0;

for (i = 0; i < cmdlistcount; i++)
  {
  cmdname = cmdlist[i].name;
  cmdlen = strlen(cmdname);
  if (strncmp((char *)(buffer+1), cmdname, cmdlen) == 0 &&
      (buffer[cmdlen+1] == 0 || isspace(buffer[cmdlen+1])))
    {
    cmd = cmdlist[i].value;
    break;
    }
  }

if (preprocess_only && cmd != CMD_IF && cmd != CMD_ENDIF)
  return PR_OK;

argptr = buffer + cmdlen + 1;

if (restrict_for_perl_test && cmd != CMD_PATTERN && cmd != CMD_SUBJECT &&
    cmd != CMD_IF && cmd != CMD_ENDIF)
  {
  cfprintf(clr_test_error, outfile, "** #%s is not allowed after #perltest\n", cmdname);
  return PR_ABEND;
  }

switch(cmd)
  {
  case CMD_UNKNOWN:
  cfprintf(clr_test_error, outfile, "** Unknown command: %s", buffer);
  break;

  case CMD_FORBID_UTF:
  forbid_utf = PCRE2_NEVER_UTF|PCRE2_NEVER_UCP;
  break;

  case CMD_PERLTEST:
  restrict_for_perl_test = TRUE;
  break;

  /* Set default pattern modifiers */

  case CMD_PATTERN:
  (void)decode_modifiers(argptr, CTX_DEFPAT, &def_patctl, NULL);
  if (def_patctl.jit == 0 && (def_patctl.control & CTL_JITVERIFY) != 0)
    def_patctl.jit = JIT_DEFAULT;
  break;

  /* Set default subject modifiers */

  case CMD_SUBJECT:
  (void)decode_modifiers(argptr, CTX_DEFDAT, NULL, &def_datctl);
  break;

  /* Check the default newline, and if not one of those listed, set up the
  first one to be forced. An empty list unsets. */

  case CMD_NEWLINE_DEFAULT:
  local_newline_default = 0;   /* Unset */
  first_listed_newline = 0;
  for (;;)
    {
    while (isspace(*argptr)) argptr++;
    if (*argptr == 0) break;
    for (uint16_t j = 1; j < sizeof(newlines)/sizeof(char *); j++)
      {
      size_t nlen = strlen(newlines[j]);
      if (strncmpic(argptr, (const uint8_t *)newlines[j], nlen) == 0 &&
          isspace(argptr[nlen]))
        {
        if (j == NEWLINE_DEFAULT) return PR_OK;  /* Default is valid */
        if (first_listed_newline == 0) first_listed_newline = j;
        }
      }
    while (*argptr != 0 && !isspace(*argptr)) argptr++;
    }
  local_newline_default = first_listed_newline;
  break;

  /* Pop or copy a compiled pattern off the stack. Modifiers that do not affect
  the compiled pattern (e.g. to give information) are permitted. The default
  pattern modifiers are ignored. */

  case CMD_POP:
  case CMD_POPCOPY:
  if (patstacknext <= 0)
    {
    cfprintf(clr_test_error, outfile, "** Can't pop off an empty stack\n");
    return PR_SKIP;
    }
  patctl_zero(&pat_patctl);  /* Completely unset */
  if (!decode_modifiers(argptr, CTX_POPPAT, &pat_patctl, NULL))
    return PR_SKIP;

  if (cmd == CMD_POP)
    {
    compiled_code = patstack[--patstacknext];
    }
  else
    {
    compiled_code = pcre2_code_copy(patstack[patstacknext - 1]);
    }

  if (pat_patctl.jit != 0)
    {
    jitrc = pcre2_jit_compile(compiled_code, pat_patctl.jit);
    }

  rc = show_pattern_info();
  if (rc != PR_OK) return rc;
  break;

  /* Save the stack of compiled patterns to a file, then empty the stack. */

  case CMD_SAVE:
  if (patstacknext <= 0)
    {
    cfprintf(clr_test_error, outfile, "** No stacked patterns to save\n");
    return PR_OK;
    }

  rc = open_file(argptr+1, BINARY_OUTPUT_MODE, &f, "#save");
  if (rc != PR_OK) return rc;

  rc = pcre2_serialize_encode((const pcre2_code **)patstack, patstacknext,
    &serial, &serial_size, general_context);
  if (rc < 0)
    {
    fclose(f);
    if (!serial_error(rc, "Serialization")) return PR_ABEND;
    break;
    }

  /* Write the length at the start of the file to make it straightforward to
  get the right memory when re-loading. This saves having to read the file size
  in different operating systems. To allow for different endianness (even
  though reloading with the opposite endianness does not work), write the
  length byte-by-byte. */

  for (i = 0; i < 4; i++) fputc((serial_size >> (i*8)) & 255, f);
  if (fwrite(serial, 1, serial_size, f) != serial_size)
    {
    cfprintf(clr_test_error, outfile, "** Wrong return from fwrite()\n");
    fclose(f);
    return PR_ABEND;
    }

  fclose(f);
  pcre2_serialize_free(serial);
  while(patstacknext > 0)
    {
    compiled_code = patstack[--patstacknext];
    pcre2_code_free(compiled_code);
    }
  compiled_code = NULL;
  break;

  /* Load a set of compiled patterns from a file onto the stack */

  case CMD_LOAD:
  rc = open_file(argptr+1, BINARY_INPUT_MODE, &f, "#load");
  if (rc != PR_OK) return rc;

  serial_size = 0;
  for (i = 0; i < 4; i++) serial_size |= fgetc(f) << (i*8);

  serial = malloc(serial_size);
  if (serial == NULL)
    {
    cfprintf(clr_test_error, outfile, "** Failed to get memory (size %" SIZ_FORM ") for #load\n",
      serial_size);
    fclose(f);
    return PR_ABEND;
    }

  i = fread(serial, 1, serial_size, f);
  fclose(f);

  if (i != serial_size)
    {
    cfprintf(clr_test_error, outfile, "** Wrong return from fread()\n");
    yield = PR_ABEND;
    }
  else
    {
    rc = pcre2_serialize_get_number_of_codes(serial);
    if (rc < 0)
      {
      if (!serial_error(rc, "Get number of codes")) yield = PR_ABEND;
      }
    else
      {
      if (rc + patstacknext > PATSTACKSIZE)
        {
        cfprintf(clr_test_error, outfile, "** Not enough space on pattern stack for %d pattern%s\n",
          rc, (rc == 1)? "" : "s");
        rc = PATSTACKSIZE - patstacknext;
        cfprintf(clr_test_error, outfile, "** Decoding %d pattern%s\n", rc,
          (rc == 1)? "" : "s");
        }
      rc = pcre2_serialize_decode(patstack + patstacknext, rc, serial,
        general_context);
      if (rc < 0)
        {
        if (!serial_error(rc, "Deserialization")) yield = PR_ABEND;
        }
      else patstacknext += rc;
      }
    }

  free(serial);
  break;

  /* Load a set of binary tables into tables3. */

  case CMD_LOADTABLES:
  rc = open_file(argptr+1, BINARY_INPUT_MODE, &f, "#loadtables");
  if (rc != PR_OK) return rc;

  if (tables3 == NULL)
    {
    int r;
    r = pcre2_config(PCRE2_CONFIG_TABLES_LENGTH, &loadtables_length);
    if (r >= 0) tables3 = malloc(loadtables_length);
    }

  if (tables3 == NULL)
    {
    cfprintf(clr_test_error, outfile, "** Failed: malloc/config for #loadtables\n");
    yield = PR_ABEND;
    }
  else if (fread(tables3, 1, loadtables_length, f) != loadtables_length)
    {
    cfprintf(clr_test_error, outfile, "** Wrong return from fread()\n");
    yield = PR_ABEND;
    }

  fclose(f);
  break;

  case CMD_IF:
  if (inside_if)
    {
    cfprintf(clr_test_error, outfile, "** Nested #if not supported\n");
    return PR_ABEND;
    }

  while (isspace(*argptr)) argptr++;
  if_inverted = FALSE;
  if (*argptr == '!')
    {
    argptr++;
    if_inverted = TRUE;
    }
  while (isspace(*argptr)) argptr++;
  for (i = 0; i < COPTLISTCOUNT; i++)
    {
    size_t optlen = strlen(coptlist[i].name);
    const uint8_t *argptr_trail;
    if (coptlist[i].type != CONF_FIX)
      continue;
    if (strncmp((const char*)argptr, coptlist[i].name, optlen) != 0)
      continue;
    argptr_trail = argptr + optlen;
    while (isspace(*argptr_trail)) argptr_trail++;
    if (*argptr_trail == 0 || *argptr_trail == '\n')
      break;
    }
  if (i == COPTLISTCOUNT)
    {
    cfprintf(clr_test_error, outfile, "** Unknown condition: %s\n", buffer);
    return PR_ABEND;
    }

  /* Condition FALSE - skip this line and everything until #endif. */
  if ((coptlist[i].value != 0) == if_inverted)
    yield = PR_ENDIF;

  inside_if = TRUE;
  break;

  case CMD_ENDIF:
  if (!inside_if)
    {
    cfprintf(clr_test_error, outfile, "** Unexpected #endif\n");
    return PR_ABEND;
    }
  inside_if = FALSE;
  break;
  }

return yield;
}



/*************************************************
*               Process pattern line             *
*************************************************/

/* This function is called when the input buffer contains the start of a
pattern. The first character is known to be a valid delimiter. The pattern is
read, modifiers are interpreted, and a suitable local context is set up for
this test. The pattern is then compiled.

Arguments:  none

Returns:    PR_OK     continue processing next line
            PR_SKIP   skip to a blank line
            PR_ABEND  abort the pcre2test run
*/

static int
process_pattern(void)
{
BOOL utf;
uint32_t k;
uint8_t *p = buffer;
unsigned int delimiter = *p++;
int rc, errorcode;
pcre2_compile_context *use_pat_context;
PCRE2_SPTR use_pbuffer;
uint32_t use_forbid_utf = forbid_utf;
PCRE2_SIZE patlen, full_patlen;
PCRE2_SIZE valgrind_access_length;
PCRE2_SIZE erroroffset;

/* The perltest.sh script supports only / as a delimiter. */

if (restrict_for_perl_test && delimiter != '/')
  {
  cfprintf(clr_test_error, outfile, "** The only allowed delimiter after #perltest is '/'\n");
  return PR_ABEND;
  }

/* Initialize the context and pattern/data controls for this test from the
defaults. */

memcpy(pat_context, default_pat_context, sizeof(pcre2_compile_context));
memcpy(&pat_patctl, &def_patctl, sizeof(patctl));

/* Find the end of the pattern, reading more lines if necessary. */

for(;;)
  {
  while (*p != 0)
    {
    if (*p == '\\' && p[1] != 0) p++;
      else if (*p == delimiter) break;
    p++;
    }
  if (*p != 0) break;
  if ((p = extend_inputline(infile, p, "    > ")) == NULL)
    {
    cfprintf(clr_test_error, outfile, "** Unexpected EOF\n");
    return PR_ABEND;
    }
  if (!INTERACTIVE(infile)) cfprintf(clr_input, outfile, "%s", (char *)p);
  }

/* If the first character after the delimiter is backslash, make the pattern
end with backslash. This is purely to provide a way of testing for the error
message when a pattern ends with backslash. */

if (p[1] == '\\') *p++ = '\\';

/* Terminate the pattern at the delimiter, and compute the length. */

*p++ = 0;
patlen = p - buffer - 2;

/* Look for modifiers and options after the final delimiter. */

if (!decode_modifiers(p, CTX_PAT, &pat_patctl, NULL)) return PR_SKIP;

/* Note that the match_invalid_utf option also sets utf when passed to
pcre2_compile(). */

utf = (pat_patctl.options & (PCRE2_UTF|PCRE2_MATCH_INVALID_UTF)) != 0;

/* The utf8_input modifier is not allowed in 8-bit mode, and is mutually
exclusive with the utf modifier. */

if ((pat_patctl.control & CTL_UTF8_INPUT) != 0)
  {
#if PCRE2_CODE_UNIT_WIDTH == 8
  cfprintf(clr_test_error, outfile, "** The utf8_input modifier is not allowed in 8-bit mode\n");
  return PR_SKIP;
#else
  if (utf)
    {
    cfprintf(clr_test_error, outfile, "** The utf and utf8_input modifiers are mutually exclusive\n");
    return PR_SKIP;
    }
#endif
  }

/* The convert and posix modifiers are mutually exclusive. */

if (pat_patctl.convert_type != CONVERT_UNSET &&
    (pat_patctl.control & CTL_POSIX) != 0)
  {
  cfprintf(clr_test_error, outfile, "** The convert and posix modifiers are mutually exclusive\n");
  return PR_SKIP;
  }

/* Check for mutually exclusive control modifiers. At present, these are all in
the first control word. */

for (k = 0; k < sizeof(exclusive_pat_controls)/sizeof(uint32_t); k++)
  {
  uint32_t c = pat_patctl.control & exclusive_pat_controls[k];
  if (c != 0 && c != (c & (~c+1)))
    {
    show_controls(clr_test_error, c, 0, "** Not allowed together:");
    fprintf(outfile, "\n");
    return PR_SKIP;
    }
  }

/* Assume full JIT compile for jitverify and/or jitfast if nothing else was
specified. */

if (pat_patctl.jit == 0 &&
    (pat_patctl.control & (CTL_JITVERIFY|CTL_JITFAST)) != 0)
  pat_patctl.jit = JIT_DEFAULT;

/* Now copy the pattern to pbuffer8 for use in 8-bit testing. Convert from hex
if requested (literal strings in quotes may be present within the hexadecimal
pairs). The result must necessarily be fewer characters so will always fit in
pbuffer8. */

if ((pat_patctl.control & CTL_HEXPAT) != 0)
  {
  uint8_t *pp, *pt;
  uint32_t c, d;

  pt = pbuffer8;
  for (pp = buffer + 1; *pp != 0; pp++)
    {
    if (isspace(*pp)) continue;
    c = *pp++;

    /* Handle a literal substring */

    if (c == '\'' || c == '"')
      {
      uint8_t *pq = pp;
      for (;; pp++)
        {
        d = *pp;
        if (d == 0)
          {
          cfprintf(clr_test_error, outfile, "** Missing closing quote in hex pattern: "
            "opening quote is at offset %" PTR_FORM ".\n", pq - buffer - 2);
          return PR_SKIP;
          }
        if (d == c) break;
        *pt++ = d;
        }
      }

    /* Expect a hex pair */

    else
      {
      if (!isxdigit(c))
        {
        cfprintf(clr_test_error, outfile, "** Unexpected non-hex-digit '%c' at offset %"
          PTR_FORM " in hex pattern: quote missing?\n", c, pp - buffer - 2);
        return PR_SKIP;
        }
      if (*pp == 0)
        {
        cfprintf(clr_test_error, outfile, "** Odd number of digits in hex pattern\n");
        return PR_SKIP;
        }
      d = *pp;
      if (!isxdigit(d))
        {
        cfprintf(clr_test_error, outfile, "** Unexpected non-hex-digit '%c' at offset %"
          PTR_FORM " in hex pattern: quote missing?\n", d, pp - buffer - 1);
        return PR_SKIP;
        }
      c = toupper(c);
      d = toupper(d);
      c = isdigit(c)? (c - '0') : (c - 'A' + 10);
      d = isdigit(d)? (d - '0') : (d - 'A' + 10);
      *pt++ = CHAR_OUTPUT(CHAR_INPUT_HEX((c << 4) + d));
      }
    }
  *pt = 0;
  patlen = pt - pbuffer8;
  }

/* If not a hex string, process for repetition expansion if requested. */

else if ((pat_patctl.control & CTL_EXPAND) != 0)
  {
  uint8_t *pp, *pt;

  pt = pbuffer8;
  for (pp = buffer + 1; *pp != 0; pp++)
    {
    uint8_t *pc = pp;
    uint32_t count = 1;
    size_t length = 1;

    /* Check for replication syntax; if not found, the defaults just set will
    prevail and one character will be copied. */

    if (pp[0] == '\\' && pp[1] == '[')
      {
      uint8_t *pe;
      for (pe = pp + 2; *pe != 0; pe++)
        {
        if (pe[0] == ']' && pe[1] == '{')
          {
          size_t clen = pe - pc - 2;
          uint32_t i = 0;
          unsigned long uli;
          char *endptr;

          pe += 2;
          uli = strtoul((const char *)pe, &endptr, 10);
          if (U32OVERFLOW(uli))
            {
            cfprintf(clr_test_error, outfile, "** Pattern repeat count too large\n");
            return PR_SKIP;
            }

          i = (uint32_t)uli;
          pe = (uint8_t *)endptr;
          if (*pe == '}')
            {
            if (i == 0)
              {
              cfprintf(clr_test_error, outfile, "** Zero repeat not allowed\n");
              return PR_SKIP;
              }
            pc += 2;
            count = i;
            length = clen;
            pp = pe;
            break;
            }
          }
        }
      }

    /* Add to output. If the buffer is too small expand it. The function for
    expanding buffers always keeps buffer and pbuffer8 in step as far as their
    size goes. */

    while (pt + count * length > pbuffer8 + pbuffer8_size)
      {
      size_t pc_offset = pc - buffer;
      size_t pp_offset = pp - buffer;
      size_t pt_offset = pt - pbuffer8;
      expand_input_buffers();
      pc = buffer + pc_offset;
      pp = buffer + pp_offset;
      pt = pbuffer8 + pt_offset;
      }

    for (; count > 0; count--)
      {
      memcpy(pt, pc, length);
      pt += length;
      }
    }

  *pt = 0;
  patlen = pt - pbuffer8;

  if ((pat_patctl.control & CTL_INFO) != 0)
    fprintf(outfile, "Expanded: %s\n", pbuffer8);
  }

/* Neither hex nor expanded, just copy the input verbatim. */

else
  {
  strncpy((char *)pbuffer8, (char *)(buffer+1), patlen + 1);
  }

/* Sort out character tables */

if (pat_patctl.locale[0] != MOD_STR_UNSET)
  {
  if (pat_patctl.tables_id != 0)
    {
    cfprintf(clr_test_error, outfile, "** 'Locale' and 'tables' must not both be set\n");
    return PR_SKIP;
    }
  if (setlocale(LC_CTYPE, (const char *)pat_patctl.locale+1) == NULL)
    {
    cfprintf(clr_test_error, outfile, "** Failed to set locale \"%s\"\n", pat_patctl.locale+1);
    return PR_SKIP;
    }
  if (strcmp((const char *)pat_patctl.locale+1, (const char *)locale_name) != 0)
    {
    strncpy((char *)locale_name, (char *)pat_patctl.locale + 1, sizeof(locale_name));
    locale_name[sizeof(locale_name) - 1] = '\0';
    if (locale_tables != NULL)
      {
      pcre2_maketables_free(general_context, locale_tables);
      }
    locale_tables = pcre2_maketables(general_context);
    }
  use_tables = locale_tables;
  }

else switch (pat_patctl.tables_id)
  {
  case 0: use_tables = NULL; break;
  case 1: use_tables = tables1; break;
  case 2: use_tables = tables2; break;

  case 3:
  if (tables3 == NULL)
    {
    cfprintf(clr_test_error, outfile, "** 'Tables = 3' is invalid: binary tables have not "
      "been loaded\n");
    return PR_SKIP;
    }
  use_tables = tables3;
  break;

  default:
  cfprintf(clr_test_error, outfile, "** 'Tables' must specify 0, 1, 2, or 3.\n");
  return PR_SKIP;
  }

pcre2_set_character_tables(pat_context, use_tables);

/* Set up for the stackguard test. */

if (pat_patctl.stackguard_test != 0)
  {
  pcre2_set_compile_recursion_guard(pat_context, stack_guard, NULL);
  }

/* Handle compiling via the POSIX interface, which doesn't support the
timing, showing, or debugging options, nor the ability to pass over
local character tables. Neither does it have 16-bit or 32-bit support. */

if ((pat_patctl.control & CTL_POSIX) != 0)
  {
#if PCRE2_CODE_UNIT_WIDTH != 8
  cfprintf(clr_test_error, outfile, "** The POSIX interface is available only in 8-bit mode\n");
  return PR_SKIP;

#else
  int cflags = 0;
  const char *msg = "** Ignored with POSIX interface:";

  /* Check for features that the POSIX interface does not support. */

  if (pat_patctl.locale[0] != MOD_STR_UNSET) prmsg(&msg, "locale");
  if (pat_patctl.replacement[0] != MOD_STR_UNSET) prmsg(&msg, "replace");
  if (pat_patctl.tables_id != 0) prmsg(&msg, "tables");
  if (pat_patctl.stackguard_test != 0) prmsg(&msg, "stackguard");
  if (timeit > 0) prmsg(&msg, "timing");
  if (pat_patctl.jit != 0) prmsg(&msg, "JIT");

  if ((pat_patctl.options & ~POSIX_SUPPORTED_COMPILE_OPTIONS) != 0)
    {
    show_compile_options(
      clr_test_error,
      pat_patctl.options & (uint32_t)(~POSIX_SUPPORTED_COMPILE_OPTIONS),
      msg, "");
    msg = "";
    }

  if ((pat_context->extra_options &
       (uint32_t)(~POSIX_SUPPORTED_COMPILE_EXTRA_OPTIONS)) != 0)
    {
    show_compile_extra_options(
      clr_test_error,
      pat_context->extra_options &
        (uint32_t)(~POSIX_SUPPORTED_COMPILE_EXTRA_OPTIONS),
      msg, "");
    msg = "";
    }

  if ((pat_patctl.control & (uint32_t)(~POSIX_SUPPORTED_COMPILE_CONTROLS)) != 0 ||
      (pat_patctl.control2 & (uint32_t)(~POSIX_SUPPORTED_COMPILE_CONTROLS2)) != 0)
    {
    show_controls(
      clr_test_error,
      pat_patctl.control & (uint32_t)(~POSIX_SUPPORTED_COMPILE_CONTROLS),
      pat_patctl.control2 & (uint32_t)(~POSIX_SUPPORTED_COMPILE_CONTROLS2),
      msg);
    msg = "";

    /* Remove ignored options so as not to get a repeated message for those
    that are actually subject controls. */

    pat_patctl.control &= (uint32_t)(POSIX_SUPPORTED_COMPILE_CONTROLS);
    pat_patctl.control2 &= (uint32_t)(POSIX_SUPPORTED_COMPILE_CONTROLS2);
    }

  if (local_newline_default != 0) prmsg(&msg, "#newline_default");
  if (pat_context->max_pattern_length != PCRE2_UNSET)
    prmsg(&msg, "max_pattern_length");
  if (pat_context->max_pattern_compiled_length != PCRE2_UNSET)
    prmsg(&msg, "max_pattern_compiled_length");
  if (pat_context->parens_nest_limit != PARENS_NEST_DEFAULT)
    prmsg(&msg, "parens_nest_limit");

  if (msg[0] == 0) fprintf(outfile, "\n");

  /* Translate PCRE2 options to POSIX options and then compile. */

  if (utf) cflags |= REG_UTF;
  if ((pat_patctl.control & CTL_POSIX_NOSUB) != 0) cflags |= REG_NOSUB;
  if ((pat_patctl.options & PCRE2_UCP) != 0) cflags |= REG_UCP;
  if ((pat_patctl.options & PCRE2_CASELESS) != 0) cflags |= REG_ICASE;
  if ((pat_patctl.options & PCRE2_LITERAL) != 0) cflags |= REG_NOSPEC;
  if ((pat_patctl.options & PCRE2_MULTILINE) != 0) cflags |= REG_NEWLINE;
  if ((pat_patctl.options & PCRE2_DOTALL) != 0) cflags |= REG_DOTALL;
  if ((pat_patctl.options & PCRE2_UNGREEDY) != 0) cflags |= REG_UNGREEDY;

  if ((pat_patctl.control & (CTL_HEXPAT|CTL_USE_LENGTH)) != 0)
    {
    preg.re_endp = (char *)pbuffer8 + patlen;
    cflags |= REG_PEND;
    }

#if defined(EBCDIC) && !EBCDIC_IO
  ascii_to_ebcdic_str(pbuffer8, patlen);
#endif

  rc = regcomp(&preg, (char *)pbuffer8, cflags);

  /* Compiling failed */

  if (rc != 0)
    {
    char *regbuffer;
    size_t bsize, usize, strsize;

    preg.re_pcre2_code = NULL;     /* In case something was left in there */
    preg.re_match_data = NULL;

    bsize = (pat_patctl.regerror_buffsize >= 0 &&
             (unsigned)pat_patctl.regerror_buffsize <= pbuffer8_size)?
      (unsigned)pat_patctl.regerror_buffsize : pbuffer8_size;
    regbuffer = (char *)pbuffer8 + (pbuffer8_size - bsize);
    usize = regerror(rc, &preg, regbuffer, bsize);
    strsize = ((usize > bsize)? bsize : usize) - 1;

    cfprintf(clr_api_error, outfile, "Failed: POSIX code %d: ", rc);
    if (bsize > 0) pchars(clr_api_error, (PCRE2_SPTR8)regbuffer, strsize, utf, outfile);
    fputs("\n", outfile);
    if (usize > bsize)
      {
      cfprintf(clr_test_error, outfile, "** regerror() message truncated\n");
      }
    if (bsize > 0 && strlen(regbuffer) != strsize)
      {
      cfprintf(clr_test_error, outfile, "** regerror() strlen incorrect\n");
      return PR_ABEND;
      }
    return PR_SKIP;
    }

  /* Compiling succeeded. Check that the values in the preg block are sensible.
  It can happen that pcre2test is accidentally linked with a different POSIX
  library which succeeds, but of course puts different things into preg. In
  this situation, calling regfree() may cause a segfault (or invalid free() in
  valgrind), so ensure that preg.re_pcre2_code is NULL, which suppresses the
  calling of regfree() on exit. */

  if (preg.re_pcre2_code == NULL ||
      ((pcre2_real_code_8 *)preg.re_pcre2_code)->magic_number != MAGIC_NUMBER ||
      ((pcre2_real_code_8 *)preg.re_pcre2_code)->top_bracket != preg.re_nsub ||
      preg.re_match_data == NULL ||
      preg.re_cflags != cflags)
    {
    cfprintf(clr_test_error, outfile,
      "** The regcomp() function returned zero (success), but the values set\n"
      "** in the preg block are not valid for PCRE2. Check that pcre2test is\n"
      "** linked with PCRE2's pcre2posix module (-lpcre2-posix) and not with\n"
      "** some other POSIX regex library.\n**\n");
    preg.re_pcre2_code = NULL;
    return PR_ABEND;
    }

  return PR_OK;
#endif  /* PCRE2_CODE_UNIT_WIDTH != 8 */
  }

/* Handle compiling via the native interface. Controls that act later are
ignored with "push". Replacements are locked out. */

if ((pat_patctl.control & (CTL_PUSH|CTL_PUSHCOPY|CTL_PUSHTABLESCOPY)) != 0)
  {
  if (pat_patctl.replacement[0] != MOD_STR_UNSET)
    {
    cfprintf(clr_test_error, outfile, "** Replacement text is not supported with 'push'.\n");
    return PR_OK;
    }
  if ((pat_patctl.control & ~PUSH_SUPPORTED_COMPILE_CONTROLS) != 0 ||
      (pat_patctl.control2 & ~PUSH_SUPPORTED_COMPILE_CONTROLS2) != 0)
    {
    show_controls(clr_test_error, pat_patctl.control & ~PUSH_SUPPORTED_COMPILE_CONTROLS,
                  pat_patctl.control2 & ~PUSH_SUPPORTED_COMPILE_CONTROLS2,
      "** Ignored when compiled pattern is stacked with 'push':");
    fprintf(outfile, "\n");
    }
  if ((pat_patctl.control & PUSH_COMPILE_ONLY_CONTROLS) != 0 ||
      (pat_patctl.control2 & PUSH_COMPILE_ONLY_CONTROLS2) != 0)
    {
    show_controls(clr_test_error, pat_patctl.control & PUSH_COMPILE_ONLY_CONTROLS,
                  pat_patctl.control2 & PUSH_COMPILE_ONLY_CONTROLS2,
      "** Applies only to compile when pattern is stacked with 'push':");
    fprintf(outfile, "\n");
    }
  }

/* Convert the input in non-8-bit modes. */

errorcode = 0;

#if defined(EBCDIC) && !EBCDIC_IO
ascii_to_ebcdic_str(pbuffer8, patlen);
#endif

#if PCRE2_CODE_UNIT_WIDTH != 8
errorcode = G(to,PCRE2_CODE_UNIT_WIDTH)(pbuffer8, utf, &patlen);
switch(errorcode)
  {
  case -1:
  cfprintf(clr_test_error, outfile, "** Failed: invalid UTF-8 string cannot be "
    "converted to " STR(PCRE2_CODE_UNIT_WIDTH) "-bit string\n");
  return PR_SKIP;

  case -2:
  cfprintf(clr_test_error, outfile, "** Failed: character value greater than 0x10ffff "
    "cannot be converted to UTF\n");
  return PR_SKIP;

  case -3:
  cfprintf(clr_test_error, outfile, "** Failed: character value greater than 0xffff "
    "cannot be converted to 16-bit in non-UTF mode\n");
  return PR_SKIP;

  default:
  break;
  }
#endif

/* When valgrind is supported, detect accesses to the 8-bit buffer now that we
have finished with it. */

#if defined SUPPORT_VALGRIND && PCRE2_CODE_UNIT_WIDTH != 8
VALGRIND_MAKE_MEM_UNDEFINED(pbuffer8, pbuffer8_size);
#endif

/* The pattern is now in pbuffer[8|16|32], with the length in code units in
patlen. If it is to be converted, copy the result back afterwards so that it
ends up back in the usual place. */

if (pat_patctl.convert_type != CONVERT_UNSET)
  {
  int convert_return = PR_OK;
  uint32_t convert_options = pat_patctl.convert_type;
  PCRE2_UCHAR *converted_pattern;
  PCRE2_SIZE converted_length = JUNK_OFFSET;
  BOOL zero_terminate;

  if (pat_patctl.convert_length != CONVERT_UNSET)
    {
    converted_length = pat_patctl.convert_length;
    converted_pattern = malloc(converted_length? CU2BYTES(converted_length) : 1);
    if (converted_pattern == NULL)
      {
      cfprintf(clr_test_error, outfile, "** Failed: malloc failed for converted pattern\n");
      return PR_ABEND;
      }
    }
  else converted_pattern = NULL;  /* Let the library allocate */

  if (utf) convert_options |= PCRE2_CONVERT_UTF;
  if ((pat_patctl.options & PCRE2_NO_UTF_CHECK) != 0)
    convert_options |= PCRE2_CONVERT_NO_UTF_CHECK;

  memcpy(con_context, default_con_context, sizeof(pcre2_convert_context));

  if (pat_patctl.convert_glob_escape != 0)
    {
    uint32_t escape = (pat_patctl.convert_glob_escape == '0')? 0 :
      pat_patctl.convert_glob_escape;
    rc = pcre2_set_glob_escape(con_context, CHAR_INPUT(escape));
    if (rc != 0)
      {
      cfprintf(clr_test_error, outfile, "** Invalid glob escape '%c'\n",
        pat_patctl.convert_glob_escape);
      convert_return = PR_SKIP;
      goto CONVERT_FINISH;
      }
    }

  if (pat_patctl.convert_glob_separator != 0)
    {
    uint32_t separator = pat_patctl.convert_glob_separator;
    rc = pcre2_set_glob_separator(con_context, CHAR_INPUT(separator));
    if (rc != 0)
      {
      cfprintf(clr_test_error, outfile, "** Invalid glob separator '%c'\n",
        pat_patctl.convert_glob_separator);
      convert_return = PR_SKIP;
      goto CONVERT_FINISH;
      }
    }

  /* Set up the input buffer in the same way as for pcre2_compile() below. */

  zero_terminate = (pat_patctl.control & (CTL_HEXPAT|CTL_USE_LENGTH)) == 0;

#ifdef SUPPORT_VALGRIND
  VALGRIND_MAKE_MEM_NOACCESS(pbuffer + CU2BYTES(patlen + zero_terminate),
    pbuffer_size - CU2BYTES(patlen + zero_terminate));
#endif

  if (zero_terminate) patlen = PCRE2_ZERO_TERMINATED;
  use_pbuffer = ((pat_patctl.control2 & CTL2_NULL_PATTERN) == 0)? pbuffer : NULL;

  rc = pcre2_pattern_convert(use_pbuffer, patlen, convert_options,
    &converted_pattern, &converted_length, con_context);

#ifdef SUPPORT_VALGRIND
  VALGRIND_MAKE_MEM_UNDEFINED(pbuffer, pbuffer_size);
#endif

  if (rc != 0)
    {
    cfprintf(clr_api_error, outfile, "** Pattern conversion error at offset %" SIZ_FORM ": ",
      converted_length);
    convert_return = print_error_message(rc, "", "\n")? PR_SKIP:PR_ABEND;
    }

  /* Output the converted pattern, then copy it. */

  else
    {
    pchars(clr_none, converted_pattern, converted_length, utf, outfile);
    fprintf(outfile, "\n");

    if (CU2BYTES(converted_length + 1) > pbuffer_size)
      {
      // TODO This seems... unfortunate? There must be some patterns that can
      // expand when converted from glob to regex, but we aren't allowing for
      // that here. Presumably we should expand the buffer rather than moan.
      cfprintf(clr_test_error, outfile, "** Pattern conversion is too long for the buffer\n");
      convert_return = PR_SKIP;
      }
    else
      {
      memcpy(pbuffer, converted_pattern, CU2BYTES(converted_length + 1));
      patlen = converted_length;
      }
    }

  /* Free the converted pattern. */

  CONVERT_FINISH:
  if (pat_patctl.convert_length != CONVERT_UNSET)
    free(converted_pattern);
  else
    pcre2_converted_pattern_free(converted_pattern);

  /* Return if conversion was unsuccessful. */

  if (convert_return != PR_OK) return convert_return;
  }

/* By default we pass a zero-terminated pattern, but a length is passed if
"use_length" was specified or this is a hex pattern (which might contain binary
zeros). When valgrind is supported, arrange for the unused part of the buffer
to be marked as no-access. */

full_patlen = patlen;
valgrind_access_length = patlen;
if ((pat_patctl.control & (CTL_HEXPAT|CTL_USE_LENGTH)) == 0)
  {
  patlen = PCRE2_ZERO_TERMINATED;
  valgrind_access_length += 1;  /* For the terminating zero */
  }

#ifdef SUPPORT_VALGRIND
VALGRIND_MAKE_MEM_NOACCESS(pbuffer + valgrind_access_length,
  pbuffer_size - CU2BYTES(valgrind_access_length));
#else  /* Valgrind not supported */
(void)valgrind_access_length;  /* Avoid compiler warning */
#endif

/* If #newline_default has been used and the library was not compiled with an
appropriate default newline setting, local_newline_default will be non-zero. We
use this if there is no explicit newline modifier. */

if ((pat_patctl.control2 & CTL2_NL_SET) == 0 && local_newline_default != 0)
  {
  pcre2_set_newline(pat_context, local_newline_default);
  }

/* The null_context modifier is used to test calling pcre2_compile() with a
NULL context. */

use_pat_context = ((pat_patctl.control & CTL_NULLCONTEXT) != 0)?
  NULL : pat_context;

/* If PCRE2_LITERAL is set, set use_forbid_utf zero because PCRE2_NEVER_UTF
and PCRE2_NEVER_UCP are invalid with it. */

if ((pat_patctl.options & PCRE2_LITERAL) != 0) use_forbid_utf = 0;

/* Set use_pbuffer to the input buffer or NULL as requested. */

use_pbuffer = ((pat_patctl.control2 & CTL2_NULL_PATTERN) == 0)? pbuffer : NULL;

/* Compile many times when timing. */

if (timeit > 0)
  {
  int i;
  clock_t time_taken = 0;
  for (i = 0; i < timeit; i++)
    {
    clock_t start_time = clock();
    compiled_code = pcre2_compile(use_pbuffer, patlen,
      pat_patctl.options|use_forbid_utf, &errorcode, &erroroffset,
        use_pat_context);
    time_taken += clock() - start_time;
    if (compiled_code != NULL)
      pcre2_code_free(compiled_code);
    }
  total_compile_time += time_taken;
  cfprintf(clr_profiling, outfile, "Compile time %8.4f microseconds\n",
    ((1000000 / CLOCKS_PER_SEC) * (double)time_taken) / timeit);
  }

/* A final compile that is used "for real". */

mallocs_called = 0;
compiled_code = pcre2_compile(use_pbuffer, patlen,
  pat_patctl.options|use_forbid_utf, &errorcode, &erroroffset, use_pat_context);

/* For malloc testing, we repeat the compilation. */

if (malloc_testing)
  {
  for (int i = 0, target_mallocs = mallocs_called; i <= target_mallocs; i++)
    {
    if (compiled_code != NULL)
      pcre2_code_free(compiled_code);

    errorcode = 0;
    erroroffset = 0;
    mallocs_until_failure = i;
    compiled_code = pcre2_compile(use_pbuffer, patlen,
      pat_patctl.options|use_forbid_utf, &errorcode, &erroroffset, use_pat_context);
    mallocs_until_failure = INT_MAX;

    if (i < target_mallocs &&
        !(compiled_code == NULL && errorcode == PCRE2_ERROR_HEAP_FAILED))
      {
      cfprintf(clr_test_error, outfile, "** malloc() compile test did not fail as expected (%d)\n",
              errorcode);
      return PR_ABEND;
      }
    }
  }

/* If valgrind is supported, mark the pbuffer as accessible again. We leave the
pattern in the test-mode's buffer defined because it may be read from a callout
during matching. */

#ifdef SUPPORT_VALGRIND
VALGRIND_MAKE_MEM_UNDEFINED(pbuffer + valgrind_access_length,
  pbuffer_size - CU2BYTES(valgrind_access_length));
#endif

/* Call the JIT compiler if requested. When timing, or testing malloc failures,
we must free and recompile the pattern each time because that is the only way to
free the JIT compiled code. We know that compilation will always succeed. */

if (compiled_code != NULL && pat_patctl.jit != 0)
  {
  if (timeit > 0)
    {
    int i;
    clock_t time_taken = 0;

    for (i = 0; i < timeit; i++)
      {
      clock_t start_time = clock();
      jitrc = pcre2_jit_compile(compiled_code, pat_patctl.jit);
      time_taken += clock() - start_time;

      pcre2_code_free(compiled_code);
      compiled_code = pcre2_compile(use_pbuffer, patlen,
        pat_patctl.options|use_forbid_utf, &errorcode, &erroroffset,
        use_pat_context);
      if (compiled_code == NULL)
        {
        cfprintf(clr_test_error, outfile, "** Unexpected - pattern compilation not successful\n");
        return PR_ABEND;
        }

      if (jitrc != 0)
        {
        cfprintf(clr_api_error, outfile, "JIT compilation was not successful");
        if (!print_error_message(jitrc, " (", ")\n")) return PR_ABEND;
        break;
        }
      }
    total_jit_compile_time += time_taken;
    if (jitrc == 0)
      cfprintf(clr_profiling, outfile, "JIT compile  %8.4f microseconds\n",
        ((1000000 / CLOCKS_PER_SEC) * (double)time_taken) / timeit);
    }

  mallocs_called = 0;
  jitrc = pcre2_jit_compile(compiled_code, pat_patctl.jit);

  /* For malloc testing, we repeat the compilation. */

  if (malloc_testing)
    {
    for (int i = 0, target_mallocs = mallocs_called; i <= target_mallocs; i++)
      {
      pcre2_code_free(compiled_code);
      compiled_code = pcre2_compile(use_pbuffer, patlen,
        pat_patctl.options|use_forbid_utf, &errorcode, &erroroffset,
        use_pat_context);
      if (compiled_code == NULL)
        {
        cfprintf(clr_test_error, outfile, "** Unexpected - pattern compilation not successful\n");
        return PR_ABEND;
        }

      mallocs_until_failure = i;
      jitrc = pcre2_jit_compile(compiled_code, pat_patctl.jit);
      mallocs_until_failure = INT_MAX;

      if (i < target_mallocs && jitrc != PCRE2_ERROR_NOMEMORY)
        {
        cfprintf(clr_test_error, outfile, "** malloc() JIT compile test did not fail as expected (%d)\n",
                jitrc);
        return PR_ABEND;
        }
      }
    }

  /* Check whether JIT compilation failed; but continue with an error message
  if not. */

  if (jitrc != 0 && (pat_patctl.control & CTL_JITVERIFY) != 0)
    {
    cfprintf(clr_api_error, outfile, "JIT compilation was not successful");
    if (!print_error_message(jitrc, " (", ")\n")) return PR_ABEND;
    }
  }

/* Compilation failed; go back for another re, skipping to blank line
if non-interactive. */

if (compiled_code == NULL)
  {
  int direction = error_direction(errorcode, erroroffset);

  cfprintf(clr_api_error, outfile, "Failed: error %d at offset %d: ", errorcode,
    (int)erroroffset);
  if (!print_error_message(errorcode, "", "\n")) return PR_ABEND;

  /* It's important that the erroroffset doesn't slice halfway through a UTF-8
  or UTF-16 character. We can verify this by checking that the input left of the
  erroroffset is valid. Note that if the input is invalid (which is exercised in
  some tests) then the offset will be positioned with the valid part to the left
  of erroroffset. */

#if PCRE2_CODE_UNIT_WIDTH == 8 || PCRE2_CODE_UNIT_WIDTH == 16
  if (utf)
    {
    uint32_t cc;
    int n = 1;
    for (PCRE2_UCHAR *q = pbuffer, *q_end = q + erroroffset; q < q_end && n > 0; q += n)
      n = utf_to_ord(q, q_end, &cc);
    if (n <= 0)
      {
      cfprintf(clr_test_error, outfile, "** Erroroffset %d splits a UTF character\n", (int)erroroffset);
      return PR_ABEND;
      }
    }
#endif

  /* Print the surrounding context around the erroroffset. */

  if (direction < 0)
    {
    cfprintf(clr_test_error, outfile, "** Error code %d not implemented in error_direction().\n", errorcode);
    cfprintf(clr_test_error, outfile, "   error_direction() should usually return '1' for newly-added errors,\n");
    cfprintf(clr_test_error, outfile, "   and the offset should be just to the right of the bad character.\n");
    return PR_ABEND;
    }

  else if (direction != 0)
    {
    cfprintf(clr_api_error, outfile, "        here: ");
    if (erroroffset > 0)
      {
      ptrunc(clr_input, pbuffer, full_patlen, erroroffset, TRUE, utf, outfile);
      fprintf(outfile, " ");
      }
    cfprintf(clr_api_error, outfile, (direction == 1)? "|<--|" : (direction == 2)? "|-->|" : "|<-->|");
    if (erroroffset < full_patlen)
      {
      fprintf(outfile, " ");
      ptrunc(clr_input, pbuffer, full_patlen, erroroffset, FALSE, utf, outfile);
      }
    fprintf(outfile, "\n");
    }

  else if (erroroffset != 0)
    {
    cfprintf(clr_test_error, outfile, "** Unexpected non-zero erroroffset %d for error code %d\n",
      (int)erroroffset, errorcode);
    return PR_ABEND;
    }

  return PR_SKIP;
  }

/* If forbid_utf is non-zero, we are running a non-UTF test. UTF and UCP are
locked out at compile time, but we must also check for occurrences of \P, \p,
and \X, which are only supported when Unicode is supported. */

if (forbid_utf != 0)
  {
  if ((compiled_code->flags & PCRE2_HASBKPORX) != 0)
    {
    cfprintf(clr_test_error, outfile, "** \\P, \\p, and \\X are not allowed after the "
      "#forbid_utf command\n");
    return PR_SKIP;
    }
  }

/* Remember the maximum lookbehind, for partial matching. */

if (pattern_info(PCRE2_INFO_MAXLOOKBEHIND, &maxlookbehind, FALSE) != 0)
  return PR_ABEND;

/* Remember the number of captures. */

if (pattern_info(PCRE2_INFO_CAPTURECOUNT, &maxcapcount, FALSE) < 0)
  return PR_ABEND;

/* If an explicit newline modifier was given, set the information flag in the
pattern so that it is preserved over push/pop. */

if ((pat_patctl.control2 & CTL2_NL_SET) != 0)
  {
  compiled_code->flags |= PCRE2_NL_SET;
  }

/* Output code size and other information if requested. */

rc = show_pattern_info();
if (rc != PR_OK) return rc;

/* The "push" control requests that the compiled pattern be remembered on a
stack. This is mainly for testing the serialization functionality. */

if ((pat_patctl.control & CTL_PUSH) != 0)
  {
  if (patstacknext >= PATSTACKSIZE)
    {
    cfprintf(clr_test_error, outfile, "** Too many pushed patterns (max %d)\n", PATSTACKSIZE);
    return PR_ABEND;
    }
  patstack[patstacknext++] = compiled_code;
  compiled_code = NULL;
  }

/* The "pushcopy" and "pushtablescopy" controls are similar, but push a
copy of the pattern, the latter with a copy of its character tables. This tests
the pcre2_code_copy() and pcre2_code_copy_with_tables() functions. */

if ((pat_patctl.control & (CTL_PUSHCOPY|CTL_PUSHTABLESCOPY)) != 0)
  {
  if (patstacknext >= PATSTACKSIZE)
    {
    cfprintf(clr_test_error, outfile, "** Too many pushed patterns (max %d)\n", PATSTACKSIZE);
    return PR_ABEND;
    }
  if ((pat_patctl.control & CTL_PUSHCOPY) != 0)
    {
    patstack[patstacknext++] = pcre2_code_copy(compiled_code);
    }
  else
    {
    patstack[patstacknext++] = pcre2_code_copy_with_tables(compiled_code);
    }
  }

return PR_OK;
}



/* Helper to test for an active pattern. */

static BOOL
have_active_pattern(void)
{
return compiled_code != NULL;
}


/* Helper to free (and null-out) the active pattern. Safe to call even if there
is no active pattern. */

static void
free_active_pattern(void)
{
pcre2_code_free(compiled_code);
compiled_code = NULL;
}



/*************************************************
*          Check heap, match or depth limit      *
*************************************************/

/* This is used for DFA, normal, and JIT fast matching. For DFA matching it
should only be called with the third argument set to PCRE2_ERROR_DEPTHLIMIT.

Arguments:
  pp        the subject string
  ulen      length of subject or PCRE2_ZERO_TERMINATED
  errnumber defines which limit to test
  msg       string to include in final message

Returns:    the return from the final match function call
*/

static int
check_match_limit(PCRE2_SPTR pp, PCRE2_SIZE ulen, int errnumber, const char *msg)
{
int capcount;
uint32_t min = 0;
uint32_t mid = 64;
uint32_t max = UINT32_MAX;
FILE *saved_outfile = outfile;

pcre2_set_match_limit(dat_context, max);
pcre2_set_depth_limit(dat_context, max);
pcre2_set_heap_limit(dat_context, max);

for (;;)
  {
  uint32_t stack_start = 0;

  /* If we are checking the heap limit, free any frames vector that is cached
  in the match_data so we always start without one. */

  if (errnumber == PCRE2_ERROR_HEAPLIMIT)
    {
    pcre2_set_heap_limit(dat_context, mid);

    match_data->memctl.free(match_data->heapframes,
      match_data->memctl.memory_data);
    match_data->heapframes = NULL;
    match_data->heapframes_size = 0;
    }

  /* No need to mess with the frames vector for match or depth limits. */

  else if (errnumber == PCRE2_ERROR_MATCHLIMIT)
    {
    pcre2_set_match_limit(dat_context, mid);
    }
  else
    {
    pcre2_set_depth_limit(dat_context, mid);
    }

  /* Do the appropriate match */

  reset_callout_state();
  outfile = NULL;  /* Suppress callout output during the repeated search */

  if ((dat_datctl.control & CTL_DFA) != 0)
    {
    stack_start = DFA_START_RWS_SIZE/1024;
    if (dfa_workspace == NULL)
      dfa_workspace = (int *)malloc(DFA_WS_DIMENSION*sizeof(int));
    if (dfa_matched++ == 0)
      dfa_workspace[0] = -1;  /* To catch bad restart */
    capcount = pcre2_dfa_match(compiled_code, pp, ulen, dat_datctl.offset,
      dat_datctl.options, match_data,
      dat_context, dfa_workspace, DFA_WS_DIMENSION);
    }

  else if ((pat_patctl.control & CTL_JITFAST) != 0)
    capcount = pcre2_jit_match(compiled_code, pp, ulen, dat_datctl.offset,
      dat_datctl.options, match_data, dat_context);

  else
    {
    capcount = pcre2_match(compiled_code, pp, ulen, dat_datctl.offset,
      dat_datctl.options, match_data, dat_context);
    }

  outfile = saved_outfile;

  if (capcount == errnumber)
    {
    if ((mid & 0x80000000u) != 0)
      {
      cfprintf(clr_test_error, outfile, "** Can't find minimum %s limit: check pattern for "
        "restriction\n", msg);
      break;
      }

    min = mid;
    mid = (mid == max - 1)? max : (max != UINT32_MAX)? (min + max)/2 : mid*2;
    }
  else if (capcount >= 0 ||
           capcount == PCRE2_ERROR_NOMATCH ||
           capcount == PCRE2_ERROR_PARTIAL)
    {
    /* If we've not hit the error with a heap limit less than the size of the
    initial stack frame vector (for pcre2_match()) or the initial stack
    workspace vector (for pcre2_dfa_match()), the heap is not being used, so
    the minimum limit is zero; there's no need to go on. The other limits are
    always greater than zero. */

    if (errnumber == PCRE2_ERROR_HEAPLIMIT && mid < stack_start)
      {
      fprintf(outfile, "Minimum %s limit = 0\n", msg);
      break;
      }
    if (mid == min + 1)
      {
      fprintf(outfile, "Minimum %s limit = %d\n", msg, mid);
      break;
      }
    max = mid;
    mid = (min + max)/2;
    }
  else break;    /* Some other error */
  }

return capcount;
}



/*************************************************
*        Substitute callout function             *
*************************************************/

/* Called from pcre2_substitute() when the substitute_callout modifier is set.
Print out the data that is passed back.

Arguments:
  scb         pointer to substitute callout block
  data_ptr    callout data

Returns:      nothing
*/

static int
substitute_callout_function(pcre2_substitute_callout_block *scb,
  void *data_ptr)
{
int yield = 0;
BOOL utf = (compiled_code->overall_options & PCRE2_UTF) != 0;
(void)data_ptr;   /* Not used */

if (outfile == NULL) goto YIELD;

fprintf(outfile, "%2d(%d) Old %" SIZ_FORM " %" SIZ_FORM " \"",
  scb->subscount, scb->oveccount,
  scb->ovector[0], scb->ovector[1]);

pchars(clr_none, scb->input + scb->ovector[0], scb->ovector[1] - scb->ovector[0],
  utf, outfile);

fprintf(outfile, "\" New %" SIZ_FORM " %" SIZ_FORM " \"",
  scb->output_offsets[0], scb->output_offsets[1]);

pchars(clr_none, scb->output + scb->output_offsets[0],
  scb->output_offsets[1] - scb->output_offsets[0], utf, outfile);

YIELD:

if (scb->subscount == dat_datctl.substitute_stop)
  {
  yield = -1;
  if (outfile != NULL) fprintf(outfile, " STOPPED");
  }
else if (scb->subscount == dat_datctl.substitute_skip)
  {
  yield = +1;
  if (outfile != NULL) fprintf(outfile, " SKIPPED");
  }

if (outfile != NULL) fprintf(outfile, "\"\n");
return yield;
}



/*************************************************
*        Substitute case callout function        *
*************************************************/

/* Called from pcre2_substitute() when the substitute_case_callout
modifier is set. The substitute callout block is not identical for all code unit
widths, so we have to duplicate the function for each supported width.

Arguments:
  input          the input character
  input_len      the length of the input
  output         the output buffer
  output_cap     the output buffer capacity
  to_case        the case conversion type
  data_ptr       callout data (unused)

Returns:         the number of code units of the output
*/

static PCRE2_SIZE
substitute_case_callout_function(
  PCRE2_SPTR input, PCRE2_SIZE input_len,
  PCRE2_UCHAR *output, PCRE2_SIZE output_cap,
  int to_case, void *data_ptr)
{
PCRE2_UCHAR buf[16];
PCRE2_SPTR input_copy;
PCRE2_SIZE written = 0;

(void)data_ptr;   /* Not used */

if (input_len > sizeof(buf)/sizeof(*buf))
  {
  PCRE2_UCHAR *input_buf = malloc(CU2BYTES(input_len));
  if (input_buf == NULL) return ~(PCRE2_SIZE)0;
  memcpy(input_buf, input, CU2BYTES(input_len));
  input_copy = input_buf;
  }
else
  {
  memcpy(buf, input, CU2BYTES(input_len));
  input_copy = buf;
  }

for (PCRE2_SIZE i = 0; i < input_len; )
  {
  int num_in = i + 1 < input_len ? 2 : 1;
  uint32_t c1 = input_copy[i];
  uint32_t c2 = i + 1 < input_len ? input_copy[i + 1] : 0;
  int num_read;
  int num_write;

  if (!case_transform(to_case, num_in, &num_read, &num_write, &c1, &c2))
    {
    written = ~(PCRE2_SIZE)0;
    goto END;
    }

  i += num_read;
  if (to_case == PCRE2_SUBSTITUTE_CASE_TITLE_FIRST)
    to_case = PCRE2_SUBSTITUTE_CASE_LOWER;

  if (written + num_write > output_cap)
    {
    written += num_write;
    }
  else
    {
    if (num_write > 0) output[written++] = c1;
    if (num_write > 1) output[written++] = c2;
    }
  }

END:
if (input_copy != buf) free((PCRE2_UCHAR *)input_copy);

/* Let's be maximally cruel. The case callout is allowed to leave the output
buffer in any state at all if it overflows, so let's use random garbage. */
if (written > output_cap)
  memset(output, time(NULL) & 1 ? 0xcd : 0xdc,
         CU2BYTES(output_cap));

return written;
}



/*************************************************
*              Callout function                  *
*************************************************/

/* Called from a PCRE2 library as a result of the (?C) item. We print out where
we are in the match (unless suppressed). Yield zero unless more callouts than
the fail count, or the callout data is not zero. The only differences in the
callout block for different code unit widths are that the pointers to the
subject, the most recent MARK, and a callout argument string point to strings
of the appropriate width. Casts can be used to deal with this.

Arguments:
  cb                a pointer to a callout block
  callout_data_ptr  the provided callout data

Returns:            0 or 1 or an error, as determined by settings
*/

static int
callout_function(pcre2_callout_block *cb, void *callout_data_ptr)
{
FILE *f, *fdefault;
uint32_t i, pre_start, post_start, subject_length;
PCRE2_SIZE current_position;
BOOL utf = (compiled_code->overall_options & PCRE2_UTF) != 0;
BOOL callout_capture = (dat_datctl.control & CTL_CALLOUT_CAPTURE) != 0;
BOOL callout_where = (dat_datctl.control2 & CTL2_CALLOUT_NO_WHERE) == 0;

if (outfile == NULL) goto YIELD;

/* The FILE f is used for echoing the subject string if it is non-NULL. This
happens only once in simple cases, but we want to repeat after any additional
output caused by CALLOUT_EXTRA. */

fdefault = (!first_callout && !callout_capture && cb->callout_string == NULL)?
  NULL : outfile;

if ((dat_datctl.control2 & CTL2_CALLOUT_EXTRA) != 0)
  {
  f = outfile;
  switch (cb->callout_flags)
    {
    case PCRE2_CALLOUT_BACKTRACK:
    fprintf(f, "Backtrack\n");
    break;

    case PCRE2_CALLOUT_STARTMATCH|PCRE2_CALLOUT_BACKTRACK:
    fprintf(f, "Backtrack\nNo other matching paths\n");
    PCRE2_FALLTHROUGH /* Fall through */

    case PCRE2_CALLOUT_STARTMATCH:
    fprintf(f, "New match attempt\n");
    break;

    default:
    f = fdefault;
    break;
    }
  }
else f = fdefault;

/* For a callout with a string argument, show the string first because there
isn't a tidy way to fit it in the rest of the data. */

if (cb->callout_string != NULL)
  {
  uint32_t delimiter = cb->callout_string[-1];
  fprintf(outfile, "Callout (%" SIZ_FORM "): %c",
    cb->callout_string_offset, CHAR_OUTPUT(delimiter));
  pchars(clr_none, cb->callout_string, cb->callout_string_length, utf, outfile);
  for (i = 0; callout_start_delims[i] != 0; i++)
    if (delimiter == callout_start_delims[i])
      {
      delimiter = callout_end_delims[i];
      break;
      }
  fprintf(outfile, "%c", CHAR_OUTPUT(delimiter));
  if (!callout_capture) fprintf(outfile, "\n");
  }

/* Show captured strings if required */

if (callout_capture)
  {
  if (cb->callout_string == NULL)
    fprintf(outfile, "Callout %d:", cb->callout_number);
  fprintf(outfile, " last capture = %d\n", cb->capture_last);
  for (i = 2; i < cb->capture_top * 2; i += 2)
    {
    fprintf(outfile, "%2d: ", i/2);
    if (cb->offset_vector[i] == PCRE2_UNSET)
      fprintf(outfile, "<unset>");
    else
      {
      pchars(clr_none, cb->subject + cb->offset_vector[i],
        cb->offset_vector[i+1] - cb->offset_vector[i], utf, f);
      }
    fprintf(outfile, "\n");
    }
  }

/* Unless suppressed, re-print the subject in canonical form (with escapes for
non-printing characters), the first time, or if giving full details. On
subsequent calls in the same match, we use pchars() just to find the printed
lengths of the substrings. */

if (callout_where)
  {
  if (f != NULL) fprintf(f, "--->");

  /* The subject before the match start. */

  pre_start = pchars(clr_none, cb->subject, cb->start_match, utf, f);

  /* If a lookbehind is involved, the current position may be earlier than the
  match start. If so, use the match start instead. */

  current_position = (cb->current_position >= cb->start_match)?
    cb->current_position : cb->start_match;

  /* The subject between the match start and the current position. */

  post_start = pchars(clr_none, cb->subject + cb->start_match,
    current_position - cb->start_match, utf, f);

  /* Print from the current position to the end. */

  pchars(clr_none, cb->subject + current_position, cb->subject_length - current_position,
    utf, f);

  /* Calculate the total subject printed length (no print). */

  subject_length = pchars(clr_none, cb->subject, cb->subject_length, utf, NULL);

  if (f != NULL) fprintf(f, "\n");

  /* For automatic callouts, show the pattern offset. Otherwise, for a
  numerical callout whose number has not already been shown with captured
  strings, show the number here. A callout with a string argument has been
  displayed above. */

  if (cb->callout_number == 255)
    {
    fprintf(outfile, "%+3d ", (int)cb->pattern_position);
    if (cb->pattern_position > 99) fprintf(outfile, "\n    ");
    }
  else
    {
    if (callout_capture || cb->callout_string != NULL) fprintf(outfile, "    ");
      else fprintf(outfile, "%3d ", cb->callout_number);
    }

  /* Now show position indicators */

  for (i = 0; i < pre_start; i++) fprintf(outfile, " ");
  fprintf(outfile, "^");

  if (post_start > 0)
    {
    for (i = 0; i < post_start - 1; i++) fprintf(outfile, " ");
    fprintf(outfile, "^");
    }

  for (i = 0; i < subject_length - pre_start - post_start + 4; i++)
    fprintf(outfile, " ");

  if (cb->next_item_length != 0)
    {
    pchars(clr_none, pbuffer + cb->pattern_position, cb->next_item_length, utf, outfile);
    }
  else
    fprintf(outfile, "End of pattern");

  fprintf(outfile, "\n");
  }

/* Show any mark info */

if (cb->mark != last_callout_mark)
  {
  if (cb->mark == NULL)
    fprintf(outfile, "Latest Mark: <unset>\n");
  else
    {
    fprintf(outfile, "Latest Mark: ");
    pchars(clr_none, cb->mark - 1, -1, utf, outfile);
    putc('\n', outfile);
    }
  }

YIELD:

/* Keep count */

first_callout = FALSE;
last_callout_mark = cb->mark;
callout_count++;

/* Show callout data if that determines the return code */

if (callout_data_ptr != NULL)
  {
  int callout_data = *((int32_t *)callout_data_ptr);
  if (callout_data != 0)
    {
    if (outfile != NULL) fprintf(outfile, "Callout data = %d\n", callout_data);
    return callout_data;
    }
  }

/* Otherwise, the callout_error and callout_fail settings provide the return
code. */

if (cb->callout_number == dat_datctl.cerror[0] &&
    callout_count >= dat_datctl.cerror[1])
  return PCRE2_ERROR_CALLOUT;

if (cb->callout_number == dat_datctl.cfail[0] &&
    callout_count >= dat_datctl.cfail[1])
  return 1;

return 0;
}



/*************************************************
*       Handle *MARK and copy/get tests          *
*************************************************/

/* This function is called after complete and partial matches. It runs the
tests for substring extraction.

Arguments:
  utf       TRUE for utf
  capcount  return from pcre2_match()

Returns:    FALSE if print_error_message() fails
*/

static BOOL
copy_and_get(BOOL utf, int capcount)
{
int i;
uint8_t *nptr;

/* Test copy strings by number */

for (i = 0; i < MAXCPYGET && dat_datctl.copy_numbers[i] >= 0; i++)
  {
  int rc, rc2;
  PCRE2_SIZE length, length2;
  PCRE2_UCHAR copybuffer[256];
  uint32_t n = (uint32_t)(dat_datctl.copy_numbers[i]);
  length = sizeof(copybuffer)/sizeof(*copybuffer);
  rc = pcre2_substring_copy_bynumber(match_data, n, copybuffer, &length);
  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "Copy substring %d failed (%d): ", n, rc);
    if (!print_error_message(rc, "", "\n")) return FALSE;
    }
  else
    {
    fprintf(outfile, "%2dC ", n);
    pchars(clr_none, copybuffer, length, utf, outfile);
    fprintf(outfile, " (%" SIZ_FORM ")\n", length);
    }
  rc2 = pcre2_substring_length_bynumber(match_data, n, &length2);
  if (rc2 < 0)
    {
    cfprintf(clr_api_error, outfile, "Get substring %d length failed (%d): ", n, rc2);
    if (!print_error_message(rc2, "", "\n")) return FALSE;
    }
  else if (rc >= 0 && length2 != length)
    {
    cfprintf(clr_test_error, outfile, "** Mismatched substring lengths: %"
      SIZ_FORM " %" SIZ_FORM "\n", length, length2);
    }
  }

/* Test copy strings by name */

nptr = dat_datctl.copy_names;
for (;;)
  {
  int rc, rc2;
  int groupnumber;
  PCRE2_SIZE length, length2;
  PCRE2_UCHAR copybuffer[256];
  size_t namelen = strlen((const char *)nptr);
#if PCRE2_CODE_UNIT_WIDTH == 16 || PCRE2_CODE_UNIT_WIDTH == 32
  PCRE2_SIZE cnl = namelen;
#endif
  if (namelen == 0) break;

#if PCRE2_CODE_UNIT_WIDTH == 8
  strcpy((char *)pbuffer8, (char *)nptr);
#endif
#if defined(EBCDIC) && !EBCDIC_IO
  ascii_to_ebcdic_str(pbuffer8, namelen);
#endif
#if PCRE2_CODE_UNIT_WIDTH == 16
  (void)to16(nptr, utf, &cnl);
#endif
#if PCRE2_CODE_UNIT_WIDTH == 32
  (void)to32(nptr, utf, &cnl);
#endif

  groupnumber = pcre2_substring_number_from_name(compiled_code, pbuffer);
  if (groupnumber < 0 && groupnumber != PCRE2_ERROR_NOUNIQUESUBSTRING)
    cfprintf(clr_api_error, outfile, "Number not found for group \"%s\"\n", nptr);

  length = sizeof(copybuffer)/sizeof(*copybuffer);
  rc = pcre2_substring_copy_byname(match_data, pbuffer, copybuffer, &length);
  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "Copy substring \"%s\" failed (%d): ", nptr, rc);
    if (!print_error_message(rc, "", "\n")) return FALSE;
    }
  else
    {
    fprintf(outfile, "  C ");
    pchars(clr_none, copybuffer, length, utf, outfile);
    fprintf(outfile, " (%" SIZ_FORM ") %s", length, nptr);
    if (groupnumber >= 0) fprintf(outfile, " (group %d)\n", groupnumber);
      else fprintf(outfile, " (non-unique)\n");
    }
  rc2 = pcre2_substring_length_byname(match_data, pbuffer, &length2);
  if (rc2 < 0)
    {
    cfprintf(clr_api_error, outfile, "Get substring \"%s\" length failed (%d): ", nptr, rc2);
    if (!print_error_message(rc2, "", "\n")) return FALSE;
    }
  else if (rc >= 0 && length2 != length)
    {
    cfprintf(clr_test_error, outfile, "** Mismatched substring lengths: %"
      SIZ_FORM " %" SIZ_FORM "\n", length, length2);
    }
  nptr += namelen + 1;
  }

/* Test get strings by number */

for (i = 0; i < MAXCPYGET && dat_datctl.get_numbers[i] >= 0; i++)
  {
  int rc;
  PCRE2_SIZE length;
  PCRE2_UCHAR *gotbuffer;
  uint32_t n = (uint32_t)(dat_datctl.get_numbers[i]);
  rc = pcre2_substring_get_bynumber(match_data, n, &gotbuffer, &length);
  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "Get substring %d failed (%d): ", n, rc);
    if (!print_error_message(rc, "", "\n")) return FALSE;
    }
  else
    {
    fprintf(outfile, "%2dG ", n);
    pchars(clr_none, gotbuffer, length, utf, outfile);
    fprintf(outfile, " (%" SIZ_FORM ")\n", length);
    pcre2_substring_free(gotbuffer);
    }
  }

/* Test get strings by name */

nptr = dat_datctl.get_names;
for (;;)
  {
  PCRE2_SIZE length;
  PCRE2_UCHAR *gotbuffer;
  int rc;
  int groupnumber;
  size_t namelen = strlen((const char *)nptr);
#if PCRE2_CODE_UNIT_WIDTH == 16 || PCRE2_CODE_UNIT_WIDTH == 32
  PCRE2_SIZE cnl = namelen;
#endif
  if (namelen == 0) break;

#if PCRE2_CODE_UNIT_WIDTH == 8
  strcpy((char *)pbuffer8, (char *)nptr);
#endif
#if defined(EBCDIC) && !EBCDIC_IO
  ascii_to_ebcdic_str(pbuffer8, namelen);
#endif
#if PCRE2_CODE_UNIT_WIDTH == 16
  (void)to16(nptr, utf, &cnl);
#endif
#if PCRE2_CODE_UNIT_WIDTH == 32
  (void)to32(nptr, utf, &cnl);
#endif

  groupnumber = pcre2_substring_number_from_name(compiled_code, pbuffer);
  if (groupnumber < 0 && groupnumber != PCRE2_ERROR_NOUNIQUESUBSTRING)
    cfprintf(clr_api_error, outfile, "Number not found for group \"%s\"\n", nptr);

  rc = pcre2_substring_get_byname(match_data, pbuffer, &gotbuffer, &length);
  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "Get substring \"%s\" failed (%d): ", nptr, rc);
    if (!print_error_message(rc, "", "\n")) return FALSE;
    }
  else
    {
    fprintf(outfile, "  G ");
    pchars(clr_none, gotbuffer, length, utf, outfile);
    fprintf(outfile, " (%" SIZ_FORM ") %s", length, nptr);
    if (groupnumber >= 0) fprintf(outfile, " (group %d)\n", groupnumber);
      else fprintf(outfile, " (non-unique)\n");
    pcre2_substring_free(gotbuffer);
    }
  nptr += namelen + 1;
  }

/* Test getting the complete list of captured strings. */

if ((dat_datctl.control & CTL_GETALL) != 0)
  {
  int rc;
  PCRE2_UCHAR **stringlist;
  PCRE2_SIZE *lengths;
  rc = pcre2_substring_list_get(match_data, &stringlist, &lengths);
  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "get substring list failed (%d): ", rc);
    if (!print_error_message(rc, "", "\n")) return FALSE;
    }
  else
    {
    for (i = 0; i < capcount; i++)
      {
      fprintf(outfile, "%2dL ", i);
      pchars(clr_none, stringlist[i], lengths[i], utf, outfile);
      putc('\n', outfile);
      }
    if (stringlist[i] != NULL)
      cfprintf(clr_test_error, outfile, "** string list not terminated by NULL\n");
    pcre2_substring_list_free(stringlist);
    }
  }

return TRUE;
}



/*************************************************
*          Copy a substitution string            *
*************************************************/

/* Copy one of the string arguments to pcre2_substitute() from its uint8_t
test input to the appropriate width buffer.
*/

static void
copy_substitute_string(BOOL utf, uint8_t *input, PCRE2_SIZE inlen,
  PCRE2_UCHAR *output, PCRE2_SIZE *outlen)
{
uint32_t c;
uint8_t *input_end = input + inlen;
PCRE2_UCHAR *output_start = output;
PCRE2_SIZE erroroffset;
BOOL badutf = FALSE;

/* When copying the replacement string to a buffer of the appropriate width, no
escape processing is done.

In UTF mode, check for an invalid UTF-8 input string, and if it is invalid, just
copy its code units without UTF interpretation. This provides a means of
checking that an invalid string is detected. Otherwise, UTF-8 can be used to
include wide characters in a replacement. */

if (utf) badutf = valid_utf(input, inlen, &erroroffset);

/* Not UTF or invalid UTF-8: just copy the code units. */

if (!utf || badutf)
  {
  while (input < input_end)
    {
    c = *input++;
#if defined(EBCDIC) && !EBCDIC_IO
    c = ascii_to_ebcdic(c);
#endif
    *output++ = c;
    }
  }

/* Valid UTF-8 replacement string */

else while (input < input_end)
  {
  c = *input++;
  if (HASUTF8EXTRALEN(c)) { GETUTF8INC(c, input); }

#if PCRE2_CODE_UNIT_WIDTH == 8
  output += ord_to_utf8(c, output);

#elif PCRE2_CODE_UNIT_WIDTH == 16
  if (c >= 0x10000u)
    {
    c-= 0x10000u;
    *output++ = 0xd800 | (c >> 10);
    *output++ = 0xdc00 | (c & 0x3ff);
    }
  else *output++ = c;

#elif PCRE2_CODE_UNIT_WIDTH == 32
  *output++ = c;
#endif
  }

*output = 0;
*outlen = output - output_start;
}



/*************************************************
*               Process a data line              *
*************************************************/

/* The line is in buffer; it will not be empty.

Arguments:  none

Returns:    PR_OK     continue processing next line
            PR_SKIP   skip to a blank line
            PR_ABEND  abort the pcre2test run
*/

static int
process_data(void)
{
PCRE2_SIZE ulen, arg_ulen;
uint32_t gmatched;
uint32_t c, k;
uint32_t g_notempty = 0;
uint8_t *p; /* Position within buffer (raw input line) */
size_t len;
size_t needlen;  /* Bytes, for sizing dbuffer */
pcre2_match_context *use_dat_context;
BOOL utf;
BOOL subject_literal;

PCRE2_SIZE *ovector;
PCRE2_SPTR ovecsave[2] = { NULL, NULL };
uint32_t oveccount;

PCRE2_UCHAR *q = NULL;   /* Typed pointer within dbuffer */
PCRE2_UCHAR *start_rep;  /* Position within dbuffer; stashed value of q */
PCRE2_UCHAR *pp;         /* Subject pointer within dbuffer */

subject_literal = (pat_patctl.control2 & CTL2_SUBJECT_LITERAL) != 0;

/* Copy the default context and data control blocks to the active ones. Then
copy from the pattern the controls that can be set in either the pattern or the
data. This allows them to be overridden in the data line. We do not do this for
options because those that are common apply separately to compiling and
matching. */

memcpy(dat_context, default_dat_context, sizeof(pcre2_match_context));
memcpy(&dat_datctl, &def_datctl, sizeof(datctl));
dat_datctl.control |= (pat_patctl.control & CTL_ALLPD);
dat_datctl.control2 |= (pat_patctl.control2 & CTL2_ALLPD);
dat_datctl.replacement[0] = pat_patctl.replacement[0];
if (pat_patctl.replacement[0] != MOD_STR_UNSET)
  memcpy(dat_datctl.replacement + 1, pat_patctl.replacement + 1,
    pat_patctl.replacement[0] + 1);
if (dat_datctl.jitstack == 0) dat_datctl.jitstack = pat_patctl.jitstack;

if (dat_datctl.substitute_skip == 0)
    dat_datctl.substitute_skip = pat_patctl.substitute_skip;
if (dat_datctl.substitute_stop == 0)
    dat_datctl.substitute_stop = pat_patctl.substitute_stop;

/* Initialize for scanning the data line. */

#if PCRE2_CODE_UNIT_WIDTH == 8
utf = ((((pat_patctl.control & CTL_POSIX) != 0)?
  ((pcre2_real_code *)preg.re_pcre2_code)->overall_options :
  compiled_code->overall_options) & PCRE2_UTF) != 0;
#else
utf = (compiled_code->overall_options & PCRE2_UTF) != 0;
#endif

start_rep = NULL;
len = strlen((const char *)buffer);
while (len > 0 && isspace(buffer[len-1])) len--;
buffer[len] = 0;
p = buffer;
while (isspace(*p))
  {
  p++;
  len--;
  }

/* Check that the data is well-formed UTF-8 if we're in UTF mode. To create
invalid input to pcre2_match(), you must use \x?? or \x{} sequences. */

if (utf)
  {
  uint8_t *ptmp;
  uint32_t cc;
  int n = 1;
  uint8_t *ptmp_end = p + len;

  for (ptmp = p; n > 0 && *ptmp; ptmp += n)
    n = utf8_to_ord(ptmp, ptmp_end, &cc);
  if (n <= 0)
    {
    cfprintf(clr_test_error, outfile, "** Failed: invalid UTF-8 string cannot be used as input "
      "in UTF mode\n");
    return PR_OK;
    }
  }

#ifdef SUPPORT_VALGRIND
/* Mark the dbuffer as addressable but undefined again. */
if (dbuffer != NULL)
  {
  VALGRIND_MAKE_MEM_UNDEFINED(dbuffer, dbuffer_size);
  }
#endif

/* Allocate a buffer to hold the data line; len+1 is an upper bound on
the number of code units that will be needed (though the buffer may have to be
extended if replication is involved). */

needlen = CU2BYTES(len+1);
if (dbuffer == NULL || needlen >= dbuffer_size)
  {
  while (needlen >= dbuffer_size)
    {
    if (dbuffer_size < SIZE_MAX/2) dbuffer_size *= 2;
      else dbuffer_size = needlen + 1;
    }
  dbuffer = (uint8_t *)realloc(dbuffer, dbuffer_size);
  if (dbuffer == NULL)
    {
    cfprintf(clr_test_error, stderr, "pcre2test: realloc(%" SIZ_FORM ") failed\n", dbuffer_size);
    exit(1);
    }
  }
q = (PCRE2_UCHAR *)dbuffer;

/* Scan the data line, interpreting data escapes, and put the result into a
buffer of the appropriate width. In UTF mode, input is always UTF-8; otherwise,
in 16- and 32-bit modes, it can be forced to UTF-8 by the utf8_input modifier.
*/

while ((c = *p++) != 0)
  {
  int i = 0;
  size_t replen;  /* Bytes, for sizing dbuffer */
  enum force_encoding encoding = FORCE_NONE;

  /* ] may mark the end of a replicated sequence */

  if (c == ']' && start_rep != NULL)
    {
    long li;
    char *endptr;

    if (*p++ != '{')
      {
      cfprintf(clr_test_error, outfile, "** Expected '{' after \\[....]\n");
      return PR_OK;
      }

    li = strtol((const char *)p, &endptr, 10);
    if (S32OVERFLOW(li))
      {
      cfprintf(clr_test_error, outfile, "** Repeat count too large\n");
      return PR_OK;
      }
    i = (int)li;

    p = (uint8_t *)endptr;
    if (*p++ != '}')
      {
      cfprintf(clr_test_error, outfile, "** Expected '}' after \\[...]{...\n");
      return PR_OK;
      }

    if (i-- <= 0)
      {
      cfprintf(clr_test_error, outfile, "** Zero or negative repeat not allowed\n");
      return PR_OK;
      }

    replen = (uint8_t *)q - (uint8_t *)start_rep;
    if (i > 0 && replen > (SIZE_MAX - needlen) / i)
      {
      cfprintf(clr_test_error, outfile, "** Expanded content too large\n");
      return PR_OK;
      }
    needlen += replen * i;

    if (needlen >= dbuffer_size)
      {
      size_t qoffset = (uint8_t *)q - dbuffer;
      size_t rep_offset = (uint8_t *)start_rep - dbuffer;
      while (needlen >= dbuffer_size)
        {
        if (dbuffer_size < SIZE_MAX/2) dbuffer_size *= 2;
          else dbuffer_size = needlen + 1;
        }
      dbuffer = (uint8_t *)realloc(dbuffer, dbuffer_size);
      if (dbuffer == NULL)
        {
        cfprintf(clr_test_error, stderr, "pcre2test: realloc(%" SIZ_FORM ") failed\n",
          dbuffer_size);
        exit(1);
        }
      q = (PCRE2_UCHAR *)(dbuffer + qoffset);
      start_rep = (PCRE2_UCHAR *)(dbuffer + rep_offset);
      }

    while (i-- > 0)
      {
      memcpy(q, start_rep, replen);
      q += BYTES2CU(replen);
      }

    start_rep = NULL;
    continue;
    }

  /* Handle a non-escaped character. In non-UTF 32-bit mode with utf8_input
  set, do the fudge for setting the top bit. */

  if (c != '\\' || subject_literal)
    {
    uint32_t topbit = 0;
#if PCRE2_CODE_UNIT_WIDTH == 32
    if (c == 0xff && *p != 0)
      {
      topbit = 0x80000000;
      c = *p++;
      }
#endif
    if ((utf || (pat_patctl.control & CTL_UTF8_INPUT) != 0) &&
        HASUTF8EXTRALEN(c))
      {
      GETUTF8INC(c, p);
      }
    c |= topbit;
    }

  /* Handle backslash escapes */

  else switch ((c = *p++))
    {
    case '\\': break;
    case 'a': c = '\a'; break;
    case 'b': c = '\b'; break;
#if defined(EBCDIC) && !EBCDIC_IO
    /* \e is the odd one out since it's not defined in the C standard,
    precisely because of EBCDIC (apparently EBCDIC 'ESC' character isn't
    an exact match to Latin-1 'ESC', hence '\e' isn't necessarily
    supported by EBCDIC compilers). */
    case 'e': c = '\x1b'; break;
#else
    case 'e': c = CHAR_ESC; break;
#endif
    case 'f': c = '\f'; break;
    case 'n': c = '\n'; break;
    case 'r': c = '\r'; break;
    case 't': c = '\t'; break;
    case 'v': c = '\v'; break;

    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    c -= '0';
    while (i++ < 2 && *p >= '0' && *p < '8')
      c = c * 8 + (*p++ - '0');
    c = CHAR_OUTPUT(CHAR_INPUT_HEX(c));

    encoding = (utf && c > 255)? FORCE_UTF : FORCE_RAW;
    break;

    case 'o':
    if (*p == '{')
      {
      uint8_t *pt = p;
      c = 0;
      for (pt++; isdigit(*pt) && *pt < '8'; ++i, pt++)
        {
        if (c >= 0x20000000u)
          {
          cfprintf(clr_test_error, outfile, "** \\o{ escape too large\n");
          return PR_OK;
          }
        else c = c * 8 + (*pt - '0');
        }
      c = CHAR_OUTPUT(CHAR_INPUT_HEX(c));
      if (i == 0 || *pt != '}')
        {
        cfprintf(clr_test_error, outfile, "** Malformed \\o{ escape\n");
        return PR_OK;
        }
      else p = pt + 1;
      }
    break;

    case 'x':
    c = 0;
    if (*p == '{')
      {
      uint8_t *pt = p;

      /* We used to have "while (isxdigit(*(++pt)))" here, but it fails
      when isxdigit() is a macro that refers to its argument more than
      once. This is banned by the C Standard, but apparently happens in at
      least one macOS environment. */

      for (pt++; isxdigit(*pt); pt++)
        {
        if (++i == 9)
          {
          cfprintf(clr_test_error, outfile, "** Too many hex digits in \\x{...} item; "
                           "using only the first eight.\n");
          while (isxdigit(*pt)) pt++;
          break;
          }
        else c = c * 16 + (tolower(*pt) - (isdigit(*pt)? '0' : 'a' - 10));
        }
      c = CHAR_OUTPUT(CHAR_INPUT_HEX(c));
      if (i == 0 || *pt != '}')
        {
        cfprintf(clr_test_error, outfile, "** Malformed \\x{ escape\n");
        return PR_OK;
        }
      else p = pt + 1;
      }
    else
      {
      /* \x without {} always defines just one byte in 8-bit mode. This
      allows UTF-8 characters to be constructed byte by byte, and also allows
      invalid UTF-8 sequences to be made. Just copy the byte in UTF-8 mode.
      Otherwise, pass it down as data. */

      while (i++ < 2 && isxdigit(*p))
        {
        c = c * 16 + (tolower(*p) - (isdigit(*p)? '0' : 'a' - 10));
        p++;
        }
      c = CHAR_OUTPUT(CHAR_INPUT_HEX(c));
#if PCRE2_CODE_UNIT_WIDTH == 8
      if (utf) encoding = FORCE_RAW;
#endif
      }
    break;

    case 'N':
#ifndef EBCDIC
    if (memcmp(p, "{U+", 3) == 0 && isxdigit(p[3]))
      {
      char *endptr;
      unsigned long uli;

      p += 3;
      errno = 0;
      uli = strtoul((const char *)p, &endptr, 16);
      if (errno == 0 && *endptr == '}' && uli <= UINT32_MAX)
        {
        c = (uint32_t)uli;
        p = (uint8_t *)endptr + 1;
        encoding = FORCE_UTF;
        break;
        }
      }
#endif
    cfprintf(clr_test_error, outfile, "** Malformed \\N{U+ escape\n");
    return PR_OK;

    case 0:     /* \ followed by EOF allows for an empty line */
    p--;
    continue;

    case '=':   /* \= terminates the data, starts modifiers */
    goto ENDSTRING;

    case '[':   /* \[ introduces a replicated character sequence */
    if (start_rep != NULL)
      {
      cfprintf(clr_test_error, outfile, "** Nested replication is not supported\n");
      return PR_OK;
      }
    start_rep = q;
    continue;

    default:
    if (isalnum(c))
      {
      cfprintf(clr_test_error, outfile, "** Unrecognized escape sequence \"\\%c\"\n", c);
      return PR_OK;
      }
    }

  /* We now have a character value in c that may be greater than 255.
  Depending of how we got it, the encoding enum could be set to tell
  us how to encode it, otherwise follow the utf modifier. */

#if PCRE2_CODE_UNIT_WIDTH == 8
  if (encoding == FORCE_RAW || !(utf || encoding == FORCE_UTF))
    {
    if (c > 0xffu)
      {
      cfprintf(clr_test_error, outfile, "** Character \\x{%x} is greater than 255 "
        "and UTF-8 mode is not enabled.\n", c);
      cfprintf(clr_test_error, outfile, "** Truncation will probably give the wrong "
        "result.\n");
      }
    *q++ = (uint8_t)c;
    }
  else
    {
    if (c > 0x7fffffff)
      {
      cfprintf(clr_test_error, outfile, "** Character \\N{U+%x} is greater than 0x7fffffff "
                        "and therefore cannot be encoded as UTF-8\n", c);
      return PR_OK;
      }
    else if (encoding == FORCE_UTF && c > MAX_UTF_CODE_POINT)
      cfprintf(clr_test_error, outfile, "** Warning: character \\N{U+%x} is greater than "
                        "0x%x and should not be encoded as UTF-8\n",
                        c, MAX_UTF_CODE_POINT);
    q += ord_to_utf8(c, q);
    }
#endif
#if PCRE2_CODE_UNIT_WIDTH == 16
  /* Unlike the 8-bit code, there are no forced raw suggestions for the
  16-bit mode, so assume raw unless utf is preferred */

  if (!(encoding == FORCE_UTF || utf))
    {
    if (c > 0xffffu)
      {
      cfprintf(clr_test_error, outfile, "** Character \\x{%x} is greater than 0xffff "
        "and UTF-16 mode is not enabled.\n", c);
      cfprintf(clr_test_error, outfile, "** Truncation will probably give the wrong "
        "result.\n");
      }
    *q++ = (uint16_t)c;
    }
  else
    {
    if (c > MAX_UTF_CODE_POINT)
      {
      cfprintf(clr_test_error, outfile, "** Failed: character \\N{U+%x} is greater than "
                        "0x%x and therefore cannot be encoded as UTF-16\n",
              c, MAX_UTF_CODE_POINT);
      return PR_OK;
      }
    else if (c >= 0x10000u)
      {
      c -= 0x10000u;
      *q++ = 0xd800 | (c >> 10);
      *q++ = 0xdc00 | (c & 0x3ff);
      }
    else
      {
      if (encoding == FORCE_UTF && 0xe000u > c && c >= 0xd800u)
        cfprintf(clr_test_error, outfile, "** Warning: character \\N{U+%x} is a surrogate "
                          "and should not be encoded as UTF-16\n", c);
      *q++ = c;
      }
    }
#endif
#if PCRE2_CODE_UNIT_WIDTH == 32
  if (encoding == FORCE_UTF && c > MAX_UTF_CODE_POINT)
    cfprintf(clr_test_error, outfile, "** Warning: character \\N{U+%x} is greater than "
                      "0x%x and should not be encoded as UTF-32\n",
                      c, MAX_UTF_CODE_POINT);
  *q++ = c;
#endif
  }

ENDSTRING:
*q = 0;
len = (uint8_t *)q - dbuffer;             /* Length in bytes */
ulen = BYTES2CU(len);                     /* Length in code units */
arg_ulen = ulen;                          /* Value to use in match arg */

/* If the string was terminated by \= we must now interpret modifiers. */

if (p[-1] != 0 && !decode_modifiers(p, CTX_DAT, NULL, &dat_datctl))
  return PR_OK;

/* Setting substitute_{skip,fail} implies a substitute callout. */

if (dat_datctl.substitute_skip != 0 || dat_datctl.substitute_stop != 0)
  dat_datctl.control2 |= CTL2_SUBSTITUTE_CALLOUT;

/* Check for mutually exclusive modifiers. At present, these are all in the
first control word. */

for (k = 0; k < sizeof(exclusive_dat_controls)/sizeof(uint32_t); k++)
  {
  c = dat_datctl.control & exclusive_dat_controls[k];
  if (c != 0 && c != (c & (~c+1)))
    {
    show_controls(clr_test_error, c, 0, "** Not allowed together:");
    fprintf(outfile, "\n");
    return PR_OK;
    }
  }

if (dat_datctl.replacement[0] != MOD_STR_UNSET)
  {
  if ((dat_datctl.control2 & CTL2_SUBSTITUTE_CALLOUT) != 0 &&
      (dat_datctl.control & CTL_NULLCONTEXT) != 0)
    {
    cfprintf(clr_test_error, outfile, "** Replacement callouts are not supported with null_context.\n");
    return PR_OK;
    }

  if ((dat_datctl.control2 & CTL2_SUBSTITUTE_CASE_CALLOUT) != 0 &&
      (dat_datctl.control & CTL_NULLCONTEXT) != 0)
    {
    cfprintf(clr_test_error, outfile, "** Replacement case callouts are not supported with null_context.\n");
    return PR_OK;
    }

  if ((dat_datctl.control & CTL_ALLCAPTURES) != 0)
    cfprintf(clr_test_error, outfile, "** Ignored with replacement text: allcaptures\n");

  if (dat_datctl.substitute_subject[0] != MOD_STR_UNSET &&
      (dat_datctl.control2 & CTL2_SUBSTITUTE_MATCHED) == 0)
    {
    cfprintf(clr_test_error, outfile, "** substitute_subject requires substitute_matched.\n");
    return PR_OK;
    }
  }

else
  {
  if (dat_datctl.substitute_subject[0] != MOD_STR_UNSET)
    {
    cfprintf(clr_test_error, outfile, "** substitute_subject requires replacement text.\n");
    return PR_OK;
    }
  }

/* Warn for modifiers that are ignored for DFA. */

if ((dat_datctl.control & CTL_DFA) != 0)
  {
  if ((dat_datctl.control & CTL_ALLCAPTURES) != 0)
    cfprintf(clr_test_error, outfile, "** Ignored for DFA matching: allcaptures\n");
  if ((dat_datctl.control2 & CTL2_HEAPFRAMES_SIZE) != 0)
    cfprintf(clr_test_error, outfile, "** Ignored for DFA matching: heapframes_size\n");
  }

/* We now have the subject in dbuffer, with len containing the byte length, and
ulen containing the code unit length, with a copy in arg_ulen for use in match
function arguments (this gets changed to PCRE2_ZERO_TERMINATED when the
zero_terminate modifier is present).

Move the data to the end of the buffer so that a read over the end can be
caught by valgrind or other means. If we have explicit valgrind support, mark
the unused start of the buffer unaddressable. If we are using the POSIX
interface, or testing zero-termination, we must include the terminating zero in
the usable data. */

c = ((pat_patctl.control & CTL_POSIX) != 0 ||
     (dat_datctl.control & CTL_ZERO_TERMINATE) != 0)? CU2BYTES(1) : 0;
pp = memmove(dbuffer + dbuffer_size - (len + c), dbuffer, len + c);
#ifdef SUPPORT_VALGRIND
VALGRIND_MAKE_MEM_NOACCESS(dbuffer, dbuffer_size - (len + c));
#endif

#if defined(EBCDIC) && !EBCDIC_IO
ascii_to_ebcdic_str(pp, len);
#endif

/* Now pp points to the subject string, but if null_subject was specified, set
it to NULL to test PCRE2's behaviour. */

if ((dat_datctl.control2 & CTL2_NULL_SUBJECT) != 0) pp = NULL;

/* POSIX matching is only possible in 8-bit mode, and it does not support
timing or other fancy features. Some were checked at compile time, but we need
to check the match-time settings here. */

#if PCRE2_CODE_UNIT_WIDTH == 8
if ((pat_patctl.control & CTL_POSIX) != 0)
  {
  int rc;
  int eflags = 0;
  regmatch_t *pmatch = NULL;
  regmatch_t startend_buf;
  const char *msg = "** Ignored with POSIX interface:";

  if (dat_datctl.cerror[0] != CFORE_UNSET || dat_datctl.cerror[1] != CFORE_UNSET)
    prmsg(&msg, "callout_error");
  if (dat_datctl.cfail[0] != CFORE_UNSET || dat_datctl.cfail[1] != CFORE_UNSET)
    prmsg(&msg, "callout_fail");
  if (dat_datctl.copy_numbers[0] >= 0 || dat_datctl.copy_names[0] != 0)
    prmsg(&msg, "copy");
  if (dat_datctl.get_numbers[0] >= 0 || dat_datctl.get_names[0] != 0)
    prmsg(&msg, "get");
  if (dat_datctl.jitstack != 0) prmsg(&msg, "jitstack");
  if (dat_datctl.offset != 0) prmsg(&msg, "offset");

  if ((dat_datctl.options & ~POSIX_SUPPORTED_MATCH_OPTIONS) != 0)
    {
    cfprintf(clr_test_error, outfile, "%s", msg);
    show_match_options(clr_test_error, dat_datctl.options & ~POSIX_SUPPORTED_MATCH_OPTIONS);
    msg = "";
    }

  if ((dat_datctl.control & ~POSIX_SUPPORTED_MATCH_CONTROLS) != 0 ||
      (dat_datctl.control2 & ~POSIX_SUPPORTED_MATCH_CONTROLS2) != 0)
    {
    show_controls(clr_test_error, dat_datctl.control & ~POSIX_SUPPORTED_MATCH_CONTROLS,
                  dat_datctl.control2 & ~POSIX_SUPPORTED_MATCH_CONTROLS2, msg);
    msg = "";
    }

  if (msg[0] == 0) fprintf(outfile, "\n");

  if (dat_datctl.oveccount > 0)
    {
    pmatch = (regmatch_t *)malloc(sizeof(regmatch_t) * dat_datctl.oveccount);
    if (pmatch == NULL)
      {
      cfprintf(clr_test_error, outfile, "** Failed to get memory for recording matching "
        "information (size set = %du)\n", dat_datctl.oveccount);
      return PR_ABEND;
      }
    }

  if (dat_datctl.startend[0] != CFORE_UNSET)
    {
    if (pmatch == NULL) pmatch = &startend_buf;
    pmatch[0].rm_so = (regoff_t)dat_datctl.startend[0];
    pmatch[0].rm_eo = (dat_datctl.startend[1] != 0)?
      (regoff_t)dat_datctl.startend[1] : (regoff_t)len;
    eflags |= REG_STARTEND;
    }

  if ((dat_datctl.options & PCRE2_NOTBOL) != 0) eflags |= REG_NOTBOL;
  if ((dat_datctl.options & PCRE2_NOTEOL) != 0) eflags |= REG_NOTEOL;
  if ((dat_datctl.options & PCRE2_NOTEMPTY) != 0) eflags |= REG_NOTEMPTY;

  rc = regexec(&preg, (const char *)pp, dat_datctl.oveccount, pmatch, eflags);
  if (rc != 0)
    {
    size_t usize = regerror(rc, &preg, (char *)pbuffer8, pbuffer8_size);
    cfprintf(clr_api_error, outfile, "No match: POSIX code %d: ", rc);
    pchars(clr_api_error, (PCRE2_SPTR8)pbuffer8, usize - 1, utf, outfile);
    fputs("\n", outfile);
    }
  else if ((pat_patctl.control & CTL_POSIX_NOSUB) != 0)
    fprintf(outfile, "Matched with REG_NOSUB\n");
  else if (dat_datctl.oveccount == 0)
    fprintf(outfile, "Matched without capture\n");
  else
    {
    size_t i, j;
    size_t last_printed = (size_t)dat_datctl.oveccount;
    for (i = 0; i < (size_t)dat_datctl.oveccount; i++)
      {
      if (pmatch[i].rm_so >= 0)
        {
        PCRE2_SIZE start = pmatch[i].rm_so;
        PCRE2_SIZE end = pmatch[i].rm_eo;
        for (j = last_printed + 1; j < i; j++)
          fprintf(outfile, "%2d: <unset>\n", (int)j);
        last_printed = i;
        if (start > end)
          {
          start = pmatch[i].rm_eo;
          end = pmatch[i].rm_so;
          cfprintf(clr_api_error, outfile, "Start of matched string is beyond its end - "
            "displaying from end to start.\n");
          }
        fprintf(outfile, "%2d: ", (int)i);
        pchars(clr_none, pp + start, end - start, utf, outfile);
        fprintf(outfile, "\n");

        if ((i == 0 && (dat_datctl.control & CTL_AFTERTEXT) != 0) ||
            (dat_datctl.control & CTL_ALLAFTERTEXT) != 0)
          {
          fprintf(outfile, "%2d+ ", (int)i);
          /* Note: don't use the start/end variables here because we want to
          show the text from what is reported as the end. */
          pchars(clr_none, pp + pmatch[i].rm_eo, len - pmatch[i].rm_eo, utf, outfile);
          fprintf(outfile, "\n");
          }
        }
      }
    }
  if (pmatch != &startend_buf) free(pmatch);
  return PR_OK;
  }
#endif  /* PCRE2_CODE_UNIT_WIDTH == 8 */

 /* Handle matching via the native interface. Check for consistency of
modifiers. */

if (dat_datctl.startend[0] != CFORE_UNSET)
  cfprintf(clr_test_error, outfile, "** \\=posix_startend ignored for non-POSIX matching\n");

/* ALLUSEDTEXT is not supported with JIT, but JIT is not used with DFA
matching, even if the JIT compiler was used. */

if ((dat_datctl.control & (CTL_ALLUSEDTEXT|CTL_DFA)) == CTL_ALLUSEDTEXT &&
    compiled_code->executable_jit != NULL)
  {
  cfprintf(clr_test_error, outfile, "** Showing all consulted text is not supported by JIT: ignored\n");
  dat_datctl.control &= ~CTL_ALLUSEDTEXT;
  }

/* Handle passing the subject as zero-terminated. */

if ((dat_datctl.control & CTL_ZERO_TERMINATE) != 0)
  arg_ulen = PCRE2_ZERO_TERMINATED;

/* The nullcontext modifier is used to test calling pcre2_[jit_]match() with a
NULL context. */

use_dat_context = ((dat_datctl.control & CTL_NULLCONTEXT) != 0)?
  NULL : dat_context;

/* Enable display of malloc/free if wanted. We can do this only if either the
pattern or the subject is processed with a context. */

show_memory = (dat_datctl.control & CTL_MEMORY) != 0;

if (show_memory &&
    (pat_patctl.control & dat_datctl.control & CTL_NULLCONTEXT) != 0)
  cfprintf(clr_test_error, outfile, "** \\=memory requires either a pattern or a subject "
    "context: ignored\n");

/* Create and assign a JIT stack if requested. */

if (dat_datctl.jitstack != 0)
  {
  if (dat_datctl.jitstack != jit_stack_size)
    {
    pcre2_jit_stack_free(jit_stack);
    jit_stack = pcre2_jit_stack_create(1, dat_datctl.jitstack * 1024, NULL);
    jit_stack_size = dat_datctl.jitstack;
    }
  pcre2_jit_stack_assign(dat_context, jit_callback, jit_stack);
  }

/* Or de-assign */

else if (jit_stack != NULL)
  {
  pcre2_jit_stack_assign(dat_context, NULL, NULL);
  pcre2_jit_stack_free(jit_stack);
  jit_stack = NULL;
  jit_stack_size = 0;
  }

/* When no JIT stack is assigned, we must ensure that there is a JIT callback
if we want to verify that JIT was actually used. */

if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_stack == NULL)
   {
   pcre2_jit_stack_assign(dat_context, jit_callback, NULL);
   }

/* Set up the match callout. The pattern remains in pbuffer8/16/32 after
compilation, for use by the callout. */

if ((dat_datctl.control & CTL_CALLOUT_NONE) == 0)
  {
  pcre2_set_callout(dat_context, callout_function,
    (void *)(&dat_datctl.callout_data));
  }
else
  {
  pcre2_set_callout(dat_context, NULL, NULL);  /* No callout */
  }

/* Adjust match_data according to size of offsets required. A size of zero
causes a new match data block to be obtained that exactly fits the pattern. */

if (dat_datctl.oveccount == 0)
  {
  pcre2_match_data_free(match_data);
  match_data = pcre2_match_data_create_from_pattern(compiled_code,
    general_context);
  max_oveccount = pcre2_get_ovector_count(match_data);
  }
else if (dat_datctl.oveccount <= max_oveccount)
  {
  match_data->oveccount = dat_datctl.oveccount;
  }
else
  {
  max_oveccount = dat_datctl.oveccount;
  pcre2_match_data_free(match_data);
  match_data = pcre2_match_data_create(max_oveccount, general_context);
  }

if (match_data == NULL)
  {
  cfprintf(clr_test_error, outfile, "** Failed to get memory for recording matching "
    "information (size requested: %d)\n", dat_datctl.oveccount);
  max_oveccount = 0;
  return PR_ABEND;
  }

ovector = match_data->ovector;
oveccount = pcre2_get_ovector_count(match_data);

/* Helper to clear any cached heap frames from the match_data. */

#define CLEAR_HEAP_FRAMES() \
  do { \
     void *heapframes = (void *)(match_data->heapframes); \
     void *memory_data = match_data->memctl.memory_data; \
     match_data->memctl.free(heapframes, memory_data); \
     match_data->heapframes = NULL; \
     match_data->heapframes_size = 0; \
     } \
  while (0)

/* Replacement processing is ignored for DFA matching. Allow this for
replacements with PCRE2_SUBSTITUTE_MATCHED, even though it won't work, in order
to exercise the error condition. */

if (dat_datctl.replacement[0] != MOD_STR_UNSET &&
    (dat_datctl.control & CTL_DFA) != 0 &&
    (dat_datctl.control2 & CTL2_SUBSTITUTE_MATCHED) == 0)
  {
  cfprintf(clr_test_error, outfile, "** Ignored for DFA matching: replace\n");
  dat_datctl.replacement[0] = MOD_STR_UNSET;
  }

/* If a replacement string is provided, call pcre2_substitute() instead of or
after one of the matching functions. First we have to convert the replacement
string to the appropriate width. */

if (dat_datctl.replacement[0] != MOD_STR_UNSET)
  {
  int rc;
  uint8_t *pr, *prend;
  PCRE2_UCHAR sbuffer[SUBSTITUTE_SUBJECT_MODSIZE]; /* Staging, not seen by pcre2_substitute() */
  PCRE2_UCHAR *rbptr;
  PCRE2_UCHAR *sbptr;
  uint32_t xoptions;
  uint32_t emoption;  /* External match option */
  PCRE2_SIZE j, rlen, full_rlen, nsize, nsize_input, slen;
  pcre2_match_data *smatch_data;

  /* Fill the ovector with junk to detect elements that do not get set
  when they should be (relevant only when "allvector" is specified). */

  for (j = 0; j < 2*oveccount; j++) ovector[j] = JUNK_OFFSET;

  if (timeitm)
    cfprintf(clr_test_error, outfile, "** Timing is not supported with replace: ignored\n");

  if ((dat_datctl.control & CTL_ALTGLOBAL) != 0)
    cfprintf(clr_test_error, outfile, "** Altglobal is not supported with replace: ignored\n");

  /* Check for a test that does substitution after an initial external match.
  If this is set, we run the external match, but leave the interpretation of
  its output to pcre2_substitute(). */

  emoption = ((dat_datctl.control2 & CTL2_SUBSTITUTE_MATCHED) == 0)? 0 :
    PCRE2_SUBSTITUTE_MATCHED;

  if (emoption != 0)
    {
    reset_callout_state();
    if ((dat_datctl.control & CTL_DFA) != 0)
      {
      if (dfa_workspace == NULL)
        dfa_workspace = (int *)malloc(DFA_WS_DIMENSION*sizeof(int));
      dfa_workspace[0] = -1;
      (void)pcre2_dfa_match(compiled_code, pp, arg_ulen,
        dat_datctl.offset, dat_datctl.options, match_data,
        use_dat_context, dfa_workspace, DFA_WS_DIMENSION);
      }
    else if ((pat_patctl.control & CTL_JITFAST) != 0)
      {
      (void)pcre2_jit_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
        dat_datctl.options, match_data, use_dat_context);
      }
    else
      {
      (void)pcre2_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
        dat_datctl.options, match_data, use_dat_context);
      }
    }

  xoptions = emoption |
             (((dat_datctl.control & CTL_GLOBAL) == 0)? 0 :
                PCRE2_SUBSTITUTE_GLOBAL) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_EXTENDED) == 0)? 0 :
                PCRE2_SUBSTITUTE_EXTENDED) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_LITERAL) == 0)? 0 :
                PCRE2_SUBSTITUTE_LITERAL) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_OVERFLOW_LENGTH) == 0)? 0 :
                PCRE2_SUBSTITUTE_OVERFLOW_LENGTH) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_REPLACEMENT_ONLY) == 0)? 0 :
                PCRE2_SUBSTITUTE_REPLACEMENT_ONLY) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_UNKNOWN_UNSET) == 0)? 0 :
                PCRE2_SUBSTITUTE_UNKNOWN_UNSET) |
             (((dat_datctl.control2 & CTL2_SUBSTITUTE_UNSET_EMPTY) == 0)? 0 :
                PCRE2_SUBSTITUTE_UNSET_EMPTY);

  pr = dat_datctl.replacement+1;
  prend = pr + dat_datctl.replacement[0];

  /* If the replacement starts with '[<number>]' we interpret that as length
  value for the replacement buffer. */

  nsize = rep_out_buffer_size;
  if (pr < prend && *pr == '[')
    {
    PCRE2_SIZE n = 0;
    ++pr;
    for (; pr < prend && (c = *pr) >= '0' && c <= '9'; ++pr)
      n = n * 10 + (c - '0');
    if (pr >= prend || *pr != ']')
      {
      cfprintf(clr_test_error, outfile, "** Bad buffer size in replacement string\n");
      return PR_OK;
      }
    ++pr;
    if (n > nsize)
      {
      cfprintf(clr_test_error, outfile, "** Replacement buffer setting (%" SIZ_FORM ") is too "
        "large (max %" SIZ_FORM ")\n", n, nsize);
      return PR_OK;
      }
    nsize = n;
    }

#ifdef SUPPORT_VALGRIND
  VALGRIND_MAKE_MEM_UNDEFINED(rep_out_buffer, CU2BYTES(nsize));
  VALGRIND_MAKE_MEM_NOACCESS(rep_out_buffer + nsize,
    CU2BYTES(rep_out_buffer_size - nsize));
#endif

  /* Now copy the rest of the replacement string to the buffer. */

#ifdef SUPPORT_VALGRIND
  VALGRIND_MAKE_MEM_UNDEFINED(rep_in_buffer, CU2BYTES(rep_in_buffer_size));
#endif

  copy_substitute_string(utf, pr, prend-pr, rep_in_buffer, &rlen);

#ifdef SUPPORT_VALGRIND
  c = ((dat_datctl.control & CTL_ZERO_TERMINATE) != 0)? 1 : 0;
  VALGRIND_MAKE_MEM_NOACCESS(rep_in_buffer + rlen + c,
    CU2BYTES(rep_in_buffer_size - rlen + c));
#endif

  full_rlen = rlen;
  if ((dat_datctl.control & CTL_ZERO_TERMINATE) != 0)
    rlen = PCRE2_ZERO_TERMINATED;
  rbptr = ((dat_datctl.control2 & CTL2_NULL_REPLACEMENT) == 0)? rep_in_buffer : NULL;

  /* If the substitute_subject modifier is set, then we will modify the
  subject in between the call to pcre2_match and pcre2_substitute. */

  sbptr = pp;
  slen = arg_ulen;

  if (dat_datctl.substitute_subject[0] != MOD_STR_UNSET)
    {
    copy_substitute_string(utf, dat_datctl.substitute_subject+1,
      dat_datctl.substitute_subject[0], sbuffer, &slen);

    /* The buffer pointed to by pp has exactly the correct length (butted up
    against the end of the memory allocation) so it would be possible but
    awkward to extend the subject. However, since pcre2_substitute() won't allow
    changing the length of the subject, and also early-exits if the subject
    pointer changes, we can test all the branches just by supporting shrinking
    the subject. */
    if (slen > ulen)
      {
      cfprintf(clr_test_error, outfile, "** substitute_subject is longer than match subject buffer\n");
      return PR_OK;
      }

    /* In the null-subject case, there's no need to copy. */
    if (pp != NULL)
      {
      memcpy(pp, sbuffer, CU2BYTES(slen));
      if (slen < ulen) ((PCRE2_UCHAR *)pp)[slen] = 0;

      /* If we shrank the subject, adjust the Valgrind readable area. */
#ifdef SUPPORT_VALGRIND
      c = ((dat_datctl.control & CTL_ZERO_TERMINATE) != 0)? 1 : 0;
      VALGRIND_MAKE_MEM_NOACCESS((uint8_t *)pp + CU2BYTES(slen+c),
        (dbuffer + dbuffer_size) - ((uint8_t *)pp + CU2BYTES(slen+c)));
#endif
      }

    if ((dat_datctl.control & CTL_ZERO_TERMINATE) != 0)
      slen = PCRE2_ZERO_TERMINATED;
    }

  /* Set up the required callouts and context, and call pcre2_substitute(). */

  smatch_data = ((CTL2_NULL_SUBSTITUTE_MATCH_DATA & dat_datctl.control2) == 0)?
    match_data : NULL;

  if ((dat_datctl.control2 & CTL2_SUBSTITUTE_CALLOUT) != 0)
    {
    pcre2_set_substitute_callout(dat_context, substitute_callout_function, NULL);
    }
  else
    {
    pcre2_set_substitute_callout(dat_context, NULL, NULL);  /* No callout */
    }

  if ((dat_datctl.control2 & CTL2_SUBSTITUTE_CASE_CALLOUT) != 0)
    {
    pcre2_set_substitute_case_callout(dat_context, substitute_case_callout_function, NULL);
    }
  else
    {
    pcre2_set_substitute_case_callout(dat_context, NULL, NULL);  /* No callout */
    }

  if (malloc_testing) CLEAR_HEAP_FRAMES();
  reset_callout_state();
  nsize_input = nsize;
  rc = pcre2_substitute(compiled_code, sbptr, slen, dat_datctl.offset,
    dat_datctl.options|xoptions, smatch_data, use_dat_context,
    rbptr, rlen, rep_out_buffer, &nsize);

  /* For malloc testing, we repeat the substitution. */

  if (malloc_testing && (dat_datctl.control2 & CTL2_SUBSTITUTE_CALLOUT) == 0)
    {
    for (int i = 0, target_mallocs = mallocs_called; i <= target_mallocs; i++)
      {
      FILE *saved_outfile = outfile;
      CLEAR_HEAP_FRAMES();
      reset_callout_state();
      mallocs_until_failure = i;
      outfile = NULL;  /* Suppress callout output during the malloc repetitions */
      nsize = nsize_input;
      rc = pcre2_substitute(compiled_code, sbptr, slen, dat_datctl.offset,
        dat_datctl.options|xoptions, smatch_data, use_dat_context,
        rbptr, rlen, rep_out_buffer, &nsize);
      mallocs_until_failure = INT_MAX;
      outfile = saved_outfile;

      if (i < target_mallocs && rc != PCRE2_ERROR_NOMEMORY)
        {
        cfprintf(clr_test_error, outfile, "** malloc() Substitution test did not fail as expected (%d)\n",
                rc);
        return PR_ABEND;
        }
      }
    }

  if (rc < 0)
    {
    cfprintf(clr_api_error, outfile, "Failed: error %d", rc);
    if (rc != PCRE2_ERROR_NOMEMORY && nsize != PCRE2_UNSET)
      cfprintf(clr_api_error, outfile, " at offset %ld in replacement", (long int)nsize);
    cfprintf(clr_api_error, outfile, ": ");
    if (!print_error_message(rc, "", "")) return PR_ABEND;
    if (rc == PCRE2_ERROR_NOMEMORY &&
        (xoptions & PCRE2_SUBSTITUTE_OVERFLOW_LENGTH) != 0)
      cfprintf(clr_api_error, outfile, ": %ld code units are needed", (long int)nsize);

    if (rc != PCRE2_ERROR_NOMEMORY && nsize != PCRE2_UNSET)
      {
      cfprintf(clr_api_error, outfile, "\n        here: ");
      if (nsize > 0)
        {
        ptrunc(clr_input, rbptr, full_rlen, nsize, TRUE, utf, outfile);
        fprintf(outfile, " ");
        }
      cfprintf(clr_api_error, outfile, "|<--|");
      if (nsize < full_rlen)
        {
        fprintf(outfile, " ");
        ptrunc(clr_input, rbptr, full_rlen, nsize, FALSE, utf, outfile);
        }
      }
    }
  else
    {
    cfprintf(clr_api_error, outfile, "%2d: ", rc);
    pchars(clr_api_error, rep_out_buffer, nsize, utf, outfile);
    }

  fprintf(outfile, "\n");
  show_memory = FALSE;

  /* Show final ovector contents and resulting heapframe size if requested. */

  if ((dat_datctl.control2 & CTL2_ALLVECTOR) != 0)
    show_ovector(ovector, oveccount);

  if ((dat_datctl.control2 & CTL2_HEAPFRAMES_SIZE) != 0 &&
      (dat_datctl.control & CTL_DFA) == 0)
    show_heapframes_size();

  return PR_OK;
  }   /* End of substitution handling */

/* When a replacement string is not provided, run a loop for global matching
with one of the basic matching functions. */

for (gmatched = 0;; gmatched++)
  {
  PCRE2_SIZE j;
  int capcount;

  /* Fill the ovector with junk to detect elements that do not get set
  when they should be. */

  for (j = 0; j < 2*oveccount; j++) ovector[j] = JUNK_OFFSET;

  /* When matching is via pcre2_match(), we will detect the use of JIT via the
  stack callback function. */

  jit_was_used = (pat_patctl.control & CTL_JITFAST) != 0;

  /* Do timing if required. */

  if (timeitm > 0)
    {
    int i;
    clock_t start_time, time_taken;
    FILE *saved_outfile = outfile;

    outfile = NULL;  /* Suppress callout output during the timing repetitions */

    if ((dat_datctl.control & CTL_DFA) != 0)
      {
      if ((dat_datctl.options & PCRE2_DFA_RESTART) != 0)
        {
        outfile = saved_outfile;
        cfprintf(clr_test_error, outfile, "** Timing DFA restarts is not supported\n");
        return PR_ABEND;
        }
      if (dfa_workspace == NULL)
        dfa_workspace = (int *)malloc(DFA_WS_DIMENSION*sizeof(int));
      start_time = clock();
      for (i = 0; i < timeitm; i++)
        {
        (void)pcre2_dfa_match(compiled_code, pp, arg_ulen,
          dat_datctl.offset, dat_datctl.options | g_notempty, match_data,
          use_dat_context, dfa_workspace, DFA_WS_DIMENSION);
        }
      }

    else if ((pat_patctl.control & CTL_JITFAST) != 0)
      {
      start_time = clock();
      for (i = 0; i < timeitm; i++)
        {
        (void)pcre2_jit_match(compiled_code, pp, arg_ulen,
          dat_datctl.offset, dat_datctl.options | g_notempty, match_data,
          use_dat_context);
        }
      }

    else
      {
      start_time = clock();
      for (i = 0; i < timeitm; i++)
        {
        (void)pcre2_match(compiled_code, pp, arg_ulen,
          dat_datctl.offset, dat_datctl.options | g_notempty, match_data,
          use_dat_context);
        }
      }
    total_match_time += (time_taken = clock() - start_time);

    outfile = saved_outfile;
    cfprintf(clr_profiling, outfile, "Match time %7.4f microseconds\n",
      ((1000000 / CLOCKS_PER_SEC) * (double)time_taken) / timeitm);
    }

  /* Find the heap, match and depth limits if requested. The depth and heap
  limits are not relevant for JIT. The return from check_match_limit() is the
  return from the final call to pcre2_match() or pcre2_dfa_match(). */

  if ((dat_datctl.control & (CTL_FINDLIMITS|CTL_FINDLIMITS_NOHEAP)) != 0)
    {
    if ((dat_datctl.control & CTL_FINDLIMITS_NOHEAP) == 0 &&
        (compiled_code->executable_jit == NULL ||
          (dat_datctl.options & PCRE2_NO_JIT) != 0))
      {
      (void)check_match_limit(pp, arg_ulen, PCRE2_ERROR_HEAPLIMIT, "heap");
      }

    capcount = check_match_limit(pp, arg_ulen, PCRE2_ERROR_MATCHLIMIT,
      "match");

    if (compiled_code->executable_jit == NULL ||
        (dat_datctl.options & PCRE2_NO_JIT) != 0 ||
        (dat_datctl.control & CTL_DFA) != 0)
      {
      capcount = check_match_limit(pp, arg_ulen, PCRE2_ERROR_DEPTHLIMIT,
        "depth");
      }

    if (capcount == 0)
      {
      cfprintf(clr_api_error, outfile, "Matched, but offsets vector is too small to show all matches\n");
      capcount = dat_datctl.oveccount;
      }
    }

  /* Otherwise just run a single match. */

  else
    {
    /* Run a single DFA or NFA match. */

    if (malloc_testing) CLEAR_HEAP_FRAMES();
    reset_callout_state();
    if ((dat_datctl.control & CTL_DFA) != 0)
      {
      if (dfa_workspace == NULL)
        dfa_workspace = (int *)malloc(DFA_WS_DIMENSION*sizeof(int));
      if (dfa_matched++ == 0)
        dfa_workspace[0] = -1;  /* To catch bad restart */
      capcount = pcre2_dfa_match(compiled_code, pp, arg_ulen,
        dat_datctl.offset, dat_datctl.options | g_notempty, match_data,
        use_dat_context, dfa_workspace, DFA_WS_DIMENSION);
      if (capcount == 0)
        {
        cfprintf(clr_api_error, outfile, "Matched, but offsets vector is too small to show all matches\n");
        capcount = dat_datctl.oveccount;
        }
      }
    else
      {
      if ((pat_patctl.control & CTL_JITFAST) != 0)
        capcount = pcre2_jit_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
          dat_datctl.options | g_notempty, match_data, use_dat_context);
      else
        capcount = pcre2_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
          dat_datctl.options | g_notempty, match_data, use_dat_context);
      if (capcount == 0)
        {
        cfprintf(clr_api_error, outfile, "Matched, but too many substrings\n");
        capcount = dat_datctl.oveccount;
        }
      }

    /* For malloc testing, we repeat the matching. */

    if (malloc_testing && (dat_datctl.control & CTL_CALLOUT_NONE) != 0)
      {
      for (int i = 0, target_mallocs = mallocs_called; i <= target_mallocs; i++)
        {
        FILE *saved_outfile = outfile;

        CLEAR_HEAP_FRAMES();
        reset_callout_state();

        mallocs_until_failure = i;
        outfile = NULL;  /* Suppress callout output during the malloc repetitions */

        if ((dat_datctl.control & CTL_DFA) != 0)
          {
          if (dfa_matched++ == 0)
            dfa_workspace[0] = -1;  /* To catch bad restart */
          capcount = pcre2_dfa_match(compiled_code, pp, arg_ulen,
            dat_datctl.offset, dat_datctl.options | g_notempty, match_data,
            use_dat_context, dfa_workspace, DFA_WS_DIMENSION);
          }
        else
          {
          if ((pat_patctl.control & CTL_JITFAST) != 0)
            capcount = pcre2_jit_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
              dat_datctl.options | g_notempty, match_data, use_dat_context);
          else
            capcount = pcre2_match(compiled_code, pp, arg_ulen, dat_datctl.offset,
              dat_datctl.options | g_notempty, match_data, use_dat_context);
          }

        mallocs_until_failure = INT_MAX;
        outfile = saved_outfile;

        if (capcount == 0)
          capcount = dat_datctl.oveccount;

        if (i < target_mallocs && capcount != PCRE2_ERROR_NOMEMORY)
          {
          cfprintf(clr_test_error, outfile, "** malloc() match test did not fail as expected (%d)\n",
                  capcount);
          return PR_ABEND;
          }
        }
      }
    }

  /* Verify that it's safe to call pcre2_next_match with rc < 0. */

  if (capcount < 0 && (dat_datctl.control & CTL_ANYGLOB) != 0)
    {
      BOOL rc_nextmatch;
      PCRE2_SIZE tmp_offset = 0xcd;
      uint32_t tmp_options = 0xcd;
      rc_nextmatch = pcre2_next_match(match_data, &tmp_offset, &tmp_options);
      if (rc_nextmatch || tmp_offset != 0xcd || tmp_options != 0xcd)
        {
        cfprintf(clr_test_error, outfile, "** unexpected pcre2_next_match() for rc < 0\n");
        return PR_ABEND;
        }
    }

  /* The result of the match is now in capcount. First handle a successful
  match. If pp was forced to be NULL (to test NULL handling) it will have been
  treated as an empty string if the length was zero. So, re-create that for
  outputting, preserving the invariant that pp is a valid pointer to a region
  of length len followed by a null. */

  if (capcount >= 0)
    {
    if (pp == NULL)
      {
#ifdef SUPPORT_VALGRIND
      /* Mark the start of dbuffer addressable again. */
      VALGRIND_MAKE_MEM_UNDEFINED(dbuffer, CU2BYTES(1));
#endif
      pp = (PCRE2_UCHAR *)dbuffer;
      *pp = 0;
      }

    if ((unsigned)capcount > oveccount)   /* Check for lunatic return value */
      {
      cfprintf(clr_test_error, outfile,
        "** PCRE2 error: returned count %d is too big for ovector count %d\n",
        capcount, oveccount);
      return PR_ABEND;
      }

    /* If PCRE2_COPY_MATCHED_SUBJECT was set, check that things are as they
    should be, but not for fast JIT, where it isn't supported. */

    if ((dat_datctl.options & PCRE2_COPY_MATCHED_SUBJECT) != 0 &&
        (pat_patctl.control & CTL_JITFAST) == 0)
      {
      if ((match_data->flags & PCRE2_MD_COPIED_SUBJECT) == 0)
        cfprintf(clr_test_error, outfile,
          "** PCRE2 error: flag not set after copy_matched_subject\n");

      if (match_data->subject == pp)
        cfprintf(clr_test_error, outfile,
          "** PCRE2 error: copy_matched_subject has not copied\n");

      if (memcmp(match_data->subject, pp, ulen) != 0)
        cfprintf(clr_test_error, outfile,
          "** PCRE2 error: copy_matched_subject mismatch\n");
      }

    /* If this is not the first time round a global loop, check that the
    returned string has advanced.

    There is one known case where this doesn't happen: when you have a
    "badly-behaved" pattern which uses \K in a lookaround, and breaks the core
    sanity rule that start_offset <= ovector[0] <= ovector[1]. An example would
    be /(?<=\Ka)/g matching "aaa".
      * first attempt, start_offset=0: ovector[0]=0, ovector[1]=1
      * second attempt, start_offset=1: ovector[0]=0, ovector[1]=1

    You can see that even though we *always* ensure that start_offset advances,
    this doesn't guarantee to avoid duplicate matches.

    The pcre2test behaviour is to return all the matches found, except in the
    case where two adjacent matches are an exact duplicate. */

    if (gmatched > 0 &&
        !(dat_datctl.offset <= ovector[0] && ovector[0] <= ovector[1]) &&
        pp + ovector[0] == ovecsave[0] && pp + ovector[1] == ovecsave[1])
      {
      cfprintf(clr_api_error, outfile, "global repeat returned the same match as previous\n");
      goto NEXT_MATCH;
      }

    /* Outside of this exceptional case, we check that either we have a
    "badly-behaved" match (note that not all badly-behaved matches are caught
    above, only *duplicate* ones); or else in the well-behaved case the match
    must make progress.

    "Progress" is measured as ovector[1] strictly advancing, or, an empty match
    after a non-empty match. */

    if (gmatched > 0 &&
        (dat_datctl.offset <= ovector[0] && ovector[0] <= ovector[1]) &&
        !(pp + ovector[1] > ovecsave[1] ||
          (ovector[1] == ovector[0] && ovecsave[1] != ovecsave[0] &&
           pp + ovector[1] == ovecsave[1])))
      {
      cfprintf(clr_test_error, outfile,
        "** PCRE2 error: global repeat did not make progress\n");
      return PR_ABEND;
      }

    ovecsave[0] = pp + ovector[0];
    ovecsave[1] = pp + ovector[1];

    /* "allcaptures" requests showing of all captures in the pattern, to check
    unset ones at the end. It may be set on the pattern or the data. Implement
    by setting capcount to the maximum. This is not relevant for DFA matching,
    so ignore it (warning given above). */

    if ((dat_datctl.control & (CTL_ALLCAPTURES|CTL_DFA)) == CTL_ALLCAPTURES)
      {
      capcount = maxcapcount + 1;   /* Allow for full match */
      if ((unsigned)capcount > oveccount) capcount = oveccount;
      }

    /* "allvector" request showing the entire ovector. */

    if ((dat_datctl.control2 & CTL2_ALLVECTOR) != 0) capcount = oveccount;

    /* Output the captured substrings. Note that, for the matched string,
    the use of \K in an assertion can make the start later than the end. */

    for (int i = 0; i < 2*capcount; i += 2)
      {
      PCRE2_SIZE lleft, lmiddle, lright;
      PCRE2_SIZE start = ovector[i];
      PCRE2_SIZE end = ovector[i+1];

      if (start > end)
        {
        start = ovector[i+1];
        end = ovector[i];
        cfprintf(clr_api_error, outfile, "Start of matched string is beyond its end - "
          "displaying from end to start.\n");
        }

      fprintf(outfile, "%2d: ", i/2);

      /* Check for an unset group */

      if (start == PCRE2_UNSET && end == PCRE2_UNSET)
        {
        fprintf(outfile, "<unset>\n");
        continue;
        }

      /* Check for silly offsets, in particular, values that have not been
      set when they should have been. However, if we are past the end of the
      captures for this pattern ("allvector" causes this), or if we are DFA
      matching, it isn't an error if the entry is unchanged. */

      if (start > ulen || end > ulen)
        {
        if (((dat_datctl.control & CTL_DFA) != 0 ||
              i >= (int)(2*maxcapcount + 2)) &&
            start == JUNK_OFFSET && end == JUNK_OFFSET)
          fprintf(outfile, "<unchanged>\n");
        else
          cfprintf(clr_test_error, outfile, "** ERROR: bad value(s) for offset(s): 0x%lx 0x%lx\n",
            (unsigned long int)start, (unsigned long int)end);
        continue;
        }

      /* When JIT is not being used, ALLUSEDTEXT may be set. (It if is set with
      JIT, it is disabled above, with a comment.) When the match is done by the
      interpreter, leftchar and rightchar are available, and if ALLUSEDTEXT is
      set, and if the leftmost consulted character is before the start of the
      match or the rightmost consulted character is past the end of the match,
      we want to show all consulted characters for the main matched string, and
      indicate which were lookarounds. */

      if (i == 0)
        {
        BOOL showallused;
        PCRE2_SIZE leftchar, rightchar;

        if ((dat_datctl.control & CTL_ALLUSEDTEXT) != 0)
          {
          leftchar = match_data->leftchar;
          rightchar = match_data->rightchar;
          showallused = i == 0 && (leftchar < start || rightchar > end);
          }
        else showallused = FALSE;

        if (showallused)
          {
          lleft = pchars(clr_none, pp + leftchar, start - leftchar, utf, outfile);
          lmiddle = pchars(clr_none, pp + start, end - start, utf, outfile);
          lright = pchars(clr_none, pp + end, rightchar - end, utf, outfile);
          if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_was_used)
            fprintf(outfile, " (JIT)");
          fprintf(outfile, "\n    ");
          for (j = 0; j < lleft; j++) fprintf(outfile, "<");
          for (j = 0; j < lmiddle; j++) fprintf(outfile, " ");
          for (j = 0; j < lright; j++) fprintf(outfile, ">");
          }

        /* When a pattern contains \K, the start of match position may be
        different to the start of the matched string. When this is the case,
        show it when requested. */

        else if ((dat_datctl.control & CTL_STARTCHAR) != 0)
          {
          PCRE2_SIZE startchar;
          startchar = pcre2_get_startchar(match_data);
          lleft = pchars(clr_none, pp + startchar, start - startchar, utf, outfile);
          pchars(clr_none, pp+start, end - start, utf, outfile);
          if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_was_used)
            fprintf(outfile, " (JIT)");
          if (startchar != start)
            {
            fprintf(outfile, "\n    ");
            for (j = 0; j < lleft; j++) fprintf(outfile, "^");
            }
          }

        /* Otherwise, just show the matched string. */

        else
          {
          pchars(clr_none, pp + start, end - start, utf, outfile);
          if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_was_used)
            fprintf(outfile, " (JIT)");
          }
        }

      /* Not the main matched string. Just show it unadorned. */

      else
        {
        pchars(clr_none, pp + start, end - start, utf, outfile);
        }

      fprintf(outfile, "\n");

      /* Note: don't use the start/end variables here because we want to
      show the text from what is reported as the end. */

      if ((dat_datctl.control & CTL_ALLAFTERTEXT) != 0 ||
          (i == 0 && (dat_datctl.control & CTL_AFTERTEXT) != 0))
        {
        fprintf(outfile, "%2d+ ", i/2);
        pchars(clr_none, pp + ovector[i+1], ulen - ovector[i+1], utf, outfile);
        fprintf(outfile, "\n");
        }
      }

    /* Output (*MARK) data if requested */

    if ((dat_datctl.control & CTL_MARK) != 0 &&
         match_data->mark != NULL)
      {
      fprintf(outfile, "MK: ");
      pchars(clr_none, match_data->mark - 1, -1, utf, outfile);
      fprintf(outfile, "\n");
      }

    /* Process copy/get strings */

    if (!copy_and_get(utf, capcount)) return PR_ABEND;

    }    /* End of handling a successful match */

  /* There was a partial match. The value of ovector[0] is the bumpalong point,
  that is, startchar, not any \K point that might have been passed. When JIT is
  not in use, "allusedtext" may be set, in which case we indicate the leftmost
  consulted character. */

  else if (capcount == PCRE2_ERROR_PARTIAL)
    {
    PCRE2_SIZE leftchar;
    int backlength;
    int rubriclength = 0;

    if ((dat_datctl.control & CTL_ALLUSEDTEXT) != 0)
      {
      leftchar = match_data->leftchar;
      }
    else leftchar = ovector[0];

    cfprintf(clr_api_error, outfile, "Partial match");
    if ((dat_datctl.control & CTL_MARK) != 0 &&
         match_data->mark != NULL)
      {
      fprintf(outfile, ", mark=");
      rubriclength = pchars(clr_none, match_data->mark - 1, -1, utf, outfile);
      rubriclength += 7;
      }
    fprintf(outfile, ": ");
    rubriclength += 15;

    backlength = pchars(clr_input, pp + leftchar, ovector[0] - leftchar, utf, outfile);
    pchars(clr_input, pp + ovector[0], ovector[1] - ovector[0], utf, outfile);

    if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_was_used)
      fprintf(outfile, " (JIT)");
    fprintf(outfile, "\n");

    if (backlength != 0)
      {
      for (int i = 0; i < rubriclength; i++) fprintf(outfile, " ");
      for (int i = 0; i < backlength; i++) fprintf(outfile, "<");
      fprintf(outfile, "\n");
      }

    if (ulen != ovector[1])
      cfprintf(clr_test_error, outfile, "** ovector[1] is not equal to the subject length: "
        "%ld != %ld\n", (unsigned long int)ovector[1], (unsigned long int)ulen);

    /* Process copy/get strings */

    if (!copy_and_get(utf, 1)) return PR_ABEND;

    /* "allvector" outputs the entire vector */

    if ((dat_datctl.control2 & CTL2_ALLVECTOR) != 0)
      show_ovector(ovector, oveccount);

    break;  /* Out of the /g loop */
    }       /* End of handling partial match */

  /* A "normal" match failure. There will be a negative error number in
  capcount. */

  else
    {
    switch(capcount)
      {
      case PCRE2_ERROR_NOMATCH:
      if (gmatched == 0)
        {
        cfprintf(clr_api_error, outfile, "No match");
        if ((dat_datctl.control & CTL_MARK) != 0 &&
             match_data->mark != NULL)
          {
          fprintf(outfile, ", mark = ");
          pchars(clr_none, match_data->mark - 1, -1, utf, outfile);
          }
        if ((pat_patctl.control & CTL_JITVERIFY) != 0 && jit_was_used)
          fprintf(outfile, " (JIT)");
        fprintf(outfile, "\n");

        /* "allvector" outputs the entire vector */

        if ((dat_datctl.control2 & CTL2_ALLVECTOR) != 0)
          show_ovector(ovector, oveccount);
        }
      break;

      case PCRE2_ERROR_BADUTFOFFSET:
      cfprintf(clr_api_error, outfile, "Error %d (bad UTF-" STR(PCRE2_CODE_UNIT_WIDTH)
        " offset)\n", capcount);
      break;

      default:
      cfprintf(clr_api_error, outfile, "Failed: error %d: ", capcount);
      if (!print_error_message(capcount, "", "")) return PR_ABEND;
      if (capcount <= PCRE2_ERROR_UTF8_ERR1 &&
          capcount >= PCRE2_ERROR_UTF32_ERR2)
        {
        PCRE2_SIZE startchar;
        startchar = pcre2_get_startchar(match_data);
        cfprintf(clr_api_error, outfile, " at offset %" SIZ_FORM, startchar);
        }
      fprintf(outfile, "\n");
      break;
      }

    break;  /* Out of the /g loop */
    }       /* End of failed match handling */

  /* Control reaches here after a match. If we are not doing a global search,
  we are done. Otherwise, we adjust the parameters for the next match and
  continue the matching loop. */

  NEXT_MATCH:

  if ((dat_datctl.control & CTL_ANYGLOB) == 0)
    break;
  else
    {
    PCRE2_SIZE new_start_offset = (PCRE2_SIZE)-1;
    BOOL rc_nextmatch;

    /* Use pcre2_next_match() to safely advance. This guarantees that the start
    offset will advance, except after an empty match, in which case it sets
    the PCRE2_NOTEMPTY_ATSTART flag to ensure the next match does not return a
    duplicate. */

    rc_nextmatch = pcre2_next_match(match_data, &new_start_offset, &g_notempty);
    if (!rc_nextmatch) break;  /* Out of the /g loop */

    /* For a normal global (/g) iteration, update the start offset, leaving
    other parameters alone. */

    if ((dat_datctl.control & CTL_GLOBAL) != 0)
      {
      dat_datctl.offset = new_start_offset;
      }

    /* For altglobal, just update the pointer and length. */

    else
      {
      pp += new_start_offset;
      len -= CU2BYTES(new_start_offset);
      ulen -= new_start_offset;
      if (arg_ulen != PCRE2_ZERO_TERMINATED) arg_ulen -= new_start_offset;
      }
    }
  }  /* End of global loop */

/* All matching is done; show the resulting heapframe size if requested. */

if ((dat_datctl.control2 & CTL2_HEAPFRAMES_SIZE) != 0 &&
    (dat_datctl.control & CTL_DFA) == 0)
  show_heapframes_size();

show_memory = FALSE;
return PR_OK;
}



/*************************************************
*      Initialise the mode-dependent globals     *
*************************************************/

/* Sets up the global variables used for the current test mode. */

static void
init_globals(void)
{
general_context = pcre2_general_context_create(&my_malloc, &my_free, NULL);
general_context_copy = pcre2_general_context_copy(general_context);
default_pat_context = pcre2_compile_context_create(general_context);
pat_context = pcre2_compile_context_copy(default_pat_context);
default_dat_context = pcre2_match_context_create(general_context);
dat_context = pcre2_match_context_copy(default_dat_context);
default_con_context = pcre2_convert_context_create(general_context);
con_context = pcre2_convert_context_copy(default_con_context);
match_data = pcre2_match_data_create(max_oveccount, general_context);
rep_in_buffer = malloc(sizeof(PCRE2_UCHAR) * rep_in_buffer_size);
rep_out_buffer = malloc(sizeof(PCRE2_UCHAR) * rep_out_buffer_size);

/* Set a default parentheses nest limit that is large enough to run the
standard tests (this also exercises the function). */

pcre2_set_parens_nest_limit(default_pat_context, PARENS_NEST_DEFAULT);
}

/* Frees the global variables used for the current test mode. */

static void
free_globals(void)
{
pcre2_maketables_free(general_context, locale_tables);
pcre2_match_data_free(match_data);
pcre2_code_free(compiled_code);

while(patstacknext-- > 0)
  {
  compiled_code = patstack[patstacknext];
  pcre2_code_free(compiled_code);
  }

pcre2_jit_free_unused_memory(general_context);
if (jit_stack != NULL)
  {
  pcre2_jit_stack_free(jit_stack);
  }

pcre2_general_context_free(general_context);
pcre2_general_context_free(general_context_copy);
pcre2_compile_context_free(pat_context);
pcre2_compile_context_free(default_pat_context);
pcre2_match_context_free(dat_context);
pcre2_match_context_free(default_dat_context);
pcre2_convert_context_free(default_con_context);
pcre2_convert_context_free(con_context);
free(rep_in_buffer);
free(rep_out_buffer);
}



/*************************************************
*            Specific function tests             *
*************************************************/

/* For tests exercising a mismatched bitmode, identify a suitable API. */

#if (defined(SUPPORT_PCRE2_8) + defined(SUPPORT_PCRE2_16) + \
     defined(SUPPORT_PCRE2_32)) >= 2

#if defined(SUPPORT_PCRE2_8) && PCRE2_CODE_UNIT_WIDTH != 8
#define BITOTHER 8
#elif defined(SUPPORT_PCRE2_16) && PCRE2_CODE_UNIT_WIDTH != 16
#define BITOTHER 16
#elif defined(SUPPORT_PCRE2_32) && PCRE2_CODE_UNIT_WIDTH != 32
#define BITOTHER 32
#else
#error "One other bit width must be supported"
#endif

#endif

/* These are tests of the public API functions in PCRE2, which wouldn't
otherwise be covered by pcre2test. This usually implies they are error cases,
or edge cases that are hard to hit in the standard flow of compile-match or
compile-substitute.

I think of them as perhaps more like unit tests, although they are still testing
the public API, rather than internal modules.

Inside pcre2test, which can be dynamically linked to lib-pcreX.so, we don't
have access to any non-exported functions. */

static void
unittest(void)
{
int rc;
uint32_t uval;
PCRE2_SIZE sizeval;
PCRE2_UCHAR *sptrval;
const char *failure = NULL;
pcre2_general_context *test_gen_context = NULL, *test_gen_context_copy = NULL;
pcre2_compile_context *test_pat_context = NULL, *test_pat_context_copy = NULL;
pcre2_match_context *test_dat_context = NULL, *test_dat_context_copy = NULL;
pcre2_convert_context *test_con_context = NULL, *test_con_context_copy = NULL;
pcre2_match_data *test_match_data = NULL;
pcre2_code *test_compiled_code = NULL;
PCRE2_UCHAR pattern[] = { CHAR_A, CHAR_B, CHAR_C, 0 };
PCRE2_UCHAR callout_int_pattern[] = {
  CHAR_LEFT_PARENTHESIS, CHAR_QUESTION_MARK, CHAR_C, CHAR_RIGHT_PARENTHESIS, 0 };
PCRE2_UCHAR callout_str_pattern[] = {
  CHAR_LEFT_PARENTHESIS, CHAR_QUESTION_MARK, CHAR_C, CHAR_QUOTATION_MARK,
  CHAR_Z, CHAR_QUOTATION_MARK, CHAR_RIGHT_PARENTHESIS, 0 };
PCRE2_UCHAR capture_pattern[] = {
  CHAR_A, CHAR_LEFT_PARENTHESIS, CHAR_QUESTION_MARK, CHAR_LESS_THAN_SIGN,
  CHAR_N, CHAR_GREATER_THAN_SIGN, CHAR_DOT, CHAR_ASTERISK,
  CHAR_RIGHT_PARENTHESIS, CHAR_Z, 0 };
PCRE2_UCHAR subject_abcz[] = {
  CHAR_A, CHAR_B, CHAR_C, CHAR_Z, 0 };
PCRE2_UCHAR substitute_subject[6];
PCRE2_UCHAR name_n[] = { CHAR_N, 0 };
#ifdef BITOTHER
G(pcre2_code_,BITOTHER) *bitother_code = NULL;
G(PCRE2_,G(UCHAR,BITOTHER)) bitother_pattern[] = { CHAR_A, CHAR_B, CHAR_C, 0 };
#endif
int errorcode;
PCRE2_SIZE erroroffset;
PCRE2_UCHAR errorbuffer[256];
#if PCRE2_CODE_UNIT_WIDTH == 8
char errorbuffer8[256];
regex_t test_preg;
#endif
void *invalid_code = NULL;
const uint8_t *test_tables = NULL;
PCRE2_UCHAR copy_buf[64];
PCRE2_UCHAR **stringlist;
PCRE2_SIZE *lengthslist;
PCRE2_UCHAR replace_buf[64];
pcre2_code *subs_other_code = NULL;

#if PCRE2_CODE_UNIT_WIDTH == 8
memset(&test_preg, 0, sizeof(test_preg));
#endif

#if defined PCRE2_DEBUG && !defined NDEBUG
#define ASSERT(cond, msg) \
  do { \
    if (!(cond)) { failure = msg " at " __FILE__ ":" STR(__LINE__); goto EXIT; } \
  } while (0)
#else
#define ASSERT(cond, msg) \
  do { \
    if (!(cond)) { failure = msg; goto EXIT; } \
  } while (0)
#endif

/* -------------------------- pcre2_config --------------------------------- */

rc = pcre2_config(PCRE2_CONFIG_BSR, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_COMPILED_WIDTHS, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_DEPTHLIMIT, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_EFFECTIVE_LINKSIZE, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_HEAPLIMIT, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_JIT, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_LINKSIZE, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_MATCHLIMIT, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_NEVER_BACKSLASH_C, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_NEWLINE, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_PARENSLIMIT, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_STACKRECURSE, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_TABLES_LENGTH, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_UNICODE, NULL);
ASSERT(rc == (int)sizeof(uint32_t), "pcre2_config(NULL)");

#ifdef SUPPORT_JIT
rc = pcre2_config(PCRE2_CONFIG_JITTARGET, NULL);
ASSERT(rc > 0, "pcre2_config(NULL)");
#endif
rc = pcre2_config(PCRE2_CONFIG_UNICODE_VERSION, NULL);
ASSERT(rc > 4, "pcre2_config(NULL)");
rc = pcre2_config(PCRE2_CONFIG_VERSION, NULL);
ASSERT(rc > 4, "pcre2_config(NULL)");

rc = pcre2_config(PCRE2_CONFIG_MATCHLIMIT, &uval);
ASSERT(rc == 0, "pcre2_config(PCRE2_CONFIG_MATCHLIMIT)");

rc = pcre2_config(999, NULL);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_config(bad option)");

rc = pcre2_config(999, &uval);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_config(bad option)");

rc = pcre2_config(PCRE2_CONFIG_STACKRECURSE, &uval);
ASSERT(rc == 0, "pcre2_config(PCRE2_CONFIG_STACKRECURSE)");

rc = pcre2_config(PCRE2_CONFIG_LINKSIZE, &uval);
ASSERT(rc == 0, "pcre2_config(PCRE2_CONFIG_LINKSIZE)");

/* ------------------------ Context functions ------------------------------ */

test_gen_context = pcre2_general_context_create(NULL, NULL, NULL);
ASSERT(test_gen_context != NULL, "pcre2_general_context_create(null)");
pcre2_general_context_free(test_gen_context);

mallocs_until_failure = 0;
test_gen_context = pcre2_general_context_create(&my_malloc, &my_free, NULL);
ASSERT(test_gen_context == NULL, "pcre2_general_context_create(malloc)");

mallocs_until_failure = 1;
test_gen_context = pcre2_general_context_create(&my_malloc, &my_free, NULL);
ASSERT(test_gen_context != NULL, "pcre2_general_context_create(malloc)");

test_pat_context = pcre2_compile_context_create(test_gen_context);
ASSERT(test_pat_context == NULL, "pcre2_compile_context_create()");
test_dat_context = pcre2_match_context_create(test_gen_context);
ASSERT(test_dat_context == NULL, "pcre2_match_context_create()");
test_con_context = pcre2_convert_context_create(test_gen_context);
ASSERT(test_con_context == NULL, "pcre2_convert_context_create()");

test_pat_context = pcre2_compile_context_create(NULL);
ASSERT(test_pat_context != NULL, "pcre2_compile_context_create(null)");
pcre2_compile_context_free(test_pat_context);
test_dat_context = pcre2_match_context_create(NULL);
ASSERT(test_dat_context != NULL, "pcre2_match_context_create(null)");
pcre2_match_context_free(test_dat_context);
test_con_context = pcre2_convert_context_create(NULL);
ASSERT(test_con_context != NULL, "pcre2_convert_context_create(null)");
pcre2_convert_context_free(test_con_context);

mallocs_until_failure = INT_MAX;
test_pat_context = pcre2_compile_context_create(test_gen_context);
ASSERT(test_pat_context != NULL, "pcre2_compile_context_create()");
test_dat_context = pcre2_match_context_create(test_gen_context);
ASSERT(test_dat_context != NULL, "pcre2_match_context_create()");
test_con_context = pcre2_convert_context_create(test_gen_context);
ASSERT(test_con_context != NULL, "pcre2_convert_context_create()");

mallocs_until_failure = 0;
test_gen_context_copy = pcre2_general_context_copy(test_gen_context);
ASSERT(test_gen_context_copy == NULL, "pcre2_general_context_copy()");
test_pat_context_copy = pcre2_compile_context_copy(test_pat_context);
ASSERT(test_pat_context_copy == NULL, "pcre2_compile_context_copy()");
test_dat_context_copy = pcre2_match_context_copy(test_dat_context);
ASSERT(test_dat_context_copy == NULL, "pcre2_match_context_copy()");
test_con_context_copy = pcre2_convert_context_copy(test_con_context);
ASSERT(test_con_context_copy == NULL, "pcre2_convert_context_copy()");

mallocs_until_failure = INT_MAX;
test_gen_context_copy = pcre2_general_context_copy(test_gen_context);
ASSERT(test_gen_context_copy != NULL, "pcre2_general_context_copy()");
test_pat_context_copy = pcre2_compile_context_copy(test_pat_context);
ASSERT(test_pat_context_copy != NULL, "pcre2_compile_context_copy()");
test_dat_context_copy = pcre2_match_context_copy(test_dat_context);
ASSERT(test_dat_context_copy != NULL, "pcre2_match_context_copy()");
test_con_context_copy = pcre2_convert_context_copy(test_con_context);
ASSERT(test_con_context_copy != NULL, "pcre2_convert_context_copy()");

rc = pcre2_set_compile_extra_options(test_pat_context, 0);
ASSERT(rc == 0, "pcre2_set_compile_extra_options()");

rc = pcre2_set_max_pattern_length(test_pat_context, 10);
ASSERT(rc == 0, "pcre2_set_max_pattern_length()");

rc = pcre2_set_max_pattern_compiled_length(test_pat_context, 256);
ASSERT(rc == 0, "pcre2_set_max_pattern_compiled_length()");

rc = pcre2_set_max_varlookbehind(test_pat_context, 0);
ASSERT(rc == 0, "pcre2_set_max_varlookbehind()");

rc = pcre2_set_offset_limit(test_dat_context, 0);
ASSERT(rc == 0, "pcre2_set_offset_limit()");

rc = pcre2_set_bsr(test_pat_context, 999);
ASSERT(rc == PCRE2_ERROR_BADDATA, "pcre2_set_bsr()");

rc = pcre2_set_newline(test_pat_context, 999);
ASSERT(rc == PCRE2_ERROR_BADDATA, "pcre2_set_newline()");

rc = pcre2_set_recursion_limit(test_dat_context, 10);
ASSERT(rc == 0, "pcre2_set_recursion_limit()");

rc = pcre2_set_recursion_memory_management(test_dat_context, NULL, NULL, NULL);
ASSERT(rc == 0, "pcre2_set_recursion_memory_management()");

rc = pcre2_set_optimize(NULL, PCRE2_OPTIMIZATION_NONE);
ASSERT(rc == PCRE2_ERROR_NULL, "pcre2_set_optimize(null)");

rc = pcre2_set_optimize(test_pat_context, PCRE2_AUTO_POSSESS - 1);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_set_optimize(bad option)");

rc = pcre2_set_optimize(test_pat_context, PCRE2_START_OPTIMIZE_OFF + 1);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_set_optimize(bad option)");

rc = pcre2_set_glob_escape(test_con_context, 0);
ASSERT(rc == 0, "pcre2_set_glob_escape(0)");

rc = pcre2_set_glob_escape(test_con_context, 1);
ASSERT(rc == PCRE2_ERROR_BADDATA, "pcre2_set_glob_escape(1)");

rc = pcre2_set_glob_escape(test_con_context, 256);
ASSERT(rc == PCRE2_ERROR_BADDATA, "pcre2_set_glob_escape(256)");

/* ----------------------- pcre2_compile ----------------------------------- */

test_compiled_code = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
  0, NULL, &erroroffset, test_pat_context);
ASSERT(test_compiled_code == NULL, "test pattern compilation");

test_compiled_code = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, NULL, test_pat_context);
ASSERT(test_compiled_code == NULL && errorcode == PCRE2_ERROR_NULL_ERROROFFSET, "test pattern compilation");

test_compiled_code = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, test_pat_context);
ASSERT(test_compiled_code != NULL && errorcode == 100 && erroroffset == 0, "test pattern compilation");

#ifdef BITOTHER
bitother_code = G(pcre2_compile_,BITOTHER)(bitother_pattern,
  PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroroffset, NULL);
ASSERT(bitother_code != NULL, "bitmode mismatch compile");
#endif

/* ---------------------- Match data functions ----------------------------- */

mallocs_until_failure = 0;
test_match_data = pcre2_match_data_create(10, test_gen_context);
ASSERT(test_match_data == NULL, "pcre2_match_data_create()");

test_match_data = pcre2_match_data_create(10, NULL);
ASSERT(test_match_data != NULL, "pcre2_match_data_create()");
ASSERT(pcre2_get_ovector_count(test_match_data) == 10, "pcre2_get_ovector_count()");

sizeval = pcre2_get_match_data_size(test_match_data);
ASSERT(sizeval >= 2, "pcre2_get_match_data_size()");

mallocs_until_failure = INT_MAX;

pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create(0, test_gen_context);
ASSERT(test_match_data != NULL, "pcre2_match_data_create()");
ASSERT(pcre2_get_ovector_count(test_match_data) == 1, "pcre2_get_ovector_count()");

pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create_from_pattern(NULL, NULL);
ASSERT(test_match_data == NULL, "pcre2_match_data_create_from_pattern(null)");

test_match_data = pcre2_match_data_create_from_pattern(test_compiled_code, NULL);
ASSERT(test_match_data != NULL, "pcre2_match_data_create_from_pattern()");
ASSERT(pcre2_get_ovector_count(test_match_data) == 1, "pcre2_get_ovector_count()");

mallocs_until_failure = 0;
pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create_from_pattern(test_compiled_code,
  test_gen_context);
ASSERT(test_match_data == NULL, "pcre2_match_data_create_from_pattern()");

mallocs_until_failure = INT_MAX;
pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create_from_pattern(test_compiled_code,
  test_gen_context);
ASSERT(test_match_data != NULL, "pcre2_match_data_create_from_pattern()");

rc = pcre2_match(test_compiled_code, pattern, PCRE2_ZERO_TERMINATED, 0,
  PCRE2_COPY_MATCHED_SUBJECT, test_match_data, NULL);
ASSERT(rc == 1, "pcre2_match()");

pcre2_match_data_free(test_match_data);
test_match_data = NULL;

/* ----------------------- pcre2_pattern_info ------------------------------ */

rc = pcre2_pattern_info(NULL, PCRE2_INFO_NEWLINE, &uval);
ASSERT(rc == PCRE2_ERROR_NULL, "pcre2_pattern_info(null)");

rc = pcre2_pattern_info(test_compiled_code, 999, NULL);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_pattern_info(bad option)");

rc = pcre2_pattern_info(test_compiled_code, 999, &uval);
ASSERT(rc == PCRE2_ERROR_BADOPTION, "pcre2_pattern_info(bad option)");

invalid_code = malloc(1024);
ASSERT(invalid_code != NULL, "malloc()");
memset(invalid_code, 0, 1024);
rc = pcre2_pattern_info(invalid_code, PCRE2_INFO_NEWLINE, &uval);
ASSERT(rc == PCRE2_ERROR_BADMAGIC, "pcre2_pattern_info(bad magic)");

#ifdef BITOTHER
rc = pcre2_pattern_info((pcre2_code *)bitother_code, PCRE2_INFO_NEWLINE, &uval);
ASSERT(rc == PCRE2_ERROR_BADMODE, "pcre2_pattern_info(bitmode mismatch)");
#endif

#ifdef SUPPORT_JIT
sizeval = 0xcdcdcdcd;
rc = pcre2_pattern_info(test_compiled_code, PCRE2_INFO_JITSIZE, &sizeval);
ASSERT(rc == 0 && sizeval == 0, "pcre2_pattern_info(JIT)");

if (pcre2_jit_compile(test_compiled_code, PCRE2_JIT_COMPLETE) == 0)
  {
  rc = pcre2_pattern_info(test_compiled_code, PCRE2_INFO_JITSIZE, &sizeval);
  ASSERT(rc == 0 && sizeval > 0, "pcre2_pattern_info(JIT after compile)");
  }
#endif

/* ----------------------- POSIX functions --------------------------------- */

#if PCRE2_CODE_UNIT_WIDTH == 8

#if defined(EBCDIC) && !EBCDIC_IO
#define BUFFER_OUTPUT ebcdic_to_ascii_str((uint8_t *)errorbuffer8, sizeof(errorbuffer8));
#else
#define BUFFER_OUTPUT
#endif

rc = pcre2_regcomp(&test_preg, "abc", 0);
ASSERT(rc == 0, "pcre2_regcomp()");

rc = pcre2_regexec(&test_preg, "zabcz", 0, NULL, 0);
ASSERT(rc == 0, "pcre2_regexec(0)");

rc = pcre2_regexec(&test_preg, "zabcz", 0, NULL, REG_STARTEND);
ASSERT(rc == REG_INVARG, "pcre2_regexec(REG_STARTEND)");

memset(errorbuffer8, 0, sizeof(errorbuffer8));
rc = regerror(REG_ASSERT, NULL, errorbuffer8, sizeof(errorbuffer8));
BUFFER_OUTPUT
ASSERT(rc > 0 && rc <= (int)sizeof(errorbuffer8) && rc == (int)strlen(errorbuffer8) + 1, "regerror()");

rc = regerror(REG_NOMATCH, NULL, errorbuffer8, sizeof(errorbuffer8));
BUFFER_OUTPUT
ASSERT(rc > 0 && rc <= (int)sizeof(errorbuffer8) && rc == (int)strlen(errorbuffer8) + 1, "regerror()");

rc = regerror(REG_ASSERT-1, NULL, errorbuffer8, sizeof(errorbuffer8));
BUFFER_OUTPUT
ASSERT(rc == (int)strlen("unknown error code")+1 && strcmp(errorbuffer8, "unknown error code") == 0, "regerror(bad error code)");

rc = regerror(REG_NOMATCH+1, NULL, errorbuffer8, sizeof(errorbuffer8));
BUFFER_OUTPUT
ASSERT(rc == (int)strlen("unknown error code")+1 && strcmp(errorbuffer8, "unknown error code") == 0, "regerror(bad error code)");

#undef BUFFER_OUTPUT

#endif

/* -------------------- pcre2_get_error_message ---------------------------- */

#if defined(EBCDIC) && !EBCDIC_IO
#define BUFFER_OUTPUT ebcdic_to_ascii_str(errorbuffer, sizeof(errorbuffer));
#else
#define BUFFER_OUTPUT
#endif

rc = pcre2_get_error_message(PCRE2_ERROR_BADDATA, NULL, 0);
ASSERT(rc == PCRE2_ERROR_NOMEMORY, "pcre2_get_error_message(null)");

memset(errorbuffer, 0, sizeof(errorbuffer));
rc = pcre2_get_error_message(PCRE2_ERROR_BADDATA, errorbuffer, 0);
BUFFER_OUTPUT
ASSERT(rc == PCRE2_ERROR_NOMEMORY, "pcre2_get_error_message(null)");

rc = pcre2_get_error_message(PCRE2_ERROR_BADDATA, errorbuffer, 4);
BUFFER_OUTPUT
ASSERT(rc == PCRE2_ERROR_NOMEMORY && pcre2_strcmp_c8(errorbuffer, "bad") == 0, "pcre2_get_error_message(null)");

rc = pcre2_get_error_message(PCRE2_ERROR_BADDATA, errorbuffer, 14);
BUFFER_OUTPUT
ASSERT(rc == PCRE2_ERROR_NOMEMORY && pcre2_strcmp_c8(errorbuffer, "bad data valu") == 0, "pcre2_get_error_message(null)");

rc = pcre2_get_error_message(PCRE2_ERROR_BADDATA, errorbuffer, 15);
BUFFER_OUTPUT
ASSERT(rc == 14 && pcre2_strcmp_c8(errorbuffer, "bad data value") == 0, "pcre2_get_error_message(null)");

#undef BUFFER_OUTPUT

/* ----------------------- pcre2_maketables -------------------------------- */

test_tables = pcre2_maketables(NULL);
ASSERT(test_tables != NULL, "pcre2_maketables(null)");
pcre2_maketables_free(NULL, test_tables);

test_tables = pcre2_maketables(test_gen_context);
ASSERT(test_tables != NULL, "pcre2_maketables()");
pcre2_maketables_free(test_gen_context, test_tables);

mallocs_until_failure = 0;
test_tables = pcre2_maketables(test_gen_context);
ASSERT(test_tables == NULL, "pcre2_maketables()");

mallocs_until_failure = INT_MAX;

/* -------------------- pcre2_callout_enumerate ---------------------------- */

rc = pcre2_callout_enumerate(NULL, callout_enumerate_function_void, NULL);
ASSERT(rc == PCRE2_ERROR_NULL, "pcre2_callout_enumerate(null)");

rc = pcre2_callout_enumerate(invalid_code, callout_enumerate_function_void, NULL);
ASSERT(rc == PCRE2_ERROR_BADMAGIC, "pcre2_callout_enumerate(invalid)");

#ifdef BITOTHER
rc = pcre2_callout_enumerate((pcre2_code *)bitother_code, callout_enumerate_function_void, NULL);
ASSERT(rc == PCRE2_ERROR_BADMODE, "pcre2_callout_enumerate(bitmode mismatch)");
#endif

pcre2_code_free(test_compiled_code);
test_compiled_code = pcre2_compile(callout_int_pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, NULL);
ASSERT(test_compiled_code != NULL, "test pattern compilation");

rc = pcre2_callout_enumerate(test_compiled_code, callout_enumerate_function_void, &errorcode);
ASSERT(rc == 0, "pcre2_callout_enumerate(void)");

errorcode = -12;
rc = pcre2_callout_enumerate(test_compiled_code, callout_enumerate_function_fail, &errorcode);
ASSERT(rc == -12, "pcre2_callout_enumerate(fail)");

pcre2_code_free(test_compiled_code);
test_compiled_code = pcre2_compile(callout_str_pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, NULL);
ASSERT(test_compiled_code != NULL, "test pattern compilation");

errorcode = -123;
rc = pcre2_callout_enumerate(test_compiled_code, callout_enumerate_function_fail, &errorcode);
ASSERT(rc == -123, "pcre2_callout_enumerate(fail)");

/* ---------------------- Substring functions ------------------------------ */

/* Must handle NULL without crashing. */
pcre2_substring_free(NULL);
pcre2_substring_list_free(NULL);

pcre2_code_free(test_compiled_code);
test_compiled_code = pcre2_compile(capture_pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, NULL);
ASSERT(test_compiled_code != NULL, "test pattern compilation");

pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create_from_pattern(
  test_compiled_code, test_gen_context);
ASSERT(test_match_data != NULL, "pcre2_match_data_create()");

rc = pcre2_match(test_compiled_code, subject_abcz, PCRE2_ZERO_TERMINATED, 0,
  0, test_match_data, NULL);
ASSERT(rc == 2, "pcre2_match()");

/* Test the functions with insufficient buffer size. It hardly seems worth
adding controls to the pcre2test input file format to exercise this case. */

sizeval = 2;
rc = pcre2_substring_copy_byname(test_match_data, name_n, copy_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMEMORY && sizeval == 2, "pcre2_substring_copy_byname(small buffer)");
sizeval = 3;
rc = pcre2_substring_copy_byname(test_match_data, name_n, copy_buf, &sizeval);
ASSERT(rc == 0 && sizeval == 2, "pcre2_substring_copy_byname(small buffer)");
sizeval = 4;
rc = pcre2_substring_copy_byname(test_match_data, name_n, copy_buf, &sizeval);
ASSERT(rc == 0 && sizeval == 2, "pcre2_substring_copy_byname(small buffer)");

sizeval = 2;
rc = pcre2_substring_copy_bynumber(test_match_data, 1, copy_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMEMORY && sizeval == 2, "pcre2_substring_copy_bynumber(small buffer)");
sizeval = 3;
rc = pcre2_substring_copy_bynumber(test_match_data, 1, copy_buf, &sizeval);
ASSERT(rc == 0 && sizeval == 2, "pcre2_substring_copy_bynumber(small buffer)");

mallocs_until_failure = 0;

sizeval = 0;
sptrval = NULL;
rc = pcre2_substring_get_byname(test_match_data, name_n, &sptrval, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMEMORY && sptrval == NULL, "pcre2_substring_get_byname(small buffer)");

sizeval = 0;
rc = pcre2_substring_get_bynumber(test_match_data, 1, &sptrval, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMEMORY && sptrval == NULL, "pcre2_substring_get_bynumber(small buffer)");

mallocs_until_failure = INT_MAX;

/* Test some unusual conditions, for which again it doesn't seem worth adding
pcre2test controls. */

sizeval = 0;
rc = pcre2_substring_length_bynumber(test_match_data, 1, &sizeval);
ASSERT(rc == 0 && sizeval == 2, "pcre2_substring_length_bynumber()");
rc = pcre2_substring_length_bynumber(test_match_data, 1, NULL);
ASSERT(rc == 0, "pcre2_substring_length_bynumber()");

sizeval = 0;
rc = pcre2_substring_length_byname(test_match_data, name_n, &sizeval);
ASSERT(rc == 0 && sizeval == 2, "pcre2_substring_length_byname()");
rc = pcre2_substring_length_byname(test_match_data, name_n, NULL);
ASSERT(rc == 0, "pcre2_substring_length_byname()");

/* Test pcre2_substring_list_get() with some NULL inputs. */

rc = pcre2_substring_list_get(test_match_data, &stringlist, &lengthslist);
ASSERT(rc == 0 && stringlist != NULL && lengthslist != NULL, "pcre2_substring_list_get()");
pcre2_substring_list_free(stringlist);

stringlist = NULL;
rc = pcre2_substring_list_get(test_match_data, &stringlist, NULL);
ASSERT(rc == 0 && stringlist != NULL, "pcre2_substring_list_get()");
pcre2_substring_list_free(stringlist);

mallocs_until_failure = 0;

stringlist = NULL;
rc = pcre2_substring_list_get(test_match_data, &stringlist, &lengthslist);
ASSERT(rc == PCRE2_ERROR_NOMEMORY && stringlist == NULL, "pcre2_substring_list_get()");

mallocs_until_failure = INT_MAX;

/* Test after an unsuccessful match. */

rc = pcre2_match(test_compiled_code, subject_abcz, PCRE2_ZERO_TERMINATED, 2,
  0, test_match_data, NULL);
ASSERT(rc == PCRE2_ERROR_NOMATCH, "pcre2_match()");

sizeval = 4;
rc = pcre2_substring_copy_byname(test_match_data, name_n, copy_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMATCH, "pcre2_substring_copy_byname(no match)");
rc = pcre2_substring_copy_bynumber(test_match_data, 1, copy_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMATCH, "pcre2_substring_copy_bynumber(no match)");
rc = pcre2_substring_get_byname(test_match_data, name_n, &sptrval, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMATCH && sptrval == NULL, "pcre2_substring_get_byname(no match)");
rc = pcre2_substring_get_bynumber(test_match_data, 1, &sptrval, &sizeval);
ASSERT(rc == PCRE2_ERROR_NOMATCH && sptrval == NULL, "pcre2_substring_get_bynumber(no match)");

/* ------------- pcre2_substitute with PCRE2_SUBSTITUTE_MATCHED ------------ */

/* There are some specific edge cases here that would be a pain to exercise via
the standard pcre2test modifiers. The documentation is clear that when you do
a match externally and pass it in with PCRE2_SUBSTITUTE_MATCHED, you must also
pass the same match options. Here we test what happens when you don't. */

pcre2_code_free(test_compiled_code);
test_compiled_code = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, NULL);
ASSERT(test_compiled_code != NULL, "test pattern compilation");

subs_other_code = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
  0, &errorcode, &erroroffset, NULL);
ASSERT(subs_other_code != NULL, "test pattern compilation");

pcre2_match_data_free(test_match_data);
test_match_data = pcre2_match_data_create_from_pattern(
  test_compiled_code, NULL);
ASSERT(test_match_data != NULL, "pcre2_match_data_create()");

memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
rc = pcre2_match(test_compiled_code, substitute_subject, PCRE2_ZERO_TERMINATED,
  0, 0, test_match_data, NULL);
ASSERT(rc == 1, "pcre2_match()");

/* Baseline, should succeed */
memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(test_compiled_code, substitute_subject,
  PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_MATCHED, test_match_data, NULL,
  NULL, 0, replace_buf, &sizeval);
ASSERT(rc == 1, "pcre2_substitute(baseline)");

/* Move the subject pointer, but keep the contents and length the same */
memcpy(substitute_subject+1, subject_abcz, sizeof(subject_abcz));
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(test_compiled_code, substitute_subject+1,
  PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_MATCHED, test_match_data, NULL,
  NULL, 0, replace_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_DIFFSUBSSUBJECT, "pcre2_substitute(moved)");

/* Keep the subject pointer the same but extend its length */
memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
substitute_subject[4] = CHAR_Y;
substitute_subject[5] = 0;
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(test_compiled_code, substitute_subject,
  PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_MATCHED, test_match_data, NULL,
  NULL, 0, replace_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_DIFFSUBSSUBJECT, "pcre2_substitute(extended)");

/* Change the offset */
memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(test_compiled_code, substitute_subject,
  PCRE2_ZERO_TERMINATED, 1, PCRE2_SUBSTITUTE_MATCHED, test_match_data, NULL,
  NULL, 0, replace_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_DIFFSUBSOFFSET, "pcre2_substitute(offset)");

/* Change the options */
memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(test_compiled_code, substitute_subject,
  PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_MATCHED | PCRE2_NOTEMPTY,
  test_match_data, NULL, NULL, 0, replace_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_DIFFSUBSOPTIONS, "pcre2_substitute(options)");

/* Change the pattern */
memcpy(substitute_subject, subject_abcz, sizeof(subject_abcz));
sizeval = sizeof(replace_buf)/sizeof(*replace_buf);
rc = pcre2_substitute(subs_other_code, substitute_subject,
  PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_MATCHED, test_match_data, NULL,
  NULL, 0, replace_buf, &sizeval);
ASSERT(rc == PCRE2_ERROR_DIFFSUBSPATTERN, "pcre2_substitute(pattern)");

/* ------------------------------------------------------------------------- */

#undef ASSERT
EXIT:

mallocs_until_failure = INT_MAX;

#if PCRE2_CODE_UNIT_WIDTH == 8
pcre2_regfree(&test_preg);
#endif

if (test_compiled_code != NULL) pcre2_code_free(test_compiled_code);
#ifdef BITOTHER
if (bitother_code != NULL) G(pcre2_code_free_,BITOTHER)(bitother_code);
#endif
if (subs_other_code != NULL) pcre2_code_free(subs_other_code);

if (test_match_data != NULL) pcre2_match_data_free(test_match_data);

if (test_con_context_copy != NULL) pcre2_convert_context_free(test_con_context_copy);
if (test_dat_context_copy != NULL) pcre2_match_context_free(test_dat_context_copy);
if (test_pat_context_copy != NULL) pcre2_compile_context_free(test_pat_context_copy);
if (test_gen_context_copy != NULL) pcre2_general_context_free(test_gen_context_copy);
if (test_con_context != NULL) pcre2_convert_context_free(test_con_context);
if (test_dat_context != NULL) pcre2_match_context_free(test_dat_context);
if (test_pat_context != NULL) pcre2_compile_context_free(test_pat_context);
if (test_gen_context != NULL) pcre2_general_context_free(test_gen_context);

free(invalid_code);

if (failure != NULL)
  {
  cfprintf(clr_test_error, stderr, "pcre2test: Unit test error in %s\n", failure);
  exit(1);
  }
}

#undef BITOTHER


/* -------------------- Undo the macro definitions --------------------------*/

#undef pbuffer
#undef pbuffer_size

#undef utf_to_ord

#undef compiled_code
#undef general_context
#undef general_context_copy
#undef pat_context
#undef default_pat_context
#undef con_context
#undef default_con_context
#undef dat_context
#undef default_dat_context
#undef match_data
#undef jit_stack
#undef jit_stack_size
#undef patstack
#undef patstacknext
#undef rep_in_buffer
#undef rep_in_buffer_size
#undef rep_out_buffer
#undef rep_out_buffer_size

#undef jit_callback
#undef pcre2_strcmp_c8
#undef pcre2_strlen
#undef pchars
#undef ptrunc
#undef config_str
#undef check_modifier
#undef decode_modifiers
#undef pattern_info
#undef show_memory_info
#undef show_framesize
#undef show_heapframes_size
#undef print_error_message_file
#undef print_error_message
#undef callout_enumerate_function
#undef callout_enumerate_function_void
#undef callout_enumerate_function_fail
#undef show_pattern_info
#undef serial_error
#undef process_command
#undef process_pattern
#undef have_active_pattern
#undef free_active_pattern
#undef check_match_limit
#undef substitute_callout_function
#undef substitute_case_callout_function
#undef callout_function
#undef copy_and_get
#undef copy_substitute_string
#undef process_data
#undef init_globals
#undef free_globals
#undef unittest



/* End of pcre2test_inc.h */
