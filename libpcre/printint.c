/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/*
This is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language. See
the file Tech.Notes for some information on the internals.

Written by: Philip Hazel <ph10@cam.ac.uk>

           Copyright (c) 1997-2003 University of Cambridge

-----------------------------------------------------------------------------
Permission is granted to anyone to use this software for any purpose on any
computer system, and to redistribute it freely, subject to the following
restrictions:

1. This software is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

2. The origin of this software must not be misrepresented, either by
   explicit claim or by omission.

3. Altered versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

4. If PCRE is embedded in any software that is released under the GNU
   General Purpose Licence (GPL), then the terms of that licence shall
   supersede any condition above with which it is incompatible.
-----------------------------------------------------------------------------
*/


/* This module contains a debugging function for printing out the internal form
of a compiled regular expression. It is kept in a separate file so that it can
be #included both in the pcretest program, and in the library itself when
compiled with the debugging switch. */


static const char *OP_names[] = { OP_NAME_LIST };


/*************************************************
*       Print single- or multi-byte character    *
*************************************************/

/* These tables are actually copies of ones in pcre.c. If we compile the
library with debugging, they are included twice, but that isn't really a
problem - compiling with debugging is pretty rare and these are very small. */

static int utf8_t3[] = { 0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01};

static uschar utf8_t4[] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5 };

static int
print_char(FILE *f, uschar *ptr, BOOL utf8)
{
int c = *ptr;

if (!utf8 || (c & 0xc0) != 0xc0)
  {
  if (isprint(c)) fprintf(f, "%c", c); else fprintf(f, "\\x%02x", c);
  return 0;
  }
else
  {
  int i;
  int a = utf8_t4[c & 0x3f];  /* Number of additional bytes */
  int s = 6*a;
  c = (c & utf8_t3[a]) << s;
  for (i = 1; i <= a; i++)
    {
    s -= 6;
    c |= (ptr[i] & 0x3f) << s;
    }
  if (c < 128) fprintf(f, "\\x%02x", c); else fprintf(f, "\\x{%x}", c);
  return a;
  }
}




/*************************************************
*         Print compiled regex                   *
*************************************************/

static void
print_internals(pcre *external_re, FILE *f)
{
real_pcre *re = (real_pcre *)external_re;
uschar *codestart =
  (uschar *)re + sizeof(real_pcre) + re->name_count * re->name_entry_size;
uschar *code = codestart;
BOOL utf8 = (re->options & PCRE_UTF8) != 0;

for(;;)
  {
  uschar *ccode;
  int c;
  int extra = 0;

  fprintf(f, "%3d ", code - codestart);

  if (*code >= OP_BRA)
    {
    if (*code - OP_BRA > EXTRACT_BASIC_MAX)
      fprintf(f, "%3d Bra extra\n", GET(code, 1));
    else
      fprintf(f, "%3d Bra %d\n", GET(code, 1), *code - OP_BRA);
    code += OP_lengths[OP_BRA];
    continue;
    }

  switch(*code)
    {
    case OP_END:
    fprintf(f, "    %s\n", OP_names[*code]);
    fprintf(f, "------------------------------------------------------------------\n");
    return;

    case OP_OPT:
    fprintf(f, " %.2x %s", code[1], OP_names[*code]);
    break;

    case OP_CHARS:
      {
      int charlength = code[1];
      ccode = code + 2;
      extra = charlength;
      fprintf(f, "%3d ", charlength);
      while (charlength > 0)
        {
        int extrabytes = print_char(f, ccode, utf8);
        ccode += 1 + extrabytes;
        charlength -= 1 + extrabytes;
        }
      }
    break;

    case OP_KETRMAX:
    case OP_KETRMIN:
    case OP_ALT:
    case OP_KET:
    case OP_ASSERT:
    case OP_ASSERT_NOT:
    case OP_ASSERTBACK:
    case OP_ASSERTBACK_NOT:
    case OP_ONCE:
    case OP_COND:
    case OP_REVERSE:
    fprintf(f, "%3d %s", GET(code, 1), OP_names[*code]);
    break;

    case OP_BRANUMBER:
    printf("%3d %s", GET2(code, 1), OP_names[*code]);
    break;

    case OP_CREF:
    if (GET2(code, 1) == CREF_RECURSE)
      fprintf(f, "    Cond recurse");
    else
      fprintf(f, "%3d %s", GET2(code,1), OP_names[*code]);
    break;

    case OP_STAR:
    case OP_MINSTAR:
    case OP_PLUS:
    case OP_MINPLUS:
    case OP_QUERY:
    case OP_MINQUERY:
    case OP_TYPESTAR:
    case OP_TYPEMINSTAR:
    case OP_TYPEPLUS:
    case OP_TYPEMINPLUS:
    case OP_TYPEQUERY:
    case OP_TYPEMINQUERY:
    fprintf(f, "    ");
    if (*code >= OP_TYPESTAR) fprintf(f, "%s", OP_names[code[1]]);
      else extra = print_char(f, code+1, utf8);
    fprintf(f, "%s", OP_names[*code]);
    break;

    case OP_EXACT:
    case OP_UPTO:
    case OP_MINUPTO:
    fprintf(f, "    ");
    extra = print_char(f, code+3, utf8);
    fprintf(f, "{");
    if (*code != OP_EXACT) fprintf(f, ",");
    fprintf(f, "%d}", GET2(code,1));
    if (*code == OP_MINUPTO) fprintf(f, "?");
    break;

    case OP_TYPEEXACT:
    case OP_TYPEUPTO:
    case OP_TYPEMINUPTO:
    fprintf(f, "    %s{", OP_names[code[3]]);
    if (*code != OP_TYPEEXACT) fprintf(f, "0,");
    fprintf(f, "%d}", GET2(code,1));
    if (*code == OP_TYPEMINUPTO) fprintf(f, "?");
    break;

    case OP_NOT:
    if (isprint(c = code[1])) fprintf(f, "    [^%c]", c);
      else fprintf(f, "    [^\\x%02x]", c);
    break;

    case OP_NOTSTAR:
    case OP_NOTMINSTAR:
    case OP_NOTPLUS:
    case OP_NOTMINPLUS:
    case OP_NOTQUERY:
    case OP_NOTMINQUERY:
    if (isprint(c = code[1])) fprintf(f, "    [^%c]", c);
      else fprintf(f, "    [^\\x%02x]", c);
    fprintf(f, "%s", OP_names[*code]);
    break;

    case OP_NOTEXACT:
    case OP_NOTUPTO:
    case OP_NOTMINUPTO:
    if (isprint(c = code[3])) fprintf(f, "    [^%c]{", c);
      else fprintf(f, "    [^\\x%02x]{", c);
    if (*code != OP_NOTEXACT) fprintf(f, ",");
    fprintf(f, "%d}", GET2(code,1));
    if (*code == OP_NOTMINUPTO) fprintf(f, "?");
    break;

    case OP_RECURSE:
    fprintf(f, "%3d %s", GET(code, 1), OP_names[*code]);
    break;

    case OP_REF:
    fprintf(f, "    \\%d", GET2(code,1));
    ccode = code + OP_lengths[*code];
    goto CLASS_REF_REPEAT;

    case OP_CALLOUT:
    fprintf(f, "    %s %d", OP_names[*code], code[1]);
    break;

    /* OP_XCLASS can only occur in UTF-8 mode. However, there's no harm in
    having this code always here, and it makes it less messy without all those
    #ifdefs. */

    case OP_CLASS:
    case OP_NCLASS:
    case OP_XCLASS:
      {
      int i, min, max;
      BOOL printmap;

      fprintf(f, "    [");

      if (*code == OP_XCLASS)
        {
        extra = GET(code, 1);
        ccode = code + LINK_SIZE + 1;
        printmap = (*ccode & XCL_MAP) != 0;
        if ((*ccode++ & XCL_NOT) != 0) fprintf(f, "^");
        }
      else
        {
        printmap = TRUE;
        ccode = code + 1;
        }

      /* Print a bit map */

      if (printmap)
        {
        for (i = 0; i < 256; i++)
          {
          if ((ccode[i/8] & (1 << (i&7))) != 0)
            {
            int j;
            for (j = i+1; j < 256; j++)
              if ((ccode[j/8] & (1 << (j&7))) == 0) break;
            if (i == '-' || i == ']') fprintf(f, "\\");
            if (isprint(i)) fprintf(f, "%c", i); else fprintf(f, "\\x%02x", i);
            if (--j > i)
              {
              fprintf(f, "-");
              if (j == '-' || j == ']') fprintf(f, "\\");
              if (isprint(j)) fprintf(f, "%c", j); else fprintf(f, "\\x%02x", j);
              }
            i = j;
            }
          }
        ccode += 32;
        }

      /* For an XCLASS there is always some additional data */

      if (*code == OP_XCLASS)
        {
        int ch;
        while ((ch = *ccode++) != XCL_END)
          {
          ccode += 1 + print_char(f, ccode, TRUE);
          if (ch == XCL_RANGE)
            {
            fprintf(f, "-");
            ccode += 1 + print_char(f, ccode, TRUE);
            }
          }
        }

      /* Indicate a non-UTF8 class which was created by negation */

      fprintf(f, "]%s", (*code == OP_NCLASS)? " (neg)" : "");

      /* Handle repeats after a class or a back reference */

      CLASS_REF_REPEAT:
      switch(*ccode)
        {
        case OP_CRSTAR:
        case OP_CRMINSTAR:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
        fprintf(f, "%s", OP_names[*ccode]);
        extra = OP_lengths[*ccode];
        break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
        min = GET2(ccode,1);
        max = GET2(ccode,3);
        if (max == 0) fprintf(f, "{%d,}", min);
        else fprintf(f, "{%d,%d}", min, max);
        if (*ccode == OP_CRMINRANGE) fprintf(f, "?");
        extra = OP_lengths[*ccode];
        break;
        }
      }
    break;

    /* Anything else is just an item with no data*/

    default:
    fprintf(f, "    %s", OP_names[*code]);
    break;
    }

  code += OP_lengths[*code] + extra;
  fprintf(f, "\n");
  }
}

/* End of printint.c */
