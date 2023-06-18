#ifdef HAVE_CONFIG_H
/* Needed for HAVE_PCRE_PCRE_H below */
#include "nmap_config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_PCRE2
/* nse_pcrelib.cc - Lua binding of PCRE2 library */
/* lrexlib pcre2 code */
/*
License of Lrexlib release
--------------------------

Copyright (C) Reuben Thomas 2000-2020
Copyright (C) Shmuel Zeigerman 2004-2020

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <ctype.h>
#include <stdint.h>

#include "nse_lua.h"

#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>

#include "nse_pcrelib.h"

/* These 2 settings may be redefined from the command-line or the makefile.
 * They should be kept in sync between themselves and with the target name.
 */
#ifndef REX_LIBNAME
#  define REX_LIBNAME "rex_pcre2"
#endif

#define REX_TYPENAME REX_LIBNAME"_regex"

/* lrexlib common.h */
#if LUA_VERSION_NUM > 501
# define lua_objlen lua_rawlen
  int luaL_typerror (lua_State *L, int narg, const char *tname);
#endif

/* Special values for maxmatch in gsub. They all must be negative. */
#define GSUB_UNLIMITED   -1
#define GSUB_CONDITIONAL -2

/* Common structs and functions */

typedef struct {
  const char* key;
  lua_Integer  val;
} flag_pair;

typedef struct {            /* compile arguments */
  const char * pattern;
  size_t       patlen;
  void       * ud;
  int          cflags;
  const char * locale;             /* PCRE, Oniguruma */
  const unsigned char * tables;    /* PCRE */
  int          tablespos;          /* PCRE */
  void       * syntax;             /* Oniguruma */
  const unsigned char * translate; /* GNU */
  int          gnusyn;             /* GNU */
} TArgComp;

typedef struct {            /* exec arguments */
  const char * text;
  size_t       textlen;
  int          startoffset;
  int          eflags;
  int          funcpos;
  int          maxmatch;
  int          funcpos2;          /* used with gsub */
  int          reptype;           /* used with gsub */
  size_t       ovecsize;          /* PCRE: dfa_exec */
  size_t       wscount;           /* PCRE: dfa_exec */
} TArgExec;

struct tagFreeList; /* forward declaration */

struct tagBuffer {
  size_t      size;
  size_t      top;
  char      * arr;
  lua_State * L;
  struct tagFreeList * freelist;
};

struct tagFreeList {
  struct tagBuffer * list[16];
  int top;
};

typedef struct tagBuffer TBuffer;
typedef struct tagFreeList TFreeList;

void freelist_init (TFreeList *fl);
void freelist_add (TFreeList *fl, TBuffer *buf);
void freelist_free (TFreeList *fl);

void buffer_init (TBuffer *buf, size_t sz, lua_State *L, TFreeList *fl);
void buffer_free (TBuffer *buf);
void buffer_clear (TBuffer *buf);
void buffer_addbuffer (TBuffer *trg, TBuffer *src);
void buffer_addlstring (TBuffer *buf, const void *src, size_t sz);
void buffer_addvalue (TBuffer *buf, int stackpos);
void buffer_pushresult (TBuffer *buf);

void bufferZ_putrepstring (TBuffer *buf, int reppos, int nsub);
int  bufferZ_next (TBuffer *buf, size_t *iter, size_t *len, const char **str);
void bufferZ_addlstring (TBuffer *buf, const void *src, size_t len);
void bufferZ_addnum (TBuffer *buf, size_t num);

int  get_int_field (lua_State *L, const char* field);
void set_int_field (lua_State *L, const char* field, int val);
int  get_flags (lua_State *L, const flag_pair **arr);
const char *get_flag_key (const flag_pair *fp, int val);
void *Lmalloc (lua_State *L, size_t size);
void *Lrealloc (lua_State *L, void *p, size_t osize, size_t nsize);
void Lfree (lua_State *L, void *p, size_t size);

#ifndef REX_NOEMBEDDEDTEST
int newmembuffer (lua_State *L);
#endif

#define ALG_CFLAGS_DFLT 0
#define ALG_EFLAGS_DFLT 0

static int getcflags (lua_State *L, int pos);
#define ALG_GETCFLAGS(L,pos)  getcflags(L, pos)

static void checkarg_compile (lua_State *L, int pos, TArgComp *argC);
#define ALG_GETCARGS(a,b,c)  checkarg_compile(a,b,c)

#define ALG_NOMATCH(res)   ((res) == PCRE2_ERROR_NOMATCH)
#define ALG_ISMATCH(res)   ((res) >= 0)
#define ALG_SUBBEG(ud,n)   ((int)(ud)->ovector[(n)+(n)])
#define ALG_SUBEND(ud,n)   ((int)(ud)->ovector[(n)+(n)+1])
#define ALG_SUBLEN(ud,n)   (ALG_SUBEND((ud),(n)) - ALG_SUBBEG((ud),(n)))
#define ALG_SUBVALID(ud,n) (0 == pcre2_substring_length_bynumber((ud)->match_data, (n), NULL))
#define ALG_NSUB(ud)       ((int)(ud)->ncapt)

#define ALG_PUSHSUB(L,ud,text,n) \
  lua_pushlstring (L, (text) + ALG_SUBBEG((ud),(n)), ALG_SUBLEN((ud),(n)))

#define ALG_PUSHSUB_OR_FALSE(L,ud,text,n) \
  (ALG_SUBVALID(ud,n) ? (void) ALG_PUSHSUB (L,ud,text,n) : lua_pushboolean (L,0))

#define ALG_PUSHSTART(L,ud,offs,n)   lua_pushinteger(L, (offs) + ALG_SUBBEG(ud,n) + 1)
#define ALG_PUSHEND(L,ud,offs,n)     lua_pushinteger(L, (offs) + ALG_SUBEND(ud,n))
#define ALG_PUSHOFFSETS(L,ud,offs,n) \
  (ALG_PUSHSTART(L,ud,offs,n), ALG_PUSHEND(L,ud,offs,n))

#define ALG_BASE(st)  0
#define ALG_PULL

typedef struct {
  pcre2_code *pr;
  pcre2_compile_context *ccontext;
  pcre2_match_data *match_data;
  PCRE2_SIZE *ovector;
  int ncapt;
  const unsigned char *tables;
  int freed;
} TPcre2;

#define TUserdata TPcre2

static void do_named_subpatterns (lua_State *L, TPcre2 *ud, const char *text);
#  define DO_NAMED_SUBPATTERNS do_named_subpatterns

/* Locations of the 2 permanent tables in the function environment */
#define INDEX_CHARTABLES_META  1      /* chartables type's metatable */
#define INDEX_CHARTABLES_LINK  2      /* link chartables to compiled regex */

const char chartables_typename[] = "chartables";

/*  Functions
 ******************************************************************************
 */

/* lrexlib common.c */
#define N_ALIGN sizeof(int)

/* the table must be on Lua stack top */
int get_int_field (lua_State *L, const char* field)
{
  int val;
  lua_getfield (L, -1, field);
  val = lua_tointeger (L, -1);
  lua_pop (L, 1);
  return val;
}

/* the table must be on Lua stack top */
void set_int_field (lua_State *L, const char* field, int val)
{
  lua_pushinteger (L, val);
  lua_setfield (L, -2, field);
}

void *Lmalloc(lua_State *L, size_t size) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  return lalloc(ud, NULL, 0, size);
}

void *Lrealloc(lua_State *L, void *p, size_t osize, size_t nsize) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  return lalloc(ud, p, osize, nsize);
}

void Lfree(lua_State *L, void *p, size_t osize) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  lalloc(ud, p, osize, 0);
}

/* This function fills a table with string-number pairs.
   The table can be passed as the 1-st lua-function parameter,
   otherwise it is created. The return value is the filled table.
*/
int get_flags (lua_State *L, const flag_pair **arrs) {
  const flag_pair *p;
  const flag_pair **pp;
  int nparams = lua_gettop(L);

  if(nparams == 0)
    lua_newtable(L);
  else {
    if(!lua_istable(L, 1))
      luaL_argerror(L, 1, "not a table");
    if(nparams > 1)
      lua_pushvalue(L, 1);
  }

  for(pp=arrs; *pp; ++pp) {
    for(p=*pp; p->key; ++p) {
      lua_pushstring(L, p->key);
      lua_pushinteger(L, p->val);
      lua_rawset(L, -3);
    }
  }
  return 1;
}

const char *get_flag_key (const flag_pair *fp, int val) {
  for (; fp->key; ++fp) {
    if (fp->val == val)
      return fp->key;
  }
  return NULL;
}

/* Classes */

/*
 *  class TFreeList
 *  ***************
 *  Simple array of pointers to TBuffer's.
 *  The array has fixed capacity (not expanded automatically).
 */

void freelist_init (TFreeList *fl) {
  fl->top = 0;
}

void freelist_add (TFreeList *fl, TBuffer *buf) {
  fl->list[fl->top++] = buf;
}

void freelist_free (TFreeList *fl) {
  while (fl->top > 0)
    buffer_free (fl->list[--fl->top]);
}

/*
 *  class TBuffer
 *  *************
 *  Auto-extensible array of characters for building long strings incrementally.
 *    * Differs from luaL_Buffer in that:
 *       *  its operations do not change Lua stack top position
 *       *  buffer_addvalue does not extract the value from Lua stack
 *       *  buffer_pushresult does not have to be the last operation
 *    * Uses TFreeList class:
 *       *  for inserting itself into a TFreeList instance for future clean-up
 *       *  calls freelist_free prior to calling luaL_error.
 *    * Has specialized "Z-operations" for maintaining mixed string/integer
 *      array:  bufferZ_addlstring, bufferZ_addnum and bufferZ_next.
 *       *  if the array is intended to be "mixed", then the methods
 *          buffer_addlstring and buffer_addvalue must not be used
 *          (the application will crash on bufferZ_next).
 *       *  conversely, if the array is not intended to be "mixed",
 *          then the method bufferZ_next must not be used.
 */

enum { ID_NUMBER, ID_STRING };

void buffer_init (TBuffer *buf, size_t sz, lua_State *L, TFreeList *fl) {
  buf->arr = (char*) Lmalloc(L, sz);
  if (!buf->arr) {
    freelist_free (fl);
    luaL_error (L, "malloc failed");
  }
  buf->size = sz;
  buf->top = 0;
  buf->L = L;
  buf->freelist = fl;
  freelist_add (fl, buf);
}

void buffer_free (TBuffer *buf) {
  Lfree(buf->L, buf->arr, buf->size);
}

void buffer_clear (TBuffer *buf) {
  buf->top = 0;
}

void buffer_pushresult (TBuffer *buf) {
  lua_pushlstring (buf->L, buf->arr, buf->top);
}

void buffer_addbuffer (TBuffer *trg, TBuffer *src) {
  buffer_addlstring (trg, src->arr, src->top);
}

void buffer_addlstring (TBuffer *buf, const void *src, size_t sz) {
  size_t newtop = buf->top + sz;
  if (newtop > buf->size) {
    char *p = (char*) Lrealloc (buf->L, buf->arr, buf->size, 2 * newtop);   /* 2x expansion */
    if (!p) {
      freelist_free (buf->freelist);
      luaL_error (buf->L, "realloc failed");
    }
    buf->arr = p;
    buf->size = 2 * newtop;
  }
  if (src)
    memcpy (buf->arr + buf->top, src, sz);
  buf->top = newtop;
}

void buffer_addvalue (TBuffer *buf, int stackpos) {
  size_t len;
  const char *p = lua_tolstring (buf->L, stackpos, &len);
  buffer_addlstring (buf, p, len);
}

void bufferZ_addlstring (TBuffer *buf, const void *src, size_t len) {
  int n;
  size_t header[2] = { ID_STRING };
  header[1] = len;
  buffer_addlstring (buf, header, sizeof (header));
  buffer_addlstring (buf, src, len);
  n = len % N_ALIGN;
  if (n) buffer_addlstring (buf, NULL, N_ALIGN - n);
}

void bufferZ_addnum (TBuffer *buf, size_t num) {
  size_t header[2] = { ID_NUMBER };
  header[1] = num;
  buffer_addlstring (buf, header, sizeof (header));
}

/* 1. When called repeatedly on the same TBuffer, its existing data
      is discarded and overwritten by the new data.
   2. The TBuffer's array is never shrunk by this function.
*/
void bufferZ_putrepstring (TBuffer *BufRep, int reppos, int nsub) {
  char dbuf[] = { 0, 0 };
  size_t replen;
  const char *p = lua_tolstring (BufRep->L, reppos, &replen);
  const char *end = p + replen;
  BufRep->top = 0;
  while (p < end) {
    const char *q;
    for (q = p; q < end && *q != '%'; ++q)
      {}
    if (q != p)
      bufferZ_addlstring (BufRep, p, q - p);
    if (q < end) {
      if (++q < end) {  /* skip % */
        if (isdigit (*q)) {
          int num;
          *dbuf = *q;
          num = strtol (dbuf, NULL, 10);
          if (num == 1 && nsub == 0)
            num = 0;
          else if (num > nsub) {
            freelist_free (BufRep->freelist);
            luaL_error (BufRep->L, "invalid capture index");
          }
          bufferZ_addnum (BufRep, num);
        }
        else bufferZ_addlstring (BufRep, q, 1);
      }
      p = q + 1;
    }
    else break;
  }
}

/******************************************************************************
  The intended use of this function is as follows:
        size_t iter = 0;
        while (bufferZ_next (buf, &iter, &num, &str)) {
          if (str) do_something_with_string (str, num);
          else     do_something_with_number (num);
        }
*******************************************************************************
*/
int bufferZ_next (TBuffer *buf, size_t *iter, size_t *num, const char **str) {
  if (*iter < buf->top) {
    size_t *ptr_header = (size_t*)(buf->arr + *iter);
    *num = ptr_header[1];
    *iter += 2 * sizeof (size_t);
    *str = NULL;
    if (*ptr_header == ID_STRING) {
      int n;
      *str = buf->arr + *iter;
      *iter += *num;
      n = *iter % N_ALIGN;
      if (n) *iter += (N_ALIGN - n);
    }
    return 1;
  }
  return 0;
}

#if LUA_VERSION_NUM > 501
int luaL_typerror (lua_State *L, int narg, const char *tname) {
  const char *msg = lua_pushfstring(L, "%s expected, got %s",
                                    tname, luaL_typename(L, narg));
  return luaL_argerror(L, narg, msg);
}
#endif

#ifndef REX_NOEMBEDDEDTEST
static int ud_topointer (lua_State *L) {
  lua_pushlightuserdata (L, lua_touserdata (L, 1));
  return 1;
}

static int ud_len (lua_State *L) {
  lua_pushinteger (L, lua_objlen (L, 1));
  return 1;
}

/* for testing purposes only */
int newmembuffer (lua_State *L) {
  size_t len;
  const char* s = luaL_checklstring (L, 1, &len);
  void *ud = lua_newuserdata (L, len);
  memcpy (ud, s, len);
  lua_newtable (L); /* metatable */
  lua_pushvalue (L, -1);
  lua_setfield (L, -2, "__index"); /* metatable.__index = metatable */
  lua_pushcfunction (L, ud_topointer);
  lua_setfield (L, -2, "topointer");
  lua_pushcfunction (L, ud_len);
  lua_setfield (L, -2, "__len");
  lua_setmetatable (L, -2);
  return 1;
}
#endif /* #ifndef REX_NOEMBEDDEDTEST */

/* lrexlib algo.h */
#define REX_VERSION "Lrexlib 2.9.1"

/* Forward declarations */
static void gmatch_pushsubject (lua_State *L, TArgExec *argE);
static int findmatch_exec  (TUserdata *ud, TArgExec *argE);
static int split_exec      (TUserdata *ud, TArgExec *argE, int offset);
static int gsub_exec       (TUserdata *ud, TArgExec *argE, int offset);
static int gmatch_exec     (TUserdata *ud, TArgExec *argE);
static int compile_regex   (lua_State *L, const TArgComp *argC, TUserdata **pud);
static int generate_error  (lua_State *L, const TUserdata *ud, int errcode);

#if LUA_VERSION_NUM == 501
#  define ALG_ENVIRONINDEX LUA_ENVIRONINDEX
#else
#  define ALG_ENVIRONINDEX lua_upvalueindex(1)
#endif

#ifndef ALG_CHARSIZE
#  define ALG_CHARSIZE 1
#endif

#ifndef BUFFERZ_PUTREPSTRING
#  define BUFFERZ_PUTREPSTRING bufferZ_putrepstring
#endif

#ifndef ALG_GETCARGS
#  define ALG_GETCARGS(a,b,c)
#endif

#ifndef DO_NAMED_SUBPATTERNS
#define DO_NAMED_SUBPATTERNS(a,b,c)
#endif

#define METHOD_FIND  0
#define METHOD_MATCH 1
#define METHOD_EXEC  2
#define METHOD_TFIND 3


static int OptLimit (lua_State *L, int pos) {
  if (lua_isnoneornil (L, pos))
    return GSUB_UNLIMITED;
  if (lua_isfunction (L, pos))
    return GSUB_CONDITIONAL;
  if (lua_isnumber (L, pos)) {
    int a = lua_tointeger (L, pos);
    return a < 0 ? 0 : a;
  }
  return luaL_typerror (L, pos, "number or function");
}


static int get_startoffset(lua_State *L, int stackpos, size_t len) {
  int startoffset = (int)luaL_optinteger(L, stackpos, 1);
  if(startoffset > 0)
    startoffset--;
  else if(startoffset < 0) {
    startoffset += len/ALG_CHARSIZE;
    if(startoffset < 0)
      startoffset = 0;
  }
  return startoffset*ALG_CHARSIZE;
}


static TUserdata* test_ud (lua_State *L, int pos)
{
  TUserdata *ud;
  if (lua_getmetatable(L, pos) &&
      lua_rawequal(L, -1, ALG_ENVIRONINDEX) &&
      (ud = (TUserdata *)lua_touserdata(L, pos)) != NULL) {
    lua_pop(L, 1);
    return ud;
  }
  return NULL;
}


static TUserdata* check_ud (lua_State *L)
{
  TUserdata *ud = test_ud(L, 1);
  if (ud == NULL) luaL_typerror(L, 1, REX_TYPENAME);
  return ud;
}


static void check_subject (lua_State *L, int pos, TArgExec *argE)
{
  int stype;
  argE->text = lua_tolstring (L, pos, &argE->textlen);
  stype = lua_type (L, pos);
  if (stype != LUA_TSTRING && stype != LUA_TTABLE && stype != LUA_TUSERDATA) {
    luaL_typerror (L, pos, "string, table or userdata");
  } else if (argE->text == NULL) {
    int type;
    lua_getfield (L, pos, "topointer");
    if (lua_type (L, -1) != LUA_TFUNCTION)
      luaL_error (L, "subject has no topointer method");
    lua_pushvalue (L, pos);
    lua_call (L, 1, 1);
    type = lua_type (L, -1);
    if (type != LUA_TLIGHTUSERDATA)
      luaL_error (L, "subject's topointer method returned %s (expected lightuserdata)",
                  lua_typename (L, type));
    argE->text = (const char*) lua_touserdata (L, -1);
    lua_pop (L, 1);
#if LUA_VERSION_NUM == 501
    if (luaL_callmeta (L, pos, "__len")) {
      if (lua_type (L, -1) != LUA_TNUMBER)
        luaL_argerror (L, pos, "subject's length is not a number");
      argE->textlen = lua_tointeger (L, -1);
      lua_pop (L, 1);
    }
    else
      argE->textlen = lua_objlen (L, pos);
#else
    argE->textlen = luaL_len (L, pos);
#endif
  }
}

static void check_pattern (lua_State *L, int pos, TArgComp *argC)
{
  if (lua_isstring (L, pos)) {
    argC->pattern = lua_tolstring (L, pos, &argC->patlen);
    argC->ud = NULL;
  }
  else if ((argC->ud = test_ud (L, pos)) == NULL)
    luaL_typerror(L, pos, "string or " REX_TYPENAME);
}

static void checkarg_new (lua_State *L, TArgComp *argC) {
  argC->pattern = luaL_checklstring (L, 1, &argC->patlen);
  argC->cflags = ALG_GETCFLAGS (L, 2);
  ALG_GETCARGS (L, 3, argC);
}


/* function gsub (s, patt, f, [n], [cf], [ef], [larg...]) */
static void checkarg_gsub (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  lua_tostring (L, 3);    /* converts number (if any) to string */
  argE->reptype = lua_type (L, 3);
  if (argE->reptype != LUA_TSTRING && argE->reptype != LUA_TTABLE &&
      argE->reptype != LUA_TFUNCTION) {
    luaL_typerror (L, 3, "string, table or function");
  }
  argE->funcpos = 3;
  argE->funcpos2 = 4;
  argE->maxmatch = OptLimit (L, 4);
  argC->cflags = ALG_GETCFLAGS (L, 5);
  argE->eflags = (int)luaL_optinteger (L, 6, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 7, argC);
}


/* function count (s, patt, [cf], [ef], [larg...]) */
static void checkarg_count (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* function find  (s, patt, [st], [cf], [ef], [larg...]) */
/* function match (s, patt, [st], [cf], [ef], [larg...]) */
static void checkarg_find_func (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argC->cflags = ALG_GETCFLAGS (L, 4);
  argE->eflags = (int)luaL_optinteger (L, 5, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 6, argC);
}


/* function gmatch (s, patt, [cf], [ef], [larg...]) */
/* function split  (s, patt, [cf], [ef], [larg...]) */
static void checkarg_gmatch_split (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* method r:tfind (s, [st], [ef]) */
/* method r:exec  (s, [st], [ef]) */
/* method r:find  (s, [st], [ef]) */
/* method r:match (s, [st], [ef]) */
static void checkarg_find_method (lua_State *L, TArgExec *argE, TUserdata **ud) {
  *ud = check_ud (L);
  check_subject (L, 2, argE);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
}


static int algf_new (lua_State *L) {
  TArgComp argC;
  checkarg_new (L, &argC);
  return compile_regex (L, &argC, NULL);
}

static void push_substrings (lua_State *L, TUserdata *ud, const char *text,
                             TFreeList *freelist) {
  int i;
  if (lua_checkstack (L, ALG_NSUB(ud)) == 0) {
    if (freelist)
      freelist_free (freelist);
    luaL_error (L, "cannot add %d stack slots", ALG_NSUB(ud));
  }
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
  }
}

static int algf_gsub (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, n_subst = 0, st = 0, last_to = -1;
  TBuffer BufOut, BufRep, BufTemp, *pBuf = &BufOut;
  TFreeList freelist;
  /*------------------------------------------------------------------*/
  checkarg_gsub (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  freelist_init (&freelist);
  /*------------------------------------------------------------------*/
  if (argE.reptype == LUA_TSTRING) {
    buffer_init (&BufRep, 256, L, &freelist);
    BUFFERZ_PUTREPSTRING (&BufRep, argE.funcpos, ALG_NSUB(ud));
  }
  /*------------------------------------------------------------------*/
  if (argE.maxmatch == GSUB_CONDITIONAL) {
    buffer_init (&BufTemp, 1024, L, &freelist);
    pBuf = &BufTemp;
  }
  /*------------------------------------------------------------------*/
  buffer_init (&BufOut, 1024, L, &freelist);
  while ((argE.maxmatch < 0 || n_match < argE.maxmatch) && st <= (int)argE.textlen) {
    int from, to, res;
    int curr_subst = 0;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      freelist_free (&freelist);
      return generate_error (L, ud, res);
    }
    from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char (not replaced) */
        buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
    if (st < from) {
      buffer_addlstring (&BufOut, argE.text + st, from - st);
#ifdef ALG_PULL
      st = from;
#endif
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TSTRING) {
      size_t iter = 0, num;
      const char *str;
      while (bufferZ_next (&BufRep, &iter, &num, &str)) {
        if (str)
          buffer_addlstring (pBuf, str, num);
        else if (num == 0 || ALG_SUBVALID (ud,num))
          buffer_addlstring (pBuf, argE.text + ALG_BASE(st) + ALG_SUBBEG(ud,num), ALG_SUBLEN(ud,num));
      }
      curr_subst = 1;
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TTABLE) {
      if (ALG_NSUB(ud) > 0)
        ALG_PUSHSUB_OR_FALSE (L, ud, argE.text + ALG_BASE(st), 1);
      else
        lua_pushlstring (L, argE.text + from, to - from);
      lua_gettable (L, argE.funcpos);
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TFUNCTION) {
      int narg;
      lua_pushvalue (L, argE.funcpos);
      if (ALG_NSUB(ud) > 0) {
        push_substrings (L, ud, argE.text + ALG_BASE(st), &freelist);
        narg = ALG_NSUB(ud);
      }
      else {
        lua_pushlstring (L, argE.text + from, to - from);
        narg = 1;
      }
      if (0 != lua_pcall (L, narg, 1, 0)) {
        freelist_free (&freelist);
        return lua_error (L);  /* re-raise the error */
      }
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TTABLE || argE.reptype == LUA_TFUNCTION) {
      if (lua_tostring (L, -1)) {
        buffer_addvalue (pBuf, -1);
        curr_subst = 1;
      }
      else if (!lua_toboolean (L, -1))
        buffer_addlstring (pBuf, argE.text + from, to - from);
      else {
        freelist_free (&freelist);
        luaL_error (L, "invalid replacement value (a %s)", luaL_typename (L, -1));
      }
      if (argE.maxmatch != GSUB_CONDITIONAL)
        lua_pop (L, 1);
    }
    /*----------------------------------------------------------------*/
    if (argE.maxmatch == GSUB_CONDITIONAL) {
      /* Call the function */
      lua_pushvalue (L, argE.funcpos2);
      lua_pushinteger (L, from/ALG_CHARSIZE + 1);
      lua_pushinteger (L, to/ALG_CHARSIZE);
      if (argE.reptype == LUA_TSTRING)
        buffer_pushresult (&BufTemp);
      else {
        lua_pushvalue (L, -4);
        lua_remove (L, -5);
      }
      if (0 != lua_pcall (L, 3, 2, 0)) {
        freelist_free (&freelist);
        lua_error (L);  /* re-raise the error */
      }
      /* Handle the 1-st return value */
      if (lua_isstring (L, -2)) {               /* coercion is allowed here */
        buffer_addvalue (&BufOut, -2);          /* rep2 */
        curr_subst = 1;
      }
      else if (lua_toboolean (L, -2))
        buffer_addbuffer (&BufOut, &BufTemp);   /* rep1 */
      else {
        buffer_addlstring (&BufOut, argE.text + from, to - from); /* "no" */
        curr_subst = 0;
      }
      /* Handle the 2-nd return value */
      if (lua_type (L, -1) == LUA_TNUMBER) {    /* no coercion is allowed here */
        int n = lua_tointeger (L, -1);
        if (n < 0)                              /* n */
          n = 0;
        argE.maxmatch = n_match + n;
      }
      else if (lua_toboolean (L, -1))           /* "yes to all" */
        argE.maxmatch = GSUB_UNLIMITED;
      else
        buffer_clear (&BufTemp);

      lua_pop (L, 2);
      if (argE.maxmatch != GSUB_CONDITIONAL)
        pBuf = &BufOut;
    }
    /*----------------------------------------------------------------*/
    n_subst += curr_subst;
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  buffer_addlstring (&BufOut, argE.text + st, argE.textlen - st);
  buffer_pushresult (&BufOut);
  lua_pushinteger (L, n_match);
  lua_pushinteger (L, n_subst);
  freelist_free (&freelist);
  return 3;
}


static int algf_count (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, st = 0, last_to = -1;
  /*------------------------------------------------------------------*/
  checkarg_count (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  /*------------------------------------------------------------------*/
  while (st <= (int)argE.textlen) {
    int to, res;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      return generate_error (L, ud, res);
    }
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char */
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
#ifdef ALG_PULL
    {
      int from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
      if (st < from)
        st = from;
    }
#endif
    /*----------------------------------------------------------------*/
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  lua_pushinteger (L, n_match);
  return 1;
}


static int finish_generic_find (lua_State *L, TUserdata *ud, TArgExec *argE,
  int method, int res)
{
  if (ALG_ISMATCH (res)) {
    if (method == METHOD_FIND)
      ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE->startoffset), 0);
    if (ALG_NSUB(ud))    /* push captures */
      push_substrings (L, ud, argE->text, NULL);
    else if (method != METHOD_FIND) {
      ALG_PUSHSUB (L, ud, argE->text, 0);
      return 1;
    }
    return (method == METHOD_FIND) ? ALG_NSUB(ud) + 2 : ALG_NSUB(ud);
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error (L, ud, res);
}


static int generic_find_func (lua_State *L, int method) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int res;

  checkarg_find_func (L, &argC, &argE);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil (L), 1;

  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  res = findmatch_exec (ud, &argE);
  return finish_generic_find (L, ud, &argE, method, res);
}


static int algf_find (lua_State *L) {
  return generic_find_func (L, METHOD_FIND);
}


static int algf_match (lua_State *L) {
  return generic_find_func (L, METHOD_MATCH);
}


static int gmatch_iter (lua_State *L) {
  int last_end, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  last_end         = lua_tointeger (L, lua_upvalueindex (5));

  while (1) {
    if (argE.startoffset > (int)argE.textlen)
      return 0;
    res = gmatch_exec (ud, &argE);
    if (ALG_ISMATCH (res)) {
      int incr = 0;
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          argE.startoffset += ALG_CHARSIZE;
          continue;
        }
        incr = ALG_CHARSIZE;
      }
      last_end = ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0);
      lua_pushinteger(L, last_end + incr); /* update start offset */
      lua_replace (L, lua_upvalueindex (4));
      lua_pushinteger(L, last_end); /* update last end of match */
      lua_replace (L, lua_upvalueindex (5));
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text, NULL);
        return ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text, 0);
        return 1;
      }
    }
    else if (ALG_NOMATCH (res))
      return 0;
    else
      return generate_error (L, ud, res);
  }
}


static int split_iter (lua_State *L) {
  int incr, last_end, newoffset, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  incr             = lua_tointeger (L, lua_upvalueindex (5));
  last_end         = lua_tointeger (L, lua_upvalueindex (6));

  if (incr < 0)
    return 0;

  while (1) {
    if ((newoffset = argE.startoffset + incr) > (int)argE.textlen)
      break;
    res = split_exec (ud, &argE, newoffset);
    if (ALG_ISMATCH (res)) {
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          incr += ALG_CHARSIZE;
          continue;
        }
      }
      lua_pushinteger(L, ALG_BASE(newoffset) + ALG_SUBEND(ud,0)); /* update start offset and last_end */
      lua_pushvalue (L, -1);
      lua_replace (L, lua_upvalueindex (4));
      lua_replace (L, lua_upvalueindex (6));
      lua_pushinteger (L, ALG_SUBLEN(ud,0) ? 0 : ALG_CHARSIZE);    /* update incr */
      lua_replace (L, lua_upvalueindex (5));
      /* push text preceding the match */
      lua_pushlstring (L, argE.text + argE.startoffset,
                       ALG_SUBBEG(ud,0) + ALG_BASE(newoffset) - argE.startoffset);
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text + ALG_BASE(newoffset), NULL);
        return 1 + ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text + ALG_BASE(newoffset), 0);
        return 2;
      }
    }
    else if (ALG_NOMATCH (res))
      break;
    else
      return generate_error (L, ud, res);
  }
  lua_pushinteger (L, -1);    /* mark as last iteration */
  lua_replace (L, lua_upvalueindex (5));   /* incr = -1 */
  lua_pushlstring (L, argE.text+argE.startoffset, argE.textlen-argE.startoffset);
  return 1;
}


static int algf_gmatch (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, -1);                    /* 5-th upvalue: last end of match */
  lua_pushcclosure (L, gmatch_iter, 5);
  return 1;
}

static int algf_split (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, 0);                     /* 5-th upvalue: incr */
  lua_pushinteger (L, -1);                    /* 6-th upvalue: last_end */
  lua_pushcclosure (L, split_iter, 6);
  return 1;
}


static void push_substring_table (lua_State *L, TUserdata *ud, const char *text) {
  int i;
  lua_newtable (L);
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
    lua_rawseti (L, -2, i);
  }
}


static void push_offset_table (lua_State *L, TUserdata *ud, int startoffset) {
  int i, j;
  lua_newtable (L);
  for (i=1, j=1; i <= ALG_NSUB(ud); i++) {
    if (ALG_SUBVALID (ud,i)) {
      ALG_PUSHSTART (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
      ALG_PUSHEND (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
    }
    else {
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
    }
  }
}


static int generic_find_method (lua_State *L, int method) {
  TUserdata *ud;
  TArgExec argE;
  int res;

  checkarg_find_method (L, &argE, &ud);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil(L), 1;

  res = findmatch_exec (ud, &argE);
  if (ALG_ISMATCH (res)) {
    switch (method) {
      case METHOD_EXEC:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_offset_table (L, ud, ALG_BASE(argE.startoffset));
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_TFIND:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_substring_table (L, ud, argE.text);
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_MATCH:
      case METHOD_FIND:
        return finish_generic_find (L, ud, &argE, method, res);
    }
    return 0;
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error(L, ud, res);
}


static int algm_find (lua_State *L) {
  return generic_find_method (L, METHOD_FIND);
}
static int algm_match (lua_State *L) {
  return generic_find_method (L, METHOD_MATCH);
}
static int algm_tfind (lua_State *L) {
  return generic_find_method (L, METHOD_TFIND);
}
static int algm_exec (lua_State *L) {
  return generic_find_method (L, METHOD_EXEC);
}

static void alg_register (lua_State *L, const luaL_Reg *r_methods,
                          const luaL_Reg *r_functions, const char *name) {
  /* Create a new function environment to serve as a metatable for methods. */
#if LUA_VERSION_NUM == 501
  lua_newtable (L);
  lua_pushvalue (L, -1);
  lua_replace (L, LUA_ENVIRONINDEX);
  luaL_register (L, NULL, r_methods);
#else
  luaL_newmetatable(L, REX_TYPENAME);
  lua_pushvalue(L, -1);
  luaL_setfuncs (L, r_methods, 1);
#endif
  lua_pushvalue(L, -1); /* mt.__index = mt */
  lua_setfield(L, -2, "__index");

  /* Register functions. */
  lua_createtable(L, 0, 8);
#if LUA_VERSION_NUM == 501
  luaL_register (L, NULL, r_functions);
#else
  lua_pushvalue(L, -2);
  luaL_setfuncs (L, r_functions, 1);
#endif
#ifdef REX_CREATEGLOBALVAR
  lua_pushvalue(L, -1);
  lua_setglobal(L, REX_LIBNAME);
#endif
  lua_pushfstring (L, REX_VERSION" (for %s)", name);
  lua_setfield (L, -2, "_VERSION");
#ifndef REX_NOEMBEDDEDTEST
  lua_pushcfunction (L, newmembuffer);
  lua_setfield (L, -2, "_newmembuffer");
#endif
}

/* lrexlib lpcre2_f.c */
#define VERSION_PCRE2 (PCRE2_MAJOR*100 + PCRE2_MINOR)

static flag_pair pcre2_flags[] = {
  { "MAJOR",                         PCRE2_MAJOR },
  { "MINOR",                         PCRE2_MINOR },
/*---------------------------------------------------------------------------*/
  { "ANCHORED",                      PCRE2_ANCHORED },
  { "NO_UTF_CHECK",                  PCRE2_NO_UTF_CHECK },
  { "ALLOW_EMPTY_CLASS",             PCRE2_ALLOW_EMPTY_CLASS },
  { "ALT_BSUX",                      PCRE2_ALT_BSUX },
  { "AUTO_CALLOUT",                  PCRE2_AUTO_CALLOUT },
  { "CASELESS",                      PCRE2_CASELESS },
  { "DOLLAR_ENDONLY",                PCRE2_DOLLAR_ENDONLY },
  { "DOTALL",                        PCRE2_DOTALL },
  { "DUPNAMES",                      PCRE2_DUPNAMES },
  { "EXTENDED",                      PCRE2_EXTENDED },
  { "FIRSTLINE",                     PCRE2_FIRSTLINE },
  { "MATCH_UNSET_BACKREF",           PCRE2_MATCH_UNSET_BACKREF },
  { "MULTILINE",                     PCRE2_MULTILINE },
  { "NEVER_UCP",                     PCRE2_NEVER_UCP },
  { "NEVER_UTF",                     PCRE2_NEVER_UTF },
  { "NO_AUTO_CAPTURE",               PCRE2_NO_AUTO_CAPTURE },
  { "NO_AUTO_POSSESS",               PCRE2_NO_AUTO_POSSESS },
  { "NO_DOTSTAR_ANCHOR",             PCRE2_NO_DOTSTAR_ANCHOR },
  { "NO_START_OPTIMIZE",             PCRE2_NO_START_OPTIMIZE },
  { "UCP",                           PCRE2_UCP },
  { "UNGREEDY",                      PCRE2_UNGREEDY },
  { "UTF",                           PCRE2_UTF },
  { "NEVER_BACKSLASH_C",             PCRE2_NEVER_BACKSLASH_C },
  { "ALT_CIRCUMFLEX",                PCRE2_ALT_CIRCUMFLEX },
  { "ALT_VERBNAMES",                 PCRE2_ALT_VERBNAMES },
  { "USE_OFFSET_LIMIT",              PCRE2_USE_OFFSET_LIMIT },
  { "JIT_COMPLETE",                  PCRE2_JIT_COMPLETE },
  { "JIT_PARTIAL_SOFT",              PCRE2_JIT_PARTIAL_SOFT },
  { "JIT_PARTIAL_HARD",              PCRE2_JIT_PARTIAL_HARD },
  { "NOTBOL",                        PCRE2_NOTBOL },
  { "NOTEOL",                        PCRE2_NOTEOL },
  { "NOTEMPTY",                      PCRE2_NOTEMPTY },
  { "NOTEMPTY_ATSTART",              PCRE2_NOTEMPTY_ATSTART },
  { "PARTIAL_SOFT",                  PCRE2_PARTIAL_SOFT },
  { "PARTIAL_HARD",                  PCRE2_PARTIAL_HARD },
  { "DFA_RESTART",                   PCRE2_DFA_RESTART },
  { "DFA_SHORTEST",                  PCRE2_DFA_SHORTEST },
  { "SUBSTITUTE_GLOBAL",             PCRE2_SUBSTITUTE_GLOBAL },
  { "SUBSTITUTE_EXTENDED",           PCRE2_SUBSTITUTE_EXTENDED },
  { "SUBSTITUTE_UNSET_EMPTY",        PCRE2_SUBSTITUTE_UNSET_EMPTY },
  { "SUBSTITUTE_UNKNOWN_UNSET",      PCRE2_SUBSTITUTE_UNKNOWN_UNSET },
  { "SUBSTITUTE_OVERFLOW_LENGTH",    PCRE2_SUBSTITUTE_OVERFLOW_LENGTH },
#ifdef PCRE2_NO_JIT
  { "NO_JIT",                        PCRE2_NO_JIT },
#endif
  { "NEWLINE_CR",                    PCRE2_NEWLINE_CR },
  { "NEWLINE_LF",                    PCRE2_NEWLINE_LF },
  { "NEWLINE_CRLF",                  PCRE2_NEWLINE_CRLF },
  { "NEWLINE_ANY",                   PCRE2_NEWLINE_ANY },
  { "NEWLINE_ANYCRLF",               PCRE2_NEWLINE_ANYCRLF },
  { "BSR_UNICODE",                   PCRE2_BSR_UNICODE },
  { "BSR_ANYCRLF",                   PCRE2_BSR_ANYCRLF },
/*---------------------------------------------------------------------------*/
  { "INFO_ALLOPTIONS",               PCRE2_INFO_ALLOPTIONS },
  { "INFO_ARGOPTIONS",               PCRE2_INFO_ARGOPTIONS },
  { "INFO_BACKREFMAX",               PCRE2_INFO_BACKREFMAX },
  { "INFO_BSR",                      PCRE2_INFO_BSR },
  { "INFO_CAPTURECOUNT",             PCRE2_INFO_CAPTURECOUNT },
  { "INFO_FIRSTCODEUNIT",            PCRE2_INFO_FIRSTCODEUNIT },
  { "INFO_FIRSTCODETYPE",            PCRE2_INFO_FIRSTCODETYPE },
  { "INFO_FIRSTBITMAP",              PCRE2_INFO_FIRSTBITMAP },
  { "INFO_HASCRORLF",                PCRE2_INFO_HASCRORLF },
  { "INFO_JCHANGED",                 PCRE2_INFO_JCHANGED },
  { "INFO_JITSIZE",                  PCRE2_INFO_JITSIZE },
  { "INFO_LASTCODEUNIT",             PCRE2_INFO_LASTCODEUNIT },
  { "INFO_LASTCODETYPE",             PCRE2_INFO_LASTCODETYPE },
  { "INFO_MATCHEMPTY",               PCRE2_INFO_MATCHEMPTY },
  { "INFO_MATCHLIMIT",               PCRE2_INFO_MATCHLIMIT },
  { "INFO_MAXLOOKBEHIND",            PCRE2_INFO_MAXLOOKBEHIND },
  { "INFO_MINLENGTH",                PCRE2_INFO_MINLENGTH },
  { "INFO_NAMECOUNT",                PCRE2_INFO_NAMECOUNT },
  { "INFO_NAMEENTRYSIZE",            PCRE2_INFO_NAMEENTRYSIZE },
  { "INFO_NAMETABLE",                PCRE2_INFO_NAMETABLE },
  { "INFO_NEWLINE",                  PCRE2_INFO_NEWLINE },
  { "INFO_RECURSIONLIMIT",           PCRE2_INFO_RECURSIONLIMIT },
  { "INFO_SIZE",                     PCRE2_INFO_SIZE },
  { "INFO_HASBACKSLASHC",            PCRE2_INFO_HASBACKSLASHC },
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

flag_pair pcre2_error_flags[] = {
  { "ERROR_NOMATCH",                 PCRE2_ERROR_NOMATCH },
  { "ERROR_PARTIAL",                 PCRE2_ERROR_PARTIAL },
  { "ERROR_UTF8_ERR1",               PCRE2_ERROR_UTF8_ERR1 },
  { "ERROR_UTF8_ERR2",               PCRE2_ERROR_UTF8_ERR2 },
  { "ERROR_UTF8_ERR3",               PCRE2_ERROR_UTF8_ERR3 },
  { "ERROR_UTF8_ERR4",               PCRE2_ERROR_UTF8_ERR4 },
  { "ERROR_UTF8_ERR5",               PCRE2_ERROR_UTF8_ERR5 },
  { "ERROR_UTF8_ERR6",               PCRE2_ERROR_UTF8_ERR6 },
  { "ERROR_UTF8_ERR7",               PCRE2_ERROR_UTF8_ERR7 },
  { "ERROR_UTF8_ERR8",               PCRE2_ERROR_UTF8_ERR8 },
  { "ERROR_UTF8_ERR9",               PCRE2_ERROR_UTF8_ERR9 },
  { "ERROR_UTF8_ERR10",              PCRE2_ERROR_UTF8_ERR10 },
  { "ERROR_UTF8_ERR11",              PCRE2_ERROR_UTF8_ERR11 },
  { "ERROR_UTF8_ERR12",              PCRE2_ERROR_UTF8_ERR12 },
  { "ERROR_UTF8_ERR13",              PCRE2_ERROR_UTF8_ERR13 },
  { "ERROR_UTF8_ERR14",              PCRE2_ERROR_UTF8_ERR14 },
  { "ERROR_UTF8_ERR15",              PCRE2_ERROR_UTF8_ERR15 },
  { "ERROR_UTF8_ERR16",              PCRE2_ERROR_UTF8_ERR16 },
  { "ERROR_UTF8_ERR17",              PCRE2_ERROR_UTF8_ERR17 },
  { "ERROR_UTF8_ERR18",              PCRE2_ERROR_UTF8_ERR18 },
  { "ERROR_UTF8_ERR19",              PCRE2_ERROR_UTF8_ERR19 },
  { "ERROR_UTF8_ERR20",              PCRE2_ERROR_UTF8_ERR20 },
  { "ERROR_UTF8_ERR21",              PCRE2_ERROR_UTF8_ERR21 },
  { "ERROR_UTF16_ERR1",              PCRE2_ERROR_UTF16_ERR1 },
  { "ERROR_UTF16_ERR2",              PCRE2_ERROR_UTF16_ERR2 },
  { "ERROR_UTF16_ERR3",              PCRE2_ERROR_UTF16_ERR3 },
  { "ERROR_UTF32_ERR1",              PCRE2_ERROR_UTF32_ERR1 },
  { "ERROR_UTF32_ERR2",              PCRE2_ERROR_UTF32_ERR2 },
  { "ERROR_BADDATA",                 PCRE2_ERROR_BADDATA },
  { "ERROR_MIXEDTABLES",             PCRE2_ERROR_MIXEDTABLES },
  { "ERROR_BADMAGIC",                PCRE2_ERROR_BADMAGIC },
  { "ERROR_BADMODE",                 PCRE2_ERROR_BADMODE },
  { "ERROR_BADOFFSET",               PCRE2_ERROR_BADOFFSET },
  { "ERROR_BADOPTION",               PCRE2_ERROR_BADOPTION },
  { "ERROR_BADREPLACEMENT",          PCRE2_ERROR_BADREPLACEMENT },
  { "ERROR_BADUTFOFFSET",            PCRE2_ERROR_BADUTFOFFSET },
  { "ERROR_CALLOUT",                 PCRE2_ERROR_CALLOUT },
  { "ERROR_DFA_BADRESTART",          PCRE2_ERROR_DFA_BADRESTART },
  { "ERROR_DFA_RECURSE",             PCRE2_ERROR_DFA_RECURSE },
  { "ERROR_DFA_UCOND",               PCRE2_ERROR_DFA_UCOND },
  { "ERROR_DFA_UFUNC",               PCRE2_ERROR_DFA_UFUNC },
  { "ERROR_DFA_UITEM",               PCRE2_ERROR_DFA_UITEM },
  { "ERROR_DFA_WSSIZE",              PCRE2_ERROR_DFA_WSSIZE },
  { "ERROR_INTERNAL",                PCRE2_ERROR_INTERNAL },
  { "ERROR_JIT_BADOPTION",           PCRE2_ERROR_JIT_BADOPTION },
  { "ERROR_JIT_STACKLIMIT",          PCRE2_ERROR_JIT_STACKLIMIT },
  { "ERROR_MATCHLIMIT",              PCRE2_ERROR_MATCHLIMIT },
  { "ERROR_NOMEMORY",                PCRE2_ERROR_NOMEMORY },
  { "ERROR_NOSUBSTRING",             PCRE2_ERROR_NOSUBSTRING },
  { "ERROR_NOUNIQUESUBSTRING",       PCRE2_ERROR_NOUNIQUESUBSTRING },
  { "ERROR_NULL",                    PCRE2_ERROR_NULL },
  { "ERROR_RECURSELOOP",             PCRE2_ERROR_RECURSELOOP },
  { "ERROR_RECURSIONLIMIT",          PCRE2_ERROR_RECURSIONLIMIT },
  { "ERROR_UNAVAILABLE",             PCRE2_ERROR_UNAVAILABLE },
  { "ERROR_UNSET",                   PCRE2_ERROR_UNSET },
  { "ERROR_BADOFFSETLIMIT",          PCRE2_ERROR_BADOFFSETLIMIT },
  { "ERROR_BADREPESCAPE",            PCRE2_ERROR_BADREPESCAPE },
  { "ERROR_REPMISSINGBRACE",         PCRE2_ERROR_REPMISSINGBRACE },
  { "ERROR_BADSUBSTITUTION",         PCRE2_ERROR_BADSUBSTITUTION },
  { "ERROR_BADSUBSPATTERN",          PCRE2_ERROR_BADSUBSPATTERN },
  { "ERROR_TOOMANYREPLACE",          PCRE2_ERROR_TOOMANYREPLACE },
#ifdef PCRE2_ERROR_BADSERIALIZEDDATA
  { "ERROR_BADSERIALIZEDDATA",       PCRE2_ERROR_BADSERIALIZEDDATA },
#endif
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

static flag_pair pcre2_config_flags[] = {
  { "PCRE2_CONFIG_BSR",              PCRE2_CONFIG_BSR },
  { "PCRE2_CONFIG_JIT",              PCRE2_CONFIG_JIT },
  { "PCRE2_CONFIG_JITTARGET",        PCRE2_CONFIG_JITTARGET },
  { "PCRE2_CONFIG_LINKSIZE",         PCRE2_CONFIG_LINKSIZE },
  { "PCRE2_CONFIG_MATCHLIMIT",       PCRE2_CONFIG_MATCHLIMIT },
  { "PCRE2_CONFIG_NEWLINE",          PCRE2_CONFIG_NEWLINE },
  { "PCRE2_CONFIG_PARENSLIMIT",      PCRE2_CONFIG_PARENSLIMIT },
  { "PCRE2_CONFIG_RECURSIONLIMIT",   PCRE2_CONFIG_RECURSIONLIMIT },
  { "PCRE2_CONFIG_STACKRECURSE",     PCRE2_CONFIG_STACKRECURSE },
  { "PCRE2_CONFIG_UNICODE",          PCRE2_CONFIG_UNICODE },
  { "PCRE2_CONFIG_UNICODE_VERSION",  PCRE2_CONFIG_UNICODE_VERSION },
  { "PCRE2_CONFIG_VERSION",          PCRE2_CONFIG_VERSION },
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

int Lpcre2_config (lua_State *L) {
  flag_pair *fp;
  if (lua_istable (L, 1))
    lua_settop (L, 1);
  else
    lua_newtable (L);
  for (fp = pcre2_config_flags; fp->key; ++fp) {
    if (fp->val == PCRE2_CONFIG_JITTARGET) {
#if PCRE2_CODE_UNIT_WIDTH == 8
      char buf[64];
      if (PCRE2_ERROR_BADOPTION != pcre2_config (fp->val, buf)) {
        lua_pushstring (L, buf);
        lua_setfield (L, -2, fp->key);
      }
#endif
    }
    else {
      int val;
      if (0 == pcre2_config (fp->val, &val)) {
        lua_pushinteger (L, val);
        lua_setfield (L, -2, fp->key);
      }
    }
  }
  return 1;
}

int Lpcre2_get_flags (lua_State *L) {
  const flag_pair* fps[] = { pcre2_flags, pcre2_error_flags, NULL };
  return get_flags (L, fps);
}

static int push_error_message (lua_State *L, int errorcode) //### is this function needed?
{
  PCRE2_UCHAR buf[256];
  if (pcre2_get_error_message(errorcode, buf, 256) > 0)
  {
    lua_pushstring(L, (const char*)buf);
    return 1;
  }
  return 0;
}

static int getcflags (lua_State *L, int pos) {
  switch (lua_type (L, pos)) {
    case LUA_TNONE:
    case LUA_TNIL:
      return ALG_CFLAGS_DFLT;
    case LUA_TNUMBER:
      return lua_tointeger (L, pos);
    case LUA_TSTRING: {
      const char *s = lua_tostring (L, pos);
      int res = 0, ch;
      while ((ch = *s++) != '\0') {
        if (ch == 'i') res |= PCRE2_CASELESS;
        else if (ch == 'm') res |= PCRE2_MULTILINE;
        else if (ch == 's') res |= PCRE2_DOTALL;
        else if (ch == 'x') res |= PCRE2_EXTENDED;
        else if (ch == 'U') res |= PCRE2_UNGREEDY;
        //else if (ch == 'X') res |= PCRE2_EXTRA; //### does not exist in PCRE2 -> reflect in manual
      }
      return res;
    }
    default:
      return luaL_typerror (L, pos, "number or string");
  }
}

static int generate_error (lua_State *L, const TPcre2 *ud, int errcode) {
  const char *key = get_flag_key (pcre2_error_flags, errcode);
  (void) ud;
  if (key)
    return luaL_error (L, "error PCRE2_%s", key);
  else
    return luaL_error (L, "PCRE2 error code %d", errcode);
}

/* method r:dfa_exec (s, [st], [ef], [ovecsize], [wscount]) */
static void checkarg_dfa_exec (lua_State *L, TArgExec *argE, TPcre2 **ud) {
  *ud = check_ud (L);
  argE->text = luaL_checklstring (L, 2, &argE->textlen);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  argE->ovecsize = (size_t)luaL_optinteger (L, 5, 100);
  argE->wscount = (size_t)luaL_optinteger (L, 6, 50);
}

static void push_chartables_meta (lua_State *L) {
  lua_pushinteger (L, INDEX_CHARTABLES_META);
  lua_rawget (L, ALG_ENVIRONINDEX);
}

static int Lpcre2_maketables (lua_State *L) {
  *(const void**)lua_newuserdata (L, sizeof(void*)) = pcre2_maketables(NULL); //### argument NULL
  push_chartables_meta (L);
  lua_setmetatable (L, -2);
  return 1;
}

static void **check_chartables (lua_State *L, int pos) {
  void **q;
  /* Compare the metatable against the C function environment. */
  if (lua_getmetatable(L, pos)) {
    push_chartables_meta (L);
    if (lua_rawequal(L, -1, -2) &&
        (q = (void **)lua_touserdata(L, pos)) != NULL) {
      lua_pop(L, 2);
      return q;
    }
  }
  luaL_argerror(L, pos, lua_pushfstring (L, "not a %s", chartables_typename));
  return NULL;
}

static int chartables_gc (lua_State *L) {
  void **ud = check_chartables (L, 1);
  if (*ud) {
    free (*ud); //### free() should be called only if pcre2_maketables was called with NULL argument
    *ud = NULL;
  }
  return 0;
}

static int chartables_tostring (lua_State *L) {
  void **ud = check_chartables (L, 1);
  lua_pushfstring (L, "%s (%p)", chartables_typename, ud);
  return 1;
}

static void checkarg_compile (lua_State *L, int pos, TArgComp *argC) {
  argC->locale = NULL;
  argC->tables = NULL;
  if (!lua_isnoneornil (L, pos)) {
    if (lua_isstring (L, pos))
      argC->locale = lua_tostring (L, pos);
    else {
      argC->tablespos = pos;
      argC->tables = (const unsigned char*) *check_chartables (L, pos);
    }
  }
}

static int compile_regex (lua_State *L, const TArgComp *argC, TPcre2 **pud) {
  int errcode;
  PCRE2_SIZE erroffset;
  TPcre2 *ud;

  ud = (TPcre2*)lua_newuserdata (L, sizeof (TPcre2));
  memset (ud, 0, sizeof (TPcre2));           /* initialize all members to 0 */
  lua_pushvalue (L, ALG_ENVIRONINDEX);
  lua_setmetatable (L, -2);

  ud->ccontext = pcre2_compile_context_create(NULL);
  if (ud->ccontext == NULL)
    return luaL_error (L, "malloc failed");

  if (argC->locale) {
    char old_locale[256];
    strcpy (old_locale, setlocale (LC_CTYPE, NULL));  /* store the locale */
    if (NULL == setlocale (LC_CTYPE, argC->locale))   /* set new locale */
      return luaL_error (L, "cannot set locale");
    ud->tables = pcre2_maketables (NULL); /* make tables with new locale */ //### argument NULL
    pcre2_set_character_tables(ud->ccontext, ud->tables);
    setlocale (LC_CTYPE, old_locale);          /* restore the old locale */
  }
  else if (argC->tables) {
    pcre2_set_character_tables(ud->ccontext, argC->tables);
    lua_pushinteger (L, INDEX_CHARTABLES_LINK);
    lua_rawget (L, ALG_ENVIRONINDEX);
    lua_pushvalue (L, -2);
    lua_pushvalue (L, argC->tablespos);
    lua_rawset (L, -3);
    lua_pop (L, 1);
  }

  ud->pr = pcre2_compile ((PCRE2_SPTR)argC->pattern, argC->patlen, argC->cflags, &errcode,
                          &erroffset, ud->ccontext); //### DOUBLE-CHECK ALL ARGUMENTS
  if (!ud->pr) {
    if (push_error_message(L, errcode))
      return luaL_error (L, "%s (pattern offset: %d)", lua_tostring(L,-1), erroffset + 1);
    else
      return luaL_error (L, "%s (pattern offset: %d)", "pattern compile error", erroffset + 1);
  }

  if (0 != pcre2_pattern_info (ud->pr, PCRE2_INFO_CAPTURECOUNT, &ud->ncapt)) //###
    return luaL_error (L, "could not get pattern info");

  /* need (2 ints per capture, plus one for substring match) * 3/2 */
  ud->match_data = pcre2_match_data_create(ud->ncapt+1, NULL); //### CHECK ALL
  if (!ud->match_data)
    return luaL_error (L, "malloc failed");

  ud->ovector = pcre2_get_ovector_pointer(ud->match_data);

  if (pud) *pud = ud;
  return 1;
}

/* the target table must be on lua stack top */
static void do_named_subpatterns (lua_State *L, TPcre2 *ud, const char *text) {
  int i, namecount, name_entry_size;
  unsigned char *name_table;
  PCRE2_SPTR tabptr;

  /* do named subpatterns - NJG */
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMECOUNT, &namecount);
  if (namecount <= 0)
    return;
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMETABLE, &name_table);
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
  tabptr = name_table;
  for (i = 0; i < namecount; i++) {
    int n = (tabptr[0] << 8) | tabptr[1]; /* number of the capturing parenthesis */
    if (n > 0 && n <= ALG_NSUB(ud)) {   /* check range */
      lua_pushstring (L, (char *)tabptr + 2); /* name of the capture, zero terminated */
      ALG_PUSHSUB_OR_FALSE (L, ud, text, n);
      lua_rawset (L, -3);
    }
    tabptr += name_entry_size;
  }
}

static int Lpcre2_dfa_exec (lua_State *L)
{
  TArgExec argE;
  TPcre2 *ud;
  int res;
  int *wspace;
  size_t wsize;

  checkarg_dfa_exec (L, &argE, &ud);
  wsize = argE.wscount * sizeof(int);
  wspace = (int*) Lmalloc (L, wsize);
  if (!wspace)
    luaL_error (L, "malloc failed");

  ud->match_data = pcre2_match_data_create(argE.ovecsize/2, NULL); //### CHECK ALL
  if (!ud->match_data)
    return luaL_error (L, "malloc failed");

  res = pcre2_dfa_match (ud->pr, (PCRE2_SPTR)argE.text, argE.textlen, argE.startoffset,
    argE.eflags, ud->match_data, NULL, wspace, argE.wscount); //### CHECK ALL

  if (ALG_ISMATCH (res) || res == PCRE2_ERROR_PARTIAL) {
    int i;
    int max = (res>0) ? res : (res==0) ? (int)argE.ovecsize/2 : 1;
    PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(ud->match_data);

    lua_pushinteger (L, ovector[0] + 1);         /* 1-st return value */
    lua_newtable (L);                            /* 2-nd return value */
    for (i=0; i<max; i++) {
      lua_pushinteger (L, ovector[i+i+1]);
      lua_rawseti (L, -2, i+1);
    }
    lua_pushinteger (L, res);                    /* 3-rd return value */
    Lfree (L, wspace, wsize);
    return 3;
  }
  else {
    Lfree (L, wspace, wsize);
    if (ALG_NOMATCH (res))
      return lua_pushnil (L), 1;
    else
      return generate_error (L, ud, res);
  }
}

static int gmatch_exec (TUserdata *ud, TArgExec *argE) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    argE->startoffset, argE->eflags, ud->match_data, NULL); //###
}

static void gmatch_pushsubject (lua_State *L, TArgExec *argE) {
  lua_pushlstring (L, argE->text, argE->textlen);
}

static int findmatch_exec (TPcre2 *ud, TArgExec *argE) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    argE->startoffset, argE->eflags, ud->match_data, NULL); //###
}

static int gsub_exec (TPcre2 *ud, TArgExec *argE, int st) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    st, argE->eflags, ud->match_data, NULL); //###
}

static int split_exec (TPcre2 *ud, TArgExec *argE, int offset) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    offset, argE->eflags, ud->match_data, NULL); //###
}

static int Lpcre2_gc (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  if (ud->freed == 0) {           /* precaution against "manual" __gc calling */
    ud->freed = 1;
    if (ud->pr) pcre2_code_free (ud->pr);
    //if (ud->tables)  pcre_free ((void *)ud->tables); //###
    if (ud->ccontext) pcre2_compile_context_free (ud->ccontext);
    if (ud->match_data) pcre2_match_data_free (ud->match_data);
  }
  return 0;
}

static int Lpcre2_tostring (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  if (ud->freed == 0)
    lua_pushfstring (L, "%s (%p)", REX_TYPENAME, (void*)ud);
  else
    lua_pushfstring (L, "%s (deleted)", REX_TYPENAME);
  return 1;
}

static int Lpcre2_version (lua_State *L) {
  char buf[64];
  pcre2_config(PCRE2_CONFIG_VERSION, buf);
  lua_pushstring (L, buf);
  return 1;
}

//### TODO: document this method.
//### TODO: write tests for this method.
static int Lpcre2_jit_compile (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  uint32_t options = (uint32_t) luaL_optinteger (L, 2, PCRE2_JIT_COMPLETE);
  int errcode = pcre2_jit_compile (ud->pr, options);
  if (errcode == 0) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  return 1 + push_error_message(L, errcode);
}

#define SET_INFO_FIELD(L,ud,what,name,valtype) { \
  valtype val; \
  if (0 == pcre2_pattern_info (ud->pr, what, &val)) { \
    lua_pushnumber (L, val); \
    lua_setfield (L, -2, name); \
  } \
}

static int Lpcre2_pattern_info (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  lua_newtable(L);

  SET_INFO_FIELD (L, ud, PCRE2_INFO_ALLOPTIONS,          "ALLOPTIONS",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_ARGOPTIONS,          "ARGOPTIONS",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_BACKREFMAX,          "BACKREFMAX",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_BSR,                 "BSR",                 uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_CAPTURECOUNT,        "CAPTURECOUNT",        uint32_t)
  //### SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTBITMAP,   "FIRSTBITMAP",         ???)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTCODETYPE,       "FIRSTCODETYPE",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTCODEUNIT,       "FIRSTCODEUNIT",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_HASBACKSLASHC,       "HASBACKSLASHC",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_HASCRORLF,           "HASCRORLF",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_JCHANGED,            "JCHANGED",            uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_JITSIZE,             "JITSIZE",             size_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_LASTCODETYPE,        "LASTCODETYPE",        uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_LASTCODEUNIT,        "LASTCODEUNIT",        uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MATCHEMPTY,          "MATCHEMPTY",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MATCHLIMIT,          "MATCHLIMIT",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MAXLOOKBEHIND,       "MAXLOOKBEHIND",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MINLENGTH,           "MINLENGTH",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMECOUNT,           "NAMECOUNT",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMEENTRYSIZE,       "NAMEENTRYSIZE",       uint32_t)
  //### SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMETABLE,     "NAMETABLE",           ???)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NEWLINE,             "NEWLINE",             uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_RECURSIONLIMIT,      "RECURSIONLIMIT",      uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_SIZE,                "SIZE",                size_t)

  return 1;
}

static const luaL_Reg chartables_meta[] = {
  { "__gc",        chartables_gc },
  { "__tostring",  chartables_tostring },
  { NULL, NULL }
};

static const luaL_Reg r_methods[] = {
  { "exec",        algm_exec },
  { "tfind",       algm_tfind },    /* old name: match */
  { "find",        algm_find },
  { "match",       algm_match },
  { "dfa_exec",    Lpcre2_dfa_exec },
  { "patterninfo", Lpcre2_pattern_info }, //### document name change: fullinfo -> patterninfo
  { "fullinfo",    Lpcre2_pattern_info }, //### compatibility name
  { "jit_compile", Lpcre2_jit_compile },
  { "__gc",        Lpcre2_gc },
  { "__tostring",  Lpcre2_tostring },
  { NULL, NULL }
};

static const luaL_Reg r_functions[] = {
  { "match",       algf_match },
  { "find",        algf_find },
  { "gmatch",      algf_gmatch },
  { "gsub",        algf_gsub },
  { "count",       algf_count },
  { "split",       algf_split },
  { "new",         algf_new },
  { "flags",       Lpcre2_get_flags },
  { "version",     Lpcre2_version },
  { "maketables",  Lpcre2_maketables },
  { "config",      Lpcre2_config },
  { NULL, NULL }
};

/* Open the library */
LUALIB_API int luaopen_rex_pcre2 (lua_State *L) {
  char buf_ver[64];
  pcre2_config(PCRE2_CONFIG_VERSION, buf_ver);
  if (PCRE2_MAJOR > atoi (buf_ver)) {
    return luaL_error (L, "%s requires at least version %d of PCRE2 library",
      REX_LIBNAME, (int)PCRE2_MAJOR);
  }

  alg_register(L, r_methods, r_functions, "PCRE2");

  /* create a table and register it as a metatable for "chartables" userdata */
  lua_newtable (L);
  lua_pushliteral (L, "access denied");
  lua_setfield (L, -2, "__metatable");
#if LUA_VERSION_NUM == 501
  luaL_register (L, NULL, chartables_meta);
  lua_rawseti (L, LUA_ENVIRONINDEX, INDEX_CHARTABLES_META);
#else
  lua_pushvalue(L, -3);
  luaL_setfuncs (L, chartables_meta, 1);
  lua_rawseti (L, -3, INDEX_CHARTABLES_META);
#endif

  /* create a table for connecting "chartables" userdata to "regex" userdata */
  lua_newtable (L);
  lua_pushliteral (L, "k");         /* weak keys */
  lua_setfield (L, -2, "__mode");
  lua_pushvalue (L, -1);            /* setmetatable (tb, tb) */
  lua_setmetatable (L, -2);
#if LUA_VERSION_NUM == 501
  lua_rawseti (L, LUA_ENVIRONINDEX, INDEX_CHARTABLES_LINK);
#else
  lua_rawseti (L, -3, INDEX_CHARTABLES_LINK);
#endif

  return 1;
}

#else
/* lrexlib.c - PCRE regular expression library */
/* Reuben Thomas   nov00-18dec04 */
/* Shmuel Zeigerman   may04-18dec04 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nse_lua.h"

#include <locale.h>

#include <nbase.h>

#ifdef HAVE_PCRE_PCRE_H
# include <pcre/pcre.h>
#else
# include <pcre.h>
#endif

#include "nse_pcrelib.h"

static int get_startoffset(lua_State *L, int stackpos, size_t len)
{
        int startoffset = luaL_optinteger(L, stackpos, 1);
        if(startoffset > 0)
                startoffset--;
        else if(startoffset < 0) {
                startoffset += (int) len;
                if(startoffset < 0)
                        startoffset = 0;
        }
        return startoffset;
}

static int udata_tostring (lua_State *L, const char* type_handle,
                const char* type_name)
{
        char buf[256];
        void *udata = luaL_checkudata(L, 1, type_handle);

        if(udata) {
                (void)Snprintf(buf, 255, "%s (%p)", type_name, udata);
                lua_pushstring(L, buf);
        }
        else {
                (void)Snprintf(buf, 255, "must be userdata of type '%s'", type_name);
                (void)luaL_argerror(L, 1, buf);
        }

        free(udata);
        return 1;
}

typedef struct { const char* key; lua_Integer val; } flags_pair;

static int get_flags (lua_State *L, const flags_pair *arr)
{
        const flags_pair *p;
        lua_newtable(L);
        for(p=arr; p->key != NULL; p++) {
                lua_pushstring(L, p->key);
                lua_pushinteger(L, p->val);
                lua_rawset(L, -3);
        }
        return 1;
}

const char pcre_handle[] = "pcre_regex_handle";
const char pcre_typename[] = "pcre_regex";

typedef struct {
        pcre *pr;
        pcre_extra *extra;
        int *match;
        int ncapt;
        const unsigned char *tables;
} pcre2;      /* a better name is needed */

static const unsigned char *Lpcre_maketables(lua_State *L, int stackpos)
{
        const unsigned char *tables;
        char old_locale[256];
        char *locale = strdup(luaL_checkstring(L, stackpos));

        if(locale == NULL)
                luaL_error(L, "cannot set locale");

        strncpy(old_locale, setlocale(LC_CTYPE, NULL), 255); /* store the locale */

        if(setlocale(LC_CTYPE, locale) == NULL)        /* set new locale */
                luaL_error(L, "cannot set locale");

        tables = pcre_maketables();              /* make tables with new locale */
        (void)setlocale(LC_CTYPE, old_locale);         /* restore the old locale */

        free(locale);
        return tables;
}

static int Lpcre_comp(lua_State *L)
{
        char buf[256];
        const char *error;
        int erroffset;
        pcre2 *ud;
        const char *pattern = luaL_checkstring(L, 1);
        int cflags = luaL_optinteger(L, 2, 0);
        const unsigned char *tables = NULL;

        if(lua_gettop(L) > 2 && !lua_isnil(L, 3))
                tables = Lpcre_maketables(L, 3);
        if(tables == NULL)
                luaL_error(L, "PCRE compilation failed");

        ud = (pcre2*)lua_newuserdata(L, sizeof(pcre2));
        luaL_getmetatable(L, pcre_handle);
        (void)lua_setmetatable(L, -2);
        ud->match = NULL;
        ud->extra = NULL;
        ud->tables = tables; /* keep this for eventual freeing */

        ud->pr = pcre_compile(pattern, cflags, &error, &erroffset, tables);
        if(!ud->pr) {
                (void)Snprintf(buf, 255, "%s (pattern offset: %d)", error, erroffset+1);
                /* show offset 1-based as it's common in Lua */
                luaL_error(L, buf);
        }

        ud->extra = pcre_study(ud->pr, 0, &error);
        if(error) luaL_error(L, error);

        pcre_fullinfo(ud->pr, ud->extra, PCRE_INFO_CAPTURECOUNT, &ud->ncapt);
        /* need (2 ints per capture, plus one for substring match) * 3/2 */
        ud->match = (int *) safe_malloc((ud->ncapt + 1) * 3 * sizeof(int));

        return 1;
}

static void Lpcre_getargs(lua_State *L, pcre2 **pud, const char **text,
                size_t *text_len)
{
        *pud = (pcre2 *)luaL_checkudata(L, 1, pcre_handle);
        if(*pud == NULL)
                (void)luaL_argerror(L, 1, ("compiled regexp expected"));
        *text = luaL_checklstring(L, 2, text_len);
}

typedef void (*Lpcre_push_matches) (lua_State *L, const char *text, pcre2 *ud);

static void Lpcre_push_substrings (lua_State *L, const char *text, pcre2 *ud)
{
        unsigned int i, j;
        unsigned int namecount;
        unsigned char *name_table;
        int name_entry_size;
        unsigned char *tabptr;
        const int *match = ud->match;

        lua_newtable(L);
        for (i = 1; i <= (unsigned) ud->ncapt; i++) {
                j = i * 2;
                if (match[j] >= 0)
                        lua_pushlstring(L, text + match[j], (size_t)(match[j + 1] - match[j]));
                else
                        lua_pushboolean(L, 0);
                lua_rawseti(L, -2, i);
        }

        /* now do named subpatterns - NJG */
        (void)pcre_fullinfo(ud->pr, ud->extra, PCRE_INFO_NAMECOUNT, &namecount);
        if (namecount <= 0)
                return;
        (void)pcre_fullinfo(ud->pr, ud->extra, PCRE_INFO_NAMETABLE, &name_table);
        (void)pcre_fullinfo(ud->pr, ud->extra, PCRE_INFO_NAMEENTRYSIZE, &name_entry_size);
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
                unsigned int n = (tabptr[0] << 8) | tabptr[1]; /* number of the capturing parenthesis */
                if (n > 0 && n <= (unsigned) ud->ncapt) {   /* check range */
                        unsigned int j = n * 2;
                        lua_pushstring(L, (char*)tabptr + 2); /* name of the capture, zero terminated */
                        if (match[j] >= 0)
                                lua_pushlstring(L, text + match[j], match[j + 1] - match[j]);
                        else
                                lua_pushboolean(L, 0);
                        lua_rawset(L, -3);
                }
                tabptr += name_entry_size;
        }
}

static void Lpcre_push_offsets (lua_State *L, const char *text, pcre2 * ud)
{
        unsigned int i, j, k;
        if(text) {
                /* suppress compiler warning */
        }
        lua_newtable(L);
        for (i=1, j=1; i <= (unsigned) ud->ncapt; i++) {
                k = i * 2;
                if (ud->match[k] >= 0) {
                        lua_pushinteger(L, ud->match[k] + 1);
                        lua_rawseti(L, -2, j++);
                        lua_pushinteger(L, ud->match[k+1]);
                        lua_rawseti(L, -2, j++);
                }
                else {
                        lua_pushboolean(L, 0);
                        lua_rawseti(L, -2, j++);
                        lua_pushboolean(L, 0);
                        lua_rawseti(L, -2, j++);
                }
        }
}

static int Lpcre_match_generic(lua_State *L, Lpcre_push_matches push_matches)
{
        int res;
        const char *text;
        pcre2 *ud;
        size_t elen;
        int startoffset;
        int eflags = luaL_optinteger(L, 4, 0);

        Lpcre_getargs(L, &ud, &text, &elen);
        startoffset = get_startoffset(L, 3, elen);

        res = pcre_exec(ud->pr, ud->extra, text, (int)elen, startoffset, eflags,
                        ud->match, (ud->ncapt + 1) * 3);
        if (res >= 0) {
                lua_pushinteger(L, (lua_Number) ud->match[0] + 1);
                lua_pushinteger(L, (lua_Number) ud->match[1]);
                (*push_matches)(L, text, ud);
                return 3;
        }
        return 0;
}

static int Lpcre_match(lua_State *L)
{
        return Lpcre_match_generic(L, Lpcre_push_substrings);
}

static int Lpcre_exec(lua_State *L)
{
        return Lpcre_match_generic(L, Lpcre_push_offsets);
}

static int Lpcre_gmatch(lua_State *L)
{
        int res;
        size_t len;
        int nmatch = 0, limit = 0;
        const char *text;
        pcre2 *ud;
        int maxmatch = luaL_optinteger(L, 4, 0);
        int eflags = luaL_optinteger(L, 5, 0);
        int startoffset = 0;
        Lpcre_getargs(L, &ud, &text, &len);
        luaL_checktype(L, 3, LUA_TFUNCTION);

        if(maxmatch > 0) /* this must be stated in the docs */
                limit = 1;

        while (!limit || nmatch < maxmatch) {
                res = pcre_exec(ud->pr, ud->extra, text, (int)len, startoffset, eflags,
                                ud->match, (ud->ncapt + 1) * 3);
                if (res >= 0) {
                        nmatch++;
                        lua_pushvalue(L, 3);
                        lua_pushlstring(L, text + ud->match[0], ud->match[1] - ud->match[0]);
                        Lpcre_push_substrings(L, text, ud);
                        lua_call(L, 2, 1);
                        if(lua_toboolean(L, -1))
                                break;
                        lua_pop(L, 1);
                        startoffset = ud->match[1];
                } else
                        break;
        }
        lua_pushinteger(L, nmatch);
        return 1;
}

static int Lpcre_gc (lua_State *L)
{
        pcre2 *ud = (pcre2 *)luaL_checkudata(L, 1, pcre_handle);
        if (ud) {
                if(ud->pr)      pcre_free(ud->pr);
                if(ud->extra)   pcre_free(ud->extra);
                if(ud->tables)  pcre_free((void *)ud->tables);
                if(ud->match)   free(ud->match);
        }
        return 0;
}

static int Lpcre_tostring (lua_State *L) {
        return udata_tostring(L, pcre_handle, pcre_typename);
}

static int Lpcre_vers (lua_State *L)
{
        lua_pushstring(L, pcre_version());
        return 1;
}

static flags_pair pcre_flags[] =
{
        { "CASELESS",        PCRE_CASELESS },
        { "MULTILINE",       PCRE_MULTILINE },
        { "DOTALL",          PCRE_DOTALL },
        { "EXTENDED",        PCRE_EXTENDED },
        { "ANCHORED",        PCRE_ANCHORED },
        { "DOLLAR_ENDONLY",  PCRE_DOLLAR_ENDONLY },
        { "EXTRA",           PCRE_EXTRA },
        { "NOTBOL",          PCRE_NOTBOL },
        { "NOTEOL",          PCRE_NOTEOL },
        { "UNGREEDY",        PCRE_UNGREEDY },
        { "NOTEMPTY",        PCRE_NOTEMPTY },
        { "UTF8",            PCRE_UTF8 },
#if PCRE_MAJOR >= 4
        { "NO_AUTO_CAPTURE", PCRE_NO_AUTO_CAPTURE },
        { "NO_UTF8_CHECK",   PCRE_NO_UTF8_CHECK },
#endif
#ifdef PCRE_AUTO_CALLOUT
        { "AUTO_CALLOUT",    PCRE_AUTO_CALLOUT },
#endif
#ifdef PCRE_PARTIAL
        { "PARTIAL",         PCRE_PARTIAL },
#endif
#ifdef PCRE_DFA_SHORTEST
        { "DFA_SHORTEST",    PCRE_DFA_SHORTEST },
#endif
#ifdef PCRE_DFA_RESTART
        { "DFA_RESTART",     PCRE_DFA_RESTART },
#endif
#ifdef PCRE_FIRSTLINE
        { "FIRSTLINE",       PCRE_FIRSTLINE },
#endif
#ifdef PCRE_DUPNAMES
        { "DUPNAMES",        PCRE_DUPNAMES },
#endif
#ifdef PCRE_NEWLINE_CR
        { "NEWLINE_CR",      PCRE_NEWLINE_CR },
#endif
#ifdef PCRE_NEWLINE_LF
        { "NEWLINE_LF",      PCRE_NEWLINE_LF },
#endif
#ifdef PCRE_NEWLINE_CRLF
        { "NEWLINE_CRLF",    PCRE_NEWLINE_CRLF },
#endif
#ifdef PCRE_NEWLINE_ANY
        { "NEWLINE_ANY",     PCRE_NEWLINE_ANY },
#endif
#ifdef PCRE_NEWLINE_ANYCRLF
        { "NEWLINE_ANYCRLF", PCRE_NEWLINE_ANYCRLF },
#endif
#ifdef PCRE_BSR_ANYCRLF
        { "BSR_ANYCRLF",     PCRE_BSR_ANYCRLF },
#endif
#ifdef PCRE_BSR_UNICODE
        { "BSR_UNICODE",     PCRE_BSR_UNICODE },
#endif
        { NULL, 0 }
};

static int Lpcre_get_flags (lua_State *L) {
        return get_flags(L, pcre_flags);
}

static const luaL_Reg pcremeta[] = {
        {"exec",       Lpcre_exec},
        {"match",      Lpcre_match},
        {"gmatch",     Lpcre_gmatch},
        {"__gc",       Lpcre_gc},
        {"__tostring", Lpcre_tostring},
        {NULL, NULL}
};

/* Open the library */
static const luaL_Reg pcrelib[] = {
        {"new",	Lpcre_comp},
        {"flags", Lpcre_get_flags},
        {"version", Lpcre_vers},
        {NULL, NULL}
};

LUALIB_API int luaopen_pcrelib(lua_State *L)
{
        luaL_newmetatable(L, pcre_handle);
        lua_pushliteral(L, "__index");
        luaL_newlib(L, pcremeta);
        lua_rawset(L, -3);
        lua_pop(L, 1);

        luaL_newlib(L, pcrelib);

        return 1;
}
#endif
