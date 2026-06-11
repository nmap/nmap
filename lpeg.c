/*
** LPeg 1.1.0 Amalgamated version for Nmap
** Generated automatically by amalgamate_lpeg.py
*/

/* ==========================================================================
** File: lptypes.h
** ==========================================================================
*/

/*
** LPeg - PEG pattern matching for Lua
** Copyright 2007-2023, Lua.org & PUC-Rio  (see 'lpeg.html' for license)
** written by Roberto Ierusalimschy
*/

#if !defined(lptypes_h)
#define lptypes_h


#include <assert.h>
#include <limits.h>
#include <string.h>

#include "lua.h"


#define VERSION         "1.1.0"


#define PATTERN_T	"lpeg-pattern"
#define MAXSTACKIDX	"lpeg-maxstack"


/*
** compatibility with Lua 5.1
*/
#if (LUA_VERSION_NUM == 501)

#define lp_equal	lua_equal

#define lua_getuservalue	lua_getfenv
#define lua_setuservalue	lua_setfenv

#define lua_rawlen		lua_objlen

#define luaL_setfuncs(L,f,n)	luaL_register(L,NULL,f)
#define luaL_newlib(L,f)	luaL_register(L,"lpeg",f)

typedef size_t lua_Unsigned;

#endif


#if !defined(lp_equal)
#define lp_equal(L,idx1,idx2)  lua_compare(L,(idx1),(idx2),LUA_OPEQ)
#endif


/* default maximum size for call/backtrack stack */
#if !defined(MAXBACK)
#define MAXBACK         400
#endif


/* maximum number of rules in a grammar (limited by 'unsigned short') */
#if !defined(MAXRULES)
#define MAXRULES        1000
#endif



/* initial size for capture's list */
#define INITCAPSIZE	32


/* index, on Lua stack, for subject */
#define SUBJIDX		2

/* number of fixed arguments to 'match' (before capture arguments) */
#define FIXEDARGS	3

/* index, on Lua stack, for capture list */
#define caplistidx(ptop)	((ptop) + 2)

/* index, on Lua stack, for pattern's ktable */
#define ktableidx(ptop)		((ptop) + 3)

/* index, on Lua stack, for backtracking stack */
#define stackidx(ptop)	((ptop) + 4)



typedef unsigned char byte;

typedef unsigned int uint;


#define BITSPERCHAR		8

#define CHARSETSIZE		((UCHAR_MAX/BITSPERCHAR) + 1)



typedef struct Charset {
  byte cs[CHARSETSIZE];
} Charset;



#define loopset(v,b)    { int v; for (v = 0; v < CHARSETSIZE; v++) {b;} }

#define fillset(s,c)	memset(s,c,CHARSETSIZE)
#define clearset(s)	fillset(s,0)

/* number of slots needed for 'n' bytes */
#define bytes2slots(n)  (((n) - 1u) / (uint)sizeof(TTree) + 1u)

/* set 'b' bit in charset 'cs' */
#define setchar(cs,b)   ((cs)[(b) >> 3] |= (1 << ((b) & 7)))


/*
** in capture instructions, 'kind' of capture and its offset are
** packed in field 'aux', 4 bits for each
*/
#define getkind(op)		((op)->i.aux1 & 0xF)
#define getoff(op)		(((op)->i.aux1 >> 4) & 0xF)
#define joinkindoff(k,o)	((k) | ((o) << 4))

#define MAXOFF		0xF
#define MAXAUX		0xFF


/* maximum number of bytes to look behind */
#define MAXBEHIND	MAXAUX


/* maximum size (in elements) for a pattern */
#define MAXPATTSIZE	(SHRT_MAX - 10)


/* size (in instructions) for l bytes (l > 0) */
#define instsize(l) ((int)(((l) + (uint)sizeof(Instruction) - 1u) \
			/ (uint)sizeof(Instruction)))


/* size (in elements) for a ISet instruction */
#define CHARSETINSTSIZE		(1 + instsize(CHARSETSIZE))

/* size (in elements) for a IFunc instruction */
#define funcinstsize(p)		((p)->i.aux + 2)



#define testchar(st,c)	((((uint)(st)[((c) >> 3)]) >> ((c) & 7)) & 1)


#endif



/* ==========================================================================
** File: lptree.h
** ==========================================================================
*/


#if !defined(lptree_h)
#define lptree_h


/* #include "lptypes.h" -- stripped */


/*
** types of trees
*/
typedef enum TTag {
  TChar = 0,  /* 'n' = char */
  TSet,  /* the set is encoded in 'u.set' and the next 'u.set.size' bytes */
  TAny,
  TTrue,
  TFalse,
  TUTFR,  /* range of UTF-8 codepoints; 'n' has initial codepoint;
             'cap' has length; 'key' has first byte;
             extra info is similar for end codepoint */
  TRep,  /* 'sib1'* */
  TSeq,  /* 'sib1' 'sib2' */
  TChoice,  /* 'sib1' / 'sib2' */
  TNot,  /* !'sib1' */
  TAnd,  /* &'sib1' */
  TCall,  /* ktable[key] is rule's key; 'sib2' is rule being called */
  TOpenCall,  /* ktable[key] is rule's key */
  TRule,  /* ktable[key] is rule's key (but key == 0 for unused rules);
             'sib1' is rule's pattern pre-rule; 'sib2' is next rule;
             extra info 'n' is rule's sequential number */
  TXInfo,  /* extra info */
  TGrammar,  /* 'sib1' is initial (and first) rule */
  TBehind,  /* 'sib1' is pattern, 'n' is how much to go back */
  TCapture,  /* captures: 'cap' is kind of capture (enum 'CapKind');
                ktable[key] is Lua value associated with capture;
                'sib1' is capture body */
  TRunTime  /* run-time capture: 'key' is Lua function;
               'sib1' is capture body */
} TTag;


/*
** Tree trees
** The first child of a tree (if there is one) is immediately after
** the tree.  A reference to a second child (ps) is its position
** relative to the position of the tree itself.
*/
typedef struct TTree {
  byte tag;
  byte cap;  /* kind of capture (if it is a capture) */
  unsigned short key;  /* key in ktable for Lua data (0 if no key) */
  union {
    int ps;  /* occasional second child */
    int n;  /* occasional counter */
    struct {
      byte offset;  /* compact set offset (in bytes) */
      byte size;  /* compact set size (in bytes) */
      byte deflt;  /* default value */
      byte bitmap[1];  /* bitmap (open array) */
    } set;  /* for compact sets */
  } u;
} TTree;


/* access to charset */
#define treebuffer(t)      ((t)->u.set.bitmap)


/*
** A complete pattern has its tree plus, if already compiled,
** its corresponding code
*/
typedef struct Pattern {
  union Instruction *code;
  TTree tree[1];
} Pattern;


/* number of children for each tree */
extern const byte numsiblings[];

/* access to children */
#define sib1(t)         ((t) + 1)
#define sib2(t)         ((t) + (t)->u.ps)






#endif



/* ==========================================================================
** File: lpcap.h
** ==========================================================================
*/


#if !defined(lpcap_h)
#define lpcap_h


/* #include "lptypes.h" -- stripped */


/* kinds of captures */
typedef enum CapKind {
  Cclose,  /* not used in trees */
  Cposition,
  Cconst,  /* ktable[key] is Lua constant */
  Cbackref,  /* ktable[key] is "name" of group to get capture */
  Carg,  /* 'key' is arg's number */
  Csimple,  /* next node is pattern */
  Ctable,  /* next node is pattern */
  Cfunction,  /* ktable[key] is function; next node is pattern */
  Cacc,  /* ktable[key] is function; next node is pattern */
  Cquery,  /* ktable[key] is table; next node is pattern */
  Cstring,  /* ktable[key] is string; next node is pattern */
  Cnum,  /* numbered capture; 'key' is number of value to return */
  Csubst,  /* substitution capture; next node is pattern */
  Cfold,  /* ktable[key] is function; next node is pattern */
  Cruntime,  /* not used in trees (is uses another type for tree) */
  Cgroup  /* ktable[key] is group's "name" */
} CapKind;


/*
** An unsigned integer large enough to index any subject entirely.
** It can be size_t, but that will double the size of the array
** of captures in a 64-bit machine.
*/
#if !defined(Index_t)
typedef uint Index_t;
#endif

#define MAXINDT		(~(Index_t)0)


typedef struct Capture {
  Index_t index;  /* subject position */
  unsigned short idx;  /* extra info (group name, arg index, etc.) */
  byte kind;  /* kind of capture */
  byte siz;  /* size of full capture + 1 (0 = not a full capture) */
} Capture;


typedef struct CapState {
  Capture *cap;  /* current capture */
  Capture *ocap;  /* (original) capture list */
  lua_State *L;
  int ptop;  /* stack index of last argument to 'match' */
  int firstcap;  /* stack index of first capture pushed in the stack */
  const char *s;  /* original string */
  int valuecached;  /* value stored in cache slot */
  int reclevel;  /* recursion level */
} CapState;


#define captype(cap)    ((cap)->kind)

#define isclosecap(cap) (captype(cap) == Cclose)
#define isopencap(cap)  ((cap)->siz == 0)

/* true if c2 is (any number of levels) inside c1 */
#define capinside(c1,c2)  \
	(isopencap(c1) ? !isclosecap(c2) \
                       : (c2)->index < (c1)->index + (c1)->siz - 1)


/**
** Maximum number of captures to visit when looking for an 'open'.
*/
#define MAXLOP		20



int runtimecap (CapState *cs, Capture *close, const char *s, int *rem);
int getcaptures (lua_State *L, const char *s, const char *r, int ptop);
int finddyncap (Capture *cap, Capture *last);

#endif




/* ==========================================================================
** File: lpvm.h
** ==========================================================================
*/


#if !defined(lpvm_h)
#define lpvm_h

/* #include "lpcap.h" -- stripped */


/*
** About Character sets in instructions: a set is a bit map with an
** initial offset, in bits, and a size, in number of instructions.
** aux1 has the default value for the bits outsize that range.
*/


/* Virtual Machine's instructions */
typedef enum Opcode {
  IAny, /* if no char, fail */
  IChar,  /* if char != aux1, fail */
  ISet,  /* if char not in set, fail */
  ITestAny,  /* in no char, jump to 'offset' */
  ITestChar,  /* if char != aux1, jump to 'offset' */
  ITestSet,  /* if char not in set, jump to 'offset' */
  ISpan,  /* read a span of chars in set */
  IUTFR,  /* if codepoint not in range [offset, utf_to], fail */
  IBehind,  /* walk back 'aux1' characters (fail if not possible) */
  IRet,  /* return from a rule */
  IEnd,  /* end of pattern */
  IChoice,  /* stack a choice; next fail will jump to 'offset' */
  IJmp,  /* jump to 'offset' */
  ICall,  /* call rule at 'offset' */
  IOpenCall,  /* call rule number 'key' (must be closed to a ICall) */
  ICommit,  /* pop choice and jump to 'offset' */
  IPartialCommit,  /* update top choice to current position and jump */
  IBackCommit,  /* backtrack like "fail" but jump to its own 'offset' */
  IFailTwice,  /* pop one choice and then fail */
  IFail,  /* go back to saved state on choice and jump to saved offset */
  IGiveup,  /* internal use */
  IFullCapture,  /* complete capture of last 'off' chars */
  IOpenCapture,  /* start a capture */
  ICloseCapture,
  ICloseRunTime,
  IEmpty  /* to fill empty slots left by optimizations */
} Opcode;


/*
** All array of instructions has a 'codesize' as its first element
** and is referred by a pointer to its second element, which is the
** first actual opcode.
*/
typedef union Instruction {
  struct Inst {
    byte code;
    byte aux1;
    union {
      short key;
      struct {
        byte offset;
        byte size;
      } set;
    } aux2;
  } i;
  int offset;
  uint codesize;
  byte buff[1];
} Instruction;


/* extract 24-bit value from an instruction */
#define utf_to(inst)	(((inst)->i.aux2.key << 8) | (inst)->i.aux1)


int charinset (const Instruction *i, const byte *buff, uint c);
const char *match (lua_State *L, const char *o, const char *s, const char *e,
                   Instruction *op, Capture *capture, int ptop);


#endif



/* ==========================================================================
** File: lpcset.h
** ==========================================================================
*/


#if !defined(lpset_h)
#define lpset_h

/* #include "lpcset.h" -- stripped */
/* #include "lpcode.h" -- stripped */
/* #include "lptree.h" -- stripped */


/*
** Extra information for the result of 'charsettype'.  When result is
** IChar, 'offset' is the character.  When result is ISet, 'cs' is the
** supporting bit array (with offset included), 'offset' is the offset
** (in bytes), 'size' is the size (in bytes), and 'delt' is the default
** value for bytes outside the set.
*/
typedef struct {
  const byte *cs;
  int offset;
  int size;
  int deflt;
} charsetinfo;


int tocharset (TTree *tree, Charset *cs);
Opcode charsettype (const byte *cs, charsetinfo *info);
byte getbytefromcharset (const charsetinfo *info, int index);
void tree2cset (TTree *tree, charsetinfo *info);

#endif


/* ==========================================================================
** File: lpcode.h
** ==========================================================================
*/


#if !defined(lpcode_h)
#define lpcode_h

#include "lua.h"

/* #include "lptypes.h" -- stripped */
/* #include "lptree.h" -- stripped */
/* #include "lpvm.h" -- stripped */

int checkaux (TTree *tree, int pred);
int fixedlen (TTree *tree);
int hascaptures (TTree *tree);
int lp_gc (lua_State *L);
Instruction *compile (lua_State *L, Pattern *p, uint size);
void freecode (lua_State *L, Pattern *p);
int sizei (const Instruction *i);


#define PEnullable      0
#define PEnofail        1

/*
** nofail(t) implies that 't' cannot fail with any input
*/
#define nofail(t)	checkaux(t, PEnofail)

/*
** (not nullable(t)) implies 't' cannot match without consuming
** something
*/
#define nullable(t)	checkaux(t, PEnullable)



#endif


/* ==========================================================================
** File: lpprint.h
** ==========================================================================
*/


#if !defined(lpprint_h)
#define lpprint_h


/* #include "lptree.h" -- stripped */
/* #include "lpvm.h" -- stripped */


#if defined(LPEG_DEBUG)

void printpatt (Instruction *p);
void printtree (TTree *tree, int ident);
void printktable (lua_State *L, int idx);
void printcharset (const byte *st);
void printcaplist (Capture *cap);
void printinst (const Instruction *op, const Instruction *p);

#else

#define printktable(L,idx)  \
	luaL_error(L, "function only implemented in debug mode")
#define printtree(tree,i)  \
	luaL_error(L, "function only implemented in debug mode")
#define printpatt(p)  \
	luaL_error(L, "function only implemented in debug mode")

#endif


#endif



/* ==========================================================================
** File: lpcset.c
** ==========================================================================
*/


/* #include "lptypes.h" -- stripped */
/* #include "lpcset.h" -- stripped */


/*
** Add to 'c' the index of the (only) bit set in byte 'b'
*/
static int onlybit (int c, int b) {
  if ((b & 0xF0) != 0) { c += 4; b >>= 4; }
  if ((b & 0x0C) != 0) { c += 2; b >>= 2; }
  if ((b & 0x02) != 0) { c += 1; }
  return c;
}


/*
** Check whether a charset is empty (returns IFail), singleton (IChar),
** full (IAny), or none of those (ISet). When singleton, 'info.offset'
** returns which character it is. When generic set, 'info' returns
** information about its range.
*/
Opcode charsettype (const byte *cs, charsetinfo *info) {
  int low0, low1, high0, high1;
  for (low1 = 0; low1 < CHARSETSIZE && cs[low1] == 0; low1++)
    /* find lowest byte with a 1-bit */;
  if (low1 == CHARSETSIZE)
    return IFail;  /* no characters in set */
  for (high1 = CHARSETSIZE - 1; cs[high1] == 0; high1--)
    /* find highest byte with a 1-bit; low1 is a sentinel */;
  if (low1 == high1) {  /* only one byte with 1-bits? */
    int b = cs[low1];
    if ((b & (b - 1)) == 0) {  /* does byte has only one 1-bit? */
      info->offset = onlybit(low1 * BITSPERCHAR, b);  /* get that bit */
      return IChar;  /* single character */
    }
  }
  for (low0 = 0; low0 < CHARSETSIZE && cs[low0] == 0xFF; low0++)
    /* find lowest byte with a 0-bit */;
  if (low0 == CHARSETSIZE)
    return IAny;  /* set has all bits set */
  for (high0 = CHARSETSIZE - 1; cs[high0] == 0xFF; high0--)
    /* find highest byte with a 0-bit; low0 is a sentinel */;
  if (high1 - low1 <= high0 - low0) {  /* range of 1s smaller than of 0s? */
    info->offset = low1;
    info->size = high1 - low1 + 1;
    info->deflt = 0;  /* all discharged bits were 0 */
  }
  else {
    info->offset = low0;
    info->size = high0 - low0 + 1;
    info->deflt = 0xFF;  /* all discharged bits were 1 */
  }
  info->cs = cs + info->offset;
  return ISet;
}


/*
** Get a byte from a compact charset. If index is inside the charset
** range, get the byte from the supporting charset (correcting it
** by the offset). Otherwise, return the default for the set.
*/
byte getbytefromcharset (const charsetinfo *info, int index) {
  if (index < info->size)
    return info->cs[index];
  else return info->deflt;
}


/*
** If 'tree' is a 'char' pattern (TSet, TChar, TAny, TFalse), convert it
** into a charset and return 1; else return 0.
*/
int tocharset (TTree *tree, Charset *cs) {
  switch (tree->tag) {
    case TChar: {  /* only one char */
      assert(0 <= tree->u.n && tree->u.n <= UCHAR_MAX);
      clearset(cs->cs);  /* erase all chars */
      setchar(cs->cs, tree->u.n);  /* add that one */
      return 1;
    }
    case TAny: {
      fillset(cs->cs, 0xFF);  /* add all characters to the set */
      return 1;
    }
    case TFalse: {
      clearset(cs->cs);  /* empty set */
      return 1;
    }
    case TSet: {  /* fill set */
      int i;
      fillset(cs->cs, tree->u.set.deflt);
      for (i = 0; i < tree->u.set.size; i++)
        cs->cs[tree->u.set.offset + i] = treebuffer(tree)[i];
      return 1;
    }
    default: return 0;
  }
}


void tree2cset (TTree *tree, charsetinfo *info) {
  assert(tree->tag == TSet);
  info->offset = tree->u.set.offset;
  info->size = tree->u.set.size;
  info->deflt = tree->u.set.deflt;
  info->cs = treebuffer(tree);
}



/* ==========================================================================
** File: lpcap.c
** ==========================================================================
*/


#include "lua.h"
#include "lauxlib.h"

/* #include "lpcap.h" -- stripped */
/* #include "lpprint.h" -- stripped */
/* #include "lptypes.h" -- stripped */


#define getfromktable(cs,v)	lua_rawgeti((cs)->L, ktableidx((cs)->ptop), v)

#define pushluaval(cs)		getfromktable(cs, (cs)->cap->idx)



#define skipclose(cs,head)  \
	if (isopencap(head)) { assert(isclosecap(cs->cap)); cs->cap++; }


/*
** Return the size of capture 'cap'. If it is an open capture, 'close'
** must be its corresponding close.
*/
static Index_t capsize (Capture *cap, Capture *close) {
  if (isopencap(cap)) {
    assert(isclosecap(close));
    return close->index - cap->index;
  }
  else
    return cap->siz - 1;
}


static Index_t closesize (CapState *cs, Capture *head) {
  return capsize(head, cs->cap);
}


/*
** Put at the cache for Lua values the value indexed by 'v' in ktable
** of the running pattern (if it is not there yet); returns its index.
*/
static int updatecache (CapState *cs, int v) {
  int idx = cs->ptop + 1;  /* stack index of cache for Lua values */
  if (v != cs->valuecached) {  /* not there? */
    getfromktable(cs, v);  /* get value from 'ktable' */
    lua_replace(cs->L, idx);  /* put it at reserved stack position */
    cs->valuecached = v;  /* keep track of what is there */
  }
  return idx;
}


static int pushcapture (CapState *cs);


/*
** Goes back in a list of captures looking for an open capture
** corresponding to a close one.
*/
static Capture *findopen (Capture *cap) {
  int n = 0;  /* number of closes waiting an open */
  for (;;) {
    cap--;
    if (isclosecap(cap)) n++;  /* one more open to skip */
    else if (isopencap(cap))
      if (n-- == 0) return cap;
  }
}


/*
** Go to the next capture at the same level.
*/
static void nextcap (CapState *cs) {
  Capture *cap = cs->cap;
  if (isopencap(cap)) {  /* must look for a close? */
    int n = 0;  /* number of opens waiting a close */
    for (;;) {  /* look for corresponding close */
      cap++;
      if (isopencap(cap)) n++;
      else if (isclosecap(cap))
        if (n-- == 0) break;
    }
    cs->cap = cap + 1;  /* + 1 to skip last close */
  }
  else {
    Capture *next;
    for (next = cap + 1; capinside(cap, next); next++)
      ;  /* skip captures inside current one */
    cs->cap = next;
  }
}


/*
** Push on the Lua stack all values generated by nested captures inside
** the current capture. Returns number of values pushed. 'addextra'
** makes it push the entire match after all captured values. The
** entire match is pushed also if there are no other nested values,
** so the function never returns zero.
*/
static int pushnestedvalues (CapState *cs, int addextra) {
  Capture *head = cs->cap++;  /* original capture */
  int n = 0;  /* number of pushed subvalues */
  /* repeat for all nested patterns */
  while (capinside(head, cs->cap))
    n += pushcapture(cs);
  if (addextra || n == 0) {  /* need extra? */
    lua_pushlstring(cs->L, cs->s + head->index, closesize(cs, head));
    n++;
  }
  skipclose(cs, head);
  return n;
}


/*
** Push only the first value generated by nested captures
*/
static void pushonenestedvalue (CapState *cs) {
  int n = pushnestedvalues(cs, 0);
  if (n > 1)
    lua_pop(cs->L, n - 1);  /* pop extra values */
}


/*
** Checks whether group 'grp' is visible to 'ref', that is, 'grp' is
** not nested inside a full capture that does not contain 'ref'.  (We
** only need to care for full captures because the search at 'findback'
** skips open-end blocks; so, if 'grp' is nested in a non-full capture,
** 'ref' is also inside it.)  To check this, we search backward for the
** inner full capture enclosing 'grp'.  A full capture cannot contain
** non-full captures, so a close capture means we cannot be inside a
** full capture anymore.
*/
static int capvisible (CapState *cs, Capture *grp, Capture *ref) {
  Capture *cap = grp;
  int i = MAXLOP;  /* maximum distance for an 'open' */
  while (i-- > 0 && cap-- > cs->ocap) {
    if (isclosecap(cap))
      return 1;  /* can stop the search */
    else if (grp->index - cap->index >= UCHAR_MAX)
      return 1;  /* can stop the search */
    else if (capinside(cap, grp))  /* is 'grp' inside cap? */
      return capinside(cap, ref);  /* ok iff cap also contains 'ref' */
  }
  return 1;  /* 'grp' is not inside any capture */
}


/*
** Try to find a named group capture with the name given at the top of
** the stack; goes backward from 'ref'.
*/
static Capture *findback (CapState *cs, Capture *ref) {
  lua_State *L = cs->L;
  Capture *cap = ref;
  while (cap-- > cs->ocap) {  /* repeat until end of list */
    if (isclosecap(cap))
      cap = findopen(cap);  /* skip nested captures */
    else if (capinside(cap, ref))
      continue;  /* enclosing captures are not visible to 'ref' */
    if (captype(cap) == Cgroup && capvisible(cs, cap, ref)) {
      getfromktable(cs, cap->idx);  /* get group name */
      if (lp_equal(L, -2, -1)) {  /* right group? */
        lua_pop(L, 2);  /* remove reference name and group name */
        return cap;
      }
      else lua_pop(L, 1);  /* remove group name */
    }
  }
  luaL_error(L, "back reference '%s' not found", lua_tostring(L, -1));
  return NULL;  /* to avoid warnings */
}


/*
** Back-reference capture. Return number of values pushed.
*/
static int backrefcap (CapState *cs) {
  int n;
  Capture *curr = cs->cap;
  pushluaval(cs);  /* reference name */
  cs->cap = findback(cs, curr);  /* find corresponding group */
  n = pushnestedvalues(cs, 0);  /* push group's values */
  cs->cap = curr + 1;
  return n;
}


/*
** Table capture: creates a new table and populates it with nested
** captures.
*/
static int tablecap (CapState *cs) {
  lua_State *L = cs->L;
  Capture *head = cs->cap++;
  int n = 0;
  lua_newtable(L);
  while (capinside(head, cs->cap)) {
    if (captype(cs->cap) == Cgroup && cs->cap->idx != 0) {  /* named group? */
      pushluaval(cs);  /* push group name */
      pushonenestedvalue(cs);
      lua_settable(L, -3);
    }
    else {  /* not a named group */
      int i;
      int k = pushcapture(cs);
      for (i = k; i > 0; i--)  /* store all values into table */
        lua_rawseti(L, -(i + 1), n + i);
      n += k;
    }
  }
  skipclose(cs, head);
  return 1;  /* number of values pushed (only the table) */
}


/*
** Table-query capture
*/
static int querycap (CapState *cs) {
  int idx = cs->cap->idx;
  pushonenestedvalue(cs);  /* get nested capture */
  lua_gettable(cs->L, updatecache(cs, idx));  /* query cap. value at table */
  if (!lua_isnil(cs->L, -1))
    return 1;
  else {  /* no value */
    lua_pop(cs->L, 1);  /* remove nil */
    return 0;
  }
}


/*
** Fold capture
*/
static int foldcap (CapState *cs) {
  int n;
  lua_State *L = cs->L;
  Capture *head = cs->cap++;
  int idx = head->idx;
  if (isclosecap(cs->cap) ||  /* no nested captures (large subject)? */
      (n = pushcapture(cs)) == 0)  /* nested captures with no values? */
    return luaL_error(L, "no initial value for fold capture");
  if (n > 1)
    lua_pop(L, n - 1);  /* leave only one result for accumulator */
  while (capinside(head, cs->cap)) {
    lua_pushvalue(L, updatecache(cs, idx));  /* get folding function */
    lua_insert(L, -2);  /* put it before accumulator */
    n = pushcapture(cs);  /* get next capture's values */
    lua_call(L, n + 1, 1);  /* call folding function */
  }
  skipclose(cs, head);
  return 1;  /* only accumulator left on the stack */
}


/*
** Function capture
*/
static int functioncap (CapState *cs) {
  int n;
  int top = lua_gettop(cs->L);
  pushluaval(cs);  /* push function */
  n = pushnestedvalues(cs, 0);  /* push nested captures */
  lua_call(cs->L, n, LUA_MULTRET);  /* call function */
  return lua_gettop(cs->L) - top;  /* return function's results */
}


/*
** Accumulator capture
*/
static int accumulatorcap (CapState *cs) {
  lua_State *L = cs->L;
  int n;
  if (lua_gettop(L) < cs->firstcap)
    luaL_error(L, "no previous value for accumulator capture");
  pushluaval(cs);  /* push function */
  lua_insert(L, -2);  /* previous value becomes first argument */
  n = pushnestedvalues(cs, 0);  /* push nested captures */
  lua_call(L, n + 1, 1);  /* call function */
  return 0;  /* did not add any extra value */
}


/*
** Select capture
*/
static int numcap (CapState *cs) {
  int idx = cs->cap->idx;  /* value to select */
  if (idx == 0) {  /* no values? */
    nextcap(cs);  /* skip entire capture */
    return 0;  /* no value produced */
  }
  else {
    int n = pushnestedvalues(cs, 0);
    if (n < idx)  /* invalid index? */
      return luaL_error(cs->L, "no capture '%d'", idx);
    else {
      lua_pushvalue(cs->L, -(n - idx + 1));  /* get selected capture */
      lua_replace(cs->L, -(n + 1));  /* put it in place of 1st capture */
      lua_pop(cs->L, n - 1);  /* remove other captures */
      return 1;
    }
  }
}


/*
** Return the stack index of the first runtime capture in the given
** list of captures (or zero if no runtime captures)
*/
int finddyncap (Capture *cap, Capture *last) {
  for (; cap < last; cap++) {
    if (cap->kind == Cruntime)
      return cap->idx;  /* stack position of first capture */
  }
  return 0;  /* no dynamic captures in this segment */
}


/*
** Calls a runtime capture. Returns number of captures "removed" by the
** call, that is, those inside the group capture. Captures to be added
** are on the Lua stack.
*/
int runtimecap (CapState *cs, Capture *close, const char *s, int *rem) {
  int n, id;
  lua_State *L = cs->L;
  int otop = lua_gettop(L);
  Capture *open = findopen(close);  /* get open group capture */
  assert(captype(open) == Cgroup);
  id = finddyncap(open, close);  /* get first dynamic capture argument */
  close->kind = Cclose;  /* closes the group */
  close->index = s - cs->s;
  cs->cap = open; cs->valuecached = 0;  /* prepare capture state */
  luaL_checkstack(L, 4, "too many runtime captures");
  pushluaval(cs);  /* push function to be called */
  lua_pushvalue(L, SUBJIDX);  /* push original subject */
  lua_pushinteger(L, s - cs->s + 1);  /* push current position */
  n = pushnestedvalues(cs, 0);  /* push nested captures */
  lua_call(L, n + 2, LUA_MULTRET);  /* call dynamic function */
  if (id > 0) {  /* are there old dynamic captures to be removed? */
    int i;
    for (i = id; i <= otop; i++)
      lua_remove(L, id);  /* remove old dynamic captures */
    *rem = otop - id + 1;  /* total number of dynamic captures removed */
  }
  else
    *rem = 0;  /* no dynamic captures removed */
  return close - open - 1;  /* number of captures to be removed */
}


/*
** Auxiliary structure for substitution and string captures: keep
** information about nested captures for future use, avoiding to push
** string results into Lua
*/
typedef struct StrAux {
  int isstring;  /* whether capture is a string */
  union {
    Capture *cp;  /* if not a string, respective capture */
    struct {  /* if it is a string... */
      Index_t idx;  /* starts here */
      Index_t siz;  /* with this size */
    } s;
  } u;
} StrAux;

#define MAXSTRCAPS	10

/*
** Collect values from current capture into array 'cps'. Current
** capture must be Cstring (first call) or Csimple (recursive calls).
** (In first call, fills %0 with whole match for Cstring.)
** Returns number of elements in the array that were filled.
*/
static int getstrcaps (CapState *cs, StrAux *cps, int n) {
  int k = n++;
  Capture *head = cs->cap++;
  cps[k].isstring = 1;  /* get string value */
  cps[k].u.s.idx = head->index;  /* starts here */
  while (capinside(head, cs->cap)) {
    if (n >= MAXSTRCAPS)  /* too many captures? */
      nextcap(cs);  /* skip extra captures (will not need them) */
    else if (captype(cs->cap) == Csimple)  /* string? */
      n = getstrcaps(cs, cps, n);  /* put info. into array */
    else {
      cps[n].isstring = 0;  /* not a string */
      cps[n].u.cp = cs->cap;  /* keep original capture */
      nextcap(cs);
      n++;
    }
  }
  cps[k].u.s.siz = closesize(cs, head);
  skipclose(cs, head);
  return n;
}


/*
** add next capture value (which should be a string) to buffer 'b'
*/
static int addonestring (luaL_Buffer *b, CapState *cs, const char *what);


/*
** String capture: add result to buffer 'b' (instead of pushing
** it into the stack)
*/
static void stringcap (luaL_Buffer *b, CapState *cs) {
  StrAux cps[MAXSTRCAPS];
  int n;
  size_t len, i;
  const char *fmt;  /* format string */
  fmt = lua_tolstring(cs->L, updatecache(cs, cs->cap->idx), &len);
  n = getstrcaps(cs, cps, 0) - 1;  /* collect nested captures */
  for (i = 0; i < len; i++) {  /* traverse format string */
    if (fmt[i] != '%')  /* not an escape? */
      luaL_addchar(b, fmt[i]);  /* add it to buffer */
    else if (fmt[++i] < '0' || fmt[i] > '9')  /* not followed by a digit? */
      luaL_addchar(b, fmt[i]);  /* add to buffer */
    else {
      int l = fmt[i] - '0';  /* capture index */
      if (l > n)
        luaL_error(cs->L, "invalid capture index (%d)", l);
      else if (cps[l].isstring)
        luaL_addlstring(b, cs->s + cps[l].u.s.idx, cps[l].u.s.siz);
      else {
        Capture *curr = cs->cap;
        cs->cap = cps[l].u.cp;  /* go back to evaluate that nested capture */
        if (!addonestring(b, cs, "capture"))
          luaL_error(cs->L, "no values in capture index %d", l);
        cs->cap = curr;  /* continue from where it stopped */
      }
    }
  }
}


/*
** Substitution capture: add result to buffer 'b'
*/
static void substcap (luaL_Buffer *b, CapState *cs) {
  const char *curr = cs->s + cs->cap->index;
  Capture *head = cs->cap++;
  while (capinside(head, cs->cap)) {
    Capture *cap = cs->cap;
    const char *caps = cs->s + cap->index;
    luaL_addlstring(b, curr, caps - curr);  /* add text up to capture */
    if (addonestring(b, cs, "replacement"))
      curr = caps + capsize(cap, cs->cap - 1);  /* continue after match */
    else  /* no capture value */
      curr = caps;  /* keep original text in final result */
  }
  /* add last piece of text */
  luaL_addlstring(b, curr, cs->s + head->index + closesize(cs, head) - curr);
  skipclose(cs, head);
}


/*
** Evaluates a capture and adds its first value to buffer 'b'; returns
** whether there was a value
*/
static int addonestring (luaL_Buffer *b, CapState *cs, const char *what) {
  switch (captype(cs->cap)) {
    case Cstring:
      stringcap(b, cs);  /* add capture directly to buffer */
      return 1;
    case Csubst:
      substcap(b, cs);  /* add capture directly to buffer */
      return 1;
    case Cacc:  /* accumulator capture? */
      return luaL_error(cs->L, "invalid context for an accumulator capture");
    default: {
      lua_State *L = cs->L;
      int n = pushcapture(cs);
      if (n > 0) {
        if (n > 1) lua_pop(L, n - 1);  /* only one result */
        if (!lua_isstring(L, -1))
          return luaL_error(L, "invalid %s value (a %s)",
                               what, luaL_typename(L, -1));
        luaL_addvalue(b);
      }
      return n;
    }
  }
}


#if !defined(MAXRECLEVEL)
#define MAXRECLEVEL	200
#endif


/*
** Push all values of the current capture into the stack; returns
** number of values pushed
*/
static int pushcapture (CapState *cs) {
  lua_State *L = cs->L;
  int res;
  luaL_checkstack(L, 4, "too many captures");
  if (cs->reclevel++ > MAXRECLEVEL)
    return luaL_error(L, "subcapture nesting too deep");
  switch (captype(cs->cap)) {
    case Cposition: {
      lua_pushinteger(L, cs->cap->index + 1);
      cs->cap++;
      res = 1;
      break;
    }
    case Cconst: {
      pushluaval(cs);
      cs->cap++;
      res = 1;
      break;
    }
    case Carg: {
      int arg = (cs->cap++)->idx;
      if (arg + FIXEDARGS > cs->ptop)
        return luaL_error(L, "reference to absent extra argument #%d", arg);
      lua_pushvalue(L, arg + FIXEDARGS);
      res = 1;
      break;
    }
    case Csimple: {
      int k = pushnestedvalues(cs, 1);
      lua_insert(L, -k);  /* make whole match be first result */
      res = k;
      break;
    }
    case Cruntime: {
      lua_pushvalue(L, (cs->cap++)->idx);  /* value is in the stack */
      res = 1;
      break;
    }
    case Cstring: {
      luaL_Buffer b;
      luaL_buffinit(L, &b);
      stringcap(&b, cs);
      luaL_pushresult(&b);
      res = 1;
      break;
    }
    case Csubst: {
      luaL_Buffer b;
      luaL_buffinit(L, &b);
      substcap(&b, cs);
      luaL_pushresult(&b);
      res = 1;
      break;
    }
    case Cgroup: {
      if (cs->cap->idx == 0)  /* anonymous group? */
        res = pushnestedvalues(cs, 0);  /* add all nested values */
      else {  /* named group: add no values */
        nextcap(cs);  /* skip capture */
        res = 0;
      }
      break;
    }
    case Cbackref: res = backrefcap(cs); break;
    case Ctable: res = tablecap(cs); break;
    case Cfunction: res = functioncap(cs); break;
    case Cacc: res = accumulatorcap(cs); break;
    case Cnum: res = numcap(cs); break;
    case Cquery: res = querycap(cs); break;
    case Cfold: res = foldcap(cs); break;
    default: assert(0); res = 0;
  }
  cs->reclevel--;
  return res;
}


/*
** Prepare a CapState structure and traverse the entire list of
** captures in the stack pushing its results. 's' is the subject
** string, 'r' is the final position of the match, and 'ptop'
** the index in the stack where some useful values were pushed.
** Returns the number of results pushed. (If the list produces no
** results, push the final position of the match.)
*/
int getcaptures (lua_State *L, const char *s, const char *r, int ptop) {
  Capture *capture = (Capture *)lua_touserdata(L, caplistidx(ptop));
  int n = 0;
  /* printcaplist(capture); */
  if (!isclosecap(capture)) {  /* is there any capture? */
    CapState cs;
    cs.ocap = cs.cap = capture; cs.L = L; cs.reclevel = 0;
    cs.s = s; cs.valuecached = 0; cs.ptop = ptop;
    cs.firstcap = lua_gettop(L) + 1;  /* where first value (if any) will go */
    do {  /* collect their values */
      n += pushcapture(&cs);
    } while (!isclosecap(cs.cap));
    assert(lua_gettop(L) - cs.firstcap == n - 1);
  }
  if (n == 0) {  /* no capture values? */
    lua_pushinteger(L, r - s + 1);  /* return only end position */
    n = 1;
  }
  return n;
}




/* ==========================================================================
** File: lpcode.c
** ==========================================================================
*/


#include <limits.h>


#include "lua.h"
#include "lauxlib.h"

/* #include "lptypes.h" -- stripped */
/* #include "lpcode.h" -- stripped */
/* #include "lpcset.h" -- stripped */


/* signals a "no-instruction */
#define NOINST		-1



static const Charset fullset_ =
  {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

static const Charset *fullset = &fullset_;


/*
** {======================================================
** Analysis and some optimizations
** =======================================================
*/


/*
** A few basic operations on Charsets
*/
static void cs_complement (Charset *cs) {
  loopset(i, cs->cs[i] = ~cs->cs[i]);
}

static int cs_disjoint (const Charset *cs1, const Charset *cs2) {
  loopset(i, if ((cs1->cs[i] & cs2->cs[i]) != 0) return 0;)
  return 1;
}


/*
** Visit a TCall node taking care to stop recursion. If node not yet
** visited, return 'f(sib2(tree))', otherwise return 'def' (default
** value)
*/
static int callrecursive (TTree *tree, int f (TTree *t), int def) {
  int key = tree->key;
  assert(tree->tag == TCall);
  assert(sib2(tree)->tag == TRule);
  if (key == 0)  /* node already visited? */
    return def;  /* return default value */
  else {  /* first visit */
    int result;
    tree->key = 0;  /* mark call as already visited */
    result = f(sib2(tree));  /* go to called rule */
    tree->key = key;  /* restore tree */
    return result;
  }
}


/*
** Check whether a pattern tree has captures
*/
int hascaptures (TTree *tree) {
 tailcall:
  switch (tree->tag) {
    case TCapture: case TRunTime:
      return 1;
    case TCall:
      return callrecursive(tree, hascaptures, 0);
    case TRule:  /* do not follow siblings */
      tree = sib1(tree); goto tailcall;
    case TOpenCall: assert(0);
    default: {
      switch (numsiblings[tree->tag]) {
        case 1:  /* return hascaptures(sib1(tree)); */
          tree = sib1(tree); goto tailcall;
        case 2:
          if (hascaptures(sib1(tree)))
            return 1;
          /* else return hascaptures(sib2(tree)); */
          tree = sib2(tree); goto tailcall;
        default: assert(numsiblings[tree->tag] == 0); return 0;
      }
    }
  }
}


/*
** Checks how a pattern behaves regarding the empty string,
** in one of two different ways:
** A pattern is *nullable* if it can match without consuming any character;
** A pattern is *nofail* if it never fails for any string
** (including the empty string).
** The difference is only for predicates and run-time captures;
** for other patterns, the two properties are equivalent.
** (With predicates, &'a' is nullable but not nofail. Of course,
** nofail => nullable.)
** These functions are all convervative in the following way:
**    p is nullable => nullable(p)
**    nofail(p) => p cannot fail
** The function assumes that TOpenCall is not nullable;
** this will be checked again when the grammar is fixed.
** Run-time captures can do whatever they want, so the result
** is conservative.
*/
int checkaux (TTree *tree, int pred) {
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny: case TUTFR:
    case TFalse: case TOpenCall:
      return 0;  /* not nullable */
    case TRep: case TTrue:
      return 1;  /* no fail */
    case TNot: case TBehind:  /* can match empty, but can fail */
      if (pred == PEnofail) return 0;
      else return 1;  /* PEnullable */
    case TAnd:  /* can match empty; fail iff body does */
      if (pred == PEnullable) return 1;
      /* else return checkaux(sib1(tree), pred); */
      tree = sib1(tree); goto tailcall;
    case TRunTime:  /* can fail; match empty iff body does */
      if (pred == PEnofail) return 0;
      /* else return checkaux(sib1(tree), pred); */
      tree = sib1(tree); goto tailcall;
    case TSeq:
      if (!checkaux(sib1(tree), pred)) return 0;
      /* else return checkaux(sib2(tree), pred); */
      tree = sib2(tree); goto tailcall;
    case TChoice:
      if (checkaux(sib2(tree), pred)) return 1;
      /* else return checkaux(sib1(tree), pred); */
      tree = sib1(tree); goto tailcall;
    case TCapture: case TGrammar: case TRule: case TXInfo:
      /* return checkaux(sib1(tree), pred); */
      tree = sib1(tree); goto tailcall;
    case TCall:  /* return checkaux(sib2(tree), pred); */
      tree = sib2(tree); goto tailcall;
    default: assert(0); return 0;
  }
}


/*
** number of characters to match a pattern (or -1 if variable)
*/
int fixedlen (TTree *tree) {
  int len = 0;  /* to accumulate in tail calls */
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny:
      return len + 1;
    case TUTFR:
      return (tree->cap == sib1(tree)->cap) ? len + tree->cap : -1;
    case TFalse: case TTrue: case TNot: case TAnd: case TBehind:
      return len;
    case TRep: case TRunTime: case TOpenCall:
      return -1;
    case TCapture: case TRule: case TGrammar: case TXInfo:
      /* return fixedlen(sib1(tree)); */
      tree = sib1(tree); goto tailcall;
    case TCall: {
      int n1 = callrecursive(tree, fixedlen, -1);
      if (n1 < 0)
        return -1;
      else
        return len + n1;
    }
    case TSeq: {
      int n1 = fixedlen(sib1(tree));
      if (n1 < 0)
        return -1;
      /* else return fixedlen(sib2(tree)) + len; */
      len += n1; tree = sib2(tree); goto tailcall;
    }
    case TChoice: {
      int n1 = fixedlen(sib1(tree));
      int n2 = fixedlen(sib2(tree));
      if (n1 != n2 || n1 < 0)
        return -1;
      else
        return len + n1;
    }
    default: assert(0); return 0;
  };
}


/*
** Computes the 'first set' of a pattern.
** The result is a conservative aproximation:
**   match p ax -> x (for some x) ==> a belongs to first(p)
** or
**   a not in first(p) ==> match p ax -> fail (for all x)
**
** The set 'follow' is the first set of what follows the
** pattern (full set if nothing follows it).
**
** The function returns 0 when this resulting set can be used for
** test instructions that avoid the pattern altogether.
** A non-zero return can happen for two reasons:
** 1) match p '' -> ''            ==> return has bit 1 set
** (tests cannot be used because they would always fail for an empty input);
** 2) there is a match-time capture ==> return has bit 2 set
** (optimizations should not bypass match-time captures).
*/
static int getfirst (TTree *tree, const Charset *follow, Charset *firstset) {
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny: case TFalse: {
      tocharset(tree, firstset);
      return 0;
    }
    case TUTFR: {
      int c;
      clearset(firstset->cs);  /* erase all chars */
      for (c = tree->key; c <= sib1(tree)->key; c++)
        setchar(firstset->cs, c);
      return 0;
    }
    case TTrue: {
      loopset(i, firstset->cs[i] = follow->cs[i]);
      return 1;  /* accepts the empty string */
    }
    case TChoice: {
      Charset csaux;
      int e1 = getfirst(sib1(tree), follow, firstset);
      int e2 = getfirst(sib2(tree), follow, &csaux);
      loopset(i, firstset->cs[i] |= csaux.cs[i]);
      return e1 | e2;
    }
    case TSeq: {
      if (!nullable(sib1(tree))) {
        /* when p1 is not nullable, p2 has nothing to contribute;
           return getfirst(sib1(tree), fullset, firstset); */
        tree = sib1(tree); follow = fullset; goto tailcall;
      }
      else {  /* FIRST(p1 p2, fl) = FIRST(p1, FIRST(p2, fl)) */
        Charset csaux;
        int e2 = getfirst(sib2(tree), follow, &csaux);
        int e1 = getfirst(sib1(tree), &csaux, firstset);
        if (e1 == 0) return 0;  /* 'e1' ensures that first can be used */
        else if ((e1 | e2) & 2)  /* one of the children has a matchtime? */
          return 2;  /* pattern has a matchtime capture */
        else return e2;  /* else depends on 'e2' */
      }
    }
    case TRep: {
      getfirst(sib1(tree), follow, firstset);
      loopset(i, firstset->cs[i] |= follow->cs[i]);
      return 1;  /* accept the empty string */
    }
    case TCapture: case TGrammar: case TRule: case TXInfo: {
      /* return getfirst(sib1(tree), follow, firstset); */
      tree = sib1(tree); goto tailcall;
    }
    case TRunTime: {  /* function invalidates any follow info. */
      int e = getfirst(sib1(tree), fullset, firstset);
      if (e) return 2;  /* function is not "protected"? */
      else return 0;  /* pattern inside capture ensures first can be used */
    }
    case TCall: {
      /* return getfirst(sib2(tree), follow, firstset); */
      tree = sib2(tree); goto tailcall;
    }
    case TAnd: {
      int e = getfirst(sib1(tree), follow, firstset);
      loopset(i, firstset->cs[i] &= follow->cs[i]);
      return e;
    }
    case TNot: {
      if (tocharset(sib1(tree), firstset)) {
        cs_complement(firstset);
        return 1;
      }  /* else */
    }    /* FALLTHROUGH */
    case TBehind: {  /* instruction gives no new information */
      /* call 'getfirst' only to check for math-time captures */
      int e = getfirst(sib1(tree), follow, firstset);
      loopset(i, firstset->cs[i] = follow->cs[i]);  /* uses follow */
      return e | 1;  /* always can accept the empty string */
    }
    default: assert(0); return 0;
  }
}


/*
** If 'headfail(tree)' true, then 'tree' can fail only depending on the
** next character of the subject.
*/
static int headfail (TTree *tree) {
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny: case TFalse:
      return 1;
    case TTrue: case TRep: case TRunTime: case TNot:
    case TBehind: case TUTFR:
      return 0;
    case TCapture: case TGrammar: case TRule: case TXInfo: case TAnd:
      tree = sib1(tree); goto tailcall;  /* return headfail(sib1(tree)); */
    case TCall:
      tree = sib2(tree); goto tailcall;  /* return headfail(sib2(tree)); */
    case TSeq:
      if (!nofail(sib2(tree))) return 0;
      /* else return headfail(sib1(tree)); */
      tree = sib1(tree); goto tailcall;
    case TChoice:
      if (!headfail(sib1(tree))) return 0;
      /* else return headfail(sib2(tree)); */
      tree = sib2(tree); goto tailcall;
    default: assert(0); return 0;
  }
}


/*
** Check whether the code generation for the given tree can benefit
** from a follow set (to avoid computing the follow set when it is
** not needed)
*/
static int needfollow (TTree *tree) {
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny: case TUTFR:
    case TFalse: case TTrue: case TAnd: case TNot:
    case TRunTime: case TGrammar: case TCall: case TBehind:
      return 0;
    case TChoice: case TRep:
      return 1;
    case TCapture:
      tree = sib1(tree); goto tailcall;
    case TSeq:
      tree = sib2(tree); goto tailcall;
    default: assert(0); return 0;
  }
}

/* }====================================================== */



/*
** {======================================================
** Code generation
** =======================================================
*/


/*
** size of an instruction
*/
int sizei (const Instruction *i) {
  switch((Opcode)i->i.code) {
    case ISet: case ISpan: return 1 + i->i.aux2.set.size;
    case ITestSet: return 2 + i->i.aux2.set.size;
    case ITestChar: case ITestAny: case IChoice: case IJmp: case ICall:
    case IOpenCall: case ICommit: case IPartialCommit: case IBackCommit:
    case IUTFR:
      return 2;
    default: return 1;
  }
}


/*
** state for the compiler
*/
typedef struct CompileState {
  Pattern *p;  /* pattern being compiled */
  int ncode;  /* next position in p->code to be filled */
  lua_State *L;
} CompileState;


/*
** code generation is recursive; 'opt' indicates that the code is being
** generated as the last thing inside an optional pattern (so, if that
** code is optional too, it can reuse the 'IChoice' already in place for
** the outer pattern). 'tt' points to a previous test protecting this
** code (or NOINST). 'fl' is the follow set of the pattern.
*/
static void codegen (CompileState *compst, TTree *tree, int opt, int tt,
                     const Charset *fl);


static void finishrelcode (lua_State *L, Pattern *p, Instruction *block,
                                         int size) {
  if (block == NULL)
    luaL_error(L, "not enough memory");
  block->codesize = size;
  p->code = (Instruction *)block + 1;
}


/*
** Initialize array 'p->code'
*/
static void newcode (lua_State *L, Pattern *p, int size) {
  void *ud;
  Instruction *block;
  lua_Alloc f = lua_getallocf(L, &ud);
  size++;  /* slot for 'codesize' */
  block = (Instruction*) f(ud, NULL, 0, size * sizeof(Instruction));
  finishrelcode(L, p, block, size);
}


void freecode (lua_State *L, Pattern *p) {
  if (p->code != NULL) {
    void *ud;
    lua_Alloc f = lua_getallocf(L, &ud);
    uint osize = p->code[-1].codesize;
    f(ud, p->code - 1, osize * sizeof(Instruction), 0);  /* free block */
  }
}


/*
** Assume that 'nsize' is not zero and that 'p->code' already exists.
*/
static void realloccode (lua_State *L, Pattern *p, int nsize) {
  void *ud;
  lua_Alloc f = lua_getallocf(L, &ud);
  Instruction *block = p->code - 1;
  uint osize = block->codesize;
  nsize++;  /* add the 'codesize' slot to size */
  block = (Instruction*) f(ud, block, osize * sizeof(Instruction),
                                      nsize * sizeof(Instruction));
  finishrelcode(L, p, block, nsize);
}


/*
** Add space for an instruction with 'n' slots and return its index.
*/
static int nextinstruction (CompileState *compst, int n) {
  int size = compst->p->code[-1].codesize - 1;
  int ncode = compst->ncode;
  if (ncode > size - n) {
    uint nsize = size + (size >> 1) + n;
    if (nsize >= INT_MAX)
      luaL_error(compst->L, "pattern code too large");
    realloccode(compst->L, compst->p, nsize);
  }
  compst->ncode = ncode + n;
  return ncode;
}


#define getinstr(cs,i)		((cs)->p->code[i])


static int addinstruction (CompileState *compst, Opcode op, int aux) {
  int i = nextinstruction(compst, 1);
  getinstr(compst, i).i.code = op;
  getinstr(compst, i).i.aux1 = aux;
  return i;
}


/*
** Add an instruction followed by space for an offset (to be set later)
*/
static int addoffsetinst (CompileState *compst, Opcode op) {
  int i = addinstruction(compst, op, 0);  /* instruction */
  addinstruction(compst, (Opcode)0, 0);  /* open space for offset */
  assert(op == ITestSet || sizei(&getinstr(compst, i)) == 2);
  return i;
}


/*
** Set the offset of an instruction
*/
static void setoffset (CompileState *compst, int instruction, int offset) {
  getinstr(compst, instruction + 1).offset = offset;
}


static void codeutfr (CompileState *compst, TTree *tree) {
  int i = addoffsetinst(compst, IUTFR);
  int to = sib1(tree)->u.n;
  assert(sib1(tree)->tag == TXInfo);
  getinstr(compst, i + 1).offset = tree->u.n;
  getinstr(compst, i).i.aux1 = to & 0xff;
  getinstr(compst, i).i.aux2.key = to >> 8;
}


/*
** Add a capture instruction:
** 'op' is the capture instruction; 'cap' the capture kind;
** 'key' the key into ktable; 'aux' is the optional capture offset
**
*/
static int addinstcap (CompileState *compst, Opcode op, int cap, int key,
                       int aux) {
  int i = addinstruction(compst, op, joinkindoff(cap, aux));
  getinstr(compst, i).i.aux2.key = key;
  return i;
}


#define gethere(compst) 	((compst)->ncode)

#define target(code,i)		((i) + code[i + 1].offset)


/*
** Patch 'instruction' to jump to 'target'
*/
static void jumptothere (CompileState *compst, int instruction, int target) {
  if (instruction >= 0)
    setoffset(compst, instruction, target - instruction);
}


/*
** Patch 'instruction' to jump to current position
*/
static void jumptohere (CompileState *compst, int instruction) {
  jumptothere(compst, instruction, gethere(compst));
}


/*
** Code an IChar instruction, or IAny if there is an equivalent
** test dominating it
*/
static void codechar (CompileState *compst, int c, int tt) {
  if (tt >= 0 && getinstr(compst, tt).i.code == ITestChar &&
                 getinstr(compst, tt).i.aux1 == c)
    addinstruction(compst, IAny, 0);
  else
    addinstruction(compst, IChar, c);
}


/*
** Add a charset posfix to an instruction.
*/
static void addcharset (CompileState *compst, int inst, charsetinfo *info) {
  int p;
  Instruction *I = &getinstr(compst, inst);
  byte *charset;
  int isize = instsize(info->size);  /* size in instructions */
  int i;
  I->i.aux2.set.offset = info->offset * 8;  /* offset in bits */
  I->i.aux2.set.size = isize;
  I->i.aux1 = info->deflt;
  p = nextinstruction(compst, isize);  /* space for charset */
  charset = getinstr(compst, p).buff;  /* charset buffer */
  for (i = 0; i < isize * (int)sizeof(Instruction); i++)
    charset[i] = getbytefromcharset(info, i);  /* copy the buffer */
}


/*
** Check whether charset 'info' is dominated by instruction 'p'
*/
static int cs_equal (Instruction *p, charsetinfo *info) {
  if (p->i.code != ITestSet)
    return 0;
  else if (p->i.aux2.set.offset != info->offset * 8 ||
           p->i.aux2.set.size != instsize(info->size) ||
           p->i.aux1 != info->deflt)
    return 0;
  else {
    int i;
    for (i = 0; i < instsize(info->size) * (int)sizeof(Instruction); i++) {
      if ((p + 2)->buff[i] != getbytefromcharset(info, i))
        return 0;
    }
  }
  return 1;
}


/*
** Code a char set, using IAny when instruction is dominated by an
** equivalent test.
*/
static void codecharset (CompileState *compst, TTree *tree, int tt) {
  charsetinfo info;
  tree2cset(tree, &info);
  if (tt >= 0 && cs_equal(&getinstr(compst, tt), &info))
    addinstruction(compst, IAny, 0);
  else {
    int i = addinstruction(compst, ISet, 0);
    addcharset(compst, i, &info);
  }
}


/*
** Code a test set, optimizing unit sets for ITestChar, "complete"
** sets for ITestAny, and empty sets for IJmp (always fails).
** 'e' is true iff test should accept the empty string. (Test
** instructions in the current VM never accept the empty string.)
*/
static int codetestset (CompileState *compst, Charset *cs, int e) {
  if (e) return NOINST;  /* no test */
  else {
    charsetinfo info;
    Opcode op = charsettype(cs->cs, &info);
    switch (op) {
      case IFail: return addoffsetinst(compst, IJmp);  /* always jump */
      case IAny: return addoffsetinst(compst, ITestAny);
      case IChar: {
        int i = addoffsetinst(compst, ITestChar);
        getinstr(compst, i).i.aux1 = info.offset;
        return i;
      }
      default: {  /* regular set */
        int i = addoffsetinst(compst, ITestSet);
        addcharset(compst, i, &info);
        assert(op == ISet);
        return i;
      }
    }
  }
}


/*
** Find the final destination of a sequence of jumps
*/
static int finaltarget (Instruction *code, int i) {
  while (code[i].i.code == IJmp)
    i = target(code, i);
  return i;
}


/*
** final label (after traversing any jumps)
*/
static int finallabel (Instruction *code, int i) {
  return finaltarget(code, target(code, i));
}


/*
** <behind(p)> == behind n; <p>   (where n = fixedlen(p))
*/
static void codebehind (CompileState *compst, TTree *tree) {
  if (tree->u.n > 0)
    addinstruction(compst, IBehind, tree->u.n);
  codegen(compst, sib1(tree), 0, NOINST, fullset);
}


/*
** Choice; optimizations:
** - when p1 is headfail or when first(p1) and first(p2) are disjoint,
** than a character not in first(p1) cannot go to p1 and a character
** in first(p1) cannot go to p2, either because p1 will accept
** (headfail) or because it is not in first(p2) (disjoint).
** (The second case is not valid if p1 accepts the empty string,
** as then there is no character at all...)
** - when p2 is empty and opt is true; a IPartialCommit can reuse
** the Choice already active in the stack.
*/
static void codechoice (CompileState *compst, TTree *p1, TTree *p2, int opt,
                        const Charset *fl) {
  int emptyp2 = (p2->tag == TTrue);
  Charset cs1, cs2;
  int e1 = getfirst(p1, fullset, &cs1);
  if (headfail(p1) ||
      (!e1 && (getfirst(p2, fl, &cs2), cs_disjoint(&cs1, &cs2)))) {
    /* <p1 / p2> == test (fail(p1)) -> L1 ; p1 ; jmp L2; L1: p2; L2: */
    int test = codetestset(compst, &cs1, 0);
    int jmp = NOINST;
    codegen(compst, p1, 0, test, fl);
    if (!emptyp2)
      jmp = addoffsetinst(compst, IJmp);
    jumptohere(compst, test);
    codegen(compst, p2, opt, NOINST, fl);
    jumptohere(compst, jmp);
  }
  else if (opt && emptyp2) {
    /* p1? == IPartialCommit; p1 */
    jumptohere(compst, addoffsetinst(compst, IPartialCommit));
    codegen(compst, p1, 1, NOINST, fullset);
  }
  else {
    /* <p1 / p2> ==
        test(first(p1)) -> L1; choice L1; <p1>; commit L2; L1: <p2>; L2: */
    int pcommit;
    int test = codetestset(compst, &cs1, e1);
    int pchoice = addoffsetinst(compst, IChoice);
    codegen(compst, p1, emptyp2, test, fullset);
    pcommit = addoffsetinst(compst, ICommit);
    jumptohere(compst, pchoice);
    jumptohere(compst, test);
    codegen(compst, p2, opt, NOINST, fl);
    jumptohere(compst, pcommit);
  }
}


/*
** And predicate
** optimization: fixedlen(p) = n ==> <&p> == <p>; behind n
** (valid only when 'p' has no captures)
*/
static void codeand (CompileState *compst, TTree *tree, int tt) {
  int n = fixedlen(tree);
  if (n >= 0 && n <= MAXBEHIND && !hascaptures(tree)) {
    codegen(compst, tree, 0, tt, fullset);
    if (n > 0)
      addinstruction(compst, IBehind, n);
  }
  else {  /* default: Choice L1; p1; BackCommit L2; L1: Fail; L2: */
    int pcommit;
    int pchoice = addoffsetinst(compst, IChoice);
    codegen(compst, tree, 0, tt, fullset);
    pcommit = addoffsetinst(compst, IBackCommit);
    jumptohere(compst, pchoice);
    addinstruction(compst, IFail, 0);
    jumptohere(compst, pcommit);
  }
}


/*
** Captures: if pattern has fixed (and not too big) length, and it
** has no nested captures, use a single IFullCapture instruction
** after the match; otherwise, enclose the pattern with OpenCapture -
** CloseCapture.
*/
static void codecapture (CompileState *compst, TTree *tree, int tt,
                         const Charset *fl) {
  int len = fixedlen(sib1(tree));
  if (len >= 0 && len <= MAXOFF && !hascaptures(sib1(tree))) {
    codegen(compst, sib1(tree), 0, tt, fl);
    addinstcap(compst, IFullCapture, tree->cap, tree->key, len);
  }
  else {
    addinstcap(compst, IOpenCapture, tree->cap, tree->key, 0);
    codegen(compst, sib1(tree), 0, tt, fl);
    addinstcap(compst, ICloseCapture, Cclose, 0, 0);
  }
}


static void coderuntime (CompileState *compst, TTree *tree, int tt) {
  addinstcap(compst, IOpenCapture, Cgroup, tree->key, 0);
  codegen(compst, sib1(tree), 0, tt, fullset);
  addinstcap(compst, ICloseRunTime, Cclose, 0, 0);
}


/*
** Create a jump to 'test' and fix 'test' to jump to next instruction
*/
static void closeloop (CompileState *compst, int test) {
  int jmp = addoffsetinst(compst, IJmp);
  jumptohere(compst, test);
  jumptothere(compst, jmp, test);
}


/*
** Try repetition of charsets:
** For an empty set, repetition of fail is a no-op;
** For any or char, code a tight loop;
** For generic charset, use a span instruction.
*/
static int coderepcharset (CompileState *compst, TTree *tree) {
  switch (tree->tag) {
    case TFalse: return 1;  /* 'fail*' is a no-op */
    case TAny: {  /* L1: testany -> L2; any; jmp L1; L2: */
      int test = addoffsetinst(compst, ITestAny);
      addinstruction(compst, IAny, 0);
      closeloop(compst, test);
      return 1;
    }
    case TChar: {  /* L1: testchar c -> L2; any; jmp L1; L2: */
      int test = addoffsetinst(compst, ITestChar);
      getinstr(compst, test).i.aux1 = tree->u.n;
      addinstruction(compst, IAny, 0);
      closeloop(compst, test);
      return 1;
    }
    case TSet: {  /* regular set */
      charsetinfo info;
      int i = addinstruction(compst, ISpan, 0);
      tree2cset(tree, &info);
      addcharset(compst, i, &info);
      return 1;
    }
    default: return 0;  /* not a charset */
  }
}


/*
** Repetion; optimizations:
** When pattern is a charset, use special code.
** When pattern is head fail, or if it starts with characters that
** are disjoint from what follows the repetions, a simple test
** is enough (a fail inside the repetition would backtrack to fail
** again in the following pattern, so there is no need for a choice).
** When 'opt' is true, the repetion can reuse the Choice already
** active in the stack.
*/
static void coderep (CompileState *compst, TTree *tree, int opt,
                     const Charset *fl) {
  if (!coderepcharset(compst, tree)) {
    Charset st;
    int e1 = getfirst(tree, fullset, &st);
    if (headfail(tree) || (!e1 && cs_disjoint(&st, fl))) {
      /* L1: test (fail(p1)) -> L2; <p>; jmp L1; L2: */
      int test = codetestset(compst, &st, 0);
      codegen(compst, tree, 0, test, fullset);
      closeloop(compst, test);
    }
    else {
      /* test(fail(p1)) -> L2; choice L2; L1: <p>; partialcommit L1; L2: */
      /* or (if 'opt'): partialcommit L1; L1: <p>; partialcommit L1; */
      int commit, l2;
      int test = codetestset(compst, &st, e1);
      int pchoice = NOINST;
      if (opt)
        jumptohere(compst, addoffsetinst(compst, IPartialCommit));
      else
        pchoice = addoffsetinst(compst, IChoice);
      l2 = gethere(compst);
      codegen(compst, tree, 0, NOINST, fullset);
      commit = addoffsetinst(compst, IPartialCommit);
      jumptothere(compst, commit, l2);
      jumptohere(compst, pchoice);
      jumptohere(compst, test);
    }
  }
}


/*
** Not predicate; optimizations:
** In any case, if first test fails, 'not' succeeds, so it can jump to
** the end. If pattern is headfail, that is all (it cannot fail
** in other parts); this case includes 'not' of simple sets. Otherwise,
** use the default code (a choice plus a failtwice).
*/
static void codenot (CompileState *compst, TTree *tree) {
  Charset st;
  int e = getfirst(tree, fullset, &st);
  int test = codetestset(compst, &st, e);
  if (headfail(tree))  /* test (fail(p1)) -> L1; fail; L1:  */
    addinstruction(compst, IFail, 0);
  else {
    /* test(fail(p))-> L1; choice L1; <p>; failtwice; L1:  */
    int pchoice = addoffsetinst(compst, IChoice);
    codegen(compst, tree, 0, NOINST, fullset);
    addinstruction(compst, IFailTwice, 0);
    jumptohere(compst, pchoice);
  }
  jumptohere(compst, test);
}


/*
** change open calls to calls, using list 'positions' to find
** correct offsets; also optimize tail calls
*/
static void correctcalls (CompileState *compst, int *positions,
                          int from, int to) {
  int i;
  Instruction *code = compst->p->code;
  for (i = from; i < to; i += sizei(&code[i])) {
    if (code[i].i.code == IOpenCall) {
      int n = code[i].i.aux2.key;  /* rule number */
      int rule = positions[n];  /* rule position */
      assert(rule == from || code[rule - 1].i.code == IRet);
      if (code[finaltarget(code, i + 2)].i.code == IRet)  /* call; ret ? */
        code[i].i.code = IJmp;  /* tail call */
      else
        code[i].i.code = ICall;
      jumptothere(compst, i, rule);  /* call jumps to respective rule */
    }
  }
  assert(i == to);
}


/*
** Code for a grammar:
** call L1; jmp L2; L1: rule 1; ret; rule 2; ret; ...; L2:
*/
static void codegrammar (CompileState *compst, TTree *grammar) {
  int positions[MAXRULES];
  int rulenumber = 0;
  TTree *rule;
  int firstcall = addoffsetinst(compst, ICall);  /* call initial rule */
  int jumptoend = addoffsetinst(compst, IJmp);  /* jump to the end */
  int start = gethere(compst);  /* here starts the initial rule */
  jumptohere(compst, firstcall);
  for (rule = sib1(grammar); rule->tag == TRule; rule = sib2(rule)) {
    TTree *r = sib1(rule);
    assert(r->tag == TXInfo);
    positions[rulenumber++] = gethere(compst);  /* save rule position */
    codegen(compst, sib1(r), 0, NOINST, fullset);  /* code rule */
    addinstruction(compst, IRet, 0);
  }
  assert(rule->tag == TTrue);
  jumptohere(compst, jumptoend);
  correctcalls(compst, positions, start, gethere(compst));
}


static void codecall (CompileState *compst, TTree *call) {
  int c = addoffsetinst(compst, IOpenCall);  /* to be corrected later */
  assert(sib1(sib2(call))->tag == TXInfo);
  getinstr(compst, c).i.aux2.key = sib1(sib2(call))->u.n;  /* rule number */
}


/*
** Code first child of a sequence
** (second child is called in-place to allow tail call)
** Return 'tt' for second child
*/
static int codeseq1 (CompileState *compst, TTree *p1, TTree *p2,
                     int tt, const Charset *fl) {
  if (needfollow(p1)) {
    Charset fl1;
    getfirst(p2, fl, &fl1);  /* p1 follow is p2 first */
    codegen(compst, p1, 0, tt, &fl1);
  }
  else  /* use 'fullset' as follow */
    codegen(compst, p1, 0, tt, fullset);
  if (fixedlen(p1) != 0)  /* can 'p1' consume anything? */
    return  NOINST;  /* invalidate test */
  else return tt;  /* else 'tt' still protects sib2 */
}


/*
** Main code-generation function: dispatch to auxiliar functions
** according to kind of tree. ('needfollow' should return true
** only for consructions that use 'fl'.)
*/
static void codegen (CompileState *compst, TTree *tree, int opt, int tt,
                     const Charset *fl) {
 tailcall:
  switch (tree->tag) {
    case TChar: codechar(compst, tree->u.n, tt); break;
    case TAny: addinstruction(compst, IAny, 0); break;
    case TSet: codecharset(compst, tree, tt); break;
    case TTrue: break;
    case TFalse: addinstruction(compst, IFail, 0); break;
    case TUTFR: codeutfr(compst, tree); break;
    case TChoice: codechoice(compst, sib1(tree), sib2(tree), opt, fl); break;
    case TRep: coderep(compst, sib1(tree), opt, fl); break;
    case TBehind: codebehind(compst, tree); break;
    case TNot: codenot(compst, sib1(tree)); break;
    case TAnd: codeand(compst, sib1(tree), tt); break;
    case TCapture: codecapture(compst, tree, tt, fl); break;
    case TRunTime: coderuntime(compst, tree, tt); break;
    case TGrammar: codegrammar(compst, tree); break;
    case TCall: codecall(compst, tree); break;
    case TSeq: {
      tt = codeseq1(compst, sib1(tree), sib2(tree), tt, fl);  /* code 'p1' */
      /* codegen(compst, p2, opt, tt, fl); */
      tree = sib2(tree); goto tailcall;
    }
    default: assert(0);
  }
}


/*
** Optimize jumps and other jump-like instructions.
** * Update labels of instructions with labels to their final
** destinations (e.g., choice L1; ... L1: jmp L2: becomes
** choice L2)
** * Jumps to other instructions that do jumps become those
** instructions (e.g., jump to return becomes a return; jump
** to commit becomes a commit)
*/
static void peephole (CompileState *compst) {
  Instruction *code = compst->p->code;
  int i;
  for (i = 0; i < compst->ncode; i += sizei(&code[i])) {
   redo:
    switch (code[i].i.code) {
      case IChoice: case ICall: case ICommit: case IPartialCommit:
      case IBackCommit: case ITestChar: case ITestSet:
      case ITestAny: {  /* instructions with labels */
        jumptothere(compst, i, finallabel(code, i));  /* optimize label */
        break;
      }
      case IJmp: {
        int ft = finaltarget(code, i);
        switch (code[ft].i.code) {  /* jumping to what? */
          case IRet: case IFail: case IFailTwice:
          case IEnd: {  /* instructions with unconditional implicit jumps */
            code[i] = code[ft];  /* jump becomes that instruction */
            code[i + 1].i.code = IEmpty;  /* 'no-op' for target position */
            break;
          }
          case ICommit: case IPartialCommit:
          case IBackCommit: {  /* inst. with unconditional explicit jumps */
            int fft = finallabel(code, ft);
            code[i] = code[ft];  /* jump becomes that instruction... */
            jumptothere(compst, i, fft);  /* but must correct its offset */
            goto redo;  /* reoptimize its label */
          }
          default: {
            jumptothere(compst, i, ft);  /* optimize label */
            break;
          }
        }
        break;
      }
      default: break;
    }
  }
  assert(code[i - 1].i.code == IEnd);
}


/*
** Compile a pattern. 'size' is the size of the pattern's tree,
** which gives a hint for the size of the final code.
*/
Instruction *compile (lua_State *L, Pattern *p, uint size) {
  CompileState compst;
  compst.p = p;  compst.ncode = 0;  compst.L = L;
  newcode(L, p, size/2u + 2);  /* set initial size */
  codegen(&compst, p->tree, 0, NOINST, fullset);
  addinstruction(&compst, IEnd, 0);
  realloccode(L, p, compst.ncode);  /* set final size */
  peephole(&compst);
  return p->code;
}


/* }====================================================== */



/* ==========================================================================
** File: lpprint.c
** ==========================================================================
*/


#include <ctype.h>
#include <limits.h>
#include <stdio.h>


/* #include "lptypes.h" -- stripped */
/* #include "lpprint.h" -- stripped */
/* #include "lpcode.h" -- stripped */


#if defined(LPEG_DEBUG)

/*
** {======================================================
** Printing patterns (for debugging)
** =======================================================
*/


void printcharset (const byte *st) {
  int i;
  printf("[");
  for (i = 0; i <= UCHAR_MAX; i++) {
    int first = i;
    while (i <= UCHAR_MAX && testchar(st, i)) i++;
    if (i - 1 == first)  /* unary range? */
      printf("(%02x)", first);
    else if (i - 1 > first)  /* non-empty range? */
      printf("(%02x-%02x)", first, i - 1);
  }
  printf("]");
}


static void printIcharset (const Instruction *inst, const byte *buff) {
  byte cs[CHARSETSIZE];
  int i;
  printf("(%02x-%d) ", inst->i.aux2.set.offset, inst->i.aux2.set.size);
  clearset(cs);
  for (i = 0; i < CHARSETSIZE * 8; i++) {
    if (charinset(inst, buff, i))
      setchar(cs, i);
  }
  printcharset(cs);
}


static void printTcharset (TTree *tree) {
  byte cs[CHARSETSIZE];
  int i;
  printf("(%02x-%d) ", tree->u.set.offset, tree->u.set.size);
  fillset(cs, tree->u.set.deflt);
  for (i = 0; i < tree->u.set.size; i++)
    cs[tree->u.set.offset + i] = treebuffer(tree)[i];
  printcharset(cs);
}


static const char *capkind (int kind) {
  const char *const modes[] = {
    "close", "position", "constant", "backref",
    "argument", "simple", "table", "function", "accumulator",
    "query", "string", "num", "substitution", "fold",
    "runtime", "group"};
  return modes[kind];
}


static void printjmp (const Instruction *op, const Instruction *p) {
  printf("-> %d", (int)(p + (p + 1)->offset - op));
}


void printinst (const Instruction *op, const Instruction *p) {
  const char *const names[] = {
    "any", "char", "set",
    "testany", "testchar", "testset",
    "span", "utf-range", "behind",
    "ret", "end",
    "choice", "jmp", "call", "open_call",
    "commit", "partial_commit", "back_commit", "failtwice", "fail", "giveup",
     "fullcapture", "opencapture", "closecapture", "closeruntime",
     "--"
  };
  printf("%02ld: %s ", (long)(p - op), names[p->i.code]);
  switch ((Opcode)p->i.code) {
    case IChar: {
      printf("'%c' (%02x)", p->i.aux1, p->i.aux1);
      break;
    }
    case ITestChar: {
      printf("'%c' (%02x)", p->i.aux1, p->i.aux1); printjmp(op, p);
      break;
    }
    case IUTFR: {
      printf("%d - %d", p[1].offset, utf_to(p));
      break;
    }
    case IFullCapture: {
      printf("%s (size = %d)  (idx = %d)",
             capkind(getkind(p)), getoff(p), p->i.aux2.key);
      break;
    }
    case IOpenCapture: {
      printf("%s (idx = %d)", capkind(getkind(p)), p->i.aux2.key);
      break;
    }
    case ISet: {
      printIcharset(p, (p+1)->buff);
      break;
    }
    case ITestSet: {
      printIcharset(p, (p+2)->buff); printjmp(op, p);
      break;
    }
    case ISpan: {
      printIcharset(p, (p+1)->buff);
      break;
    }
    case IOpenCall: {
      printf("-> %d", (p + 1)->offset);
      break;
    }
    case IBehind: {
      printf("%d", p->i.aux1);
      break;
    }
    case IJmp: case ICall: case ICommit: case IChoice:
    case IPartialCommit: case IBackCommit: case ITestAny: {
      printjmp(op, p);
      break;
    }
    default: break;
  }
  printf("\n");
}


void printpatt (Instruction *p) {
  Instruction *op = p;
  uint n = op[-1].codesize - 1;
  while (p < op + n) {
    printinst(op, p);
    p += sizei(p);
  }
}


static void printcap (Capture *cap, int ident) {
  while (ident--) printf(" ");
  printf("%s (idx: %d - size: %d) -> %lu  (%p)\n",
         capkind(cap->kind), cap->idx, cap->siz, (long)cap->index, (void*)cap);
}


/*
** Print a capture and its nested captures
*/
static Capture *printcap2close (Capture *cap, int ident) {
  Capture *head = cap++;
  printcap(head, ident);  /* print head capture */
  while (capinside(head, cap))
    cap = printcap2close(cap, ident + 2);  /* print nested captures */
  if (isopencap(head)) {
    assert(isclosecap(cap));
    printcap(cap++, ident);  /* print and skip close capture */
  }
  return cap;
}


void printcaplist (Capture *cap) {
  {  /* for debugging, print first a raw list of captures */
    Capture *c = cap;
    while (c->index != MAXINDT) { printcap(c, 0); c++; }
  }
  printf(">======\n");
  while (!isclosecap(cap))
    cap = printcap2close(cap, 0);
  printf("=======\n");
}

/* }====================================================== */


/*
** {======================================================
** Printing trees (for debugging)
** =======================================================
*/

static const char *tagnames[] = {
  "char", "set", "any",
  "true", "false", "utf8.range",
  "rep",
  "seq", "choice",
  "not", "and",
  "call", "opencall", "rule", "xinfo", "grammar",
  "behind",
  "capture", "run-time"
};


void printtree (TTree *tree, int ident) {
  int i;
  int sibs = numsiblings[tree->tag];
  for (i = 0; i < ident; i++) printf(" ");
  printf("%s", tagnames[tree->tag]);
  switch (tree->tag) {
    case TChar: {
      int c = tree->u.n;
      if (isprint(c))
        printf(" '%c'\n", c);
      else
        printf(" (%02X)\n", c);
      break;
    }
    case TSet: {
      printTcharset(tree);
      printf("\n");
      break;
    }
    case TUTFR: {
      assert(sib1(tree)->tag == TXInfo);
      printf(" %d (%02x %d) - %d (%02x %d) \n",
        tree->u.n, tree->key, tree->cap,
        sib1(tree)->u.n, sib1(tree)->key, sib1(tree)->cap);
      break;
    }
    case TOpenCall: case TCall: {
      assert(sib1(sib2(tree))->tag == TXInfo);
      printf(" key: %d  (rule: %d)\n", tree->key, sib1(sib2(tree))->u.n);
      break;
    }
    case TBehind: {
      printf(" %d\n", tree->u.n);
      break;
    }
    case TCapture: {
      printf(" kind: '%s'  key: %d\n", capkind(tree->cap), tree->key);
      break;
    }
    case TRule: {
      printf(" key: %d\n", tree->key);
      sibs = 1;  /* do not print 'sib2' (next rule) as a sibling */
      break;
    }
    case TXInfo: {
      printf(" n: %d\n", tree->u.n);
      break;
    }
    case TGrammar: {
      TTree *rule = sib1(tree);
      printf(" %d\n", tree->u.n);  /* number of rules */
      for (i = 0; i < tree->u.n; i++) {
        printtree(rule, ident + 2);
        rule = sib2(rule);
      }
      assert(rule->tag == TTrue);  /* sentinel */
      sibs = 0;  /* siblings already handled */
      break;
    }
    default:
      printf("\n");
      break;
  }
  if (sibs >= 1) {
    printtree(sib1(tree), ident + 2);
    if (sibs >= 2)
      printtree(sib2(tree), ident + 2);
  }
}


void printktable (lua_State *L, int idx) {
  int n, i;
  lua_getuservalue(L, idx);
  if (lua_isnil(L, -1))  /* no ktable? */
    return;
  n = lua_rawlen(L, -1);
  printf("[");
  for (i = 1; i <= n; i++) {
    printf("%d = ", i);
    lua_rawgeti(L, -1, i);
    if (lua_isstring(L, -1))
      printf("%s  ", lua_tostring(L, -1));
    else
      printf("%s  ", lua_typename(L, lua_type(L, -1)));
    lua_pop(L, 1);
  }
  printf("]\n");
  /* leave ktable at the stack */
}

/* }====================================================== */

#endif


/* ==========================================================================
** File: lptree.c
** ==========================================================================
*/


#include <ctype.h>
#include <limits.h>
#include <string.h>


#include "lua.h"
#include "lauxlib.h"

/* #include "lptypes.h" -- stripped */
/* #include "lpcap.h" -- stripped */
/* #include "lpcode.h" -- stripped */
/* #include "lpprint.h" -- stripped */
/* #include "lptree.h" -- stripped */
/* #include "lpcset.h" -- stripped */


/* number of siblings for each tree */
const byte numsiblings[] = {
  0, 0, 0,	/* char, set, any */
  0, 0, 0,	/* true, false, utf-range */
  1,		/* acc */
  2, 2,		/* seq, choice */
  1, 1,		/* not, and */
  0, 0, 2, 1, 1,  /* call, opencall, rule, prerule, grammar */
  1,  /* behind */
  1, 1  /* capture, runtime capture */
};


static TTree *newgrammar (lua_State *L, int arg);


/*
** returns a reasonable name for value at index 'idx' on the stack
*/
static const char *val2str (lua_State *L, int idx) {
  const char *k = lua_tostring(L, idx);
  if (k != NULL)
    return lua_pushfstring(L, "%s", k);
  else
    return lua_pushfstring(L, "(a %s)", luaL_typename(L, idx));
}


/*
** Fix a TOpenCall into a TCall node, using table 'postable' to
** translate a key to its rule address in the tree. Raises an
** error if key does not exist.
*/
static void fixonecall (lua_State *L, int postable, TTree *g, TTree *t) {
  int n;
  lua_rawgeti(L, -1, t->key);  /* get rule's name */
  lua_gettable(L, postable);  /* query name in position table */
  n = lua_tonumber(L, -1);  /* get (absolute) position */
  lua_pop(L, 1);  /* remove position */
  if (n == 0) {  /* no position? */
    lua_rawgeti(L, -1, t->key);  /* get rule's name again */
    luaL_error(L, "rule '%s' undefined in given grammar", val2str(L, -1));
  }
  t->tag = TCall;
  t->u.ps = n - (t - g);  /* position relative to node */
  assert(sib2(t)->tag == TRule);
  sib2(t)->key = t->key;  /* fix rule's key */
}


/*
** Transform left associative constructions into right
** associative ones, for sequence and choice; that is:
** (t11 + t12) + t2  =>  t11 + (t12 + t2)
** (t11 * t12) * t2  =>  t11 * (t12 * t2)
** (that is, Op (Op t11 t12) t2 => Op t11 (Op t12 t2))
*/
static void correctassociativity (TTree *tree) {
  TTree *t1 = sib1(tree);
  assert(tree->tag == TChoice || tree->tag == TSeq);
  while (t1->tag == tree->tag) {
    int n1size = tree->u.ps - 1;  /* t1 == Op t11 t12 */
    int n11size = t1->u.ps - 1;
    int n12size = n1size - n11size - 1;
    memmove(sib1(tree), sib1(t1), n11size * sizeof(TTree)); /* move t11 */
    tree->u.ps = n11size + 1;
    sib2(tree)->tag = tree->tag;
    sib2(tree)->u.ps = n12size + 1;
  }
}


/*
** Make final adjustments in a tree. Fix open calls in tree 't',
** making them refer to their respective rules or raising appropriate
** errors (if not inside a grammar). Correct associativity of associative
** constructions (making them right associative). Assume that tree's
** ktable is at the top of the stack (for error messages).
*/
static void finalfix (lua_State *L, int postable, TTree *g, TTree *t) {
 tailcall:
  switch (t->tag) {
    case TGrammar:  /* subgrammars were already fixed */
      return;
    case TOpenCall: {
      if (g != NULL)  /* inside a grammar? */
        fixonecall(L, postable, g, t);
      else {  /* open call outside grammar */
        lua_rawgeti(L, -1, t->key);
        luaL_error(L, "rule '%s' used outside a grammar", val2str(L, -1));
      }
      break;
    }
    case TSeq: case TChoice:
      correctassociativity(t);
      break;
  }
  switch (numsiblings[t->tag]) {
    case 1: /* finalfix(L, postable, g, sib1(t)); */
      t = sib1(t); goto tailcall;
    case 2:
      finalfix(L, postable, g, sib1(t));
      t = sib2(t); goto tailcall;  /* finalfix(L, postable, g, sib2(t)); */
    default: assert(numsiblings[t->tag] == 0); break;
  }
}



/*
** {===================================================================
** KTable manipulation
**
** - The ktable of a pattern 'p' can be shared by other patterns that
** contain 'p' and no other constants. Because of this sharing, we
** should not add elements to a 'ktable' unless it was freshly created
** for the new pattern.
**
** - The maximum index in a ktable is USHRT_MAX, because trees and
** patterns use unsigned shorts to store those indices.
** ====================================================================
*/

/*
** Create a new 'ktable' to the pattern at the top of the stack.
*/
static void newktable (lua_State *L, int n) {
  lua_createtable(L, n, 0);  /* create a fresh table */
  lua_setuservalue(L, -2);  /* set it as 'ktable' for pattern */
}


/*
** Add element 'idx' to 'ktable' of pattern at the top of the stack;
** Return index of new element.
** If new element is nil, does not add it to table (as it would be
** useless) and returns 0, as ktable[0] is always nil.
*/
static int addtoktable (lua_State *L, int idx) {
  if (lua_isnil(L, idx))  /* nil value? */
    return 0;
  else {
    int n;
    lua_getuservalue(L, -1);  /* get ktable from pattern */
    n = lua_rawlen(L, -1);
    if (n >= USHRT_MAX)
      luaL_error(L, "too many Lua values in pattern");
    lua_pushvalue(L, idx);  /* element to be added */
    lua_rawseti(L, -2, ++n);
    lua_pop(L, 1);  /* remove 'ktable' */
    return n;
  }
}


/*
** Return the number of elements in the ktable at 'idx'.
** In Lua 5.2/5.3, default "environment" for patterns is nil, not
** a table. Treat it as an empty table. In Lua 5.1, assumes that
** the environment has no numeric indices (len == 0)
*/
static int ktablelen (lua_State *L, int idx) {
  if (!lua_istable(L, idx)) return 0;
  else return lua_rawlen(L, idx);
}


/*
** Concatentate the contents of table 'idx1' into table 'idx2'.
** (Assume that both indices are negative.)
** Return the original length of table 'idx2' (or 0, if no
** element was added, as there is no need to correct any index).
*/
static int concattable (lua_State *L, int idx1, int idx2) {
  int i;
  int n1 = ktablelen(L, idx1);
  int n2 = ktablelen(L, idx2);
  if (n1 + n2 > USHRT_MAX)
    luaL_error(L, "too many Lua values in pattern");
  if (n1 == 0) return 0;  /* nothing to correct */
  for (i = 1; i <= n1; i++) {
    lua_rawgeti(L, idx1, i);
    lua_rawseti(L, idx2 - 1, n2 + i);  /* correct 'idx2' */
  }
  return n2;
}


/*
** When joining 'ktables', constants from one of the subpatterns must
** be renumbered; 'correctkeys' corrects their indices (adding 'n'
** to each of them)
*/
static void correctkeys (TTree *tree, int n) {
  if (n == 0) return;  /* no correction? */
 tailcall:
  switch (tree->tag) {
    case TOpenCall: case TCall: case TRunTime: case TRule: {
      if (tree->key > 0)
        tree->key += n;
      break;
    }
    case TCapture: {
      if (tree->key > 0 && tree->cap != Carg && tree->cap != Cnum)
        tree->key += n;
      break;
    }
    default: break;
  }
  switch (numsiblings[tree->tag]) {
    case 1:  /* correctkeys(sib1(tree), n); */
      tree = sib1(tree); goto tailcall;
    case 2:
      correctkeys(sib1(tree), n);
      tree = sib2(tree); goto tailcall;  /* correctkeys(sib2(tree), n); */
    default: assert(numsiblings[tree->tag] == 0); break;
  }
}


/*
** Join the ktables from p1 and p2 the ktable for the new pattern at the
** top of the stack, reusing them when possible.
*/
static void joinktables (lua_State *L, int p1, TTree *t2, int p2) {
  int n1, n2;
  lua_getuservalue(L, p1);  /* get ktables */
  lua_getuservalue(L, p2);
  n1 = ktablelen(L, -2);
  n2 = ktablelen(L, -1);
  if (n1 == 0 && n2 == 0)  /* are both tables empty? */
    lua_pop(L, 2);  /* nothing to be done; pop tables */
  else if (n2 == 0 || lp_equal(L, -2, -1)) {  /* 2nd table empty or equal? */
    lua_pop(L, 1);  /* pop 2nd table */
    lua_setuservalue(L, -2);  /* set 1st ktable into new pattern */
  }
  else if (n1 == 0) {  /* first table is empty? */
    lua_setuservalue(L, -3);  /* set 2nd table into new pattern */
    lua_pop(L, 1);  /* pop 1st table */
  }
  else {
    lua_createtable(L, n1 + n2, 0);  /* create ktable for new pattern */
    /* stack: new p; ktable p1; ktable p2; new ktable */
    concattable(L, -3, -1);  /* from p1 into new ktable */
    concattable(L, -2, -1);  /* from p2 into new ktable */
    lua_setuservalue(L, -4);  /* new ktable becomes 'p' environment */
    lua_pop(L, 2);  /* pop other ktables */
    correctkeys(t2, n1);  /* correction for indices from p2 */
  }
}


/*
** copy 'ktable' of element 'idx' to new tree (on top of stack)
*/
static void copyktable (lua_State *L, int idx) {
  lua_getuservalue(L, idx);
  lua_setuservalue(L, -2);
}


/*
** merge 'ktable' from 'stree' at stack index 'idx' into 'ktable'
** from tree at the top of the stack, and correct corresponding
** tree.
*/
static void mergektable (lua_State *L, int idx, TTree *stree) {
  int n;
  lua_getuservalue(L, -1);  /* get ktables */
  lua_getuservalue(L, idx);
  n = concattable(L, -1, -2);
  lua_pop(L, 2);  /* remove both ktables */
  correctkeys(stree, n);
}


/*
** Create a new 'ktable' to the pattern at the top of the stack, adding
** all elements from pattern 'p' (if not 0) plus element 'idx' to it.
** Return index of new element.
*/
static int addtonewktable (lua_State *L, int p, int idx) {
  newktable(L, 1);
  if (p)
    mergektable(L, p, NULL);
  return addtoktable(L, idx);
}

/* }====================================================== */


/*
** {======================================================
** Tree generation
** =======================================================
*/

/*
** In 5.2, could use 'luaL_testudata'...
*/
static int testpattern (lua_State *L, int idx) {
  if (lua_touserdata(L, idx)) {  /* value is a userdata? */
    if (lua_getmetatable(L, idx)) {  /* does it have a metatable? */
      luaL_getmetatable(L, PATTERN_T);
      if (lua_rawequal(L, -1, -2)) {  /* does it have the correct mt? */
        lua_pop(L, 2);  /* remove both metatables */
        return 1;
      }
    }
  }
  return 0;
}


static Pattern *getpattern (lua_State *L, int idx) {
  return (Pattern *)luaL_checkudata(L, idx, PATTERN_T);
}


static int getsize (lua_State *L, int idx) {
  return (lua_rawlen(L, idx) - offsetof(Pattern, tree)) / sizeof(TTree);
}


static TTree *gettree (lua_State *L, int idx, int *len) {
  Pattern *p = getpattern(L, idx);
  if (len)
    *len = getsize(L, idx);
  return p->tree;
}


/*
** create a pattern followed by a tree with 'len' nodes. Set its
** uservalue (the 'ktable') equal to its metatable. (It could be any
** empty sequence; the metatable is at hand here, so we use it.)
*/
static TTree *newtree (lua_State *L, int len) {
  size_t size = offsetof(Pattern, tree) + len * sizeof(TTree);
  Pattern *p = (Pattern *)lua_newuserdata(L, size);
  luaL_getmetatable(L, PATTERN_T);
  lua_pushvalue(L, -1);
  lua_setuservalue(L, -3);
  lua_setmetatable(L, -2);
  p->code = NULL;
  return p->tree;
}


static TTree *newleaf (lua_State *L, int tag) {
  TTree *tree = newtree(L, 1);
  tree->tag = tag;
  return tree;
}


/*
** Create a tree for a charset, optimizing for special cases: empty set,
** full set, and singleton set.
*/
static TTree *newcharset (lua_State *L, byte *cs) {
  charsetinfo info;
  Opcode op = charsettype(cs, &info);
  switch (op) {
    case IFail: return newleaf(L, TFalse);  /* empty set */
    case IAny: return newleaf(L, TAny);  /* full set */
    case IChar: {  /* singleton set */
      TTree *tree =newleaf(L, TChar);
      tree->u.n = info.offset;
      return tree;
    }
    default: {  /* regular set */
      int i;
      int bsize =  /* tree size in bytes */
                  (int)offsetof(TTree, u.set.bitmap) + info.size;
      TTree *tree = newtree(L, bytes2slots(bsize));
      assert(op == ISet);
      tree->tag = TSet;
      tree->u.set.offset = info.offset;
      tree->u.set.size = info.size;
      tree->u.set.deflt = info.deflt;
      for (i = 0; i < info.size; i++) {
        assert(&treebuffer(tree)[i] < (byte*)tree + bsize);
        treebuffer(tree)[i] = cs[info.offset + i];
      }
      return tree;
    }
  }
}


/*
** Add to tree a sequence where first sibling is 'sib' (with size
** 'sibsize'); return position for second sibling.
*/
static TTree *seqaux (TTree *tree, TTree *sib, int sibsize) {
  tree->tag = TSeq; tree->u.ps = sibsize + 1;
  memcpy(sib1(tree), sib, sibsize * sizeof(TTree));
  return sib2(tree);
}


/*
** Build a sequence of 'n' nodes, each with tag 'tag' and 'u.n' got
** from the array 's' (or 0 if array is NULL). (TSeq is binary, so it
** must build a sequence of sequence of sequence...)
*/
static void fillseq (TTree *tree, int tag, int n, const char *s) {
  int i;
  for (i = 0; i < n - 1; i++) {  /* initial n-1 copies of Seq tag; Seq ... */
    tree->tag = TSeq; tree->u.ps = 2;
    sib1(tree)->tag = tag;
    sib1(tree)->u.n = s ? (byte)s[i] : 0;
    tree = sib2(tree);
  }
  tree->tag = tag;  /* last one does not need TSeq */
  tree->u.n = s ? (byte)s[i] : 0;
}


/*
** Numbers as patterns:
** 0 == true (always match); n == TAny repeated 'n' times;
** -n == not (TAny repeated 'n' times)
*/
static TTree *numtree (lua_State *L, int n) {
  if (n == 0)
    return newleaf(L, TTrue);
  else {
    TTree *tree, *nd;
    if (n > 0)
      tree = nd = newtree(L, 2 * n - 1);
    else {  /* negative: code it as !(-n) */
      n = -n;
      tree = newtree(L, 2 * n);
      tree->tag = TNot;
      nd = sib1(tree);
    }
    fillseq(nd, TAny, n, NULL);  /* sequence of 'n' any's */
    return tree;
  }
}


/*
** Convert value at index 'idx' to a pattern
*/
static TTree *getpatt (lua_State *L, int idx, int *len) {
  TTree *tree;
  switch (lua_type(L, idx)) {
    case LUA_TSTRING: {
      size_t slen;
      const char *s = lua_tolstring(L, idx, &slen);  /* get string */
      if (slen == 0)  /* empty? */
        tree = newleaf(L, TTrue);  /* always match */
      else {
        tree = newtree(L, 2 * (slen - 1) + 1);
        fillseq(tree, TChar, slen, s);  /* sequence of 'slen' chars */
      }
      break;
    }
    case LUA_TNUMBER: {
      int n = lua_tointeger(L, idx);
      tree = numtree(L, n);
      break;
    }
    case LUA_TBOOLEAN: {
      tree = (lua_toboolean(L, idx) ? newleaf(L, TTrue) : newleaf(L, TFalse));
      break;
    }
    case LUA_TTABLE: {
      tree = newgrammar(L, idx);
      break;
    }
    case LUA_TFUNCTION: {
      tree = newtree(L, 2);
      tree->tag = TRunTime;
      tree->key = addtonewktable(L, 0, idx);
      sib1(tree)->tag = TTrue;
      break;
    }
    default: {
      return gettree(L, idx, len);
    }
  }
  lua_replace(L, idx);  /* put new tree into 'idx' slot */
  if (len)
    *len = getsize(L, idx);
  return tree;
}


/*
** create a new tree, whith a new root and one sibling.
** Sibling must be on the Lua stack, at index 1.
*/
static TTree *newroot1sib (lua_State *L, int tag) {
  int s1;
  TTree *tree1 = getpatt(L, 1, &s1);
  TTree *tree = newtree(L, 1 + s1);  /* create new tree */
  tree->tag = tag;
  memcpy(sib1(tree), tree1, s1 * sizeof(TTree));
  copyktable(L, 1);
  return tree;
}


/*
** create a new tree, whith a new root and 2 siblings.
** Siblings must be on the Lua stack, first one at index 1.
*/
static TTree *newroot2sib (lua_State *L, int tag) {
  int s1, s2;
  TTree *tree1 = getpatt(L, 1, &s1);
  TTree *tree2 = getpatt(L, 2, &s2);
  TTree *tree = newtree(L, 1 + s1 + s2);  /* create new tree */
  tree->tag = tag;
  tree->u.ps =  1 + s1;
  memcpy(sib1(tree), tree1, s1 * sizeof(TTree));
  memcpy(sib2(tree), tree2, s2 * sizeof(TTree));
  joinktables(L, 1, sib2(tree), 2);
  return tree;
}


static int lp_P (lua_State *L) {
  luaL_checkany(L, 1);
  getpatt(L, 1, NULL);
  lua_settop(L, 1);
  return 1;
}


/*
** sequence operator; optimizations:
** false x => false, x true => x, true x => x
** (cannot do x . false => false because x may have runtime captures)
*/
static int lp_seq (lua_State *L) {
  TTree *tree1 = getpatt(L, 1, NULL);
  TTree *tree2 = getpatt(L, 2, NULL);
  if (tree1->tag == TFalse || tree2->tag == TTrue)
    lua_pushvalue(L, 1);  /* false . x == false, x . true = x */
  else if (tree1->tag == TTrue)
    lua_pushvalue(L, 2);  /* true . x = x */
  else
    newroot2sib(L, TSeq);
  return 1;
}


/*
** choice operator; optimizations:
** charset / charset => charset
** true / x => true, x / false => x, false / x => x
** (x / true is not equivalent to true)
*/
static int lp_choice (lua_State *L) {
  Charset st1, st2;
  TTree *t1 = getpatt(L, 1, NULL);
  TTree *t2 = getpatt(L, 2, NULL);
  if (tocharset(t1, &st1) && tocharset(t2, &st2)) {
    loopset(i, st1.cs[i] |= st2.cs[i]);
    newcharset(L, st1.cs);
  }
  else if (nofail(t1) || t2->tag == TFalse)
    lua_pushvalue(L, 1);  /* true / x => true, x / false => x */
  else if (t1->tag == TFalse)
    lua_pushvalue(L, 2);  /* false / x => x */
  else
    newroot2sib(L, TChoice);
  return 1;
}


/*
** p^n
*/
static int lp_star (lua_State *L) {
  int size1;
  int n = (int)luaL_checkinteger(L, 2);
  TTree *tree1 = getpatt(L, 1, &size1);
  if (n >= 0) {  /* seq tree1 (seq tree1 ... (seq tree1 (rep tree1))) */
    TTree *tree = newtree(L, (n + 1) * (size1 + 1));
    if (nullable(tree1))
      luaL_error(L, "loop body may accept empty string");
    while (n--)  /* repeat 'n' times */
      tree = seqaux(tree, tree1, size1);
    tree->tag = TRep;
    memcpy(sib1(tree), tree1, size1 * sizeof(TTree));
  }
  else {  /* choice (seq tree1 ... choice tree1 true ...) true */
    TTree *tree;
    n = -n;
    /* size = (choice + seq + tree1 + true) * n, but the last has no seq */
    tree = newtree(L, n * (size1 + 3) - 1);
    for (; n > 1; n--) {  /* repeat (n - 1) times */
      tree->tag = TChoice; tree->u.ps = n * (size1 + 3) - 2;
      sib2(tree)->tag = TTrue;
      tree = sib1(tree);
      tree = seqaux(tree, tree1, size1);
    }
    tree->tag = TChoice; tree->u.ps = size1 + 1;
    sib2(tree)->tag = TTrue;
    memcpy(sib1(tree), tree1, size1 * sizeof(TTree));
  }
  copyktable(L, 1);
  return 1;
}


/*
** #p == &p
*/
static int lp_and (lua_State *L) {
  newroot1sib(L, TAnd);
  return 1;
}


/*
** -p == !p
*/
static int lp_not (lua_State *L) {
  newroot1sib(L, TNot);
  return 1;
}


/*
** [t1 - t2] == Seq (Not t2) t1
** If t1 and t2 are charsets, make their difference.
*/
static int lp_sub (lua_State *L) {
  Charset st1, st2;
  int s1, s2;
  TTree *t1 = getpatt(L, 1, &s1);
  TTree *t2 = getpatt(L, 2, &s2);
  if (tocharset(t1, &st1) && tocharset(t2, &st2)) {
    loopset(i, st1.cs[i] &= ~st2.cs[i]);
    newcharset(L, st1.cs);
  }
  else {
    TTree *tree = newtree(L, 2 + s1 + s2);
    tree->tag = TSeq;  /* sequence of... */
    tree->u.ps =  2 + s2;
    sib1(tree)->tag = TNot;  /* ...not... */
    memcpy(sib1(sib1(tree)), t2, s2 * sizeof(TTree));  /* ...t2 */
    memcpy(sib2(tree), t1, s1 * sizeof(TTree));  /* ... and t1 */
    joinktables(L, 1, sib1(tree), 2);
  }
  return 1;
}


static int lp_set (lua_State *L) {
  size_t l;
  const char *s = luaL_checklstring(L, 1, &l);
  byte buff[CHARSETSIZE];
  clearset(buff);
  while (l--) {
    setchar(buff, (byte)(*s));
    s++;
  }
  newcharset(L, buff);
  return 1;
}


static int lp_range (lua_State *L) {
  int arg;
  int top = lua_gettop(L);
  byte buff[CHARSETSIZE];
  clearset(buff);
  for (arg = 1; arg <= top; arg++) {
    int c;
    size_t l;
    const char *r = luaL_checklstring(L, arg, &l);
    luaL_argcheck(L, l == 2, arg, "range must have two characters");
    for (c = (byte)r[0]; c <= (byte)r[1]; c++)
      setchar(buff, c);
  }
  newcharset(L, buff);
  return 1;
}


/*
** Fills a tree node with basic information about the UTF-8 code point
** 'cpu': its value in 'n', its length in 'cap', and its first byte in
** 'key'
*/
static void codeutftree (lua_State *L, TTree *t, lua_Unsigned cpu, int arg) {
  int len, fb, cp;
  cp = (int)cpu;
  if (cp <= 0x7f) {  /* one byte? */
    len = 1;
    fb = cp;
  } else if (cp <= 0x7ff) {
    len = 2;
    fb = 0xC0 | (cp >> 6);
  } else if (cp <= 0xffff) {
    len = 3;
    fb = 0xE0 | (cp >> 12);
  }
  else {
    luaL_argcheck(L, cpu <= 0x10ffffu, arg, "invalid code point");
    len = 4;
    fb = 0xF0 | (cp >> 18);
  }
  t->u.n = cp;
  t->cap = len;
  t->key = fb;
}


static int lp_utfr (lua_State *L) {
  lua_Unsigned from = (lua_Unsigned)luaL_checkinteger(L, 1);
  lua_Unsigned to = (lua_Unsigned)luaL_checkinteger(L, 2);
  luaL_argcheck(L, from <= to, 2, "empty range");
  if (to <= 0x7f) {  /* ascii range? */
    uint f;
    byte buff[CHARSETSIZE];  /* code it as a regular charset */
    clearset(buff);
    for (f = (int)from; f <= to; f++)
      setchar(buff, f);
    newcharset(L, buff);
  }
  else {  /* multi-byte utf-8 range */
    TTree *tree = newtree(L, 2);
    tree->tag = TUTFR;
    codeutftree(L, tree, from, 1);
    sib1(tree)->tag = TXInfo;
    codeutftree(L, sib1(tree), to, 2);
  }
  return 1;
}


/*
** Look-behind predicate
*/
static int lp_behind (lua_State *L) {
  TTree *tree;
  TTree *tree1 = getpatt(L, 1, NULL);
  int n = fixedlen(tree1);
  luaL_argcheck(L, n >= 0, 1, "pattern may not have fixed length");
  luaL_argcheck(L, !hascaptures(tree1), 1, "pattern have captures");
  luaL_argcheck(L, n <= MAXBEHIND, 1, "pattern too long to look behind");
  tree = newroot1sib(L, TBehind);
  tree->u.n = n;
  return 1;
}


/*
** Create a non-terminal
*/
static int lp_V (lua_State *L) {
  TTree *tree = newleaf(L, TOpenCall);
  luaL_argcheck(L, !lua_isnoneornil(L, 1), 1, "non-nil value expected");
  tree->key = addtonewktable(L, 0, 1);
  return 1;
}


/*
** Create a tree for a non-empty capture, with a body and
** optionally with an associated Lua value (at index 'labelidx' in the
** stack)
*/
static int capture_aux (lua_State *L, int cap, int labelidx) {
  TTree *tree = newroot1sib(L, TCapture);
  tree->cap = cap;
  tree->key = (labelidx == 0) ? 0 : addtonewktable(L, 1, labelidx);
  return 1;
}


/*
** Fill a tree with an empty capture, using an empty (TTrue) sibling.
** (The 'key' field must be filled by the caller to finish the tree.)
*/
static TTree *auxemptycap (TTree *tree, int cap) {
  tree->tag = TCapture;
  tree->cap = cap;
  sib1(tree)->tag = TTrue;
  return tree;
}


/*
** Create a tree for an empty capture.
*/
static TTree *newemptycap (lua_State *L, int cap, int key) {
  TTree *tree = auxemptycap(newtree(L, 2), cap);
  tree->key = key;
  return tree;
}


/*
** Create a tree for an empty capture with an associated Lua value.
*/
static TTree *newemptycapkey (lua_State *L, int cap, int idx) {
  TTree *tree = auxemptycap(newtree(L, 2), cap);
  tree->key = addtonewktable(L, 0, idx);
  return tree;
}


/*
** Captures with syntax p / v
** (function capture, query capture, string capture, or number capture)
*/
static int lp_divcapture (lua_State *L) {
  switch (lua_type(L, 2)) {
    case LUA_TFUNCTION: return capture_aux(L, Cfunction, 2);
    case LUA_TTABLE: return capture_aux(L, Cquery, 2);
    case LUA_TSTRING: return capture_aux(L, Cstring, 2);
    case LUA_TNUMBER: {
      int n = lua_tointeger(L, 2);
      TTree *tree = newroot1sib(L, TCapture);
      luaL_argcheck(L, 0 <= n && n <= SHRT_MAX, 1, "invalid number");
      tree->cap = Cnum;
      tree->key = n;
      return 1;
    }
    default:
      return luaL_error(L, "unexpected %s as 2nd operand to LPeg '/'",
                           luaL_typename(L, 2));
  }
}


static int lp_acccapture (lua_State *L) {
  return capture_aux(L, Cacc, 2);
}


static int lp_substcapture (lua_State *L) {
  return capture_aux(L, Csubst, 0);
}


static int lp_tablecapture (lua_State *L) {
  return capture_aux(L, Ctable, 0);
}


static int lp_groupcapture (lua_State *L) {
  if (lua_isnoneornil(L, 2))
    return capture_aux(L, Cgroup, 0);
  else
    return capture_aux(L, Cgroup, 2);
}


static int lp_foldcapture (lua_State *L) {
  luaL_checktype(L, 2, LUA_TFUNCTION);
  return capture_aux(L, Cfold, 2);
}


static int lp_simplecapture (lua_State *L) {
  return capture_aux(L, Csimple, 0);
}


static int lp_poscapture (lua_State *L) {
  newemptycap(L, Cposition, 0);
  return 1;
}


static int lp_argcapture (lua_State *L) {
  int n = (int)luaL_checkinteger(L, 1);
  luaL_argcheck(L, 0 < n && n <= SHRT_MAX, 1, "invalid argument index");
  newemptycap(L, Carg, n);
  return 1;
}


static int lp_backref (lua_State *L) {
  luaL_checkany(L, 1);
  newemptycapkey(L, Cbackref, 1);
  return 1;
}


/*
** Constant capture
*/
static int lp_constcapture (lua_State *L) {
  int i;
  int n = lua_gettop(L);  /* number of values */
  if (n == 0)  /* no values? */
    newleaf(L, TTrue);  /* no capture */
  else if (n == 1)
    newemptycapkey(L, Cconst, 1);  /* single constant capture */
  else {  /* create a group capture with all values */
    TTree *tree = newtree(L, 1 + 3 * (n - 1) + 2);
    newktable(L, n);  /* create a 'ktable' for new tree */
    tree->tag = TCapture;
    tree->cap = Cgroup;
    tree->key = 0;
    tree = sib1(tree);
    for (i = 1; i <= n - 1; i++) {
      tree->tag = TSeq;
      tree->u.ps = 3;  /* skip TCapture and its sibling */
      auxemptycap(sib1(tree), Cconst);
      sib1(tree)->key = addtoktable(L, i);
      tree = sib2(tree);
    }
    auxemptycap(tree, Cconst);
    tree->key = addtoktable(L, i);
  }
  return 1;
}


static int lp_matchtime (lua_State *L) {
  TTree *tree;
  luaL_checktype(L, 2, LUA_TFUNCTION);
  tree = newroot1sib(L, TRunTime);
  tree->key = addtonewktable(L, 1, 2);
  return 1;
}

/* }====================================================== */


/*
** {======================================================
** Grammar - Tree generation
** =======================================================
*/

/*
** push on the stack the index and the pattern for the
** initial rule of grammar at index 'arg' in the stack;
** also add that index into position table.
*/
static void getfirstrule (lua_State *L, int arg, int postab) {
  lua_rawgeti(L, arg, 1);  /* access first element */
  if (lua_isstring(L, -1)) {  /* is it the name of initial rule? */
    lua_pushvalue(L, -1);  /* duplicate it to use as key */
    lua_gettable(L, arg);  /* get associated rule */
  }
  else {
    lua_pushinteger(L, 1);  /* key for initial rule */
    lua_insert(L, -2);  /* put it before rule */
  }
  if (!testpattern(L, -1)) {  /* initial rule not a pattern? */
    if (lua_isnil(L, -1))
      luaL_error(L, "grammar has no initial rule");
    else
      luaL_error(L, "initial rule '%s' is not a pattern", lua_tostring(L, -2));
  }
  lua_pushvalue(L, -2);  /* push key */
  lua_pushinteger(L, 1);  /* push rule position (after TGrammar) */
  lua_settable(L, postab);  /* insert pair at position table */
}

/*
** traverse grammar at index 'arg', pushing all its keys and patterns
** into the stack. Create a new table (before all pairs key-pattern) to
** collect all keys and their associated positions in the final tree
** (the "position table").
** Return the number of rules and (in 'totalsize') the total size
** for the new tree.
*/
static int collectrules (lua_State *L, int arg, int *totalsize) {
  int n = 1;  /* to count number of rules */
  int postab = lua_gettop(L) + 1;  /* index of position table */
  int size;  /* accumulator for total size */
  lua_newtable(L);  /* create position table */
  getfirstrule(L, arg, postab);
  size = 3 + getsize(L, postab + 2);  /* TGrammar + TRule + TXInfo + rule */
  lua_pushnil(L);  /* prepare to traverse grammar table */
  while (lua_next(L, arg) != 0) {
    if (lua_tonumber(L, -2) == 1 ||
        lp_equal(L, -2, postab + 1)) {  /* initial rule? */
      lua_pop(L, 1);  /* remove value (keep key for lua_next) */
      continue;
    }
    if (!testpattern(L, -1))  /* value is not a pattern? */
      luaL_error(L, "rule '%s' is not a pattern", val2str(L, -2));
    luaL_checkstack(L, LUA_MINSTACK, "grammar has too many rules");
    lua_pushvalue(L, -2);  /* push key (to insert into position table) */
    lua_pushinteger(L, size);
    lua_settable(L, postab);
    size += 2 + getsize(L, -1);  /* add 'TRule + TXInfo + rule' to size */
    lua_pushvalue(L, -2);  /* push key (for next lua_next) */
    n++;
  }
  *totalsize = size + 1;  /* space for 'TTrue' finishing list of rules */
  return n;
}


static void buildgrammar (lua_State *L, TTree *grammar, int frule, int n) {
  int i;
  TTree *nd = sib1(grammar);  /* auxiliary pointer to traverse the tree */
  for (i = 0; i < n; i++) {  /* add each rule into new tree */
    int ridx = frule + 2*i + 1;  /* index of i-th rule */
    int rulesize;
    TTree *rn = gettree(L, ridx, &rulesize);
    TTree *pr = sib1(nd);  /* points to rule's prerule */
    nd->tag = TRule;
    nd->key = 0;  /* will be fixed when rule is used */
    pr->tag = TXInfo;
    pr->u.n = i;  /* rule number */
    nd->u.ps = rulesize + 2;  /* point to next rule */
    memcpy(sib1(pr), rn, rulesize * sizeof(TTree));  /* copy rule */
    mergektable(L, ridx, sib1(nd));  /* merge its ktable into new one */
    nd = sib2(nd);  /* move to next rule */
  }
  nd->tag = TTrue;  /* finish list of rules */
}


/*
** Check whether a tree has potential infinite loops
*/
static int checkloops (TTree *tree) {
 tailcall:
  if (tree->tag == TRep && nullable(sib1(tree)))
    return 1;
  else if (tree->tag == TGrammar)
    return 0;  /* sub-grammars already checked */
  else {
    switch (numsiblings[tree->tag]) {
      case 1:  /* return checkloops(sib1(tree)); */
        tree = sib1(tree); goto tailcall;
      case 2:
        if (checkloops(sib1(tree))) return 1;
        /* else return checkloops(sib2(tree)); */
        tree = sib2(tree); goto tailcall;
      default: assert(numsiblings[tree->tag] == 0); return 0;
    }
  }
}


/*
** Give appropriate error message for 'verifyrule'. If a rule appears
** twice in 'passed', there is path from it back to itself without
** advancing the subject.
*/
static int verifyerror (lua_State *L, unsigned short *passed, int npassed) {
  int i, j;
  for (i = npassed - 1; i >= 0; i--) {  /* search for a repetition */
    for (j = i - 1; j >= 0; j--) {
      if (passed[i] == passed[j]) {
        lua_rawgeti(L, -1, passed[i]);  /* get rule's key */
        return luaL_error(L, "rule '%s' may be left recursive", val2str(L, -1));
      }
    }
  }
  return luaL_error(L, "too many left calls in grammar");
}


/*
** Check whether a rule can be left recursive; raise an error in that
** case; otherwise return 1 iff pattern is nullable.
** The return value is used to check sequences, where the second pattern
** is only relevant if the first is nullable.
** Parameter 'nb' works as an accumulator, to allow tail calls in
** choices. ('nb' true makes function returns true.)
** Parameter 'passed' is a list of already visited rules, 'npassed'
** counts the elements in 'passed'.
** Assume ktable at the top of the stack.
*/
static int verifyrule (lua_State *L, TTree *tree, unsigned short *passed,
                                     int npassed, int nb) {
 tailcall:
  switch (tree->tag) {
    case TChar: case TSet: case TAny:
    case TFalse: case TUTFR:
      return nb;  /* cannot pass from here */
    case TTrue:
    case TBehind:  /* look-behind cannot have calls */
      return 1;
    case TNot: case TAnd: case TRep:
      /* return verifyrule(L, sib1(tree), passed, npassed, 1); */
      tree = sib1(tree); nb = 1; goto tailcall;
    case TCapture: case TRunTime: case TXInfo:
      /* return verifyrule(L, sib1(tree), passed, npassed, nb); */
      tree = sib1(tree); goto tailcall;
    case TCall:
      /* return verifyrule(L, sib2(tree), passed, npassed, nb); */
      tree = sib2(tree); goto tailcall;
    case TSeq:  /* only check 2nd child if first is nb */
      if (!verifyrule(L, sib1(tree), passed, npassed, 0))
        return nb;
      /* else return verifyrule(L, sib2(tree), passed, npassed, nb); */
      tree = sib2(tree); goto tailcall;
    case TChoice:  /* must check both children */
      nb = verifyrule(L, sib1(tree), passed, npassed, nb);
      /* return verifyrule(L, sib2(tree), passed, npassed, nb); */
      tree = sib2(tree); goto tailcall;
    case TRule:
      if (npassed >= MAXRULES)  /* too many steps? */
        return verifyerror(L, passed, npassed);  /* error */
      else {
        passed[npassed++] = tree->key;  /* add rule to path */
        /* return verifyrule(L, sib1(tree), passed, npassed); */
        tree = sib1(tree); goto tailcall;
      }
    case TGrammar:
      return nullable(tree);  /* sub-grammar cannot be left recursive */
    default: assert(0); return 0;
  }
}


static void verifygrammar (lua_State *L, TTree *grammar) {
  unsigned short passed[MAXRULES];
  TTree *rule;
  /* check left-recursive rules */
  for (rule = sib1(grammar); rule->tag == TRule; rule = sib2(rule)) {
    if (rule->key == 0) continue;  /* unused rule */
    verifyrule(L, sib1(rule), passed, 0, 0);
  }
  assert(rule->tag == TTrue);
  /* check infinite loops inside rules */
  for (rule = sib1(grammar); rule->tag == TRule; rule = sib2(rule)) {
    if (rule->key == 0) continue;  /* unused rule */
    if (checkloops(sib1(rule))) {
      lua_rawgeti(L, -1, rule->key);  /* get rule's key */
      luaL_error(L, "empty loop in rule '%s'", val2str(L, -1));
    }
  }
  assert(rule->tag == TTrue);
}


/*
** Give a name for the initial rule if it is not referenced
*/
static void initialrulename (lua_State *L, TTree *grammar, int frule) {
  if (sib1(grammar)->key == 0) {  /* initial rule is not referenced? */
    int n = lua_rawlen(L, -1) + 1;  /* index for name */
    lua_pushvalue(L, frule);  /* rule's name */
    lua_rawseti(L, -2, n);  /* ktable was on the top of the stack */
    sib1(grammar)->key = n;
  }
}


static TTree *newgrammar (lua_State *L, int arg) {
  int treesize;
  int frule = lua_gettop(L) + 2;  /* position of first rule's key */
  int n = collectrules(L, arg, &treesize);
  TTree *g = newtree(L, treesize);
  luaL_argcheck(L, n <= MAXRULES, arg, "grammar has too many rules");
  g->tag = TGrammar;  g->u.n = n;
  lua_newtable(L);  /* create 'ktable' */
  lua_setuservalue(L, -2);
  buildgrammar(L, g, frule, n);
  lua_getuservalue(L, -1);  /* get 'ktable' for new tree */
  finalfix(L, frule - 1, g, sib1(g));
  initialrulename(L, g, frule);
  verifygrammar(L, g);
  lua_pop(L, 1);  /* remove 'ktable' */
  lua_insert(L, -(n * 2 + 2));  /* move new table to proper position */
  lua_pop(L, n * 2 + 1);  /* remove position table + rule pairs */
  return g;  /* new table at the top of the stack */
}

/* }====================================================== */


static Instruction *prepcompile (lua_State *L, Pattern *p, int idx) {
  lua_getuservalue(L, idx);  /* push 'ktable' (may be used by 'finalfix') */
  finalfix(L, 0, NULL, p->tree);
  lua_pop(L, 1);  /* remove 'ktable' */
  return compile(L, p, getsize(L, idx));
}


static int lp_printtree (lua_State *L) {
  TTree *tree = getpatt(L, 1, NULL);
  int c = lua_toboolean(L, 2);
  if (c) {
    lua_getuservalue(L, 1);  /* push 'ktable' (may be used by 'finalfix') */
    finalfix(L, 0, NULL, tree);
    lua_pop(L, 1);  /* remove 'ktable' */
  }
  printktable(L, 1);
  printtree(tree, 0);
  return 0;
}


static int lp_printcode (lua_State *L) {
  Pattern *p = getpattern(L, 1);
  printktable(L, 1);
  if (p->code == NULL)  /* not compiled yet? */
    prepcompile(L, p, 1);
  printpatt(p->code);
  return 0;
}


/*
** Get the initial position for the match, interpreting negative
** values from the end of the subject
*/
static size_t initposition (lua_State *L, size_t len) {
  lua_Integer ii = luaL_optinteger(L, 3, 1);
  if (ii > 0) {  /* positive index? */
    if ((size_t)ii <= len)  /* inside the string? */
      return (size_t)ii - 1;  /* return it (corrected to 0-base) */
    else return len;  /* crop at the end */
  }
  else {  /* negative index */
    if ((size_t)(-ii) <= len)  /* inside the string? */
      return len - ((size_t)(-ii));  /* return position from the end */
    else return 0;  /* crop at the beginning */
  }
}


/*
** Main match function
*/
static int lp_match (lua_State *L) {
  Capture capture[INITCAPSIZE];
  const char *r;
  size_t l;
  Pattern *p = (getpatt(L, 1, NULL), getpattern(L, 1));
  Instruction *code = (p->code != NULL) ? p->code : prepcompile(L, p, 1);
  const char *s = luaL_checklstring(L, SUBJIDX, &l);
  size_t i = initposition(L, l);
  int ptop = lua_gettop(L);
  luaL_argcheck(L, l < MAXINDT, SUBJIDX, "subject too long");
  lua_pushnil(L);  /* initialize subscache */
  lua_pushlightuserdata(L, capture);  /* initialize caplistidx */
  lua_getuservalue(L, 1);  /* initialize ktableidx */
  r = match(L, s, s + i, s + l, code, capture, ptop);
  if (r == NULL) {
    lua_pushnil(L);
    return 1;
  }
  return getcaptures(L, s, r, ptop);
}



/*
** {======================================================
** Library creation and functions not related to matching
** =======================================================
*/

/* maximum limit for stack size */
#define MAXLIM		(INT_MAX / 100)

static int lp_setmax (lua_State *L) {
  lua_Integer lim = luaL_checkinteger(L, 1);
  luaL_argcheck(L, 0 < lim && lim <= MAXLIM, 1, "out of range");
  lua_settop(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, MAXSTACKIDX);
  return 0;
}


static int lp_type (lua_State *L) {
  if (testpattern(L, 1))
    lua_pushliteral(L, "pattern");
  else
    lua_pushnil(L);
  return 1;
}


int lp_gc (lua_State *L) {
  Pattern *p = getpattern(L, 1);
  freecode(L, p);  /* delete code block */
  return 0;
}


/*
** Create a charset representing a category of characters, given by
** the predicate 'catf'.
*/
static void createcat (lua_State *L, const char *catname, int (catf) (int)) {
  int c;
  byte buff[CHARSETSIZE];
  clearset(buff);
  for (c = 0; c <= UCHAR_MAX; c++)
    if (catf(c)) setchar(buff, c);
  newcharset(L, buff);
  lua_setfield(L, -2, catname);
}


static int lp_locale (lua_State *L) {
  if (lua_isnoneornil(L, 1)) {
    lua_settop(L, 0);
    lua_createtable(L, 0, 12);
  }
  else {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_settop(L, 1);
  }
  createcat(L, "alnum", isalnum);
  createcat(L, "alpha", isalpha);
  createcat(L, "cntrl", iscntrl);
  createcat(L, "digit", isdigit);
  createcat(L, "graph", isgraph);
  createcat(L, "lower", islower);
  createcat(L, "print", isprint);
  createcat(L, "punct", ispunct);
  createcat(L, "space", isspace);
  createcat(L, "upper", isupper);
  createcat(L, "xdigit", isxdigit);
  return 1;
}


static struct luaL_Reg pattreg[] = {
  {"ptree", lp_printtree},
  {"pcode", lp_printcode},
  {"match", lp_match},
  {"B", lp_behind},
  {"V", lp_V},
  {"C", lp_simplecapture},
  {"Cc", lp_constcapture},
  {"Cmt", lp_matchtime},
  {"Cb", lp_backref},
  {"Carg", lp_argcapture},
  {"Cp", lp_poscapture},
  {"Cs", lp_substcapture},
  {"Ct", lp_tablecapture},
  {"Cf", lp_foldcapture},
  {"Cg", lp_groupcapture},
  {"P", lp_P},
  {"S", lp_set},
  {"R", lp_range},
  {"utfR", lp_utfr},
  {"locale", lp_locale},
  {"version", NULL},
  {"setmaxstack", lp_setmax},
  {"type", lp_type},
  {NULL, NULL}
};


static struct luaL_Reg metareg[] = {
  {"__mul", lp_seq},
  {"__add", lp_choice},
  {"__pow", lp_star},
  {"__gc", lp_gc},
  {"__len", lp_and},
  {"__div", lp_divcapture},
  {"__mod", lp_acccapture},
  {"__unm", lp_not},
  {"__sub", lp_sub},
  {NULL, NULL}
};


int luaopen_lpeg (lua_State *L);
int luaopen_lpeg (lua_State *L) {
  luaL_newmetatable(L, PATTERN_T);
  lua_pushnumber(L, MAXBACK);  /* initialize maximum backtracking */
  lua_setfield(L, LUA_REGISTRYINDEX, MAXSTACKIDX);
  luaL_setfuncs(L, metareg, 0);
  luaL_newlib(L, pattreg);
  lua_pushvalue(L, -1);
  lua_setfield(L, -3, "__index");
  lua_pushliteral(L, "LPeg " VERSION);
  lua_setfield(L, -2, "version");
  return 1;
}

/* }====================================================== */


/* ==========================================================================
** File: lpvm.c
** ==========================================================================
*/


#include <limits.h>
#include <string.h>


#include "lua.h"
#include "lauxlib.h"

/* #include "lpcap.h" -- stripped */
/* #include "lptypes.h" -- stripped */
/* #include "lpvm.h" -- stripped */
/* #include "lpprint.h" -- stripped */


/* initial size for call/backtrack stack */
#if !defined(INITBACK)
#define INITBACK	MAXBACK
#endif


#define getoffset(p)	(((p) + 1)->offset)

static const Instruction giveup = {{IGiveup, 0, {0}}};


int charinset (const Instruction *i, const byte *buff, uint c) {
  c -= i->i.aux2.set.offset;
  if (c >= ((uint)i->i.aux2.set.size  /* size in instructions... */
           * (uint)sizeof(Instruction)  /* in bytes... */
           * 8u))  /* in bits */
    return i->i.aux1;  /* out of range; return default value */
  return testchar(buff, c);
}


/*
** Decode one UTF-8 sequence, returning NULL if byte sequence is invalid.
*/
static const char *utf8_decode (const char *o, int *val) {
  static const uint limits[] = {0xFF, 0x7F, 0x7FF, 0xFFFFu};
  const unsigned char *s = (const unsigned char *)o;
  uint c = s[0];  /* first byte */
  uint res = 0;  /* final result */
  if (c < 0x80)  /* ascii? */
    res = c;
  else {
    int count = 0;  /* to count number of continuation bytes */
    while (c & 0x40) {  /* still have continuation bytes? */
      int cc = s[++count];  /* read next byte */
      if ((cc & 0xC0) != 0x80)  /* not a continuation byte? */
        return NULL;  /* invalid byte sequence */
      res = (res << 6) | (cc & 0x3F);  /* add lower 6 bits from cont. byte */
      c <<= 1;  /* to test next bit */
    }
    res |= (c & 0x7F) << (count * 5);  /* add first byte */
    if (count > 3 || res > 0x10FFFFu || res <= limits[count])
      return NULL;  /* invalid byte sequence */
    s += count;  /* skip continuation bytes read */
  }
  *val = res;
  return (const char *)s + 1;  /* +1 to include first byte */
}


/*
** {======================================================
** Virtual Machine
** =======================================================
*/


typedef struct Stack {
  const char *s;  /* saved position (or NULL for calls) */
  const Instruction *p;  /* next instruction */
  int caplevel;
} Stack;


#define getstackbase(L, ptop)	((Stack *)lua_touserdata(L, stackidx(ptop)))


/*
** Ensures the size of array 'capture' (with size '*capsize' and
** 'captop' elements being used) is enough to accomodate 'n' extra
** elements plus one.  (Because several opcodes add stuff to the capture
** array, it is simpler to ensure the array always has at least one free
** slot upfront and check its size later.)
*/

/* new size in number of elements cannot overflow integers, and new
   size in bytes cannot overflow size_t. */
#define MAXNEWSIZE  \
    (((size_t)INT_MAX) <= (~(size_t)0 / sizeof(Capture)) ?  \
     ((size_t)INT_MAX) : (~(size_t)0 / sizeof(Capture)))

static Capture *growcap (lua_State *L, Capture *capture, int *capsize,
                                       int captop, int n, int ptop) {
  if (*capsize - captop > n)
    return capture;  /* no need to grow array */
  else {  /* must grow */
    Capture *newc;
    uint newsize = captop + n + 1;  /* minimum size needed */
    if (newsize < (MAXNEWSIZE / 3) * 2)
      newsize += newsize / 2;  /* 1.5 that size, if not too big */
    else if (newsize < (MAXNEWSIZE / 9) * 8)
      newsize += newsize / 8;  /* else, try 9/8 that size */
    else
      luaL_error(L, "too many captures");
    newc = (Capture *)lua_newuserdata(L, newsize * sizeof(Capture));
    memcpy(newc, capture, captop * sizeof(Capture));
    *capsize = newsize;
    lua_replace(L, caplistidx(ptop));
    return newc;
  }
}


/*
** Double the size of the stack
*/
static Stack *doublestack (lua_State *L, Stack **stacklimit, int ptop) {
  Stack *stack = getstackbase(L, ptop);
  Stack *newstack;
  int n = *stacklimit - stack;  /* current stack size */
  int max, newn;
  lua_getfield(L, LUA_REGISTRYINDEX, MAXSTACKIDX);
  max = lua_tointeger(L, -1);  /* maximum allowed size */
  lua_pop(L, 1);
  if (n >= max)  /* already at maximum size? */
    luaL_error(L, "backtrack stack overflow (current limit is %d)", max);
  newn = 2 * n;  /* new size */
  if (newn > max) newn = max;
  newstack = (Stack *)lua_newuserdata(L, newn * sizeof(Stack));
  memcpy(newstack, stack, n * sizeof(Stack));
  lua_replace(L, stackidx(ptop));
  *stacklimit = newstack + newn;
  return newstack + n;  /* return next position */
}


/*
** Interpret the result of a dynamic capture: false -> fail;
** true -> keep current position; number -> next position.
** Return new subject position. 'fr' is stack index where
** is the result; 'curr' is current subject position; 'limit'
** is subject's size.
*/
static int resdyncaptures (lua_State *L, int fr, int curr, int limit) {
  lua_Integer res;
  if (!lua_toboolean(L, fr)) {  /* false value? */
    lua_settop(L, fr - 1);  /* remove results */
    return -1;  /* and fail */
  }
  else if (lua_isboolean(L, fr))  /* true? */
    res = curr;  /* keep current position */
  else {
    res = lua_tointeger(L, fr) - 1;  /* new position */
    if (res < curr || res > limit)
      luaL_error(L, "invalid position returned by match-time capture");
  }
  lua_remove(L, fr);  /* remove first result (offset) */
  return res;
}


/*
** Add capture values returned by a dynamic capture to the list
** 'capture', nested inside a group. 'fd' indexes the first capture
** value, 'n' is the number of values (at least 1). The open group
** capture is already in 'capture', before the place for the new entries.
*/
static void adddyncaptures (Index_t index, Capture *capture, int n, int fd) {
  int i;
  assert(capture[-1].kind == Cgroup && capture[-1].siz == 0);
  capture[-1].idx = 0;  /* make group capture an anonymous group */
  for (i = 0; i < n; i++) {  /* add runtime captures */
    capture[i].kind = Cruntime;
    capture[i].siz = 1;  /* mark it as closed */
    capture[i].idx = fd + i;  /* stack index of capture value */
    capture[i].index = index;
  }
  capture[n].kind = Cclose;  /* close group */
  capture[n].siz = 1;
  capture[n].index = index;
}


/*
** Remove dynamic captures from the Lua stack (called in case of failure)
*/
static int removedyncap (lua_State *L, Capture *capture,
                         int level, int last) {
  int id = finddyncap(capture + level, capture + last);  /* index of 1st cap. */
  int top = lua_gettop(L);
  if (id == 0) return 0;  /* no dynamic captures? */
  lua_settop(L, id - 1);  /* remove captures */
  return top - id + 1;  /* number of values removed */
}


/*
** Find the corresponding 'open' capture before 'cap', when that capture
** can become a full capture. If a full capture c1 is followed by an
** empty capture c2, there is no way to know whether c2 is inside
** c1. So, full captures can enclose only captures that start *before*
** its end.
*/
static Capture *findopen (Capture *cap, Index_t currindex) {
  int i;
  cap--;  /* check last capture */
  /* Must it be inside current one, but starts where current one ends? */
  if (!isopencap(cap) && cap->index == currindex)
    return NULL;  /* current one cannot be a full capture */
  /* else, look for an 'open' capture */
  for (i = 0; i < MAXLOP; i++, cap--) {
    if (currindex - cap->index >= UCHAR_MAX)
      return NULL;  /* capture too long for a full capture */
    else if (isopencap(cap))  /* open capture? */
      return cap;  /* that's the one to be closed */
    else if (cap->kind == Cclose)
      return NULL;  /* a full capture should not nest a non-full one */
  }
  return NULL;  /* not found within allowed search limit */
}


/*
** Opcode interpreter
*/
const char *match (lua_State *L, const char *o, const char *s, const char *e,
                   Instruction *op, Capture *capture, int ptop) {
  Stack stackbase[INITBACK];
  Stack *stacklimit = stackbase + INITBACK;
  Stack *stack = stackbase;  /* point to first empty slot in stack */
  int capsize = INITCAPSIZE;
  int captop = 0;  /* point to first empty slot in captures */
  int ndyncap = 0;  /* number of dynamic captures (in Lua stack) */
  const Instruction *p = op;  /* current instruction */
  stack->p = &giveup; stack->s = s; stack->caplevel = 0; stack++;
  lua_pushlightuserdata(L, stackbase);
  for (;;) {
#if defined(DEBUG)
      printf("-------------------------------------\n");
      printcaplist(capture, capture + captop);
      printf("s: |%s| stck:%d, dyncaps:%d, caps:%d  ",
             s, (int)(stack - getstackbase(L, ptop)), ndyncap, captop);
      printinst(op, p);
#endif
    assert(stackidx(ptop) + ndyncap == lua_gettop(L) && ndyncap <= captop);
    switch ((Opcode)p->i.code) {
      case IEnd: {
        assert(stack == getstackbase(L, ptop) + 1);
        capture[captop].kind = Cclose;
        capture[captop].index = MAXINDT;
        return s;
      }
      case IGiveup: {
        assert(stack == getstackbase(L, ptop));
        return NULL;
      }
      case IRet: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s == NULL);
        p = (--stack)->p;
        continue;
      }
      case IAny: {
        if (s < e) { p++; s++; }
        else goto fail;
        continue;
      }
      case IUTFR: {
        int codepoint;
        if (s >= e)
          goto fail;
        s = utf8_decode (s, &codepoint);
        if (s && p[1].offset <= codepoint && codepoint <= utf_to(p))
          p += 2;
        else
          goto fail;
        continue;
      }
      case ITestAny: {
        if (s < e) p += 2;
        else p += getoffset(p);
        continue;
      }
      case IChar: {
        if ((byte)*s == p->i.aux1 && s < e) { p++; s++; }
        else goto fail;
        continue;
      }
      case ITestChar: {
        if ((byte)*s == p->i.aux1 && s < e) p += 2;
        else p += getoffset(p);
        continue;
      }
      case ISet: {
        uint c = (byte)*s;
        if (charinset(p, (p+1)->buff, c) && s < e)
          { p += 1 + p->i.aux2.set.size; s++; }
        else goto fail;
        continue;
      }
      case ITestSet: {
        uint c = (byte)*s;
        if (charinset(p, (p + 2)->buff, c) && s < e)
          p += 2 + p->i.aux2.set.size;
        else p += getoffset(p);
        continue;
      }
      case IBehind: {
        int n = p->i.aux1;
        if (n > s - o) goto fail;
        s -= n; p++;
        continue;
      }
      case ISpan: {
        for (; s < e; s++) {
          uint c = (byte)*s;
          if (!charinset(p, (p+1)->buff, c)) break;
        }
        p += 1 + p->i.aux2.set.size;
        continue;
      }
      case IJmp: {
        p += getoffset(p);
        continue;
      }
      case IChoice: {
        if (stack == stacklimit)
          stack = doublestack(L, &stacklimit, ptop);
        stack->p = p + getoffset(p);
        stack->s = s;
        stack->caplevel = captop;
        stack++;
        p += 2;
        continue;
      }
      case ICall: {
        if (stack == stacklimit)
          stack = doublestack(L, &stacklimit, ptop);
        stack->s = NULL;
        stack->p = p + 2;  /* save return address */
        stack++;
        p += getoffset(p);
        continue;
      }
      case ICommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        stack--;
        p += getoffset(p);
        continue;
      }
      case IPartialCommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        (stack - 1)->s = s;
        (stack - 1)->caplevel = captop;
        p += getoffset(p);
        continue;
      }
      case IBackCommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        s = (--stack)->s;
        if (ndyncap > 0)  /* are there matchtime captures? */
          ndyncap -= removedyncap(L, capture, stack->caplevel, captop);
        captop = stack->caplevel;
        p += getoffset(p);
        continue;
      }
      case IFailTwice:
        assert(stack > getstackbase(L, ptop));
        stack--;
        /* FALLTHROUGH */
      case IFail:
      fail: { /* pattern failed: try to backtrack */
        do {  /* remove pending calls */
          assert(stack > getstackbase(L, ptop));
          s = (--stack)->s;
        } while (s == NULL);
        if (ndyncap > 0)  /* is there matchtime captures? */
          ndyncap -= removedyncap(L, capture, stack->caplevel, captop);
        captop = stack->caplevel;
        p = stack->p;
#if defined(DEBUG)
        printf("**FAIL**\n");
#endif
        continue;
      }
      case ICloseRunTime: {
        CapState cs;
        int rem, res, n;
        int fr = lua_gettop(L) + 1;  /* stack index of first result */
        cs.reclevel = 0; cs.L = L;
        cs.s = o; cs.ocap = capture; cs.ptop = ptop;
        n = runtimecap(&cs, capture + captop, s, &rem);  /* call function */
        captop -= n;  /* remove nested captures */
        ndyncap -= rem;  /* update number of dynamic captures */
        fr -= rem;  /* 'rem' items were popped from Lua stack */
        res = resdyncaptures(L, fr, s - o, e - o);  /* get result */
        if (res == -1)  /* fail? */
          goto fail;
        s = o + res;  /* else update current position */
        n = lua_gettop(L) - fr + 1;  /* number of new captures */
        ndyncap += n;  /* update number of dynamic captures */
        if (n == 0)  /* no new captures? */
          captop--;  /* remove open group */
        else {  /* new captures; keep original open group */
          if (fr + n >= SHRT_MAX)
            luaL_error(L, "too many results in match-time capture");
          /* add new captures + close group to 'capture' list */
          capture = growcap(L, capture, &capsize, captop, n + 1, ptop);
          adddyncaptures(s - o, capture + captop, n, fr);
          captop += n + 1;  /* new captures + close group */
        }
        p++;
        continue;
      }
      case ICloseCapture: {
        Capture *open = findopen(capture + captop, s - o);
        assert(captop > 0);
        if (open) {  /* if possible, turn capture into a full capture */
          open->siz = (s - o) - open->index + 1;
          p++;
          continue;
        }
        else {  /* must create a close capture */
          capture[captop].siz = 1;  /* mark entry as closed */
          capture[captop].index = s - o;
          goto pushcapture;
        }
      }
      case IOpenCapture:
        capture[captop].siz = 0;  /* mark entry as open */
        capture[captop].index = s - o;
        goto pushcapture;
      case IFullCapture:
        capture[captop].siz = getoff(p) + 1;  /* save capture size */
        capture[captop].index = s - o - getoff(p);
        /* goto pushcapture; */
      pushcapture: {
        capture[captop].idx = p->i.aux2.key;
        capture[captop].kind = getkind(p);
        captop++;
        capture = growcap(L, capture, &capsize, captop, 0, ptop);
        p++;
        continue;
      }
      default: assert(0); return NULL;
    }
  }
}

/* }====================================================== */




