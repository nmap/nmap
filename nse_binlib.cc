/*
 * -- nse_packlib.cc
 * -- adapted from:
 * lpack.c
 * a Lua library for packing and unpacking binary data
 * Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
 * 29 Jun 2007 19:27:20
 * This code is hereby placed in the public domain.
 * with contributions from Ignacio Castaño <castanyo@yahoo.es> and
 * Roberto Ierusalimschy <roberto@inf.puc-rio.br>.
 * -- modified:
 * BinStringHandling
*/

#define	OP_ZSTRING	'z'		/* zero-terminated string */
#define	OP_BSTRING	'p'		/* string preceded by 1 byte integer */
#define	OP_WSTRING	'P'		/* string preceded by 2 byte integer */
#define	OP_SSTRING	'a'		/* string preceded by 4 byte integer */
#define	OP_STRING	'A'		/* string */
#define	OP_FLOAT	'f'		/* float */
#define	OP_DOUBLE	'd'		/* double */
#define	OP_NUMBER	'n'		/* Lua number */
#define	OP_CHAR		'c'		/* char (1-byte int) */
#define	OP_BYTE		'C'		/* byte = unsigned char (1-byte unsigned int) */
#define	OP_SHORT	's'		/* short (2-byte int) */
#define	OP_USHORT	'S'		/* unsigned short (2-byte unsigned int) */
#define	OP_INT		'i'		/* int (4-byte int) */
#define	OP_UINT		'I'		/* unsigned int (4-byte unsigned int) */
#define	OP_LONG		'l'		/* long (8-byte int) */
#define	OP_ULONG	'L'		/* unsigned long (8-byte unsigned int) */
#define	OP_LITTLEENDIAN	'<'		/* little endian */
#define	OP_BIGENDIAN	'>'		/* big endian */
#define	OP_NATIVE	'='		/* native endian */

#define OP_BINMSB 'B'

#define OP_HEX 'H'

#define OP_NULL 'x'


#include <ctype.h>
#include <string.h>
#include <nbase.h>

extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}
#include "nse_binlib.h"

static void badcode(lua_State *L, int c)
{
 char s[]="bad code `?'";
 s[sizeof(s)-3]=c;
 luaL_argerror(L,1,s);
}

static int doendian(int c)
{
 int x=1;
 int e=*(char*)&x;
 if (c==OP_LITTLEENDIAN) return !e;
 if (c==OP_BIGENDIAN) return e;
 if (c==OP_NATIVE) return 0;
 return 0;
}

static void doswap(int swap, void *p, size_t n)
{
 if (swap)
 {
  char *a=(char*)p;
  int i,j;
  for (i=0, j=n-1, n=n/2; n--; i++, j--)
  {
   char t=a[i]; a[i]=a[j]; a[j]=t;
  }
 }
}

#define UNPACKNUMBER(OP,T)		\
   case OP:				\
   {					\
    T a;				\
    int m=sizeof(a);			\
    if (i+m>len) { done = 1;	break;}	\
    memcpy(&a,s+i,m);			\
    i+=m;				\
    doswap(swap,&a,m);			\
    lua_pushnumber(L,(lua_Number)a);	\
    ++n;				\
    break;				\
   }

#define UNPACKSTRING(OP,T)		\
   case OP:				\
   {					\
    T l;				\
    int m=sizeof(l);			\
    if (i+m>len) { done = 1;	break; }	\
    memcpy(&l,s+i,m);			\
    doswap(swap,&l,m);			\
    if (i+m+l>len) { done = 1; break;}		\
    i+=m;				\
    lua_pushlstring(L,s+i,l);		\
    i+=l;				\
    ++n;				\
    break;				\
   }

#define HEXDIGITS(DIG) \
 "0123456789ABCDEF"[DIG]


static int l_unpack(lua_State *L) 		/** unpack(f,s, [init]) */
{
 size_t len;
 const char *s=luaL_checklstring(L,2,&len); /* switched s and f */
 const char *f=luaL_checkstring(L,1);
 int i_read = luaL_optint(L,3,1)-1;
 unsigned int i;
 if (i_read >= 0) {
   i = i_read;
 } else {
   i = 0;
 }
 int n=0;
 int swap=0;
 int done=0;
 lua_pushnil(L);
 while (*f && done == 0)
 {
  int c=*f++;
  int N=1;
  if (isdigit((int) (unsigned char) *f)) 
  {
   N=0;
   while (isdigit((int) (unsigned char) *f)) N=10*N+(*f++)-'0';
   if (N==0 && c==OP_STRING) { lua_pushliteral(L,""); ++n; }
  }
  while (N-- && done == 0) switch (c)
  {
   case OP_LITTLEENDIAN:
   case OP_BIGENDIAN:
   case OP_NATIVE:
   {
    swap=doendian(c);
    N=0;
    break;
   }
   case OP_STRING:
   {
    ++N;
    if (i+N>len) {done = 1; break; }
    lua_pushlstring(L,s+i,N);
    i+=N;
    ++n;
    N=0;
    break;
   }
   case OP_ZSTRING:
   {
    size_t l;
    if (i>=len) {done = 1; break; }
    l=strlen(s+i);
    lua_pushlstring(L,s+i,l);
    i+=l+1;
    ++n;
    break;
   }
   UNPACKSTRING(OP_BSTRING, u8)
   UNPACKSTRING(OP_WSTRING, u16)
   UNPACKSTRING(OP_SSTRING, u32)
   UNPACKNUMBER(OP_NUMBER, lua_Number)
   UNPACKNUMBER(OP_DOUBLE, double)
   UNPACKNUMBER(OP_FLOAT, float)
   UNPACKNUMBER(OP_CHAR, s8)
   UNPACKNUMBER(OP_BYTE, u8)
   UNPACKNUMBER(OP_SHORT, s16)
   UNPACKNUMBER(OP_USHORT, u16)
   UNPACKNUMBER(OP_INT, s32)
   UNPACKNUMBER(OP_UINT, u32)
   UNPACKNUMBER(OP_LONG, s64)
   UNPACKNUMBER(OP_ULONG, u64)

   case OP_BINMSB:
     {
       luaL_Buffer buf;
       luaL_buffinit(L,&buf);
       unsigned char sbyte = 0x80;
       N++;
       if (i+N > len) {done = 1; break;}
       for (unsigned int ii = i; ii < i+N; ii++) {
	 sbyte = 0x80;
	 for (int ij = 0; ij < 8; ij++) {
	   if (s[ii] & sbyte) {
	     luaL_addlstring(&buf, "1", 1);
	   } else {
	     luaL_addlstring(&buf, "0", 1);
	   }
	   sbyte = sbyte >> 1;
	 }
       }
       luaL_pushresult(&buf);
       n++;
       i += N;
       N = 0;
       break;
     }

   case OP_HEX:
     {
       luaL_Buffer buf;
       char hdigit = '0';
       int val = 0;
       luaL_buffinit(L,&buf);
       N++;
       if (i+N > len) {done = 1; break;}
       for (unsigned int ii = i; ii < i+N; ii++) {
	 val = s[ii] & 0xF0;
	 val = val >> 4;
	 hdigit = HEXDIGITS(val);
	 luaL_addlstring(&buf, &hdigit, 1);

	 val = s[ii] & 0x0F;
	 hdigit = HEXDIGITS(val);
	 luaL_addlstring(&buf, &hdigit, 1);
       }
       luaL_pushresult(&buf);
       n++;
       i += N;
       N = 0;
       break;
     }
  case OP_NULL:
    {
      i+= N + 1;
      N = 0;
      break;
    }
   case ' ': case ',':
    break;
   default:
    badcode(L,c);
    break;
  }
 }
 lua_pushnumber(L,i+1);
 lua_replace(L,-n-2);
 return n+1;
}

#define PACKNUMBER(OP,T)			\
   case OP:					\
   {						\
    T a=(T)luaL_checknumber(L,i++);		\
    doswap(swap,&a,sizeof(a));			\
    luaL_addlstring(&b,(char*)&a,sizeof(a));	\
    break;					\
   }

#define PACKSTRING(OP,T)			\
   case OP:					\
   {						\
    size_t l;					\
    const char *a=luaL_checklstring(L,i++,&l);	\
    T ll=(T)l;					\
    doswap(swap,&ll,sizeof(ll));		\
    luaL_addlstring(&b,(char*)&ll,sizeof(ll));	\
    luaL_addlstring(&b,a,l);			\
    break;					\
   }

static int l_pack(lua_State *L) 		/** pack(f,...) */
{
 int i=2;
 const char *f=luaL_checkstring(L,1);
 int swap=0;
 luaL_Buffer b;
 luaL_buffinit(L,&b);
 while (*f)
 {
  int c=*f++;
  int N=1;
  if (isdigit((int) (unsigned char) *f)) 
  {
   N=0;
   while (isdigit((int) (unsigned char) *f)) N=10*N+(*f++)-'0';
  }
  while (N--) switch (c)
  {
   case OP_LITTLEENDIAN:
   case OP_BIGENDIAN:
   case OP_NATIVE:
   {
    swap=doendian(c);
    N=0;
    break;
   }
   case OP_STRING:
   case OP_ZSTRING:
   {
    size_t l;
    const char *a=luaL_checklstring(L,i++,&l);
    luaL_addlstring(&b,a,l+(c==OP_ZSTRING));
    break;
   }
   PACKSTRING(OP_BSTRING, u8)
   PACKSTRING(OP_WSTRING, u16)
   PACKSTRING(OP_SSTRING, u32)
   PACKNUMBER(OP_NUMBER, lua_Number)
   PACKNUMBER(OP_DOUBLE, double)
   PACKNUMBER(OP_FLOAT, float)
   PACKNUMBER(OP_CHAR, s8)
   PACKNUMBER(OP_BYTE, u8)
   PACKNUMBER(OP_SHORT, s16)
   PACKNUMBER(OP_USHORT, u16)
   PACKNUMBER(OP_INT, s32)
   PACKNUMBER(OP_UINT, u32)
   PACKNUMBER(OP_LONG, s64)
   PACKNUMBER(OP_ULONG, u64)
   case OP_BINMSB:
     {
       unsigned char sbyte = 0;
       size_t l;
       unsigned int ii = 0, ia = 0;
       const char *a = luaL_checklstring(L, i++, &l);
       for (ia = 0; ia < l; ia+= 8) {
	 sbyte = 0;
	 for (ii = 0; ii+ia < l && ii < 8; ii++) {
	   sbyte = sbyte << 1;
	   if (a[ii+ia] != '0') {
	     sbyte++;
	   }
	 }
	 for (; ii < 8; ii++) {
	   sbyte = sbyte << 1;
	 }
	 luaL_addlstring(&b, (char *) &sbyte, 1);
       }
       break;
     }
   
  case OP_NULL:
    {
      char nullbyte = 0;
      luaL_addlstring(&b, &nullbyte, 1);
      break;
    }
    
  case OP_HEX: 
    { // doing digit parsing the lpack way
      unsigned char sbyte = 0;
      size_t l;
      unsigned int ii = 0;
      int odd = 0;
      const char *a = luaL_checklstring(L, i++, &l);
      for (ii = 0; ii < l; ii++) {
	if (isxdigit((int) (unsigned char) a[ii])) {
	  if (isdigit((int) (unsigned char) a[ii])) {
	    sbyte += a[ii] - '0';
	    odd++;
	  } else if (a[ii] >= 'A' && a[ii] <= 'F') {
	    sbyte += a[ii] - 'A' + 10;
	    odd++;
	  } else if (a[ii] >= 'a' && a[ii] <= 'f') {
	    sbyte += a[ii] - 'a' + 10;
	    odd++;
	  }	  
	  if (odd == 1) {
	    sbyte = sbyte << 4;
	  } else if (odd == 2) {
	    luaL_addlstring(&b, (char *) &sbyte, 1);
	    sbyte = 0;
	    odd = 0;
	  }
	} else if (isspace(a[ii])) {
	  /* ignore */
	} else {
	  /* err ... ignore too*/
	}
      }
      if (odd == 1) {
	luaL_addlstring(&b, (char *) &sbyte, 1);
      }
      break;
    }
   case ' ': case ',':
    break;
   default:
    badcode(L,c);
    break;
  }
 }
 luaL_pushresult(&b);
 return 1;
}

static const luaL_Reg binlib[] =
{
	{"pack",	l_pack},
	{"unpack",	l_unpack},
	{NULL,	NULL}
};

/*
** Open bin library
*/
LUALIB_API int luaopen_binlib (lua_State *L) {
  luaL_newlib(L, binlib);
  return 1;
}

