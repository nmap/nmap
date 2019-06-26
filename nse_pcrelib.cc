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
