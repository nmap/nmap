/************************************************************************
* Author    : Tiago Dionizio <tiago.dionizio@gmail.com>                 *
* Library   : lzlib - Lua 5 interface to access zlib library functions  *
*                                                                       *
* Permission is hereby granted, free of charge, to any person obtaining *
* a copy of this software and associated documentation files (the       *
* "Software"), to deal in the Software without restriction, including   *
* without limitation the rights to use, copy, modify, merge, publish,   *
* distribute, sublicense, and/or sell copies of the Software, and to    *
* permit persons to whom the Software is furnished to do so, subject to *
* the following conditions:                                             *
*                                                                       *
* The above copyright notice and this permission notice shall be        *
* included in all copies or substantial portions of the Software.       *
*                                                                       *
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       *
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    *
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  *
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,  *
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE     *
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                *
************************************************************************/

#include <stdlib.h>
#include <string.h>

#include "nse_lua.h"

#include <zlib.h>

/*
** =========================================================================
** compile time options which determine available functionality
** =========================================================================
*/

/* TODO

- also call flush on table/userdata when flush function is detected
- remove io_cb check inflate_block if condition
- only set eos when ZSTREAM_END is reached
- check for stream errors to close stream when really needed

*/


/*
** =========================================================================
** zlib stream metamethods
** =========================================================================
*/
#define ZSTREAMMETA "zlib:zstream"

#define LZ_ANY     -1
#define LZ_NONE    0
#define LZ_DEFLATE 1
#define LZ_INFLATE 2

#if 0
    #define LZ_BUFFER_SIZE LUAL_BUFFERSIZE
#else
    #define LZ_BUFFER_SIZE 8192
#endif

typedef struct {
    /* zlib structures */
    z_stream zstream;
    /* stream state. LZ_DEFLATE | LZ_INFLATE */
    int state;
    int error;
    int peek;
    int eos;
    /* user callback source for reading/writing */
    int io_cb;
    /* input buffer */
    int i_buffer_ref;
    size_t i_buffer_pos;
    size_t i_buffer_len;
    const char *i_buffer;
    /* output buffer */
    size_t o_buffer_len;
    size_t o_buffer_max;
    char o_buffer[LZ_BUFFER_SIZE];
    /* dictionary */
    const Bytef *dictionary;
    size_t dictionary_len;
} lz_stream;


/* forward declarations */
static int lzstream_docompress(lua_State *L, lz_stream *s, int from, int to, int flush);


static lz_stream *lzstream_new(lua_State *L, int src) {
    lz_stream *s = (lz_stream*)lua_newuserdata(L, sizeof(lz_stream));

    luaL_getmetatable(L, ZSTREAMMETA);
    lua_setmetatable(L, -2);        /* set metatable */

    s->state = LZ_NONE;
    s->error = Z_OK;
    s->eos = 0;
    s->io_cb = LUA_REFNIL;

    s->i_buffer = NULL;
    s->i_buffer_ref = LUA_REFNIL;
    s->i_buffer_pos = 0;
    s->i_buffer_len = 0;

    s->peek = 0;
    s->o_buffer_len = 0;
    s->o_buffer_max = sizeof(s->o_buffer) / sizeof(s->o_buffer[0]);

    s->zstream.zalloc = Z_NULL;
    s->zstream.zfree = Z_NULL;

    /* prepare source */
    if (lua_isstring(L, src)) {
        lua_pushvalue(L, src);
        s->i_buffer_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        s->i_buffer = lua_tolstring(L, src, &s->i_buffer_len);
    } else {
        /* table | function | userdata */
        lua_pushvalue(L, src);
        s->io_cb = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    return s;
}

static void lzstream_cleanup(lua_State *L, lz_stream *s) {
    if (s && s->state != LZ_NONE) {
        if (s->state == LZ_INFLATE) {
            inflateEnd(&s->zstream);
        }
        if (s->state == LZ_DEFLATE) {
            deflateEnd(&s->zstream);
        }

        luaL_unref(L, LUA_REGISTRYINDEX, s->io_cb);
        luaL_unref(L, LUA_REGISTRYINDEX, s->i_buffer_ref);
        s->state = LZ_NONE;
    }
}

/* ====================================================================== */

static lz_stream *lzstream_get(lua_State *L, int index) {
    lz_stream *s = (lz_stream*)luaL_checkudata(L, index, ZSTREAMMETA);
    if (s == NULL) luaL_argerror(L, index, "bad zlib stream");
    return s;
}

static lz_stream *lzstream_check(lua_State *L, int index, int state) {
    lz_stream *s = lzstream_get(L, index);
    if ((state != LZ_ANY && s->state != state) || s->state == LZ_NONE) {
        luaL_argerror(L, index, "attempt to use invalid zlib stream");
    }
    return s;
}

/* ====================================================================== */

static int lzstream_tostring(lua_State *L) {
    lz_stream *s = (lz_stream*)luaL_checkudata(L, 1, ZSTREAMMETA);
    if (s == NULL) return luaL_argerror(L, 1, "bad zlib stream");

    if (s->state == LZ_NONE) {
        lua_pushstring(L, "zlib stream (closed)");
    } else if (s->state == LZ_DEFLATE) {
        lua_pushfstring(L, "zlib deflate stream (%p)", (void*)s);
    } else if (s->state == LZ_INFLATE) {
        lua_pushfstring(L, "zlib inflate stream (%p)", (void*)s);
    } else {
        lua_pushfstring(L, "%p", (void*)s);
    }

    return 1;
}

/* ====================================================================== */

static int lzstream_gc(lua_State *L) {
    lz_stream *s = lzstream_get(L, 1);
    lzstream_cleanup(L, s);
    return 0;
}

/* ====================================================================== */

static int lzstream_close(lua_State *L) {
    lz_stream *s = lzstream_get(L, 1);

    if (s->state == LZ_DEFLATE) {
        lua_settop(L, 0);
        lua_pushliteral(L, "");
        return lzstream_docompress(L, s, 1, 1, Z_FINISH);
    }

    lzstream_cleanup(L, s);
    lua_pushboolean(L, 1);
    return 1;
}

/* ====================================================================== */

static int lzstream_adler(lua_State *L) {
    lz_stream *s = lzstream_check(L, 1, LZ_ANY);
    lua_pushnumber(L, s->zstream.adler);
    return 1;
}

/* ====================================================================== */

/*
    zlib.deflate(
        sink: function | { write: function [, close: function, flush: function] },
        compression level, [Z_DEFAILT_COMPRESSION]
        method, [Z_DEFLATED]
        windowBits, [15]
        memLevel, [8]
        strategy, [Z_DEFAULT_STRATEGY]
        dictionary: [""]
    )
*/
static int lzlib_deflate(lua_State *L) {
    int level, method, windowBits, memLevel, strategy;
    lz_stream *s;
    const char *dictionary;
    size_t dictionary_len;

    if (lua_istable(L, 1) || lua_isuserdata(L, 1)) {
        /* is there a :write function? */
        lua_getfield(L, 1, "write");
        if (!lua_isfunction(L, -1)) {
            luaL_argerror(L, 1, "output parameter does not provide :write function");
        }
        lua_pop(L, 1);
    }
    else if (!lua_isfunction(L, 1)) {
        luaL_argerror(L, 1, "output parameter must be a function, table or userdata value");
    }

    level = (int) luaL_optinteger(L, 2, Z_DEFAULT_COMPRESSION);
    method = (int) luaL_optinteger(L, 3, Z_DEFLATED);
    windowBits = (int) luaL_optinteger(L, 4, 15);
    memLevel = (int) luaL_optinteger(L, 5, 8);
    strategy = (int) luaL_optinteger(L, 6, Z_DEFAULT_STRATEGY);
    dictionary = luaL_optlstring(L, 7, NULL, &dictionary_len);

    s = lzstream_new(L, 1);

    if (deflateInit2(&s->zstream, level, method, windowBits, memLevel, strategy) != Z_OK) {
        lua_pushliteral(L, "call to deflateInit2 failed");
        lua_error(L);
    }

    if (dictionary) {
        if (deflateSetDictionary(&s->zstream, (const Bytef *) dictionary, dictionary_len) != Z_OK) {
            lua_pushliteral(L, "call to deflateSetDictionnary failed");
            lua_error(L);
        }
    }

    s->state = LZ_DEFLATE;
    return 1;
}

/*
    zlib.inflate(
        source: string | function | { read: function, close: function },
        windowBits: number, [15]
        dictionary: [""]
    )
*/
static int lzlib_inflate(lua_State *L)
{
    int windowBits;
    lz_stream *s;
    int have_peek = 0;
    const char *dictionary;
    size_t dictionary_len;

    if (lua_istable(L, 1) || lua_isuserdata(L, 1)) {
        /* is there a :read function? */
        lua_getfield(L, 1, "read");
        if (!lua_isfunction(L, -1)) {
            luaL_argerror(L, 1, "input parameter does not provide :read function");
        }
        lua_pop(L, 1);
        /* check for peek function */
        lua_getfield(L, 1, "peek");
        have_peek = lua_isfunction(L, -1);
        lua_pop(L, 1);
    }
    else if (!lua_isstring(L, 1) && !lua_isfunction(L, 1)) {
        luaL_argerror(L, 1, "input parameter must be a string, function, table or userdata value");
    }

    windowBits = (int) luaL_optinteger(L, 2, 15);
    dictionary = luaL_optlstring(L, 3, NULL, &dictionary_len);

    s = lzstream_new(L, 1);

    if (windowBits > 0 && windowBits < 16) {
        windowBits |= 32;
    }

    if (inflateInit2(&s->zstream, windowBits) != Z_OK) {
        lua_pushliteral(L, "call to inflateInit2 failed");
        lua_error(L);
    }

    if (dictionary) {
        s->dictionary = (const Bytef *) dictionary;
        s->dictionary_len = dictionary_len;
    }

    s->peek = have_peek;
    s->state = LZ_INFLATE;
    return 1;
}

/* ====================================================================== */

static int lz_pushresult (lua_State *L, lz_stream *s) {
    if (s->error == Z_OK) {
        lua_pushboolean(L, 1);
        return 1;
    } else {
        lua_pushnil(L);
        lua_pushstring(L, zError(s->error));
        lua_pushinteger(L, s->error);
        return 3;
    }
}

/*
    Get block to process:
        - top of stack gets
*/
static const char* lzstream_fetch_block(lua_State *L, lz_stream *s, int hint) {
    if (s->i_buffer_pos >= s->i_buffer_len) {
        luaL_unref(L, LUA_REGISTRYINDEX, s->i_buffer_ref);
        s->i_buffer_ref = LUA_NOREF;
        s->i_buffer = NULL;

        lua_rawgeti(L, LUA_REGISTRYINDEX, s->io_cb);
        if (!lua_isnil(L, -1)) {
            if (lua_isfunction(L, -1)) {
                lua_pushinteger(L, hint);
                lua_call(L, 1, 1);
            } else {
                lua_getfield(L, -1, (s->peek ? "peek" : "read"));
                lua_insert(L, -2);
                lua_pushinteger(L, hint);
                lua_call(L, 2, 1);
            }

            if (lua_isstring(L, -1)) {
                s->i_buffer_pos = 0;
                s->i_buffer = lua_tolstring(L, -1, &s->i_buffer_len);
                if (s->i_buffer_len > 0) {
                    s->i_buffer_ref = luaL_ref(L, LUA_REGISTRYINDEX);
                } else {
                    lua_pop(L, 1);
                }
            } else if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
            } else {
                lua_pushliteral(L, "deflate callback must return string or nil");
                lua_error(L);
            }
        } else {
            lua_pop(L, 1);
        }
    }

    return s->i_buffer;
}

static int lzstream_inflate_block(lua_State *L, lz_stream *s) {
    if (lzstream_fetch_block(L, s, LZ_BUFFER_SIZE) || !s->eos) {
        int r;

        if (s->i_buffer_len == s->i_buffer_pos) {
            s->zstream.next_in = NULL;
            s->zstream.avail_in = 0;
        } else {
            s->zstream.next_in = (unsigned char*)(s->i_buffer + s->i_buffer_pos);
            s->zstream.avail_in = s->i_buffer_len - s->i_buffer_pos;
        }

        s->zstream.next_out = (unsigned char*)s->o_buffer + s->o_buffer_len;
        s->zstream.avail_out = s->o_buffer_max - s->o_buffer_len;

        /* munch some more */
        r = inflate(&s->zstream, Z_SYNC_FLUSH);

        if (r == Z_NEED_DICT) {
            if (s->dictionary == NULL) {
                lua_pushliteral(L, "no inflate dictionary provided");
                lua_error(L);
            }

            if (inflateSetDictionary(&s->zstream, s->dictionary, s->dictionary_len) != Z_OK) {
                lua_pushliteral(L, "call to inflateSetDictionnary failed");
                lua_error(L);
            }

            r = inflate(&s->zstream, Z_SYNC_FLUSH);
        }

        if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) {
            lzstream_cleanup(L, s);
            s->error = r;
            #if 1
            lua_pushfstring(L, "failed to decompress [%d]", r);
            lua_error(L);
            #endif
        }

        if (r == Z_STREAM_END) {
            luaL_unref(L, LUA_REGISTRYINDEX, s->i_buffer_ref);
            s->i_buffer_ref = LUA_NOREF;
            s->i_buffer = NULL;

            s->eos = 1;
        }

        /* number of processed bytes */
        if (s->peek) {
            size_t processed = s->i_buffer_len - s->i_buffer_pos - s->zstream.avail_in;

            lua_rawgeti(L, LUA_REGISTRYINDEX, s->io_cb);
            lua_getfield(L, -1, "read");
            lua_insert(L, -2);
            lua_pushinteger(L, processed);
            lua_call(L, 2, 0);
        }

        s->i_buffer_pos = s->i_buffer_len - s->zstream.avail_in;
        s->o_buffer_len = s->o_buffer_max - s->zstream.avail_out;
    }

    return s->o_buffer_len;
}

/*
** Remove n bytes from the output buffer.
*/
static void lzstream_remove(lz_stream *s, size_t n) {
    memmove(s->o_buffer, s->o_buffer + n, s->o_buffer_len - n);
    s->o_buffer_len -= n;
}

/*
** Copy at most n bytes to buffer b and remove them from the
** output stream buffer.
*/
static int lzstream_flush_buffer(lua_State *L, lz_stream *s, size_t n, luaL_Buffer *b) {
    /* check output */
    if (n > s->o_buffer_len) {
        n = s->o_buffer_len;
    }

    if (n > 0) {
        lua_pushlstring(L, s->o_buffer, n);
        luaL_addvalue(b);

        lzstream_remove(s, n);
    }

    return n;
}

/*
    z:read(
        {number | '*l' | '*a'}*
    )
*/
static int lz_test_eof(lua_State *L, lz_stream *s) {
    lua_pushlstring(L, NULL, 0);
    if (s->o_buffer_len > 0) {
        return 1;
    } else if (s->eos) {
        return 0;
    } else {
        return lzstream_inflate_block(L, s);
    }
}

static int lz_read_line(lua_State *L, lz_stream *s) {
    luaL_Buffer b;
    size_t l = 0, n;

    luaL_buffinit(L, &b);

    if (s->o_buffer_len > 0 || !s->eos) do {
        char *p = s->o_buffer;
        size_t len = s->o_buffer_len;

        /* find newline in output buffer */
        for (n = 0; n < len; ++n, ++p) {
            if (*p == '\n' || *p == '\r') {
                int eat_nl = *p == '\r';
                luaL_addlstring(&b, s->o_buffer, n);
                lzstream_remove(s, n+1);
                l += n;

                if (eat_nl && lzstream_inflate_block(L, s)) {
                    if (s->o_buffer_len > 0 && *s->o_buffer == '\n') {
                        lzstream_remove(s, 1);
                    }
                }

                luaL_pushresult(&b);
                return 1;
            }
        }

        if (len > 0) {
            luaL_addlstring(&b, s->o_buffer, len);
            lzstream_remove(s, len);
            l += len;
        }
    } while (lzstream_inflate_block(L, s));

    luaL_pushresult(&b);
    return l > 0 || !s->eos || s->o_buffer_len > 0;
}


static int lz_read_chars(lua_State *L, lz_stream *s, size_t n) {
    size_t len;
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    if (s->o_buffer_len > 0 || !s->eos) do {
        size_t rlen = lzstream_flush_buffer(L, s, n, &b);
        n -= rlen;
    } while (n > 0 && lzstream_inflate_block(L, s));

    luaL_pushresult(&b);
    lua_tolstring(L, -1, &len);
    return n == 0 || len > 0;
}

static int lzstream_decompress(lua_State *L) {
    lz_stream *s = lzstream_check(L, 1, LZ_INFLATE);
    int nargs = lua_gettop(L) - 1;
    int success;
    int n;
    if (nargs == 0) {  /* no arguments? */
        success = lz_read_line(L, s);
        n = 3;  /* to return 1 result */
    }
    else {  /* ensure stack space for all results and for auxlib's buffer */
        luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
        success = 1;
        for (n = 2; nargs-- && success; n++) {
            if (lua_type(L, n) == LUA_TNUMBER) {
                size_t l = (size_t)lua_tointeger(L, n);
                success = (l == 0) ? lz_test_eof(L, s) : lz_read_chars(L, s, l);
            }
            else {
                const char *p = lua_tostring(L, n);
                luaL_argcheck(L, p && p[0] == '*', n, "invalid option");
                switch (p[1]) {
                    case 'l':  /* line */
                        success = lz_read_line(L, s);
                        break;
                    case 'a':  /* file */
                        lz_read_chars(L, s, ~((size_t)0));  /* read MAX_SIZE_T chars */
                        success = 1; /* always success */
                        break;
                    default:
                        return luaL_argerror(L, n, "invalid format");
                }
            }
        }
    }
    if (s->error != Z_OK) {
        return lz_pushresult(L, s);
    }
    if (!success) {
        lua_pop(L, 1);  /* remove last result */
        lua_pushnil(L);  /* push nil instead */
    }
    return n - 2;
}


static int lzstream_readline(lua_State *L) {
    lz_stream *s;
    int success;

    s = lzstream_check(L, lua_upvalueindex(1), LZ_INFLATE);
    success = lz_read_line(L, s);

    if (s->error != Z_OK) {
        return lz_pushresult(L, s);
    }

    if (success) {
        return 1;
    } else {
        /* EOF */
        return 0;
    }
}

static int lzstream_lines(lua_State *L) {
    lzstream_check(L, 1, LZ_INFLATE);
    lua_settop(L, 1);
    lua_pushcclosure(L, lzstream_readline, 1);
    return 1;
}

/* ====================================================================== */

static int lzstream_docompress(lua_State *L, lz_stream *s, int from, int to, int flush) {
    int r, arg;
    int self = 0;
    size_t b_size = s->o_buffer_max;
    unsigned char *b = (unsigned char *)s->o_buffer;

    /* number of processed bytes */
    lua_rawgeti(L, LUA_REGISTRYINDEX, s->io_cb);
    if (!lua_isfunction(L, -1)) {
        self = 1;
        lua_getfield(L, -1, "write");
    }

    for (arg = from; arg <= to; arg++) {
        s->zstream.next_in = (unsigned char*)luaL_checklstring(L, arg, (size_t*)&s->zstream.avail_in);

        do {
            s->zstream.next_out = b;
            s->zstream.avail_out = b_size;

            /* bake some more */
            r = deflate(&s->zstream, flush);
            if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) {
                lzstream_cleanup(L, s);
                lua_pushboolean(L, 0);
                lua_pushfstring(L, "failed to compress [%d]", r);
                return 2;
            }

            if (s->zstream.avail_out != b_size) {
                /* write output */
                lua_pushvalue(L, -1); /* function */
                if (self) lua_pushvalue(L, -3); /* self */
                lua_pushlstring(L, (char*)b, b_size - s->zstream.avail_out); /* data */
                lua_call(L, (self ? 2 : 1), 0);
            }

            if (r == Z_STREAM_END) {
                lzstream_cleanup(L, s);
                break;
            }

            /* process all input */
        } while (s->zstream.avail_in > 0 || s->zstream.avail_out == 0);
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int lzstream_compress(lua_State *L) {
    lz_stream *s = lzstream_check(L, 1, LZ_DEFLATE);
    return lzstream_docompress(L, s, 2, lua_gettop(L), Z_NO_FLUSH);
}


/* ====================================================================== */

static int lzstream_flush(lua_State *L) {
    static int flush_values[] = { Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH };
    static const char *const flush_opts[] = { "sync", "full", "finish" };

    lz_stream *s = lzstream_check(L, 1, LZ_DEFLATE);
    int flush = luaL_checkoption(L, 2, flush_opts[0], flush_opts);

    lua_settop(L, 0);
    lua_pushliteral(L, "");
    return lzstream_docompress(L, s, 1, 1, flush_values[flush]);
}

/*
** =========================================================================
** zlib functions
** =========================================================================
*/

static int lzlib_version(lua_State *L)
{
    lua_pushstring(L, zlibVersion());
    return 1;
}

/* ====================================================================== */
static int lzlib_adler32(lua_State *L)
{
    if (lua_gettop(L) == 0)
    {
        /* adler32 initial value */
        lua_pushnumber(L, adler32(0L, Z_NULL, 0));
    }
    else
    {
        /* update adler32 checksum */
        size_t len;
        int adler = (int) luaL_checkinteger(L, 1);
        const unsigned char* buf = (unsigned char*)luaL_checklstring(L, 2, &len);

        lua_pushnumber(L, adler32(adler, buf, len));
    }
    return 1;
}

/* ====================================================================== */
static int lzlib_crc32(lua_State *L)
{
    if (lua_gettop(L) == 0)
    {
        /* crc32 initial value */
        lua_pushnumber(L, crc32(0L, Z_NULL, 0));
    }
    else
    {
        /* update crc32 checksum */
        size_t len;
        int crc = (int) luaL_checkinteger(L, 1);
        const unsigned char* buf = (unsigned char*)luaL_checklstring(L, 2, &len);

        lua_pushnumber(L, crc32(crc, buf, len));
    }
    return 1;
}

/* ====================================================================== */


static int lzlib_compress(lua_State *L) {
    size_t avail_in;
    const char *next_in = luaL_checklstring(L, 1, &avail_in);
    int level = (int) luaL_optinteger(L, 2, Z_DEFAULT_COMPRESSION);
    int method = (int) luaL_optinteger(L, 3, Z_DEFLATED);
    int windowBits = (int) luaL_optinteger(L, 4, 15);
    int memLevel = (int) luaL_optinteger(L, 5, 8);
    int strategy = (int) luaL_optinteger(L, 6, Z_DEFAULT_STRATEGY);

    int ret;
    luaL_Buffer b;
    z_stream zs;

    luaL_buffinit(L, &b);

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;

    zs.next_out = Z_NULL;
    zs.avail_out = 0;
    zs.next_in = Z_NULL;
    zs.avail_in = 0;

    ret = deflateInit2(&zs, level, method, windowBits, memLevel, strategy);

    if (ret != Z_OK)
    {
        lua_pushnil(L);
        lua_pushnumber(L, ret);
        return 2;
    }

    zs.next_in = (unsigned char*)next_in;
    zs.avail_in = avail_in;

    for(;;)
    {
        zs.next_out = (unsigned char*)luaL_prepbuffer(&b);
        zs.avail_out = LUAL_BUFFERSIZE;

        /* munch some more */
        ret = deflate(&zs, Z_FINISH);

        /* push gathered data */
        luaL_addsize(&b, LUAL_BUFFERSIZE - zs.avail_out);

        /* done processing? */
        if (ret == Z_STREAM_END)
            break;

        /* error condition? */
        if (ret != Z_OK)
            break;
    }

    /* cleanup */
    deflateEnd(&zs);

    luaL_pushresult(&b);
    lua_pushnumber(L, ret);
    return 2;
}

/* ====================================================================== */

static int lzlib_decompress(lua_State *L)
{
    size_t avail_in;
    const char *next_in = luaL_checklstring(L, 1, &avail_in);
    int windowBits = (int) luaL_optinteger(L, 2, 15);

    int ret;
    luaL_Buffer b;
    z_stream zs;

    luaL_buffinit(L, &b);

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;

    zs.next_out = Z_NULL;
    zs.avail_out = 0;
    zs.next_in = Z_NULL;
    zs.avail_in = 0;

    ret = inflateInit2(&zs, windowBits);

    if (ret != Z_OK) {
        lua_pushliteral(L, "failed to initialize zstream structures");
        lua_error(L);
    }

    zs.next_in = (unsigned char*)next_in;
    zs.avail_in = avail_in;

    for (;;) {
        zs.next_out = (unsigned char*)luaL_prepbuffer(&b);
        zs.avail_out = LUAL_BUFFERSIZE;

        /* bake some more */
        ret = inflate(&zs, Z_FINISH);

        /* push gathered data */
        luaL_addsize(&b, LUAL_BUFFERSIZE - zs.avail_out);

        /* done processing? */
        if (ret == Z_STREAM_END)
            break;

        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            /* cleanup */
            inflateEnd(&zs);

            lua_pushliteral(L, "failed to process zlib stream");
            lua_error(L);
        }
    }

    /* cleanup */
    inflateEnd(&zs);

    luaL_pushresult(&b);
    return 1;
}


/*
** =========================================================================
** Register functions
** =========================================================================
*/

#if (LUA_VERSION_NUM >= 502)

#define luaL_register(L,n,f)	luaL_setfuncs(L,f,0)

#endif

LUALIB_API int luaopen_zlib(lua_State *L)
{
    const luaL_Reg lzstream_meta[] =
    {
        {"write",           lzstream_compress   },
        {"read",            lzstream_decompress },
        {"lines",           lzstream_lines      },
        {"flush",           lzstream_flush      },
        {"close",           lzstream_close      },

        {"adler",           lzstream_adler      },

        {"__tostring",      lzstream_tostring   },
        {"__gc",            lzstream_gc         },
        {NULL, NULL}
    };

    const luaL_Reg zlib[] =
    {
        {"version",         lzlib_version       },
        {"adler32",         lzlib_adler32       },
        {"crc32",           lzlib_crc32         },

        {"deflate",         lzlib_deflate       },
        {"inflate",         lzlib_inflate       },

        {"compress",        lzlib_compress      },
        {"decompress",      lzlib_decompress    },

        {NULL, NULL}
    };

    /* ====================================================================== */

    /* create new metatable for zlib compression structures */
    luaL_newmetatable(L, ZSTREAMMETA);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -2);               /* push metatable */
    lua_rawset(L, -3);                  /* metatable.__index = metatable */

    /*
    ** Stack: metatable
    */
    luaL_register(L, NULL, lzstream_meta);

    lua_pop(L, 1);                      /* remove metatable from stack */

    /*
    ** Stack:
    */
    lua_newtable(L);

    lua_pushliteral (L, "_COPYRIGHT");
    lua_pushliteral (L, "Copyright (C) 2003-2010 Tiago Dionizio");
    lua_settable (L, -3);
    lua_pushliteral (L, "_DESCRIPTION");
    lua_pushliteral (L, "Lua 5 interface to access zlib library functions");
    lua_settable (L, -3);
    lua_pushliteral (L, "_VERSION");
    lua_pushliteral (L, "lzlib 0.4-work3");
    lua_settable (L, -3);

#define PUSH_LITERAL(name) \
    lua_pushliteral (L, #name); \
    lua_pushinteger (L, Z_##name); \
    lua_settable (L, -3);

#define PUSH_NUMBER(name, value) \
    lua_pushliteral (L, #name); \
    lua_pushinteger (L, value); \
    lua_settable (L, -3);

    PUSH_LITERAL(NO_COMPRESSION)
    PUSH_LITERAL(BEST_SPEED)
    PUSH_LITERAL(BEST_COMPRESSION)
    PUSH_LITERAL(DEFAULT_COMPRESSION)

    PUSH_LITERAL(FILTERED)
    PUSH_LITERAL(HUFFMAN_ONLY)
#ifdef Z_RLE
    PUSH_LITERAL(RLE)
#endif
#ifdef Z_FIXED
    PUSH_LITERAL(FIXED)
#endif
    PUSH_LITERAL(DEFAULT_STRATEGY)

    PUSH_NUMBER(MINIMUM_MEMLEVEL, 1)
    PUSH_NUMBER(MAXIMUM_MEMLEVEL, 9)
    PUSH_NUMBER(DEFAULT_MEMLEVEL, 8)

    PUSH_NUMBER(DEFAULT_WINDOWBITS, 15)
    PUSH_NUMBER(MINIMUM_WINDOWBITS, 8)
    PUSH_NUMBER(MAXIMUM_WINDOWBITS, 15)

    PUSH_NUMBER(GZIP_WINDOWBITS, 16)
    PUSH_NUMBER(RAW_WINDOWBITS, -1)

    luaL_register(L, NULL, zlib);

    /*
    ** Stack: zlib table
    */
    return 1;
}
