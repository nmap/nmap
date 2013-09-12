/***************************************************************************
 * ncat_lua_filters.c -- Ncat Lua filters shared code                      *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.       *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "ncat.h"
#include "ncat_lua.h"
#include "ncat_lua_filters.h"

static int make_socket_function_idx;

static void lua_set_registry(const char *key);

static int lua_do_nothing(lua_State *L)
{
    return 0;
}

static void lua_create_supersocket()
{
    lua_newtable(filters_L);

    lua_pushstring(filters_L, "recv");
    if (o.listen)
        lua_pushcfunction(filters_L, lua_do_nothing); /* TODO */
    else
        lua_pushcfunction(filters_L, lua_nsock_recv_raw);
    lua_settable(filters_L, -3);

    lua_pushstring(filters_L, "send");
    if (o.listen)
        lua_pushcfunction(filters_L, lua_do_nothing);
    else
        lua_pushcfunction(filters_L, lua_nsock_write_raw);
    lua_settable(filters_L, -3);

    lua_set_registry("socket");
}

void lua_filters_setup()
{
    /* Initialize the registry. */
    lua_pushlightuserdata(filters_L, filters_L);
    lua_newtable(filters_L);
    lua_settable(filters_L, LUA_REGISTRYINDEX);

    lua_newtable(filters_L);
    lua_set_registry("connections");

    lua_newtable(filters_L);
    lua_set_registry("connection_roots");

    lua_create_supersocket();

    luaL_loadstring(filters_L, "return function(function_self, self, arg2) "
            "local super = arg2 or self.super "
            "local ret "
            "if super then "
                "ret = {} "
                "for _, m in pairs({'send','recv'}) do "
                    /* Set the method to one that calls super and passes it
                       all the arguments we got, returning everything we'd get.
                    */
                    "ret[m] = function(self, ...) "
                            "return table.unpack({self.super[m](self.super, ...)}) "
                        "end "
                "end "
            "else "
                "ret = {} "
            "end "
            "for k, v in pairs(self) do "
                "ret[k] = v "
            "end "
            "if super then "
                "ret.super = function_self(function_self, super) "
            "end "
            "return ret "
        "end ");
    lua_pcall(filters_L, 0, 1, error_handler_idx);
    make_socket_function_idx = lua_gettop(filters_L);
}

void lua_fetch_registry(const char *key)
{
    lua_pushlightuserdata(filters_L, filters_L);
    lua_gettable(filters_L, LUA_REGISTRYINDEX);
    lua_pushstring(filters_L, key);
    lua_gettable(filters_L, -2);
    lua_insert(filters_L, -2);
    lua_pop(filters_L, 1);
}

static void lua_set_registry(const char *key)
{
    lua_pushlightuserdata(filters_L, filters_L);
    lua_gettable(filters_L, LUA_REGISTRYINDEX);
    lua_insert(filters_L, -2);
    lua_pushstring(filters_L, key);
    lua_insert(filters_L, -2);
    lua_settable(filters_L, -3);
    lua_pop(filters_L, 1);
}

void lua_run_filter(char *cmdexec)
{
    lua_pcall(filters_L, 0, 1, error_handler_idx);
    if (!lua_istable(filters_L, -1))
        bye("%s did not return a table.", cmdexec);
    /* Overwrite the socket variable with new_socket(socket_from_file,
       socket). */
    lua_pushvalue(filters_L, make_socket_function_idx);
    lua_insert(filters_L, -2);
    lua_pushvalue(filters_L, make_socket_function_idx);
    lua_insert(filters_L, -3);
    lua_fetch_registry("socket");
    if (lua_pcall(filters_L, 3, 1, error_handler_idx) != LUA_OK)
        lua_report(filters_L, cmdexec, 1);
    lua_set_registry("socket");
}

/* Try to find the connection in the global table named "connections" with fd
   as the key. If it's not there, create it, find its topmost "super", set its
   "fd" to the given struct ncat_lua_state and save it in connection_supers.
   Leave the socket on the stack. If *fdn is NULL, we assume that fd=0 and
   we're in connect mode. Also, if *created is not NULL, it is set to 1 if
   the socket put on the stack was just created. */
struct ncat_lua_state* get_connection(struct fdinfo *fdn, int *created)
{
    struct ncat_lua_state *ret;
    int connections_key;
    if (fdn == NULL)
        connections_key = 0;
    else
        connections_key = fdn->fd;
    /* Try to access connections[fd]. Leave connections[] on the stack. */
    lua_fetch_registry("connections");
    lua_pushinteger(filters_L, connections_key);
    lua_gettable(filters_L, -2);

    if (lua_isnil(filters_L, -1)) {

        lua_pop(filters_L, 1); /* nil means we hadn't added the connection yet, pop it. */

        /* Basically: connections[fd] = new_socket(socket) */
        lua_pushinteger(filters_L, connections_key);
        lua_pushvalue(filters_L, make_socket_function_idx);
        lua_pushvalue(filters_L, make_socket_function_idx);
        lua_fetch_registry("socket");
        if (lua_pcall(filters_L, 2, 1, error_handler_idx) != LUA_OK)
            lua_report(filters_L, "Error creating the socket", 1);
        lua_pushvalue(filters_L, -1); /* Make a copy of the connection we created. */
        lua_insert(filters_L, -4); /* Move it below connection, 5 and original table. */
        lua_settable(filters_L, -3);
        lua_pop(filters_L, 1); /* Get rid of connections[]. */

        /* Make another copy of the table - we'll work on the current one
           looking for the topmost super. */
        lua_pushvalue(filters_L, -1);
        for(;;) {
            lua_pushvalue(filters_L, -1); /* Copy the current table */
            lua_pushstring(filters_L, "super");
            lua_gettable(filters_L, -2);
            lua_insert(filters_L, -2); /* Move the copy to the top, pop it */
            lua_pop(filters_L, 1);
            if (lua_isnil(filters_L, -1)) {
                lua_pop(filters_L, 1); /* Pop the nil */
                break; /* There's no super, we're at the top */
            }
            lua_insert(filters_L, -2); /* Get rid of the old table */
            lua_pop(filters_L, 1);
        }

        ret = (struct ncat_lua_state *) Calloc(1, sizeof(*ret));
        if (fdn != NULL)
            ret->fdn = *fdn;

        /* Set the "lua_state" to a pointer to ret. */
        lua_pushlightuserdata(filters_L, ret);
        lua_setfield(filters_L, -2, "lua_state");

        lua_fetch_registry("connection_roots");
        lua_pushinteger(filters_L, connections_key);
        lua_pushvalue(filters_L, -3);
        lua_remove(filters_L, -4);
        lua_settable(filters_L, -3);
        lua_pop(filters_L, 1);

        if (created != NULL)
            *created = 1;
    } else {
        lua_insert(filters_L, -2); /* Get rid of connections[]. */
        lua_pop(filters_L, 1);

        /* Get the struct ncat_lua_state from connection_roots[fd].lua_state. */
        lua_fetch_registry("connection_roots");
        lua_pushinteger(filters_L, connections_key);
        lua_gettable(filters_L, -2);
        lua_getfield(filters_L, -1, "lua_state");
        ret = (struct ncat_lua_state *) lua_touserdata(filters_L, -1);
        lua_pop(filters_L, 3); /* Pop the userdata, the table and connection_roots. */

        if (created != NULL)
            *created = 0;
    }

    return ret;
}


/* Read "lua_state" field from socket table available under stack index given
   as the second argument. If after the call *ret is set to a non-negative
   value, it must be returned. */
struct ncat_lua_state* lua_fetch_userdata(lua_State *L, int idx, int *ret)
{
    struct ncat_lua_state *nls;
    *ret = -1;
    lua_getfield(L, idx, "lua_state");
    nls = (struct ncat_lua_state *) lua_touserdata(L, -1);
    if (nls == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "Socket already closed");
        *ret = 2;
    }
    return nls;
}
