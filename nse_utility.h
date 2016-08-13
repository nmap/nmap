#ifndef NMAP_NSE_UTILITY_H
#define NMAP_NSE_UTILITY_H

class Port;
class Target;

#if HAVE_STDINT_H
#include <stdint.h>
#endif

/* int nseU_checkinteger (lua_State *L, int arg)
 *
 * Replacement for luaL_checkinteger that does a floor operation first
 */
int nseU_checkinteger (lua_State *L, int arg);

/* int nseU_traceback (lua_State *L)
 *
 * Traceback C Lua function.
 */
int nseU_traceback (lua_State *L);

/* int nseU_placeholder (lua_State *L)
 *
 * Placeholder C Lua function that simply throws a nil error.
 */
int nseU_placeholder (lua_State *L);

/* void nseU_tablen (lua_State *L, int idx)                [-0, +0, -]
 *
 * Calculates the number of entries in the table by iterating over
 * each key/value pair.
 */
size_t nseU_tablen (lua_State *L, int idx);

/* void nseU_setsfield (lua_State *L, int idx,             [-0, +0, e]
 *                      const char *field, const char *value)
 *
 * Sets the field for table at index idx to string value.
 *  (t[field] = value).
 */
void nseU_setsfield (lua_State *L, int idx, const char *field, const char *value);

/* void nseU_setnfield (lua_State *L, int idx,             [-0, +0, e]
 *                      const char *field, lua_Number value)
 *
 * Sets the field for table at index idx to numerical value.
 *  (t[field] = value).
 */
void nseU_setnfield (lua_State *L, int idx, const char *field, lua_Number value);

/* void nseU_setifield (lua_State *L, int idx,             [-0, +0, e]
 *                      const char *field, lua_Integer value)
 *
 * Sets the field for table at index idx to numerical value.
 *  (t[field] = value).
 */
void nseU_setifield (lua_State *L, int idx, const char *field, lua_Integer value);

/* void nseU_setbfield (lua_State *L, int idx,             [-0, +0, e]
 *                      const char *field, int value)
 *
 * Sets the field for table at index idx to boolean value.
 *  (t[field] = value).
 */
void nseU_setbfield (lua_State *L, int idx, const char *field, int value);

/* void nseU_appendfstr (lua_State *L, int idx,             [-0, +0, m]
 *                      const char *fmt, ...)
 *
 * Appends the formatted string to the table at index idx.
 */
void nseU_appendfstr (lua_State *L, int idx, const char *fmt, ...);

/* void nseU_weaktable (lua_State *L, int narr, int nrec,  [-0, +1, e]
 *                      const char *mode)
 *
 * Creates a table using lua_createtable with sizes narr and nrec. Creates
 * a metatable with its __mode field set to mode.
 */
void nseU_weaktable (lua_State *L, int narr, int nrec, const char *mode);

/* int nseU_success (lua_State *L)                         [-0, +1, -]
 *
 * Indicates successful return of the running function by pushing
 * boolean true and returning 1. Use as a tail call:
 *   return nseU_success(L);
 */
int nseU_success (lua_State *L);

/* int nseU_safeerror (lua_State *L, const char *fmt, ...) [-0, +1, -]
 *
 * Indicates unsuccessful return of the running function by pushing
 * boolean false and and a formatted error message. Use as a tail call:
 *   return nseU_safeerror(L, "%s", "a generic error");
 */
int nseU_safeerror (lua_State *L, const char *fmt, ...);

/* void nseU_typeerror (lua_State *L, int idx,             [-0, +1, v]
 *                      const char *err)
 *
 * Raises a type error. Same as Lua 5.1.
 */
void nseU_typeerror (lua_State *L, int idx, const char *err);

/* void *nseU_checkudata (lua_State *L, int idx,           [-0, +0, v]
 *                        int upvalue, const char *name)
 *
 * Checks that value at index idx is a full userdata which a metatable
 * equal to upvalue. name is the name of your object for error message
 * purposes.
 */
void *nseU_checkudata (lua_State *L, int idx, int upvalue, const char *name);

/* void nseU_checktarget (lua_State *L, int idx,           [-0, +0, v]
 *                        const char **address,
 *                        const char **targetname)
 *
 * Check for a valid target specification at index idx.  This function checks
 * for a string at idx or a table containing the typical host table fields,
 * 'ip' and 'targetname' in particular.
 *
 * The address and targetname string pointers are only valid if the target
 * specification persists.
 */
void nseU_checktarget (lua_State *L, int idx, const char **address, const char **targetname);

/* void nseU_opttarget (lua_State *L, int idx,           [-0, +0, v]
 *                      const char **address,
 *                      const char **targetname)
 *
 * Like nseU_checktarget, but sets *address and *targetname to NULL and returns
 * success if the argument at idx is none or nil.
 */
void nseU_opttarget (lua_State *L, int idx, const char **address, const char **targetname);

/* uint16_t nseU_checkport (lua_State *L, int idx,         [-0, +0, v]
 *                          const char **protocol)
 *
 * Check for a valid port specification at index idx.
 *
 * The protocol string pointer is only valid if the port specification
 * persists.
 */
uint16_t nseU_checkport (lua_State *L, int idx, const char **protocol);

/* Target *nseU_gettarget (lua_State *L, int idx)          [-0, +0, v]
 *
 * This function checks the value at index for a valid host table. It locates
 * the associated Target (C++) class object associated with the host and
 * returns it. If the Target is not being scanned then an error will be raised.
 */
Target *nseU_gettarget (lua_State *L, int idx);

/* Port *nseU_getport (lua_State *L, Target *target,       [-0, +0, v]
 *                     Port *port, int idx)
 *
 * This function checks the value at index for a valid port table. It locates
 * the associated Port (C++) class object associated with the host and
 * returns it.
 */
Port *nseU_getport (lua_State *L, Target *target, Port *port, int idx);

#endif

