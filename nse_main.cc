#include "nmap.h"
#include "nbase.h"
#include "nmap_error.h"
#include "portlist.h"
#include "nsock.h"
#include "NmapOps.h"
#include "timing.h"
#include "Target.h"
#include "nmap_tty.h"
#include "xml.h"

#include "nse_main.h"
#include "nse_utility.h"
#include "nse_fs.h"
#include "nse_nsock.h"
#include "nse_nmaplib.h"
#include "nse_pcrelib.h"
#include "nse_openssl.h"
#include "nse_debug.h"
#include "nse_lpeg.h"

#include <math.h>

#define NSE_MAIN "NSE_MAIN" /* the main function */

/* Script Scan phases */
#define NSE_PRE_SCAN  "NSE_PRE_SCAN"
#define NSE_SCAN      "NSE_SCAN"
#define NSE_POST_SCAN "NSE_POST_SCAN"

/* These are indices into the registry, for data shared with nse_main.lua. The
   definitions here must match those in nse_main.lua. */
#define NSE_YIELD "NSE_YIELD"
#define NSE_BASE "NSE_BASE"
#define NSE_WAITING_TO_RUNNING "NSE_WAITING_TO_RUNNING"
#define NSE_DESTRUCTOR "NSE_DESTRUCTOR"
#define NSE_SELECTED_BY_NAME "NSE_SELECTED_BY_NAME"
#define NSE_CURRENT_HOSTS "NSE_CURRENT_HOSTS"

#define NSE_FORMAT_TABLE "NSE_FORMAT_TABLE"
#define NSE_FORMAT_XML "NSE_FORMAT_XML"
#define NSE_PARALLELISM "NSE_PARALLELISM"

#ifndef MAXPATHLEN
#  define MAXPATHLEN 2048
#endif

extern NmapOps o;

/* global object to store Pre-Scan and Post-Scan script results */
static ScriptResults script_scan_results;

static int timedOut (lua_State *L)
{
  Target *target = nseU_gettarget(L, 1);
  lua_pushboolean(L, target->timedOut(NULL));
  return 1;
}

static int startTimeOutClock (lua_State *L)
{
  Target *target = nseU_gettarget(L, 1);
  if (!target->timeOutClockRunning())
    target->startTimeOutClock(NULL);
  return 0;
}

static int stopTimeOutClock (lua_State *L)
{
  Target *target = nseU_gettarget(L, 1);
  if (target->timeOutClockRunning())
    target->stopTimeOutClock(NULL);
  return 0;
}

static int next_port (lua_State *L)
{
  lua_settop(L, 2);
  lua_pushvalue(L, lua_upvalueindex(1));
  lua_pushvalue(L, 2);
  if (lua_next(L, -2) == 0)
    return 0;
  else {
    lua_pop(L, 1); /* pop boolean value */
    return 1;
  }
}

static int ports (lua_State *L)
{
  static const int states[] = {
    PORT_OPEN,
    PORT_OPENFILTERED,
    PORT_UNFILTERED,
    PORT_HIGHEST_STATE /* last one marks end */
  };
  Target *target = nseU_gettarget(L, 1);
  PortList *plist = &(target->ports);
  Port *current = NULL;
  Port port;
  lua_newtable(L);
  for (int i = 0; states[i] != PORT_HIGHEST_STATE; i++)
    while ((current = plist->nextPort(current, &port, TCPANDUDPANDSCTP,
            states[i])) != NULL)
    {
      lua_newtable(L);
      set_portinfo(L, target, current);
      lua_pushboolean(L, 1);
      lua_rawset(L, -3);
    }
  lua_pushcclosure(L, next_port, 1);
  lua_pushnil(L);
  lua_pushnil(L);
  return 3;
}

static int script_set_output (lua_State *L)
{
  ScriptResult sr;
  sr.set_id(luaL_checkstring(L, 1));
  sr.set_output_tab(L, 2);
  if (!lua_isnil(L, 3)) {
    lua_len(L, 3);
    sr.set_output_str(luaL_checkstring(L, 3), luaL_checkinteger(L,-1));
  }
  script_scan_results.push_back(sr);
  return 0;
}

static int host_set_output (lua_State *L)
{
  ScriptResult sr;
  Target *target = nseU_gettarget(L, 1);
  sr.set_id(luaL_checkstring(L, 2));
  sr.set_output_tab(L, 3);
  if (!lua_isnil(L, 4)) {
    lua_len(L, 4);
    sr.set_output_str(luaL_checkstring(L, 4), luaL_checkinteger(L,-1));
  }
  target->scriptResults.push_back(sr);
  return 0;
}

static int port_set_output (lua_State *L)
{
  Port *p;
  Port port;
  ScriptResult sr;
  Target *target = nseU_gettarget(L, 1);
  p = nseU_getport(L, target, &port, 2);
  sr.set_id(luaL_checkstring(L, 3));
  sr.set_output_tab(L, 4);
  if (!lua_isnil(L, 5)) {
    lua_len(L, 5);
    sr.set_output_str(luaL_checkstring(L, 5), luaL_checkinteger(L,-1));
  }
  target->ports.addScriptResult(p->portno, p->proto, sr);
  target->ports.numscriptresults++;
  return 0;
}

static int key_was_pressed (lua_State *L)
{
  lua_pushboolean(L, keyWasPressed());
  return 1;
}

static int scp (lua_State *L)
{
  static const char * const ops[] = {"printStats", "printStatsIfNecessary",
    "mayBePrinted", "endTask", NULL};
  ScanProgressMeter *progress =
    (ScanProgressMeter *) lua_touserdata(L, lua_upvalueindex(1));
  switch (luaL_checkoption(L, 1, NULL, ops))
  {
    case 0: /* printStats */
      progress->printStats((double) luaL_checknumber(L, 2), NULL);
      break;
    case 1:
      progress->printStatsIfNecessary((double) luaL_checknumber(L, 2), NULL);
      break;
    case 2: /*mayBePrinted */
      lua_pushboolean(L, progress->mayBePrinted(NULL));
      return 1;
    case 3: /* endTask */
      progress->endTask(NULL, NULL);
      delete progress;
      break;
  }
  return 0;
}

static int scan_progress_meter (lua_State *L)
{
  lua_pushlightuserdata(L, new ScanProgressMeter(luaL_checkstring(L, 1)));
  lua_pushcclosure(L, scp, 1);
  return 1;
}

/* This is like nmap.log_write, but doesn't append "NSE:" to the beginning of
   messages. It is only used internally by nse_main.lua and is not available to
   scripts. */
static int l_log_write(lua_State *L)
{
  static const char *const ops[] = {"stdout", "stderr", NULL};
  static const int logs[] = {LOG_STDOUT, LOG_STDERR};
  int log = logs[luaL_checkoption(L, 1, NULL, ops)];
  log_write(log, "%s", luaL_checkstring(L, 2));
  return 0;
}

static int l_xml_start_tag(lua_State *L)
{
  const char *name;

  name = luaL_checkstring(L, 1);
  xml_open_start_tag(name);

  if (lua_isnoneornil(L, 2)) {
    lua_newtable(L);
    lua_replace(L, 2);
  }

  for (lua_pushnil(L); lua_next(L, 2); lua_pop(L, 1))
    xml_attribute(luaL_checkstring(L, -2), "%s", luaL_checkstring(L, -1));

  xml_close_start_tag();

  return 0;
}

static int l_xml_end_tag(lua_State *L)
{
  xml_end_tag();

  return 0;
}

static int l_xml_write_escaped(lua_State *L)
{
  const char *text;

  text = luaL_checkstring(L, 1);
  xml_write_escaped("%s", text);

  return 0;
}

static int l_xml_newline(lua_State *L)
{
  xml_newline();

  return 0;
}

static int l_protect_xml(lua_State *L)
{
  const char *text;
  size_t len;
  std::string output;

  text = luaL_checklstring(L, 1, &len);
  output = protect_xml(std::string(text, len));
  lua_pushlstring(L, output.c_str(), output.size());

  return 1;
}

static int nse_fetch (lua_State *L, int (*fetch)(char *, size_t, const char *))
{
  char path[MAXPATHLEN];
  switch (fetch(path, sizeof(path), luaL_checkstring(L, 1)))
  {
    case 0: // no such path
      lua_pushnil(L);
      lua_pushfstring(L, "no path to file/directory: %s", lua_tostring(L, 1));
      break;
    case 1: // file returned
      lua_pushliteral(L, "file");
      lua_pushstring(L, path);
      break;
    case 2: // directory returned
      lua_pushliteral(L, "directory");
      lua_pushstring(L, path);
      break;
    default:
      return luaL_error(L, "nse_fetch returned bad code");
  }
  return 2;
}

static bool filename_is_absolute(const char *file) {
  if (file[0] == '/')
    return true;
#ifdef WIN32
  if ((file[0] != '\0' && file[1] == ':') || file[0] == '\\')
    return true;
#endif
  return false;
}

/* This is a modification of nmap_fetchfile that first looks for an
 * absolute file name.
 */
static int nse_fetchfile_absolute(char *path, size_t path_len, const char *file) {
  if (filename_is_absolute(file)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
    Strncpy(path, file, path_len);
    return file_is_readable(file);
  }

  return nmap_fetchfile(path, path_len, file);
}

/* This is a modification of nmap_fetchfile specialized to look for files
 * in the scripts subdirectory. If the path is absolute, it is always tried
 * verbatim. Otherwise, the file is looked for under scripts/, and then finally
 * in the current directory.
 */
static int nse_fetchscript(char *path, size_t path_len, const char *file) {
  std::string scripts_path = std::string(SCRIPT_ENGINE_LUA_DIR) + std::string(file);
  int type;

  if (filename_is_absolute(file)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
    Strncpy(path, file, path_len);
    return file_is_readable(file);
  }

  // lets look in <path>/scripts
  type = nmap_fetchfile(path, path_len, scripts_path.c_str());

  if (type == 0) {
    // current directory
    Strncpy(path, file, path_len);
    return file_is_readable(file);
  }

  return type;
}

static int fetchscript (lua_State *L)
{
  return nse_fetch(L, nse_fetchscript);
}

static int fetchfile_absolute (lua_State *L)
{
  return nse_fetch(L, nse_fetchfile_absolute);
}

static void open_cnse (lua_State *L)
{
  static const luaL_Reg nse[] = {
    {"fetchfile_absolute", fetchfile_absolute},
    {"fetchscript", fetchscript},
    {"key_was_pressed", key_was_pressed},
    {"scan_progress_meter", scan_progress_meter},
    {"timedOut", timedOut},
    {"startTimeOutClock", startTimeOutClock},
    {"stopTimeOutClock", stopTimeOutClock},
    {"ports", ports},
    {"script_set_output", script_set_output},
    {"host_set_output", host_set_output},
    {"port_set_output", port_set_output},
    {"log_write", l_log_write},
    {"xml_start_tag", l_xml_start_tag},
    {"xml_end_tag", l_xml_end_tag},
    {"xml_write_escaped", l_xml_write_escaped},
    {"xml_newline", l_xml_newline},
    {"protect_xml", l_protect_xml},
    {NULL, NULL}
  };

  luaL_newlib(L, nse);
  /* Add some other fields */
  nseU_setbfield(L, -1, "default", o.script == 1);
  nseU_setbfield(L, -1, "scriptversion", o.scriptversion == 1);
  nseU_setbfield(L, -1, "scriptupdatedb", o.scriptupdatedb == 1);
  nseU_setbfield(L, -1, "scripthelp", o.scripthelp);
  nseU_setsfield(L, -1, "script_dbpath", SCRIPT_ENGINE_DATABASE);
  nseU_setsfield(L, -1, "scriptargs", o.scriptargs);
  nseU_setsfield(L, -1, "scriptargsfile", o.scriptargsfile);
  nseU_setsfield(L, -1, "NMAP_URL", NMAP_URL);

}

/* Global persistent Lua state used by the engine. */
static lua_State *L_NSE = NULL;

void ScriptResult::clear (void)
{
  if (o.debugging > 3)
    log_write(LOG_STDOUT, "ScriptResult::clear %d id %s\n", output_ref, get_id());
  luaL_unref(L_NSE, LUA_REGISTRYINDEX, output_ref);
  output_ref = LUA_NOREF;
}

void ScriptResult::set_output_tab (lua_State *L, int pos)
{
  clear();
  lua_pushvalue(L, pos);
  output_ref = luaL_ref(L_NSE, LUA_REGISTRYINDEX);
  if (o.debugging > 3)
    log_write(LOG_STDOUT, "ScriptResult::set_output_tab %d id %s\n", output_ref, get_id());
}

void ScriptResult::set_output_str (const char *out)
{
  output_str = std::string(out);
}

void ScriptResult::set_output_str (const char *out, size_t len)
{
  output_str = std::string(out, len);
}

static std::string format_obj(lua_State *L, int pos)
{
  std::string output;

  pos = lua_absindex(L, pos);

  /* Look up the FORMAT_TABLE function from nse_main.lua and call it. */
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_FORMAT_TABLE);
  if (lua_isnil(L, -1)) {
    log_write(LOG_STDOUT, "%s: Cannot find function _R[\"%s\"] that should be in nse_main.lua\n",
      SCRIPT_ENGINE, NSE_FORMAT_TABLE);
    lua_pop(L, 1);
    return output;
  }

  lua_pushvalue(L, pos);
  if (lua_pcall(L, 1, 1, 0) != 0) {
    if (o.debugging)
      log_write(LOG_STDOUT, "%s: Error in FORMAT_TABLE: %s\n", SCRIPT_ENGINE, lua_tostring(L, -1));
    lua_pop(L, 1);
    return output;
  }

  lua_len(L, -1);
  output = std::string(lua_tostring(L, -2), luaL_checkinteger(L, -1));
  lua_pop(L, 1);

  return output;
}

std::string ScriptResult::get_output_str (void) const
{
  std::string output;

  /* Explicit string output? */
  if (!output_str.empty())
    return output_str;

  /* Auto-formatted table output? */
  lua_rawgeti(L_NSE, LUA_REGISTRYINDEX, output_ref);
  if (!lua_isnil(L_NSE, -1))
    output = format_obj(L_NSE, -1);

  lua_pop(L_NSE, 1);

  return output;
}

void ScriptResult::set_id (const char *ident)
{
  id = std::string(ident);
}

const char *ScriptResult::get_id (void) const
{
  return id.c_str();
}

ScriptResults *get_script_scan_results_obj (void)
{
  return &script_scan_results;
}

static void format_xml(lua_State *L, int pos)
{
  pos = lua_absindex(L, pos);

  /* Look up the FORMAT_XML function from nse_main.lua and call it. */
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_FORMAT_XML);
  if (lua_isnil(L, -1)) {
    log_write(LOG_STDOUT, "%s: Cannot find function _R[\"%s\"] that should be in nse_main.lua\n",
      SCRIPT_ENGINE, NSE_FORMAT_XML);
    lua_pop(L, 1);
    return;
  }

  lua_pushvalue(L, pos);
  if (lua_pcall(L, 1, 1, 0) != 0) {
    if (o.debugging)
      log_write(LOG_STDOUT, "%s: Error in FORMAT_XML: %s\n", SCRIPT_ENGINE, lua_tostring(L, -1));
    lua_pop(L, 1);
    return;
  }
}

void ScriptResult::write_xml() const
{
  std::string output_str;

  xml_open_start_tag("script");
  xml_attribute("id", "%s", get_id());

  output_str = get_output_str();
  if (!output_str.empty())
    xml_attribute("output", "%s", protect_xml(output_str).c_str());

  /* Any table output? */
  lua_rawgeti(L_NSE, LUA_REGISTRYINDEX, output_ref);
  if (!lua_isnil(L_NSE, -1)) {
    xml_close_start_tag();
    format_xml(L_NSE, -1);
    xml_end_tag();
  } else {
    xml_close_empty_tag();
  }

  lua_pop(L_NSE, 1);
}

/* int panic (lua_State *L)
 *
 * Panic function set via lua_atpanic().
 */
static int panic (lua_State *L)
{
  const char *err = lua_tostring(L, 1);
  fatal("Unprotected error in Lua:\n%s\n", err);
  return 0;
}

static void set_nmap_libraries (lua_State *L)
{
  static const luaL_Reg libs[] = {
    {NSE_PCRELIBNAME, luaopen_pcrelib},
    {NSE_NMAPLIBNAME, luaopen_nmap},
    {LFSLIBNAME, luaopen_lfs},
    {LPEGLIBNAME, luaopen_lpeg},
#ifdef HAVE_OPENSSL
    {OPENSSLLIBNAME, luaopen_openssl},
#endif
    {NULL, NULL}
  };

  for (int i = 0; libs[i].name; i++) {
    luaL_requiref(L, libs[i].name, libs[i].func, 1);
    lua_pop(L, 1);
  }
}

static int init_main (lua_State *L)
{
  char path[MAXPATHLEN];
  std::vector<std::string> *rules = (std::vector<std::string> *)
      lua_touserdata(L, 1);

  /* Load some basic libraries */
  luaL_openlibs(L);
  set_nmap_libraries(L);

  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);

  if (nmap_fetchfile(path, sizeof(path), "nse_main.lua") != 1)
    luaL_error(L, "could not locate nse_main.lua");
  if (luaL_loadfile(L, path) != 0)
    luaL_error(L, "could not load nse_main.lua: %s", lua_tostring(L, -1));

  /* The first argument to the NSE Main Lua code is the private nse
   * library table which exposes certain necessary C functions to
   * the Lua engine.
   */
  open_cnse(L); /* first argument */

  /* The second argument is the script rules, including the
   * files/directories/categories passed as the userdata to this function.
   */
  lua_createtable(L, rules->size(), 0); /* second argument */
  for (std::vector<std::string>::iterator si = rules->begin(); si != rules->end(); si++)
    nseU_appendfstr(L, -1, "%s", si->c_str());

  lua_call(L, 2, 1); /* returns the NSE main function */

  lua_setfield(L, LUA_REGISTRYINDEX, NSE_MAIN);

  lua_pushinteger(L, o.min_parallelism);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_PARALLELISM);

  return 0;
}

static int run_main (lua_State *L)
{
  std::vector<Target *> *targets = (std::vector<Target*> *)
      lua_touserdata(L, 1);

  /* New host group */
  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);

  lua_getfield(L, LUA_REGISTRYINDEX, NSE_MAIN);
  assert(lua_isfunction(L, -1));

  /* The first argument to the NSE main function is the list of targets.  This
   * has all the target names, 1-N, in a list.
   */
  lua_createtable(L, targets->size(), 0);
  int targets_table = lua_gettop(L);
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);
  int current_hosts = lua_gettop(L);
  for (std::vector<Target *>::iterator ti = targets->begin(); ti != targets->end(); ti++)
  {
    Target *target = (Target *) *ti;
    const char *TargetName = target->TargetName();
    const char *targetipstr = target->targetipstr();
    lua_newtable(L);
    set_hostinfo(L, target);
    lua_rawseti(L, targets_table, lua_rawlen(L, targets_table) + 1);
    if (TargetName != NULL && strcmp(TargetName, "") != 0)
      lua_pushstring(L, TargetName);
    else
      lua_pushstring(L, targetipstr);
    lua_pushlightuserdata(L, target);
    lua_rawset(L, current_hosts); /* add to NSE_CURRENT_HOSTS */
  }
  lua_settop(L, targets_table);

  /* Push script scan phase type. Second argument to NSE main function */
  switch (o.current_scantype)
  {
    case SCRIPT_PRE_SCAN:
      lua_pushliteral(L, NSE_PRE_SCAN);
      break;
    case SCRIPT_SCAN:
      lua_pushliteral(L, NSE_SCAN);
      break;
    case SCRIPT_POST_SCAN:
      lua_pushliteral(L, NSE_POST_SCAN);
      break;
    default:
      fatal("%s: failed to set the script scan phase.\n", SCRIPT_ENGINE);
  }

  lua_call(L, 2, 0);

  return 0;
}

/* int nse_yield (lua_State *L, int ctx, lua_CFunction k)  [-?, +?, e]
 *
 * This function will yield the running thread back to NSE, even across script
 * auxiliary coroutines. All NSE initiated yields must use this function. The
 * correct and only way to call is as a tail call:
 *   return nse_yield(L, 0, NULL);
 */
int nse_yield (lua_State *L, lua_KContext ctx, lua_KFunction k)
{
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_YIELD);
  lua_pushthread(L);
  lua_call(L, 1, 1); /* returns NSE_YIELD_VALUE */
  return lua_yieldk(L, 1, ctx, k); /* yield with NSE_YIELD_VALUE */
}

/* void nse_restore (lua_State *L, int number)             [-, -, e]
 *
 * Restore the thread 'L' back into the running NSE queue. 'number' is the
 * number of values on the stack to be passed when the thread is resumed. This
 * function may cause a panic due to extraordinary and unavoidable
 * circumstances.
 */
void nse_restore (lua_State *L, int number)
{
  luaL_checkstack(L, 5, "nse_restore: stack overflow");
  lua_pushthread(L);
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_WAITING_TO_RUNNING);
  lua_insert(L, -(number+2)); /* move WAITING_TO_RUNNING down below the args */
  lua_insert(L, -(number+1)); /* move thread above WAITING_TO_RUNNING */
  /* Call WAITING_TO_RUNNING (defined in nse_main.lua) on the thread and any
     other arguments. */
  if (lua_pcall(L, number+1, 0, 0) != 0)
    fatal("%s: WAITING_TO_RUNNING error!\n%s", __func__, lua_tostring(L, -1));
}

/* void nse_destructor (lua_State *L, char what)           [-(1|2), +0, e]
 *
 * This function adds (what = 'a') or removes (what = 'r') a destructor from
 * the Thread owning the running Lua thread (L). A destructor is called when
 * the thread finishes for any reason (including error). A unique key is used
 * to associate with the destructor so it is removable later.
 *
 * what == 'r', destructor key on stack
 * what == 'a', destructor key and destructor function on stack
 */
void nse_destructor (lua_State *L, char what)
{
  assert(what == 'a' || what == 'r');
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_DESTRUCTOR);
  lua_pushstring(L, what == 'a' ? "add" : "remove");
  lua_pushthread(L);
  if (what == 'a')
  {
    lua_pushvalue(L, -5); /* destructor key */
    lua_pushvalue(L, -5); /* destructor */
  }
  else
  {
    lua_pushvalue(L, -4); /* destructor key */
    lua_pushnil(L); /* no destructor, we are removing */
  }
  if (lua_pcall(L, 4, 0, 0) != 0)
    fatal("%s: NSE_DESTRUCTOR error!\n%s", __func__, lua_tostring(L, -1));
  lua_pop(L, what == 'a' ? 2 : 1);
}

/* void nse_base (lua_State *L)                             [-0, +1, e]
 *
 * Returns the base Lua thread (coroutine) for the running thread. The base
 * thread is resumed by NSE (runs the action function). Other coroutines being
 * used by the base thread may be in a chain of resumes, we use the base thread
 * as the "holder" of resources (for the Nsock binding in particular).
 */
void nse_base (lua_State *L)
{
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_BASE);
  lua_call(L, 0, 1); /* returns base thread */
}

/* void nse_selectedbyname (lua_State *L)                  [-0, +1, e]
 *
 * Returns a boolean signaling whether the running script was selected by name
 * on the command line (--script).
 */
void nse_selectedbyname (lua_State *L)
{
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_SELECTED_BY_NAME);
  if (lua_isnil(L, -1)) {
    lua_pushboolean(L, 0);
    lua_replace(L, -2);
  } else {
    lua_call(L, 0, 1);
  }
}

/* void nse_gettarget (lua_State *L)                  [-0, +1, -]
 *
 * Given the index to a string on the stack identifying the host, an ip or a
 * targetname (host name specified on the command line, see Target.h), returns
 * a lightuserdatum that points to the host's Target (see Target.h). If the
 * host cannot be found, nil is returned.
 */
void nse_gettarget (lua_State *L, int index)
{
  lua_pushvalue(L, index);
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);
  lua_insert(L, -2);
  lua_rawget(L, -2);
  lua_replace(L, -2);
}

void open_nse (void)
{
  if (L_NSE == NULL)
  {
    /*
     Set the random seed value on behalf of scripts.  Since Lua uses the
     C rand and srand functions, which have a static seed for the entire
     program, we don't want scripts doing this themselves.
     */
    srand(get_random_uint());

    const lua_Number *version = lua_version(NULL);
    double major = (*version) / 100.0;
    double minor = fmod(*version, 10.0);
    if (o.debugging >= 1)
      log_write(LOG_STDOUT, "%s: Using Lua %.0f.%.0f.\n", SCRIPT_ENGINE, major, minor);
    if (*version < 503)
      fatal("%s: This version of NSE only works with Lua 5.3 or greater.", SCRIPT_ENGINE);
    if ((L_NSE = luaL_newstate()) == NULL)
      fatal("%s: failed to open a Lua state!", SCRIPT_ENGINE);
    lua_atpanic(L_NSE, panic);
    lua_settop(L_NSE, 0);

    lua_pushcfunction(L_NSE, nseU_traceback);
    lua_pushcfunction(L_NSE, init_main);
    lua_pushlightuserdata(L_NSE, &o.chosenScripts);
    if (lua_pcall(L_NSE, 1, 0, 1))
      fatal("%s: failed to initialize the script engine:\n%s\n", SCRIPT_ENGINE, lua_tostring(L_NSE, -1));
    lua_settop(L_NSE, 0);
  }
}

void script_scan (std::vector<Target *> &targets, stype scantype)
{
  o.current_scantype = scantype;

  assert(L_NSE != NULL);
  lua_settop(L_NSE, 0); /* clear the stack */

  lua_pushcfunction(L_NSE, nseU_traceback);
  lua_pushcfunction(L_NSE, run_main);
  lua_pushlightuserdata(L_NSE, &targets);
  if (lua_pcall(L_NSE, 1, 0, 1))
    error("%s: Script Engine Scan Aborted.\nAn error was thrown by the "
          "engine: %s", SCRIPT_ENGINE, lua_tostring(L_NSE, -1));
  lua_settop(L_NSE, 0);
}

void close_nse (void)
{
  if (L_NSE != NULL)
  {
    lua_close(L_NSE);
    L_NSE = NULL;
  }
}
