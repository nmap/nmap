#include "nse_main.h"

#include "nse_init.h"
#include "nse_fs.h"
#include "nse_nsock.h"
#include "nse_nmaplib.h"
#include "nse_debug.h"
#include "nse_macros.h"

#include "nmap.h"
#include "nmap_error.h"
#include "portlist.h"
#include "nsock.h"
#include "NmapOps.h"
#include "timing.h"
#include "Target.h"
#include "nmap_tty.h"

extern NmapOps o;

struct run_record {
  short type; // 0 - hostrule; 1 - portrule
  Port* port;
  Target* host;
};

struct thread_record {
  lua_State* thread;
  int resume_arguments;
  unsigned int registry_idx; // index in the main state registry
  double runlevel;
  struct run_record rr;
};

int current_hosts = 0;
int errfunc = 0;
std::list<std::list<struct thread_record> > torun_scripts;
std::list<struct thread_record> running_scripts;
std::list<struct thread_record> waiting_scripts;

class CompareRunlevels {
public:
  bool operator() (const struct thread_record& lhs, const struct thread_record& rhs) {
    return lhs.runlevel < rhs.runlevel;
  }
};

// prior execution
int process_preparerunlevels(std::list<struct thread_record> torun_threads);
int process_preparehost(lua_State* L, Target* target, std::list<struct thread_record>& torun_threads);
int process_preparethread(lua_State* L, struct thread_record* tr);

// helper functions
int process_getScriptId(lua_State* L, ScriptResult * ssr);
int process_pickScriptsForPort(
    lua_State* L,
    Target* target,
    Port* port,
    std::list<thread_record>& torun_threads);

// execution
int process_mainloop(lua_State* L);
int process_waiting2running(lua_State* L, int resume_arguments);
int process_finalize(lua_State* L, unsigned int registry_idx);

// post execution
int cleanup_threads(std::list<struct thread_record> trs);

void ScriptResult::set_output (const char *out)
{
  output = std::string(out);
}

std::string ScriptResult::get_output (void)
{
  return output;
}

void ScriptResult::set_id (const char *ident)
{
  id = std::string(ident);
}

std::string ScriptResult::get_id (void)
{
  return id;
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

/* size_t table_length (lua_State *L, int index)
 *
 * Returns the length of the table at index index.
 * This length is the number of elements, not just array elements.
 */
size_t table_length (lua_State *L, int index)
{
  size_t len = 0;
  lua_pushvalue(L, index);
  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    len++;
    lua_pop(L, 1);
  }
  lua_pop(L, 1); // table
  return len;
}

/* int escape_char (lua_State *L)
 *
 * This function is called via Lua through string.gsub. Its purpose is to
 * escape characters. So the first sole character is changed to "\xFF" (hex).
 */
static int escape_char (lua_State *L)
{
  char hold[10];
  const char *str = luaL_checkstring(L, 1);
  int size = sprintf(hold, "\\x%02X", *str & 0xff);
  lua_pushlstring(L, hold, size);
  return 1;
}

int script_updatedb (void)
{
  int status;
  int ret = SCRIPT_ENGINE_SUCCESS;
  lua_State *L;

  SCRIPT_ENGINE_VERBOSE(
      log_write(LOG_STDOUT, "%s: Updating rule database.\n",
        SCRIPT_ENGINE);
      )

  L = luaL_newstate();
  if (L == NULL)
  {
    error("%s: Failed luaL_newstate()", SCRIPT_ENGINE);
    return 0;
  }
  lua_atpanic(L, panic);

  status = lua_cpcall(L, init_lua, NULL);
  if (status != 0)
  {
    error("%s: error while initializing Lua State:\n%s\n",
          SCRIPT_ENGINE, lua_tostring(L, -1));
    ret = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }

  lua_settop(L, 0); // safety, is 0 anyway
  lua_rawgeti(L, LUA_REGISTRYINDEX, errfunc); // index 1

  lua_pushcclosure(L, init_updatedb, 0);
  status = lua_pcall(L, 0, 0, 1);
  if(status != 0)
  {
    error("%s: error while updating Script Database:\n%s\n",
        SCRIPT_ENGINE, lua_tostring(L, -1));
    ret = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }

  log_write(LOG_STDOUT, "NSE script database updated successfully.\n");

  finishup:
    lua_close(L);
    if (ret != SCRIPT_ENGINE_SUCCESS)
    {
      error("%s: Aborting database update.\n", SCRIPT_ENGINE);
      return SCRIPT_ENGINE_ERROR;
    }
    else
      return SCRIPT_ENGINE_SUCCESS;
}

/* check the script-arguments provided to nmap (--script-args) before
 * scanning starts - otherwise the whole scan will run through and be
 * aborted before script-scanning
 */
int script_check_args (void)
{
  int ret = SCRIPT_ENGINE_SUCCESS, status;
  lua_State* L = luaL_newstate();

  if (L == NULL)
    fatal("Error opening lua, for checking arguments\n");
  lua_atpanic(L, panic);

  /* set all global libraries (we'll need the string-lib) */
  status = lua_cpcall(L, init_lua, NULL);
  if (status != 0)
  {
    error("%s: error while initializing Lua State:\n%s\n",
        SCRIPT_ENGINE, lua_tostring(L, -1));
    ret = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }

  lua_pushcclosure(L, init_parseargs, 0);
  lua_pushstring(L, o.scriptargs);
  lua_pcall(L, 1, 1, 0);

  if (!lua_isfunction(L, -1))
    ret = SCRIPT_ENGINE_ERROR;

  finishup:
  lua_close(L);
  return ret;
}

/* open a lua instance
 * open the lua standard libraries
 * open all the scripts and prepare them for execution
 *  (export nmap bindings, add them to host/port rulesets etc.)
 * apply all scripts on all hosts
 * */
int script_scan(std::vector<Target*> &targets) {
  int status;
  std::vector<Target*>::iterator target_iter;
  std::list<std::list<struct thread_record> >::iterator runlevel_iter;
  std::list<struct thread_record>::iterator thr_iter;
  std::list<struct thread_record> torun_threads;
  std::vector<std::string>::iterator script_iter;
  lua_State* L;

  o.current_scantype = SCRIPT_SCAN;

  SCRIPT_ENGINE_VERBOSE(
    log_write(LOG_STDOUT, "%s: Initiating script scanning.\n", SCRIPT_ENGINE);
  )

  SCRIPT_ENGINE_DEBUGGING(
    unsigned int tlen = targets.size();
    char targetstr[128];
    if(tlen > 1)
      log_write(LOG_STDOUT, "%s: Script scanning %d hosts.\n",
        SCRIPT_ENGINE, tlen);
    else
      log_write(LOG_STDOUT, "%s: Script scanning %s.\n",
        SCRIPT_ENGINE, (*targets.begin())->NameIP(targetstr, sizeof(targetstr)));
  )

  L = luaL_newstate();
  if (L == NULL) {
    error("%s: Failed luaL_newstate()", SCRIPT_ENGINE);
        return SCRIPT_ENGINE_ERROR;
  }
  lua_atpanic(L, panic);

  status = lua_cpcall(L, init_lua, NULL);
  if (status != 0)
  {
    error("%s: error while initializing Lua State:\n%s\n",
          SCRIPT_ENGINE, lua_tostring(L, -1));
    status = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }

  //set the arguments - if provided
  status = lua_cpcall(L, init_setargs, NULL);
  if (status != 0)
  {
    error("%s: error while setting arguments for scripts:\n%s\n",
          SCRIPT_ENGINE, lua_tostring(L, -1));
    status = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }


  /* Get the error function to use with the lua_pcall of init_rules. */
  lua_rawgeti(L, LUA_REGISTRYINDEX, errfunc);
  lua_pushcclosure(L, init_rules, 0);
  /* We need room for the list of scripts. */
  if (!lua_checkstack(L, o.chosenScripts.size())) {
    error("%s: stack overflow at %s:%d", SCRIPT_ENGINE, __FILE__, __LINE__);
    status = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }
  /* Push each of the selected scripts. */
  for (script_iter = o.chosenScripts.begin();
       script_iter != o.chosenScripts.end();
       script_iter++) {
    lua_pushstring(L, script_iter->c_str());
  }
  /* Call init_rules using the error function at index 1. */
  status = lua_pcall(L, o.chosenScripts.size(), 0, 1);
  if (status != 0) {
    error("%s: error while initializing script rules:\n%s\n",
          SCRIPT_ENGINE, lua_tostring(L, -1));
    status = SCRIPT_ENGINE_ERROR;
    goto finishup;
  }
  /* Pop the error function. */
  lua_pop(L, 1);

  assert(lua_gettop(L) == 0);

  SCRIPT_ENGINE_DEBUGGING(log_write(LOG_STDOUT, "%s: Matching rules.\n", SCRIPT_ENGINE);)

  for(target_iter = targets.begin(); target_iter != targets.end(); target_iter++) {
    std::string key = ((Target*) (*target_iter))->targetipstr();
    lua_rawgeti(L, LUA_REGISTRYINDEX, current_hosts);
    lua_pushstring(L, key.c_str());
    lua_pushlightuserdata(L, (void *) *target_iter);
    lua_settable(L, -3);
    lua_pop(L, 1);

    status = process_preparehost(L, *target_iter, torun_threads);
    if(status != SCRIPT_ENGINE_SUCCESS){
      goto finishup;
    }
  }

  status = process_preparerunlevels(torun_threads);
  if(status != SCRIPT_ENGINE_SUCCESS) {
    goto finishup;
  }

  SCRIPT_ENGINE_DEBUGGING(log_write(LOG_STDOUT, "%s: Running scripts.\n", SCRIPT_ENGINE);)

  for(runlevel_iter = torun_scripts.begin(); runlevel_iter != torun_scripts.end(); runlevel_iter++) {
    running_scripts = (*runlevel_iter);

    SCRIPT_ENGINE_DEBUGGING(log_write(LOG_STDOUT, "%s: Runlevel: %f\n",
      SCRIPT_ENGINE,
      running_scripts.front().runlevel);)

    /* Start the time-out clocks for targets with scripts in this
     * runlevel.  The clock is stopped in process_finalize().
     */
    for (thr_iter = running_scripts.begin();
         thr_iter != running_scripts.end();
         thr_iter++)
      if (!thr_iter->rr.host->timeOutClockRunning())
        thr_iter->rr.host->startTimeOutClock(NULL);

    status = process_mainloop(L);
    if(status != SCRIPT_ENGINE_SUCCESS){
      goto finishup;
    }
  }


finishup:
  SCRIPT_ENGINE_DEBUGGING(
    log_write(LOG_STDOUT, "%s: Script scanning completed.\n", SCRIPT_ENGINE);
  )
  lua_close(L);
  torun_scripts.clear();
  if(status != SCRIPT_ENGINE_SUCCESS) {
    error("%s: Aborting script scan.", SCRIPT_ENGINE);
    return SCRIPT_ENGINE_ERROR;
  } else {
    return SCRIPT_ENGINE_SUCCESS;
  }
}

int process_mainloop(lua_State *L) {
  int state;
  int unfinished = running_scripts.size() + waiting_scripts.size();
  struct thread_record current;
  ScanProgressMeter progress = ScanProgressMeter(SCRIPT_ENGINE);

  double total = (double) unfinished;
  double done = 0;

  std::list<struct thread_record>::iterator iter;
  struct timeval now;

  // while there are scripts in running or waiting state, we loop.
  // we rely on nsock_loop to protect us from busy loops when
  // all scripts are waiting.
  while( unfinished > 0 ) {

    if(l_nsock_loop(50) == NSOCK_LOOP_ERROR) {
      error("%s: An error occured in the nsock loop", SCRIPT_ENGINE);
      return SCRIPT_ENGINE_ERROR;
    }

    unfinished = running_scripts.size() + waiting_scripts.size();

    if (keyWasPressed()) {
      done = 1.0 - (((double) unfinished) / total);
      if (o.verbose > 1 || o.debugging) {
        log_write(LOG_STDOUT, "Active NSE scripts: %d\n", unfinished);
        log_flush(LOG_STDOUT);
      }
      progress.printStats(done, NULL);
    }

    SCRIPT_ENGINE_VERBOSE(
      if(progress.mayBePrinted(NULL)) {
        done = 1.0 - (((double) unfinished) / total);
        if(o.verbose > 1 || o.debugging)
          progress.printStats(done, NULL);
        else
          progress.printStatsIfNeccessary(done, NULL);
      })

    gettimeofday(&now, NULL);

    for(iter = waiting_scripts.begin(); iter != waiting_scripts.end(); iter++)
      if (iter->rr.host->timedOut(&now)) {
        running_scripts.push_front((*iter));
        waiting_scripts.erase(iter);
        iter = waiting_scripts.begin();
      }

    // Run the garbage collecter. FIXME: This can error in a __gc metamethod
    lua_gc(L, LUA_GCSTEP, 5);

    while (!running_scripts.empty()) {
      current = *(running_scripts.begin());

      if (current.rr.host->timedOut(&now))
        state = LUA_ERRRUN;
      else
        state = lua_resume(current.thread, current.resume_arguments);

      if(state == LUA_YIELD) {
        // this script has performed a network io operation
        // we put it in the waiting
        // when the network io operation has completed,
        // a callback from the nsock library will put the
        // script back into the running state

        waiting_scripts.push_back(current);
        running_scripts.pop_front();
      } else if( state == 0) {
        // this script has finished
        // we first check if it produced output
        // then we release the thread and remove it from the
        // running_scripts list

        if(lua_isstring (current.thread, 2)) { // FIXME
                    ScriptResult sr;
                    lua_State *thread = current.thread;
          SCRIPT_ENGINE_TRY(process_getScriptId(thread, &sr));
                    lua_getfield(thread, 2, "gsub");
                    lua_pushvalue(thread, 2); // output FIXME
                    lua_pushliteral(thread, "[^%w%s%p]");
                    lua_pushcclosure(thread, escape_char, 0);
                    lua_call(thread, 3, 1);
          sr.set_output(lua_tostring(thread, -1));
          if(current.rr.type == 0) {
            current.rr.host->scriptResults.push_back(sr);
          } else if(current.rr.type == 1) {
            current.rr.port->scriptResults.push_back(sr);
            current.rr.host->ports.numscriptresults++;
          }
          lua_pop(thread, 2);
        }

        SCRIPT_ENGINE_TRY(process_finalize(L, current.registry_idx));
      } else {
        // this script returned because of an error
        // print the failing reason if the verbose level is high enough
        SCRIPT_ENGINE_DEBUGGING(
          const char* errmsg = lua_tostring(current.thread, -1);
          log_write(LOG_STDOUT, "%s: %s\n", SCRIPT_ENGINE, errmsg);
        )
        SCRIPT_ENGINE_TRY(process_finalize(L, current.registry_idx));
      }
    } // while
  }

  progress.endTask(NULL, NULL);

  return SCRIPT_ENGINE_SUCCESS;
}

// If the target still has scripts in either running_scripts
// or waiting_scripts then it is still running.  This only
// pertains to scripts in the current runlevel.

int has_target_finished(Target *target) {
  std::list<struct thread_record>::iterator iter;

  for (iter = waiting_scripts.begin(); iter != waiting_scripts.end(); iter++)
    if (target == iter->rr.host) return 0;

  for (iter = running_scripts.begin(); iter != running_scripts.end(); iter++)
    if (target == iter->rr.host) return 0;

  return 1;
}

int process_finalize(lua_State* L, unsigned int registry_idx) {
  luaL_unref(L, LUA_REGISTRYINDEX, registry_idx);
  struct thread_record thr = running_scripts.front();

  running_scripts.pop_front();

  if (has_target_finished(thr.rr.host))
    thr.rr.host->stopTimeOutClock(NULL);

  return SCRIPT_ENGINE_SUCCESS;
}

int process_waiting2running(lua_State* L, int resume_arguments) {
  std::list<struct thread_record>::iterator iter;

  // find the lua state which has received i/o
  for(iter = waiting_scripts.begin(); (*iter).thread != L; iter++) {

    // It is very unlikely that a thread which
    // is not in the waiting queue tries to
    // continue
    // it does happen when they try to do socket i/o
    // inside a pcall

    // This also happens when we timeout a script
    // In this case, the script is still in the waiting
    // queue and we will have manually removed it from
    // the waiting queue so we just return.

    if(iter == waiting_scripts.end())
      return SCRIPT_ENGINE_SUCCESS;
  }

  (*iter).resume_arguments = resume_arguments;

  // put the thread back into the running
  // queue
  //running_scripts.push_front((*iter));
  running_scripts.push_back((*iter));
  waiting_scripts.erase(iter);

  return SCRIPT_ENGINE_SUCCESS;
}

/* Gets the basename of a script filename and removes any ".nse" extension. */
static char *abbreviate_script_filename(const char *filename) {
  char *abbrev;

  abbrev = path_get_basename(filename);
  if (abbrev == NULL)
    return NULL;
  if (nse_check_extension(SCRIPT_ENGINE_EXTENSION, abbrev))
    abbrev[strlen(abbrev) - strlen(SCRIPT_ENGINE_EXTENSION)] = '\0';

  return abbrev;
}

/* Tries to get the script id (based on the filename) and stores it in the
 * script scan result structure. If someone changed the filename field to a
 * nonstring we complain. */
int process_getScriptId(lua_State* L, ScriptResult *sr) {
  const char *filename;
  char *id;

  lua_getfield(L, 1, FILENAME);
  filename = lua_tostring(L, -1);
  if (filename == NULL) {
    error("%s: The script's 'filename' entry was changed to: %s",
      SCRIPT_ENGINE, luaL_typename(L, -1));
    return SCRIPT_ENGINE_ERROR;
  }
  lua_pop(L, 1);

  id = abbreviate_script_filename(filename);
  if (id == NULL) {
    /* On error just use the filename. */
    sr->set_id(filename);
  } else {
    sr->set_id(id);
    free(id);
  }

  return SCRIPT_ENGINE_SUCCESS;
}

/* try all host and all port rules against the
 * state of the current target
 * make a list with run records for the scripts
 * which want to run
 * process all scripts in the list
 * */
int process_preparehost(lua_State* L, Target* target, std::list<struct thread_record>& torun_threads) {
  PortList* plist = &(target->ports);
  Port* current = NULL;

  /* find the matching hostrules */
  lua_getfield(L, LUA_REGISTRYINDEX, HOSTTESTS);
  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    // Hostrule function & file closure on stack
    lua_pushvalue(L, -2); // hostrule function (key)
    lua_newtable(L);
    set_hostinfo(L, target); // hostrule argument
    SCRIPT_ENGINE_LUA_TRY(lua_pcall(L, 1, 1, 0));

    if (lua_isboolean(L, -1) && lua_toboolean(L, -1))
    {
      struct thread_record tr;
      tr.rr.type = 0;
      tr.rr.port = NULL;
      tr.rr.host = target;

      SCRIPT_ENGINE_TRY(process_preparethread(L, &tr));

      torun_threads.push_back(tr);

      SCRIPT_ENGINE_DEBUGGING(
        lua_getfenv(L, -2); // file closure environment
        lua_getfield(L, -1, FILENAME);
        log_write(LOG_STDOUT, "%s: Will run %s against %s\n",
          SCRIPT_ENGINE,
          lua_tostring(L, -1),
          target->targetipstr());
        lua_pop(L, 2);
      )
    }
    lua_pop(L, 2); // boolean and file closure
  }

  /* find the matching port rules */
  lua_getfield(L, LUA_REGISTRYINDEX, PORTTESTS);

  /* because of the port iteration API we need to awkwardly iterate
   * over the kinds of ports we're interested in explictely. */
  current = NULL;
  while((current = plist->nextPort(current, TCPANDUDP, PORT_OPEN)) != NULL) {
    SCRIPT_ENGINE_TRY(process_pickScriptsForPort(L, target, current, torun_threads));
  }

  while((current = plist->nextPort(current, TCPANDUDP, PORT_OPENFILTERED)) != NULL) {
    SCRIPT_ENGINE_TRY(process_pickScriptsForPort(L, target, current, torun_threads));
  }

  while((current = plist->nextPort(current, TCPANDUDP, PORT_UNFILTERED)) != NULL) {
    SCRIPT_ENGINE_TRY(process_pickScriptsForPort(L, target, current, torun_threads));
  }

  lua_pop(L, 2); // Hostrules, Portrules

  return SCRIPT_ENGINE_SUCCESS;
}

int process_preparerunlevels(std::list<struct thread_record> torun_threads) {
  std::list<struct thread_record> current_runlevel;
  std::list<struct thread_record>::iterator runlevel_iter;
  double runlevel_idx = 0.0;

  torun_threads.sort(CompareRunlevels());

  for(  runlevel_iter = torun_threads.begin();
    runlevel_iter != torun_threads.end();
    runlevel_iter++) {

    if(runlevel_idx < (*runlevel_iter).runlevel) {
      runlevel_idx = (*runlevel_iter).runlevel;
      current_runlevel.clear();
      //push_back an empty list in which we store all scripts of the
      //current runlevel...
      torun_scripts.push_back(current_runlevel);
    }

    torun_scripts.back().push_back(*runlevel_iter);
  }

  return SCRIPT_ENGINE_SUCCESS;
}

/* Because we can't iterate over all ports of interest in one go
 * we need to do port matching in a separate function (unlike host
 * rule matching)
 * Note that we assume that at -1 on the stack we can find the portrules
 * */
int process_pickScriptsForPort(lua_State* L, Target* target, Port* port, std::list<thread_record>& torun_threads) {
  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    // Portrule function & file closure on stack
    lua_pushvalue(L, -2); // portrule function (key)
    lua_newtable(L);
    set_hostinfo(L, target); // portrule argument 1
    lua_newtable(L);
    set_portinfo(L, port); // portrule argument 2
    SCRIPT_ENGINE_LUA_TRY(lua_pcall(L, 2, 1, 0));

    if (lua_isboolean(L, -1) && lua_toboolean(L, -1))
    {
      struct thread_record tr;
      tr.rr.type = 1;
      tr.rr.port = port;
      tr.rr.host = target;

      SCRIPT_ENGINE_TRY(process_preparethread(L, &tr));

      torun_threads.push_back(tr);

      SCRIPT_ENGINE_DEBUGGING(
        lua_getfenv(L, -2); // file closure environment
        lua_getfield(L, -1, FILENAME);
        log_write(LOG_STDOUT, "%s: Will run %s against %s\n",
          SCRIPT_ENGINE,
          lua_tostring(L, -1),
          target->targetipstr());
        lua_pop(L, 2);
      )
    }
    lua_pop(L, 2); // boolean and file closure
  }
  return SCRIPT_ENGINE_SUCCESS;
}

/* Create a new lua thread and prepare it for execution
 * we store target info in the thread so that the mainloop
 * knows where to put the script result. File closure is expected
 * at stack index -2.
 * */
int process_preparethread(lua_State* L, struct thread_record *tr){

  lua_State *thread = lua_newthread(L);
  tr->registry_idx = luaL_ref(L, LUA_REGISTRYINDEX); // store thread
  tr->thread = thread;

  lua_pushvalue(L, -2); // File closure
  lua_getfenv(L, -1); // get script file environment
  lua_getfield(L, -1, FILENAME); // get its filename

  lua_createtable(L, 0, 11); // new environment
  lua_pushvalue(L, -2); // script filename
  lua_setfield(L, -2, FILENAME);
  lua_pushnumber(L, 1.0); // set a default RUNLEVEL
  lua_setfield(L, -2, RUNLEVEL);
  lua_createtable(L, 0, 1); // metatable for env
  lua_pushvalue(L, LUA_GLOBALSINDEX);
  lua_setfield(L, -2, "__index"); // global access
  lua_setmetatable(L, -2);

  lua_pushvalue(L, -4); // script file closure
  lua_pushvalue(L, -2); // script env
  lua_setfenv(L, -2);
  SCRIPT_ENGINE_LUA_TRY(
    lua_pcall(L, 0, 0, 0) // file closure loads globals (action, id, etc.)
  );

  lua_getfield(L, -1, RUNLEVEL);
  tr->runlevel = lua_tonumber(L, -1);
  lua_pop(L, 1);

  // move the script action closure into the thread
  lua_getfield(L, -1, ACTION); // action closure
  lua_xmove(L, thread, 2);
  lua_pop(L, 1); // filename
  lua_setfenv(L, -2); // reset old env
  lua_pop(L, 1); // file closure

  // make the info table
  lua_newtable(thread);
  set_hostinfo(thread, tr->rr.host);

  /* if this is a host rule we don't have a port state */
  if(tr->rr.port != NULL) {
    lua_newtable(thread);
    set_portinfo(thread, tr->rr.port);
    tr->resume_arguments = 2;
  } else
    tr->resume_arguments = 1;

  return SCRIPT_ENGINE_SUCCESS;
}
