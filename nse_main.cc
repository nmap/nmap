#include "nse_main.h"

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

#include "nse_init.h"
#include "nse_nsock.h"
#include "nse_nmaplib.h"
#include "nse_debug.h"
#include "nse_macros.h"
#include "nse_string.h"

#include "nmap.h"
#include "nmap_error.h"
#include "portlist.h"
#include "nsock.h"
#include "NmapOps.h"
#include "timing.h"
#include "Target.h"

extern NmapOps o;

struct run_record {
	short type; // 0 - hostrule; 1 - portrule
	unsigned int index; // index in the corresponding table
	Port* port;
	Target* host;
};

struct thread_record {
	lua_State* thread;
	int resume_arguments;
	unsigned int registry_idx; // index in the main state registry
	double runlevel;
	run_record* rr;
};

std::map<std::string, Target*> current_hosts;
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
int process_preparehost(lua_State* l, Target* target, std::list<struct thread_record>& torun_threads);
int process_preparethread(lua_State* l, struct run_record rr, struct thread_record* tr);

// helper functions
int process_getScriptId(lua_State* l, struct script_scan_result* ssr);
int process_pickScriptsForPort(
		lua_State* l, 
		Target* target, 
		Port* port,
		std::vector<run_record>& torun);

// execution
int process_mainloop(lua_State* l);
int process_waiting2running(lua_State* l, int resume_arguments);
int process_finalize(lua_State* l, unsigned int registry_idx);

int script_updatedb() {
	int status;
	lua_State* l;
	
	SCRIPT_ENGINE_VERBOSE(
		log_write(LOG_STDOUT, "%s: Updating rule database.\n", 
			SCRIPT_ENGINE);
	)

	l = lua_open();
	if(l == NULL) {
		error("%s: Failed lua_open()", SCRIPT_ENGINE);
		return 0;
	}

	status = init_lua(l);
	if(status != SCRIPT_ENGINE_SUCCESS) {
		goto finishup;
	}

	status = init_updatedb(l);
	if(status != SCRIPT_ENGINE_SUCCESS) {
		goto finishup;
	}

	log_write(LOG_STDOUT, "NSE script database updated successfully.\n");

finishup:
	lua_close(l);
	if(status != SCRIPT_ENGINE_SUCCESS) {
		error("%s: Aborting database update.\n", SCRIPT_ENGINE);
		return SCRIPT_ENGINE_ERROR;
	} else {
		return SCRIPT_ENGINE_SUCCESS;
	}
}

/* open a lua instance
 * open the lua standard libraries
 * open all the scripts and prepare them for execution
 * 	(export nmap bindings, add them to host/port rulesets etc.)
 * apply all scripts on all hosts
 * */
int script_scan(std::vector<Target*> &targets) {
	int status;
	std::vector<Target*>::iterator target_iter;
	std::list<std::list<struct thread_record> >::iterator runlevel_iter;
	std::list<struct thread_record> torun_threads;
	lua_State* l;

	o.current_scantype = SCRIPT_SCAN;

	SCRIPT_ENGINE_VERBOSE(
			log_write(LOG_STDOUT, "%s: Initiating script scanning.\n", SCRIPT_ENGINE);
			)

	SCRIPT_ENGINE_DEBUGGING(
		unsigned int tlen = targets.size();
		if(tlen > 1)
			log_write(LOG_STDOUT, "%s: Script scanning %d hosts.\n", 
				SCRIPT_ENGINE, tlen);
		else
			log_write(LOG_STDOUT, "%s: Script scanning %s.\n", 
				SCRIPT_ENGINE, (*targets.begin())->HostName());
	)

	l = lua_open();
	if(l == NULL) {
		error("%s: Failed lua_open()", SCRIPT_ENGINE);
		return 0;
	}

	status = init_lua(l);
	if(status != SCRIPT_ENGINE_SUCCESS) {
		goto finishup;
	}

	status = init_rules(l, o.chosenScripts);
	if(status != SCRIPT_ENGINE_SUCCESS) {
		goto finishup;
	}

	SCRIPT_ENGINE_DEBUGGING(log_write(LOG_STDOUT, "%s: Matching rules.\n", SCRIPT_ENGINE);)

	for(target_iter = targets.begin(); target_iter != targets.end(); target_iter++) {
		std::string key = ((Target*) (*target_iter))->targetipstr();
		current_hosts[key] = (Target*) *target_iter;

		status = process_preparehost(l, *target_iter, torun_threads);
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

		status = process_mainloop(l);
		if(status != SCRIPT_ENGINE_SUCCESS){
			goto finishup;
		}
	}
	

finishup:
	SCRIPT_ENGINE_DEBUGGING(
			log_write(LOG_STDOUT, "%s: Script scanning completed.\n", SCRIPT_ENGINE);
			)
	lua_close(l);
	current_hosts.clear();
	torun_scripts.clear();
	if(status != SCRIPT_ENGINE_SUCCESS) {
		error("%s: Aborting script scan.\n", SCRIPT_ENGINE);
		return SCRIPT_ENGINE_ERROR;
	} else {
		return SCRIPT_ENGINE_SUCCESS;
	}
}

int process_mainloop(lua_State* l) {
	int state;
	int unfinished = running_scripts.size() + waiting_scripts.size(); 
	struct script_scan_result ssr;
	struct thread_record current;
	ScanProgressMeter progress = ScanProgressMeter(SCRIPT_ENGINE);

	double total = (double) unfinished;
	double done = 0;

	// while there are scripts in running or waiting state, we loop.
	// we rely on nsock_loop to protect us from busy loops when 
	// all scripts are waiting.
	while( unfinished > 0 ) {

		if(l_nsock_loop(50) == NSOCK_LOOP_ERROR) {
			error("%s: An error occured in the nsock loop", SCRIPT_ENGINE);
			return SCRIPT_ENGINE_ERROR;
		}

		unfinished = running_scripts.size() + waiting_scripts.size();

		SCRIPT_ENGINE_VERBOSE(
			if(progress.mayBePrinted(NULL)) { 
				done = 1.0 - (((double) unfinished) / total);
				if(o.verbose > 1 || o.debugging)
					progress.printStats(done, NULL);
				else
					progress.printStatsIfNeccessary(done, NULL);
			})


		if(running_scripts.begin() == running_scripts.end())
			continue;

		current = *(running_scripts.begin());
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

			if(lua_isstring (current.thread, -1)) {
				SCRIPT_ENGINE_TRY(process_getScriptId(current.thread, &ssr));
				ssr.output = nse_printable
					(lua_tostring(current.thread, -1), lua_objlen(current.thread, -1));
				if(current.rr->type == 0) {
					current.rr->host->scriptResults.push_back(ssr);
				} else if(current.rr->type == 1) {
					current.rr->port->scriptResults.push_back(ssr);
					current.rr->host->ports.numscriptresults++;
				}
				lua_pop(current.thread, 2);
			}

			SCRIPT_ENGINE_TRY(process_finalize(l, current.registry_idx));
		} else {
			// this script returned because of an error
			// print the failing reason if the verbose level is high enough	
			SCRIPT_ENGINE_DEBUGGING(
				const char* errmsg = lua_tostring(current.thread, -1);
				log_write(LOG_STDOUT, "%s: %s\n", SCRIPT_ENGINE, errmsg);
			)
			SCRIPT_ENGINE_TRY(process_finalize(l, current.registry_idx));
		}
	}

	progress.endTask(NULL, NULL);

	return SCRIPT_ENGINE_SUCCESS;
}

int process_finalize(lua_State* l, unsigned int registry_idx) {
	luaL_unref(l, LUA_REGISTRYINDEX, registry_idx);
	running_scripts.pop_front();

	return SCRIPT_ENGINE_SUCCESS;
}

int process_waiting2running(lua_State* l, int resume_arguments) {
	std::list<struct thread_record>::iterator iter;

	// find the lua state which has received i/o
	for(	iter = waiting_scripts.begin(); 
		(*iter).thread != l;
		iter++) {
		// It is very unlikely that a thread which
		// is not in the waiting queue tries to
		// continue
		// it does happen when they try to do socket i/o
		// inside a pcall
		if(iter == waiting_scripts.end())
			fatal("%s: In: %s:%i This should never happen.", 
					SCRIPT_ENGINE, __FILE__, __LINE__);
	}

	(*iter).resume_arguments = resume_arguments;

	// put the thread back into the running
	// queue
	running_scripts.push_back((*iter));
	waiting_scripts.erase(iter);

	return SCRIPT_ENGINE_SUCCESS;
}

/* Tries to get the script id and store it in the script scan result structure
 * if no 'id' field is found, the filename field is used which we set in the 
 * setup phase. If someone changed the filename field to a nonstring we complain
 * */
int process_getScriptId(lua_State* l, struct script_scan_result *ssr) {

	lua_getfield(l, -2, "id");
	lua_getfield(l, -3, "filename");

	if(lua_isstring(l, -2)) {
		ssr->id = strdup(lua_tostring (l, -2));
	} else if(lua_isstring(l, -1)) {
		ssr->id = strdup(lua_tostring (l, -1));
	} else {
		error("%s: The script has no 'id' entry, the 'filename' entry was changed to: \n",
			SCRIPT_ENGINE);
		l_dumpValue(l, -1);
		return SCRIPT_ENGINE_ERROR;
	}

	lua_pop(l, 2);

	return SCRIPT_ENGINE_SUCCESS;
}

/* try all host and all port rules against the 
 * state of the current target
 * make a list with run records for the scripts
 * which want to run
 * process all scripts in the list
 * */
int process_preparehost(lua_State* l, Target* target, std::list<struct thread_record>& torun_threads) {
	PortList* plist = &(target->ports);
	Port* current = NULL;
	size_t rules_count;
	unsigned int i;
	std::vector<run_record> torun;
	std::vector<run_record>::iterator iter;
	struct run_record rr;

	/* find the matching hostrules
	 * */
	lua_getglobal(l, HOSTTESTS);
	rules_count = lua_objlen(l, -1);

	for(i = 1; i <= rules_count; i++) {
		lua_rawgeti(l, -1, i);

		lua_getfield(l, -1, "hostrule");

		lua_newtable(l);
		set_hostinfo(l, target);

		SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 1, 1, 0));

		if(lua_isboolean (l, -1) && lua_toboolean(l, -1)) {
			rr.type = 0;
			rr.index = i;
			rr.port = NULL;
			rr.host = target;
			torun.push_back(rr);

			SCRIPT_ENGINE_DEBUGGING(
				lua_getfield(l, -2, "filename");
				log_write(LOG_STDOUT, "%s: Will run %s against %s\n",
					SCRIPT_ENGINE,
					lua_tostring(l, -1),
					target->targetipstr());
				lua_pop(l, 1);
			)
		}
		lua_pop(l, 2);
	}

	/* find the matching port rules
	 * */
	lua_getglobal(l, PORTTESTS);

	/* we only publish hostinfo once per portrule */
	lua_newtable(l);
	set_hostinfo(l, target);

	/* because of the port iteration API we need to awkwardly iterate
	 * over the kinds of ports we're interested in explictely.
	 * */
	current = NULL;
	while((current = plist->nextPort(current, TCPANDUDP, PORT_OPEN)) != NULL) {
		SCRIPT_ENGINE_TRY(process_pickScriptsForPort(l, target, current, torun));
	}

	while((current = plist->nextPort(current, TCPANDUDP, PORT_OPENFILTERED)) != NULL) {
		SCRIPT_ENGINE_TRY(process_pickScriptsForPort(l, target, current, torun));
	}

	// pop the hostinfo, we don't need it anymore
	lua_pop(l, 1);

	/* ok, let's setup threads for the scripts which said they'd like
	 * to run 
	 * Remember:
	 * we have the hosttestset and the porttestset on the stack!
	 * */
	struct thread_record tr;

	for(iter = torun.begin(); iter != torun.end(); iter++) {
		/* If it is a host rule, execute the action
		 * and append the output to the host output i
		 * If it is a port rule, append the output to
		 * the port and increase the number of scripts
		 * which produced output. We need that number
		 * to generate beautiful output later.
		 * */
		switch((*iter).type) {
			case 0: // this script runs against a host
				lua_pushvalue(l, -2);
				SCRIPT_ENGINE_TRY(process_preparethread(l, (*iter), &tr));
				lua_pop(l, 1);
				break;
			case 1: // this script runs against a port
				lua_pushvalue(l, -1);
				SCRIPT_ENGINE_TRY(process_preparethread(l, (*iter), &tr));
				lua_pop(l, 1);
				break;
			default:
				fatal("%s: In: %s:%i This should never happen.", 
						SCRIPT_ENGINE, __FILE__, __LINE__);
		}

		torun_threads.push_back(tr);
	}
	lua_pop(l, 2);

	torun.clear();
	return SCRIPT_ENGINE_SUCCESS;
}

int process_preparerunlevels(std::list<struct thread_record> torun_threads) {
	std::list<struct thread_record> current_runlevel;
	std::list<struct thread_record>::iterator runlevel_iter;
	double runlevel_idx = 0.0;
	
	torun_threads.sort(CompareRunlevels());

	for(	runlevel_iter = torun_threads.begin(); 
		runlevel_iter != torun_threads.end(); 
		runlevel_iter++) {

		if(runlevel_idx < (*runlevel_iter).runlevel) {
			runlevel_idx = (*runlevel_iter).runlevel;
			current_runlevel.clear();
			//push_back an empty in which we store all scripts of the current 
			//runlevel...
			torun_scripts.push_back(current_runlevel);
		}

		torun_scripts.back().push_back(*runlevel_iter);
	}

	return SCRIPT_ENGINE_SUCCESS;
}

/* Because we can't iterate over all ports of interest in one go
 * we need to du port matching in a separate function (unlike host
 * rule matching)
 * Note that we assume that at -2 on the stack we can find the portrules
 * and at -1 the hostinfo table
 * */
int process_pickScriptsForPort(
		lua_State* l, 
		Target* target, 
		Port* port,
		std::vector<run_record>& torun) {
	size_t rules_count = lua_objlen(l, -2);
	struct run_record rr;
	unsigned int i;

	for(i = 1; i <= rules_count; i++) {
		lua_rawgeti(l, -2, i);

		lua_getfield(l, -1, PORTRULE);

		lua_pushvalue(l, -3);

		lua_newtable(l);
		set_portinfo(l, port);

		SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 2, 1, 0));

		if(lua_isboolean (l, -1) && lua_toboolean(l, -1)) {
			rr.type = 1;
			rr.index = i;
			rr.port = port;
			rr.host = target;
			torun.push_back(rr);

			SCRIPT_ENGINE_DEBUGGING(
					lua_getfield(l, -2, "filename");
					log_write(LOG_STDOUT, "%s: Will run %s against %s:%d\n",
						SCRIPT_ENGINE,
						lua_tostring(l, -1),
						target->targetipstr(),
						port->portno);
					lua_pop(l, 1);
					)
		} else if(!lua_isboolean (l, -1)) {
			lua_getfield(l, -2, "filename");
			error("%s: Rule in %s returned %s but boolean was expected.",
					SCRIPT_ENGINE,
					lua_tostring(l, -1),
					lua_typename(l, lua_type(l, -2)));
			return SCRIPT_ENGINE_LUA_ERROR;
		}
		lua_pop(l, 2);
	}

	return SCRIPT_ENGINE_SUCCESS;
}

/* Create a new lua thread and prepare it for execution
 * we store target info in the thread so that the mainloop
 * knows where to put the script result
 * */
int process_preparethread(lua_State* l, struct run_record rr, struct thread_record* tr){

	lua_State *thread = lua_newthread(l);

	lua_rawgeti(l, -2, rr.index); // get the script closure

	// move the script closure into the thread
	lua_xmove(l, thread, 1); 

	// store the target of this thread in the thread
	struct run_record *rr_thread = (struct run_record*) safe_malloc(sizeof(struct run_record));
	rr_thread->type = rr.type;
	rr_thread->index = rr.index;
	rr_thread->host = rr.host;
	rr_thread->port = rr.port;

	
	lua_getfield(thread, -1, RUNLEVEL);
	tr->runlevel = lua_tonumber(thread, -1);
	lua_pop(thread, 1);

	// prepare the thread for a resume by
	// pushing the action method onto the stack
	lua_getfield(thread, -1, ACTION);

	// make the info table
	lua_newtable(thread); 
	set_hostinfo(thread, rr.host);

	tr->thread = thread;
	tr->rr = rr_thread;
	tr->resume_arguments = 1;

	// we store the thread in the registry to prevent
	// garbage collection +
	tr->registry_idx = luaL_ref(l, LUA_REGISTRYINDEX);

	/* if this is a host rule we don't have
	 * a port state
	 * */
	if(rr.port != NULL) {
		lua_newtable(thread);
		set_portinfo(thread, rr.port);
		tr->resume_arguments = 2;
	}

	return SCRIPT_ENGINE_SUCCESS;
}


