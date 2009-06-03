#ifndef NSE_MACROS
#define NSE_MACROS

#define HOSTRULE	"hostrule"
#define HOSTTESTS	"hosttests"
#define PORTRULE	"portrule"
#define PORTTESTS	"porttests"
#define SCRIPTFILES	"scriptfiles"
#define ACTION		"action"
#define HOST        "host"
#define PORT        "port"
#define PORT_U      "Port"
#define DESCRIPTION	"description"
#define AUTHOR		"author"
#define LICENSE		"license"
#define RUNLEVEL	 "runlevel"
#define TARGET_CLASS "Target Class"
#define TARGET      "target"
#define TYPE        "type"
#define ID          "id"
#define FILENAME    "filename"
#define CATEGORY    "category"
#define WAITING     "nse_waiting"
#define FILES		 1
#define DIRS		 2

#define SCRIPT_ENGINE 			   "NSE"
#define SCRIPT_ENGINE_LUA 		   "LUA INTERPRETER"
#define SCRIPT_ENGINE_SUCCESS 		   0
#define SCRIPT_ENGINE_ERROR	 	   2
#define SCRIPT_ENGINE_LUA_ERROR		   3

#ifdef WIN32
	#define SCRIPT_ENGINE_LUA_DIR 	   "scripts\\"
#else
	#define SCRIPT_ENGINE_LUA_DIR 	   "scripts/"
#endif

#define SCRIPT_ENGINE_LIB_DIR 	   "nselib/"

#define SCRIPT_ENGINE_DATABASE 		   "script.db"
#define SCRIPT_ENGINE_EXTENSION		   ".nse"

#define SCRIPT_ENGINE_LUA_TRY(func) if (func != 0) {\
	error("LUA INTERPRETER in %s:%d: %s", __FILE__, __LINE__, (char *)lua_tostring(L, -1));\
	return SCRIPT_ENGINE_LUA_ERROR;\
}

#define SCRIPT_ENGINE_TRY(func) if (func != 0) {\
	return SCRIPT_ENGINE_ERROR;\
}

#define ARRAY_LEN(a)  ((int)(sizeof(a) / sizeof(a[0])))

#define SCRIPT_ENGINE_VERBOSE(msg) if (o.debugging || o.verbose > 0) {msg};
#define SCRIPT_ENGINE_DEBUGGING(msg) if (o.debugging) {msg};

#define MAX_FILENAME_LEN 4096

#endif

