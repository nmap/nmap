#include "nse_init.h"
#include "nse_nmaplib.h"
#include "nse_macros.h"
#include "nse_debug.h"

// 3rd Party libs
#include "nse_pcrelib.h"

#include "nbase.h"

#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"

#ifndef WIN32
	#include "dirent.h"
#endif

#include "errno.h"

#include <algorithm>
int init_setlualibpath(lua_State* l);
int init_setargs(lua_State *l);
int init_parseargs(lua_State* l);
int init_loadfile(lua_State* l, char* filename);
int init_loaddir(lua_State* l, char* dirname);
int init_loadcategories(lua_State* l, std::vector<std::string> categories, std::vector<std::string> &unusedTags);
int init_scandir(char* dirname, std::vector<std::string>& result, int files_or_dirs);
int init_fetchfile(char *result, size_t result_max_len, char* file);
int init_fetchfile_absolute(char *path, size_t path_len, char *file);
int init_updatedb(lua_State* l);
int init_pick_default_categories(std::vector<std::string>& chosenScripts);

int check_extension(const char* ext, const char* path);

extern NmapOps o;

/* open the standard libs */
int init_lua(lua_State* l) { // FIXME: Use cpcall, let Lua error normally.
	static const luaL_Reg lualibs[] = {
		{"", luaopen_base},
		{LUA_LOADLIBNAME, luaopen_package},
		{LUA_TABLIBNAME, luaopen_table},
		{LUA_IOLIBNAME, luaopen_io},
		{LUA_OSLIBNAME, luaopen_os},
		{LUA_STRLIBNAME, luaopen_string},
		{LUA_MATHLIBNAME, luaopen_math},
		{LUA_DBLIBNAME, luaopen_debug},
		{NSE_PCRELIBNAME, luaopen_pcrelib},
		{NULL, NULL}
	}; 

	const luaL_Reg* lib;
	for (lib = lualibs; lib->func; lib++) {
		lua_pushcfunction(l, lib->func);
		lua_pushstring(l, lib->name);
		SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 1, 0, 0));
	}


	/* publish the nmap bindings to the script */
	lua_newtable(l);
	SCRIPT_ENGINE_TRY(set_nmaplib(l));
	lua_setglobal(l, "nmap");
	SCRIPT_ENGINE_TRY(init_setlualibpath(l));
	return SCRIPT_ENGINE_SUCCESS;
}

/*sets two variables, which control where lua looks for modules (implemented in C or lua */
int init_setlualibpath(lua_State* l){
	char path[MAX_FILENAME_LEN];
	char cpath[MAX_FILENAME_LEN];

	const char*oldpath, *oldcpath;
	std::string luapath, luacpath;
	/* set the path lua searches for modules*/
	if(nmap_fetchfile(path, MAX_FILENAME_LEN, SCRIPT_ENGINE_LIB_DIR)!=2){
		/*SCRIPT_ENGINE_LIB_DIR is not a directory - error */
		error("%s: %s not a directory", SCRIPT_ENGINE, SCRIPT_ENGINE_LIB_DIR);
		return SCRIPT_ENGINE_ERROR;
	}

	if(nmap_fetchfile(cpath, MAX_FILENAME_LEN, SCRIPT_ENGINE_LIBEXEC_DIR)!=2){
		error("%s: %s not a directory", SCRIPT_ENGINE, SCRIPT_ENGINE_LIBEXEC_DIR);
		return SCRIPT_ENGINE_ERROR;
	}

	/* the path lua uses to search for modules is setted to the 
	 * SCRIPT_ENGINE_LIBDIR/ *.lua with the default path 
	 * (which is read from the package-module) appended  - 
	 * the path for C-modules is as above but it searches for shared libs (*.so)	*/
	luapath= std::string(path) + "?.lua;"; 

#ifdef WIN32
	luacpath= std::string(cpath) + "?.dll;";
#else
	luacpath= std::string(cpath) + "?.so;";
#endif
 
	lua_getglobal(l,"package");
	if(!lua_istable(l,-1)){
		error("%s: the lua global-variable package is not a table?!", SCRIPT_ENGINE);
		return SCRIPT_ENGINE_ERROR;
	}
	lua_getfield(l,-1, "path");
	lua_getfield(l,-2, "cpath");
	if(!lua_isstring(l,-1)||!lua_isstring(l,-2)){
		error("%s: no default paths setted in package table (needed in %s at line %d) -- probably a problem of the lua-configuration?!", SCRIPT_ENGINE, __FILE__, __LINE__);
		return SCRIPT_ENGINE_ERROR;
	}
	oldcpath= lua_tostring(l,-1);
	oldpath = lua_tostring(l,-2);
	luacpath= luacpath + oldcpath;
	luapath= luapath + oldpath;
	lua_pop(l,2);
	lua_pushstring(l, luapath.c_str());
	lua_setfield(l, -2, "path");
	lua_pushstring(l, luacpath.c_str());
	lua_setfield(l, -2, "cpath");
	lua_getfield(l,-1, "path");
	lua_getfield(l,-2, "cpath");
	SCRIPT_ENGINE_DEBUGGING(log_write(LOG_STDOUT, "%s: Using %s to search for C-modules and %s for Lua-modules\n", SCRIPT_ENGINE, lua_tostring(l,-1), lua_tostring(l,-2));)
	/*pop the two strings (luapath and luacpath) and the package table off 
	 * the stack */
	lua_pop(l,3);
	return SCRIPT_ENGINE_SUCCESS;
}

/* parses the argument provided to --script-args and leaves the processed 
 * string on the stack, after this it only has to be prepended with 
 * "<tablename>={" and appended by "}", before it can be called by
 * luaL_loadbuffer() 
 */
int init_parseargs(lua_State* l){
	//FIXME - free o.script-args after we're finished!!!
	
	if (o.scriptargs==NULL)
		return SCRIPT_ENGINE_SUCCESS; //if no arguments are provided we're done

    lua_pushstring(l, o.scriptargs);
    luaL_getmetafield(l, -1, "__index");
    lua_getfield(l, -1, "gsub");
    lua_pushvalue(l, -3);
    lua_pushliteral(l, "=([^{},]+)");
    lua_pushliteral(l, "=\"%1\"");
	SCRIPT_ENGINE_TRY(lua_pcall(l,3,1,0));
    lua_replace(l, 1);
	lua_settop(l,1); //clear stack

	return SCRIPT_ENGINE_SUCCESS;
}
/* set the arguments inside the nmap.registry, for use by scripts
 */
int init_setargs(lua_State *l){
	const char *argbuf;
	size_t argbuflen;
	if(o.scriptargs==NULL){
		return SCRIPT_ENGINE_SUCCESS;
	}
	/* we'll concatenate the stuff we need to prepend and append to the 
	 * processed using lua's functionality
	 */
	SCRIPT_ENGINE_TRY(init_parseargs(l));
	lua_pushliteral(l,"nmap.registry.args={");
	lua_insert(l,-2);
	lua_pushliteral(l,"}");
	lua_concat(l,3);
	argbuf=lua_tolstring(l,-1,&argbuflen);
	luaL_loadbuffer(l,argbuf,argbuflen, "Script-Arguments");
    lua_replace(l, -2); // remove argbuf string
	if(lua_pcall(l,0,0,0)!=0){
		error("error loading --script-args: %s",lua_tostring(l,-1));
		return SCRIPT_ENGINE_ERROR;
	}
	return SCRIPT_ENGINE_SUCCESS;
}
/* if there were no command line arguments specifying
 * which scripts should be run, a default script set is
 * chosen
 * otherwise the script locators given at the command line
 * (either directories with lua files or lua files) are
 * loaded
 * */
int init_rules(lua_State* l, std::vector<std::string> chosenScripts) {
	char path[MAX_FILENAME_LEN];
	int type;
	char* c_iter;
	std::vector<std::string> unusedTags;

	lua_newtable(l);
	lua_setglobal(l, PORTTESTS);

	lua_newtable(l);
	lua_setglobal(l, HOSTTESTS);

	SCRIPT_ENGINE_TRY(init_pick_default_categories(chosenScripts));

	// we try to interpret the choices as categories
	SCRIPT_ENGINE_TRY(init_loadcategories(l, chosenScripts, unusedTags));
	
	// if there's more, we try to interpret as directory or file
	std::vector<std::string>::iterator iter;
	bool extension_not_matched = false;
	for(iter = unusedTags.begin(); iter != unusedTags.end(); iter++) {

		c_iter = strdup((*iter).c_str());
		type = init_fetchfile_absolute(path, sizeof(path), c_iter);
		free(c_iter);

		if (type == 0) {
			c_iter = strdup((*iter + std::string(SCRIPT_ENGINE_EXTENSION)).c_str());
			type = init_fetchfile_absolute(path, sizeof(path), c_iter);
			free(c_iter);
		}
		
		switch(type) {
			case 0: // no such path
				error("%s: No such category, file or directory: '%s'", SCRIPT_ENGINE, (*iter).c_str());
				return SCRIPT_ENGINE_ERROR;
				break;
			case 1: // nmap_fetchfile returned a file
				if(check_extension(SCRIPT_ENGINE_EXTENSION, path) != MATCH
						&& extension_not_matched == false) {
					error("%s: Warning: Loading '%s' - the recommended file extension is '.nse'.",
							SCRIPT_ENGINE, path);
					extension_not_matched = true;
				}
					SCRIPT_ENGINE_TRY(init_loadfile(l, path));
				break;
			case 2: // nmap_fetchfile returned a dir
				SCRIPT_ENGINE_TRY(init_loaddir(l, path));
				break;
			default:
				fatal("%s: In: %s:%i This should never happen.", 
						SCRIPT_ENGINE, __FILE__, __LINE__);
		}
	}

	// Compute some stats 
	SCRIPT_ENGINE_DEBUGGING(
		int rules_count;

		lua_getglobal(l, HOSTTESTS);
		rules_count = lua_objlen(l, -1);

		lua_getglobal(l, PORTTESTS);
		rules_count += lua_objlen(l, -1);
		lua_pop(l, 2);
		log_write(LOG_STDOUT, "%s: Initialized %d rules\n", SCRIPT_ENGINE, rules_count);
	)

	return SCRIPT_ENGINE_SUCCESS;
}

class ExtensionalCategory {
public:
	std::string category;
	int option;

	ExtensionalCategory(std::string _category, int _option) {
		category = _category;
		option = _option;
	}
};

int init_pick_default_categories(std::vector<std::string>& chosenScripts) {
	std::vector<ExtensionalCategory> reserved_categories;
	std::vector<ExtensionalCategory>::iterator rcat_iter;

	reserved_categories.push_back(ExtensionalCategory(std::string("version"), o.scriptversion));

	// if they tried to explicitely select an implicit category, we complain
	if(o.script) {
		for(	rcat_iter = reserved_categories.begin();
			rcat_iter != reserved_categories.end();
			rcat_iter++) {
			if(	(*rcat_iter).option == 0
				&& std::find(
					chosenScripts.begin(), 
					chosenScripts.end(), 
					(*rcat_iter).category) != chosenScripts.end())
				fatal("%s: specifying the \"%s\" category explicitly is not allowed.", 
				SCRIPT_ENGINE, (*rcat_iter).category.c_str());
		}
	}

	// if no scripts were chosen, we use a default set
	if(	(o.script == 1 
		 && chosenScripts.size() == 0) )
	{
		chosenScripts.push_back(std::string("default"));
	}

	// we append the implicitely selected categories
	for(	rcat_iter = reserved_categories.begin();
		rcat_iter != reserved_categories.end();
		rcat_iter++) {
		if((*rcat_iter).option == 1)
			chosenScripts.push_back((*rcat_iter).category);
	}

	return SCRIPT_ENGINE_SUCCESS;
}

int init_updatedb(lua_State* l) {
	char path[MAX_FILENAME_LEN];
	FILE* scriptdb;
	std::vector<std::string> files;
	std::vector<std::string>::iterator iter;
	char* c_iter;
	
	if(nmap_fetchfile(path, sizeof(path)-sizeof(SCRIPT_ENGINE_DATABASE)-1, SCRIPT_ENGINE_LUA_DIR) == 0) {
		error("%s: Couldn't find '%s'", SCRIPT_ENGINE, SCRIPT_ENGINE_LUA_DIR);
		return SCRIPT_ENGINE_ERROR;
	}

	SCRIPT_ENGINE_TRY(init_scandir(path, files, FILES));

	// we rely on the fact that nmap_fetchfile returned a string which leaves enough room
	// to append the db filename (see call to nmap_fetchfile above)
	strncat(path, SCRIPT_ENGINE_DATABASE, MAX_FILENAME_LEN-1);
	
	scriptdb = fopen(path, "w");
	if(scriptdb == NULL) {
		error("%s: Could not open '%s' for writing: %s", 
				SCRIPT_ENGINE, path, strerror(errno));
		return SCRIPT_ENGINE_ERROR;
	}
				
	SCRIPT_ENGINE_DEBUGGING(
		log_write(LOG_STDOUT, "%s: Trying to add %d scripts to the database.\n", 
			SCRIPT_ENGINE, (int) files.size());
	)
	
	lua_newtable(l);
	/*give the script global namespace access*/
	lua_newtable(l);
    lua_pushvalue(l, LUA_GLOBALSINDEX);
	lua_setfield(l, -2, "__index");
	lua_setmetatable(l, -2);

	std::sort(files.begin(), files.end());

	for(iter = files.begin(); iter != files.end(); iter++) {
		c_iter = strdup((*iter).c_str());
		if(check_extension(SCRIPT_ENGINE_EXTENSION, c_iter) == MATCH 
		   && strstr(c_iter, SCRIPT_ENGINE_DATABASE) == NULL) {

			SCRIPT_ENGINE_LUA_TRY(luaL_loadfile(l, c_iter));
			lua_pushvalue(l, -2);
			lua_setfenv(l, -2);
			SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 0, 0, 0));

			lua_getfield(l, -1, "categories");
			if(lua_isnil(l, -1)) {
				error("%s: Script '%s' does not contain any category categories.", SCRIPT_ENGINE, c_iter);
				return SCRIPT_ENGINE_ERROR;
			}
			
			lua_pushnil(l);
			while(lua_next(l, -2) != 0) {
				char *filename = path_get_basename(c_iter);
				if (filename == NULL) {
					error("%s: Could not allocate temporary memory.", SCRIPT_ENGINE);
					return SCRIPT_ENGINE_ERROR;
				}
				fprintf(scriptdb,
					"Entry{ category = \"%s\", filename = \"%s\" }\n",
					lua_tostring(l, -1), filename);
				free(filename);
				lua_pop(l, 1);
			}
			lua_pop(l, 1); // pop the categories table
		} 

		free(c_iter);
	}
	lua_pop(l, 1); // pop the closure

	if(fclose(scriptdb) != 0) {
		error("%s: Could not close %s: %s", SCRIPT_ENGINE, path, strerror(errno));
		return SCRIPT_ENGINE_ERROR;
	}
	
	return SCRIPT_ENGINE_SUCCESS;
}

int init_loadcategories(lua_State* l, std::vector<std::string> categories, std::vector<std::string> &unusedTags) {
	std::vector<std::string>::iterator iter;
	std::vector<std::string> files;
	std::string dbpath = std::string(SCRIPT_ENGINE_LUA_DIR) + std::string(SCRIPT_ENGINE_DATABASE);
	char* c_dbpath_buf;
	char c_dbpath[MAX_FILENAME_LEN];
	const char* stub = "\
files = {}\n\
Entry = function(e)\n\
	if (categories[e.category] ~= nil) then\n\
		categories[e.category] = categories[e.category] + 1\n\
		files[e.filename] = true\n\
	end\n\
	if (categories[\"all\"] ~= nil and e.category ~= \"version\") then\n\
		categories[\"all\"] = categories[\"all\"] + 1\n\
		files[e.filename] = true\n\
	end\n\
end\n";	
	int categories_usage;
	char* c_iter;
	char script_path[MAX_FILENAME_LEN];
	int type;

	// closure
	lua_newtable(l);
	
	// categories table
	lua_newtable(l);
	for(iter = categories.begin(); iter != categories.end(); iter++) {
		lua_pushinteger(l, 0);
		lua_setfield(l, -2, (*iter).c_str());
	}
	lua_setfield(l, -2, "categories");

	// we load the stub
	// the strlen is safe in this case because the stub is a constant string
	SCRIPT_ENGINE_LUA_TRY(luaL_loadbuffer(l, stub, strlen(stub), "Database Stub"));
	lua_pushvalue(l, -2);
	lua_setfenv(l, -2);
	SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 0, 0, 0));
	
	// if we can't find the database we try to create it
	c_dbpath_buf = strdup(dbpath.c_str());
	if(nmap_fetchfile(c_dbpath, sizeof(c_dbpath), c_dbpath_buf) == 0) {
		SCRIPT_ENGINE_TRY(init_updatedb(l));
	}
	free(c_dbpath_buf);

	SCRIPT_ENGINE_LUA_TRY(luaL_loadfile(l, c_dbpath));
	lua_pushvalue(l, -2);
	lua_setfenv(l, -2);
	SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 0, 0, 0));

	// retrieve the filenames produced by the stub
	lua_getfield(l, -1, "files");	
	lua_pushnil(l);
	while(lua_next(l, -2) != 0) {
		if(lua_isstring(l, -2))
			files.push_back(std::string(lua_tostring(l, -2)));
		else {
			error("%s: One of the filenames in '%s' is not a string?!", 
					SCRIPT_ENGINE,
					SCRIPT_ENGINE_DATABASE);
			return SCRIPT_ENGINE_ERROR;
		}
		lua_pop(l, 1);
	}
	lua_pop(l, 1);

	// find out which categories didn't produce any filenames
	lua_getfield(l, -1, "categories");
	lua_pushnil(l);
	while(lua_next(l, -2) != 0) {
		categories_usage = lua_tointeger(l, -1);
		if(categories_usage == 0) {
			unusedTags.push_back(std::string(lua_tostring(l, -2)));	
		}
		lua_pop(l, 1);
	}
	lua_pop(l, 2);

	// load all the files we have found for the given categories
	for(iter = files.begin(); iter != files.end(); iter++) {
		c_iter = strdup((*iter).c_str());
		type = init_fetchfile(script_path, sizeof(script_path), c_iter);

		if(type != 1) {
			error("%s: %s is not a file.", SCRIPT_ENGINE, c_iter);
			return SCRIPT_ENGINE_ERROR;
		}

		free(c_iter);

		SCRIPT_ENGINE_TRY(init_loadfile(l, script_path));
	}

	return SCRIPT_ENGINE_SUCCESS;
}

int init_fetchfile(char *path, size_t path_len, char* file) {
	int type;

	type = nmap_fetchfile(path, path_len, file);

	// lets look in <nmap>/scripts too
	if(type == 0) {
		char* alt_path = strdup((std::string(SCRIPT_ENGINE_LUA_DIR) + std::string(file)).c_str());
		type = nmap_fetchfile(path, path_len, alt_path);
		free(alt_path);
			
	}

	return type;
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

/* This is a modification of init_fetchfile that first looks for an
 * absolute file name.
 */
int init_fetchfile_absolute(char *path, size_t path_len, char *file) {
	if (filename_is_absolute(file)) {
		if (o.debugging > 1)
			log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
		Strncpy(path, file, path_len);
		return nmap_fileexistsandisreadable(file);
	}

	return init_fetchfile(path, path_len, file);
}

/* This is simply the most portable way to check
 * if a file has a given extension.
 * The portability comes at the price of reduced
 * flexibility.
 */
int check_extension(const char* ext, const char* path) {
	int pathlen = strlen(path);
	int extlen = strlen(ext);
	const char* offset;

	if(	extlen > pathlen
		|| pathlen > MAX_FILENAME_LEN)
		return -1;
	
	offset = path + pathlen - extlen;

	if(strcmp(offset, ext) != MATCH)
		return 1;
	else
		return MATCH;
}

int init_loaddir(lua_State* l, char* dirname) {
	std::vector<std::string> files;
	char* c_iter;

	SCRIPT_ENGINE_TRY(init_scandir(dirname, files, FILES));
	
	std::vector<std::string>::iterator iter;
	for(iter = files.begin(); iter != files.end(); iter++) {
		c_iter = strdup((*iter).c_str());
		SCRIPT_ENGINE_TRY(init_loadfile(l, c_iter));
		free(c_iter);
	}

	return SCRIPT_ENGINE_SUCCESS;
}

#ifdef WIN32

int init_scandir(char* dirname, std::vector<std::string>& result, int files_or_dirs) {
	HANDLE dir;
	WIN32_FIND_DATA entry;
	std::string path;
	BOOL morefiles = FALSE;

	dir = FindFirstFile((std::string(dirname) + "\\*").c_str(), &entry);

	if (dir == INVALID_HANDLE_VALUE)
    	{ 
		error("%s: No files in '%s\\*'", SCRIPT_ENGINE, dirname);
		return SCRIPT_ENGINE_ERROR;
	}

	while(!(morefiles == FALSE && GetLastError() == ERROR_NO_MORE_FILES)) {
		// if we are looking for files and this file doesn't end with .nse or
		// is a directory, then we don't look further at it
		if(files_or_dirs == FILES) {
			if(!(
						(check_extension(SCRIPT_ENGINE_EXTENSION, entry.cFileName) == MATCH) 
						&& !(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			    )) { 
				morefiles = FindNextFile(dir, &entry);
				continue;
			}

		// if we are looking for dirs and this dir
		// isn't a directory, then we don't look further at it
		} else if(files_or_dirs == DIRS) {
			if(!(
						(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			    )) {
				morefiles = FindNextFile(dir, &entry);
				continue;
			}
		
		// they have passed an invalid value for files_or_dirs 
		} else {
			fatal("%s: In: %s:%i This should never happen.", 
					SCRIPT_ENGINE, __FILE__, __LINE__);
		}

		// otherwise we add it to the results
		// we assume that dirname ends with a directory separator of some kind
		path = std::string(dirname) + "\\" + std::string(entry.cFileName);
		result.push_back(path);
		morefiles = FindNextFile(dir, &entry);
	}


	return SCRIPT_ENGINE_SUCCESS;
}

#else

int init_scandir(char* dirname, std::vector<std::string>& result, int files_or_dirs) {
	DIR* dir;
	struct dirent* entry;
	std::string path;
	struct stat stat_entry;

	dir = opendir(dirname);
	if(dir == NULL) {
		error("%s: Could not open directory '%s'.", SCRIPT_ENGINE, dirname);
		return SCRIPT_ENGINE_ERROR;
	}
	
	// note that if there is a symlink in the dir, we have to rely on
	// the .nse extension
	// if they provide a symlink to a dir which ends with .nse, things
	// break :/
	while((entry = readdir(dir)) != NULL) {
		path = std::string(dirname) + "/" + std::string(entry->d_name);
		
		if(stat(path.c_str(), &stat_entry) != 0)
			fatal("%s: In: %s:%i This should never happen.", 
					SCRIPT_ENGINE, __FILE__, __LINE__);

		// if we are looking for files and this file doesn't end with .nse and
		// isn't a file or a link, then we don't look further at it
		if(files_or_dirs == FILES) {
			if(!(
						(check_extension(SCRIPT_ENGINE_EXTENSION, entry->d_name) == MATCH) 
						&& (S_ISREG(stat_entry.st_mode) 
							|| S_ISLNK(stat_entry.st_mode))
			    )) { 
				continue;
			}

			// if we are looking for dirs and this dir
			// isn't a dir or a link, then we don't look further at it
		} else if(files_or_dirs == DIRS) {
			if(!(
						(S_ISDIR(stat_entry.st_mode) 
						 || S_ISLNK(stat_entry.st_mode))
			    )) {
				continue;
			}

			// they have passed an invalid value for files_or_dirs 
		} else {
			fatal("%s: In: %s:%i This should never happen.", 
					SCRIPT_ENGINE, __FILE__, __LINE__);
		}

		// otherwise we add it to the results
		result.push_back(path);
	}
	
	closedir(dir);

	return SCRIPT_ENGINE_SUCCESS;
}

#endif

/* Error function if a user script attempts to create a new global */
/* TODO: Why wasn't _changing_ globals handled? */
static int global_error(lua_State *L)
{
  lua_pushvalue(L, lua_upvalueindex(1));
  lua_pushvalue(L, 2);
  if (!lua_tostring(L, -1))
  {
    lua_pushliteral(L, "? (of type ");
    lua_pushstring(L, lua_typename(L, lua_type(L, -2)));
    lua_pushliteral(L, ")");
    lua_concat(L, 3);
    lua_replace(L, -2);
  }
  lua_pushvalue(L, lua_upvalueindex(2));
  lua_concat(L, 3);
  fprintf(stderr, "%s\n", lua_tostring(L, -1));
  return lua_error(L);
}

/* load an nmap-lua script
 * create a new closure to store the script
 * tell the closure where to find the standard
 * lua libs and the nmap bindings
 * we do some error checking to make sure that
 * the script is well formed
 * the script is then added to either the hostrules
 * or the portrules
 * */
int init_loadfile(lua_State* l, char* filename) {
	int rule_count;

	/* create a closure for encapsuled execution
	 * give the closure access to the global enviroment
	 */
	lua_newtable(l);

	/* tell the script about its filename */
	lua_pushstring(l, filename);
	lua_setfield(l, -2, "filename");
	
	/* we give the script access to the global name space 
	 * */
	lua_newtable(l);
    lua_pushvalue(l, LUA_GLOBALSINDEX);
	lua_setfield(l, -2, "__index");
	lua_setmetatable(l, -2);

	/* load the *.nse file, set the closure and execute (init) the test 
	 * */
	SCRIPT_ENGINE_LUA_TRY(luaL_loadfile(l, filename));
	lua_pushvalue(l, -2);
	lua_setfenv(l, -2);
	SCRIPT_ENGINE_LUA_TRY(lua_pcall(l, 0, 0, 0));

	/* look at the runlevel, if it is not set, we set it to 1.0 
	 * */
	lua_getfield(l, -1, RUNLEVEL);
	if(lua_isnil(l, -1)) {
		lua_pushnumber(l, 1.0);
		lua_setfield(l, -3, RUNLEVEL);
	}
	lua_pop(l, 1);

	/* finally we make sure nobody tampers with the global name space any more
	 * and prepare for runlevel sorting
	 * */
	lua_getmetatable(l, -1);

    lua_pushliteral(l, "Attempted to change the global '");
    lua_pushliteral(l, "' in ");
    lua_pushstring(l, filename);
    lua_pushliteral(l, " - use nmap.registry if you really want to share "
                       "data between scripts.");
    lua_concat(l, 3);
    lua_pushcclosure(l, global_error, 2);
	lua_setfield(l, -2, "__newindex");

	lua_setmetatable(l, -2);

	/* store the initialized test in either
	 * the hosttests or the porttests
	 * */
	lua_getfield(l, -1, PORTRULE);
	lua_getfield(l, -2, HOSTRULE);

	/* if we are looking at a portrule then store it in the porttestsets table
	 * if it is a hostrule, then it goes into the hosttestsets table
	 * otherwise we fail
	 * if there is no action in the script we also fail
	 * */
	if(lua_isnil(l, -2) == 0) {
		lua_pop(l, 2);				
		lua_getglobal(l, PORTTESTS);
		rule_count = lua_objlen(l, -1);
		lua_pushvalue(l, -2);
		lua_rawseti(l, -2, (rule_count + 1));
		lua_pop(l, 1); // pop the porttests table
	} else if(lua_isnil(l, -1) == 0) {
		lua_pop(l, 2);				
		lua_getglobal(l, HOSTTESTS);
		rule_count = lua_objlen(l, -1);
		lua_pushvalue(l, -2);
		lua_rawseti(l, -2, (rule_count + 1));
		lua_pop(l, 1); // pop the hosttests table
	} else {
		error("%s: No rules in script '%s'.", SCRIPT_ENGINE, filename);
		return SCRIPT_ENGINE_ERROR;	
	}

	std::vector<std::string> required_fields;
	required_fields.push_back(std::string(ACTION));
	required_fields.push_back(std::string(DESCRIPTION));

	std::vector<std::string>::iterator iter;
	for(iter = required_fields.begin(); iter != required_fields.end(); iter++) {
		lua_getfield(l, -1, (*iter).c_str());
		if(lua_isnil(l, -1) == 1) {
			error("%s: No '%s' field in script '%s'.", SCRIPT_ENGINE, (*iter).c_str(), filename);
			return SCRIPT_ENGINE_ERROR;	
		}
		lua_pop(l, 1); // pop the action
	}


	lua_pop(l, 1); // pop the closure

	return SCRIPT_ENGINE_SUCCESS;
}

