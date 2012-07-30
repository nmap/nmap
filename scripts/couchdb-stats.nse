local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Gets database statistics from a CouchDB database.

For more info about the CouchDB HTTP API and the statistics, see 
http://wiki.apache.org/couchdb/Runtime_Statistics
and
http://wiki.apache.org/couchdb/HTTP_database_API.
]]

---
-- @usage
-- nmap -p 5984 --script "couchdb-stats.nse" <host>
-- @output
-- PORT     STATE SERVICE REASON
-- 5984/tcp open  httpd   syn-ack
-- | couchdb-stats:  
-- |   httpd_request_methods
-- |     GET (number of HTTP GET requests)
-- |       current = 5
-- |       count = 1617
-- |   couchdb
-- |     request_time (length of a request inside CouchDB without MochiWeb)
-- |       current = 1
-- |       count = 5
-- |   httpd_status_codes
-- |     200 (number of HTTP 200 OK responses)
-- |       current = 5
-- |       count = 1617
-- |   httpd
-- |     requests (number of HTTP requests)
-- |       current = 5
-- |       count = 1617
-- |_  Authentication : NOT enabled ('admin party')

-- version 0.3
--
-- Created 01/20/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Modified 07/02/2010 - v0.2 - added test if auth is enabled, compacted output a bit (mhs)

author = "Martin Holst Swende"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = shortport.port_or_service({5984})
-- Some lazy shortcuts
local function dbg(str,...)
	stdnse.print_debug("couchdb-stats:"..str, ...)
end


local DISCARD = {stddev=1,min=1,max=1, mean=1}
--- Removes uninteresting data from the table
-- uses the DISCARD table above to see what
-- keys should be omitted from the results
-- @param data a table containg data
--@return another table containing data, with some keys removed
local function queryResultToTable(data)
	local result = {}
	for k,v in pairs(data) do
		dbg("(%s,%s)",k,tostring(v))
		if DISCARD[k] ~= 1 then
			if type(v) == 'table' then
				if v["description"] ~= nil then
					k = string.format("%s (%s)",tostring(k), tostring(v["description"]))
					v["description"] = nil
				end
				table.insert(result,k)
				table.insert(result,queryResultToTable(v))
			else
				table.insert(result,(("%s = %s"):format(tostring(k), tostring(v))))
			end
		end
	end
	return result
end


action = function(host, port)
	local data, result, err
	
	data = http.get( host, port, '/_stats' )
	
	-- check that body was received
	if not data.body or data.body == "" then
		local msg = ("%s did not respond with any data."):format(host.targetname or host.ip )
		dbg( msg ) 
		return  msg
	end
	
	-- The html body should look like this : 
	--
	--{"httpd_status_codes":{"200":{"current":10,"count":29894,"mean":0.0003345152873486337,"min":0,"max":1,"stddev":0.01828669972606202,"description":"number of HTTP 200 OK responses"},"500":{"current":1,"count":28429,"mean":0.00003517534911534013,"min":0,"max":1,"stddev":0.005930776661631644,"description":"number of HTTP 500 Internal Server Error responses"}},"httpd_request_methods":{"GET":{"current":12,"count":29894,"mean":0.00040141834481835866,"min":0,"max":2,"stddev":0.02163701147572207,"description":"number of HTTP GET requests"}},"httpd":{"requests":{"current":12,"count":29894,"mean":0.00040141834481835866,"min":0,"max":2,"stddev":0.02163701147572207,"description":"number of HTTP requests"}},"couchdb":{"request_time":{"current":23,"count":12,"mean":32.58333333333333,"min":1,"max":287,"stddev":77.76723638882608,"description":"length of a request inside CouchDB without MochiWeb"}}}

	local status, result = json.parse(data.body)
	if not status then
		dbg(result)
		return result
	end
	
	-- Here we know it is a couchdb
	port.version.name ='httpd'
	port.version.product='Apache CouchDB'
	nmap.set_port_version(host,port)
	
	-- We have a valid table in result containing the parsed json
	-- now, get all the interesting bits		
	
	result = queryResultToTable(result)
	
	-- Additionally, we can check if authentication is used :
	-- The following actions are restricted if auth is used 
-- 	create db (PUT /database)
-- 	delete db (DELETE /database)
-- 	Creating a design document (PUT /database/_design/app)
-- 	Updating a design document (PUT /database/_design/app?rev=1-4E2)
-- 	Deleting a design document (DELETE /database/_design/app?rev=1-6A7)
-- 	Triggering compaction (POST /_compact)
-- 	Reading the task status list (GET /_active_tasks)
-- 	Restart the server (POST /_restart)
-- 	Read the active configuration (GET /_config)
-- 	Update the active configuration (PUT /_config)
	
	data = http.get( host, port, '/_config' ) 
	local status, authresult = json.parse(data.body)

	-- If authorization is used, we should get back something like
	-- {"error":"unauthorized","reason":"You are not a server admin."}
	-- Otherwise, a *lot* of data,  : 
-- 	{"httpd_design_handlers":{"_info":"{couch_httpd_db,   handle_design_info_req}",
-- 	"_list":"{couch_httpd_show, handle_view_list_req}","_show":"{couch_httpd_show, handle_doc_show_req}",
-- 	"_update":"{couch_httpd_show, handle_doc_update_req}","_view":"{couch_httpd_view, handle_view_req}"},
-- 	"httpd_global_handlers":{"/":"{couch_httpd_misc_handlers, handle_welcome_req, <<\"Welcome\">>}",
-- 	"_active_tasks":"{couch_httpd_misc_handlers, handle_task_status_req}",
-- 	"_all_dbs":"{couch_httpd_misc_handlers, handle_all_dbs_req}",
-- 	"_config":"{couch_httpd_misc_handlers, handle_config_req}",
-- 	"_log":"{couch_httpd_misc_handlers, handle_log_req}","_oauth":"{couch_httpd_oauth, handle_oauth_req}",
-- 	"_replicate":"{couch_httpd_misc_handlers, handle_replicate_req}","_restart":"{couch_httpd_misc_handlers, handle_restart_req}",
-- 	"_session":"{couch_httpd_auth, handle_session_req}","_sleep":"{couch_httpd_misc_handlers, handle_sleep_req}",
-- 	"_stats":"{couch_httpd_stats_handlers, handle_stats_req}","_user":"{couch_httpd_auth, handle_user_req}",
-- 	"_utils":"{couch_httpd_misc_handlers, handle_utils_dir_req, \"/usr/share/couchdb/www\"}",
-- 	"_uuids":"{couch_httpd_misc_handlers, handle_uuids_req}","favicon.ico":"{couch_httpd_misc_handlers, handle_favicon_req, \"/usr/share/couchdb/www\"}"},
-- 	"query_server_config":{"reduce_limit":"true"},"log":{"file":"/var/log/couchdb/0.10.0/couch.log","level":"info"},
-- 	"query_servers":{"javascript":"/usr/bin/couchjs /usr/share/couchdb/server/main.js"},
-- 	"daemons":{"batch_save":"{couch_batch_save_sup, start_link, []}","db_update_notifier":"{couch_db_update_notifier_sup, start_link, []}",
-- 	"external_manager":"{couch_external_manager, start_link, []}","httpd":"{couch_httpd, start_link, []}",
-- 	"query_servers":"{couch_query_servers, start_link, []}","stats_aggregator":"{couch_stats_aggregator, start, []}",
-- 	"stats_collector":"{couch_stats_collector, start, []}","view_manager":"{couch_view, start_link, []}"},
-- 	"httpd":{"WWW-Authenticate":"Basic realm=\"administrator\"","authentication_handlers":"{couch_httpd_oauth, oauth_authentication_handler}, {couch_httpd_auth, default_authentication_handler}",
-- 	"bind_address":"127.0.0.1","default_handler":"{couch_httpd_db, handle_request}","port":"5984"},"httpd_db_handlers":{"_changes":"{couch_httpd_db, handle_changes_req}",
-- 	"_compact":"{couch_httpd_db, handle_compact_req}","_design":"{couch_httpd_db, handle_design_req}","_temp_view":"{couch_httpd_view, handle_temp_view_req}",
-- 	"_view":"{couch_httpd_view, handle_db_view_req}","_view_cleanup":"{couch_httpd_db, handle_view_cleanup_req}"},
-- 	"couch_httpd_auth":{"authentication_db":"users","require_valid_user":"false","secret":"replace this with a real secret in your local.ini file"},
-- 	"couchdb":{"batch_save_interval":"1000","batch_save_size":"1000","database_dir":"/var/lib/couchdb/0.10.0","delayed_commits":"true",
-- 	"max_attachment_chunk_size":"4294967296","max_dbs_open":"100","max_document_size":"4294967296",
-- 	"os_process_timeout":"5000","util_driver_dir":"/usr/lib/couchdb/erlang/lib/couch-0.10.0/priv/lib","view_index_dir":"/var/lib/couchdb/0.10.0"}}
	local auth = "Authentication : %s"
	local authEnabled = "unknown"

	if(status) then 
		if(authresult["error"] == "unauthorized") then authEnabled = "enabled"
		elseif (authresult["httpd_design_handlers"] ~= nil) then authEnabled = "NOT enabled ('admin party')" 
		end
	end
	table.insert(result, auth:format(authEnabled))
	return stdnse.format_output(true, result )
end
