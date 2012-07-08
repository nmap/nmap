local _G = require "_G"
local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Retrieves information (hostname, OS, uptime, etc.) from the CouchBase
Web Administration port.  The information retrieved by this script
does not require any credentials.
]]

---
-- @usage
-- nmap -p 8091 <ip> --script membase-http-info
--
-- @output
-- PORT     STATE SERVICE
-- 8091/tcp open  unknown
-- | membase-http-info: 
-- |   Hostname           192.168.0.5:8091
-- |   OS                 x86_64-unknown-linux-gnu
-- |   Version            1.7.2r-20-g6604356
-- |   Kernel version     2.14.4
-- |   Mnesia version     4.4.19
-- |   Stdlib version     1.17.4
-- |   OS mon version     2.2.6
-- |   NS server version  1.7.2r-20-g6604356
-- |   SASL version       2.1.9.4
-- |   Status             healthy
-- |   Uptime             21465
-- |   Total memory       522022912
-- |   Free memory        41779200
-- |_  Server list        192.168.0.5:11210
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(8091, "http", "tcp")

local function fail(err) return ("\n  ERROR: %s"):format(err) end

local filter = {
	["parsed[1]['nodes'][1]['os']"] = { name = "OS" },
	["parsed[1]['nodes'][1]['version']"] = { name = "Version" },
	["parsed[1]['nodes'][1]['hostname']"] = { name = "Hostname" },
	["parsed[1]['nodes'][1]['status']"] = { name = "Status" },
	["parsed[1]['nodes'][1]['uptime']"] = { name = "Uptime" },
	["parsed[1]['nodes'][1]['memoryTotal']"] = { name = "Total memory" },
	["parsed[1]['nodes'][1]['memoryFree']"] = { name = "Free memory" },
	["parsed[1]['vBucketServerMap']['serverList']"] = { name = "Server list" },	
	["parsed['componentsVersion']['kernel']"] = { name = "Kernel version" },
	["parsed['componentsVersion']['mnesia']"] = { name = "Mnesia version" },
	["parsed['componentsVersion']['stdlib']"] = { name = "Stdlib version" },
	["parsed['componentsVersion']['os_mon']"] = { name = "OS mon version" },
	["parsed['componentsVersion']['ns_server']"] = { name = "NS server version" },
	["parsed['componentsVersion']['sasl']"] = { name = "SASL version" },
}

local order = {
	"parsed[1]['nodes'][1]['hostname']",
	"parsed[1]['nodes'][1]['os']",
	"parsed[1]['nodes'][1]['version']",
	"parsed['componentsVersion']['kernel']",
	"parsed['componentsVersion']['mnesia']",
	"parsed['componentsVersion']['stdlib']",
	"parsed['componentsVersion']['os_mon']",
	"parsed['componentsVersion']['ns_server']",
	"parsed['componentsVersion']['sasl']",
	"parsed[1]['nodes'][1]['status']",
	"parsed[1]['nodes'][1]['uptime']",
	"parsed[1]['nodes'][1]['memoryTotal']",
	"parsed[1]['nodes'][1]['memoryFree']",
	"parsed[1]['vBucketServerMap']['serverList']",
}

local function cmdReq(host, port, url, result)
	local response = http.get(host, port, url)
	
	if ( 200 ~= response.status ) or ( response.header['server'] == nil ) then
		return false
	end
	
	if ( response.header['server'] and
		 not( response.header['server']:match("^Couchbase Server") or response.header['server']:match("^Membase Server")  ) ) then
		return false
	end
	
	local status, parsed = json.parse(response.body)
	if ( not(status) ) then
		return false, "Failed to parse response from server"
	end

	result = result or {}
	for item in pairs(filter) do
		local var, val = ""
		for x in item:gmatch("(.-%])") do
			var = var .. x
			local env = setmetatable({parsed=parsed}, {__index = _G})
			local func = load("return " .. var, nil, "t", env)

			if ( not(func()) ) then
				val = nil
				break
			end
			val = func()
		end
		
		if ( val ) then
			local name = filter[item].name			
			val = ( "table" == type(val) and stdnse.strjoin(",", val) or val )
			result[item] = { name = name, value = val }
		end
	end
	return true, result
end

action = function(host, port)
  
	-- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
	local _, http_status, _ = http.identify_404(host,port)
	if ( http_status == 200 ) then
		stdnse.print_debug(1, "%s: Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", SCRIPT_NAME, host.ip, port.number)
		return false
	end

	local urls = { "/pools/default/buckets", "/pools" }
	
	local status, result
	for _, u in ipairs(urls) do
		status, result = cmdReq(host, port, u, result)
	end

	if ( not(result) or not(next(result)) ) then
	 	return
	end
	
	local output = tab.new(2)
	for _, item in ipairs(order) do
		if ( result[item] ) then
			tab.addrow(output, result[item].name, result[item].value)
		end
	end
	
	return stdnse.format_output(true, tab.dump(output))
end
