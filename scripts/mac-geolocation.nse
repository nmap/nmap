description = [[
Looks up geolocation information for BSSID (MAC) addresses of WiFi access points
in the Google geolocation database. Geolocation information in this databasea 
usually includes coordinates, country, state, city, 
street address, etc. The MAC addresses can be supplied as an argument 
<code>mac-geolocation.macs</code>, or in the registry under
<code>nmap.registry.[host.ip][mac-geolocation]</code>.
]]

---
-- @usage
-- nmap --script mac-geolocation <target> --script-args 'mac-geolocation.macs="00:24:B2:1E:24:FE,00:23:69:2A:B1:27"'
--
-- @arg mac-geolocation.macs a list of MAC addresses separated by "," for which to do a geolocation lookup 
-- @arg mac-geolocation.extra_info include additional information in the output such as lookup accuracy, street address etc.
--
-- @output Location info arranged by MAC and geolocation database
-- | mac-geolocation: 
-- |   00:24:B2:1E:24:FE (Netgear)
-- |     Google:
-- |       coordinates (lat,lon): 44.9507415,-93.100682
-- |       city: St Paul, Minnesota, United States
-- |_  Additional geolocation info may be available through --script-args mac-geolocation.extra_info
--


-- Important notice:
--
--   Google Geolocation lookup related information:
--   When given a wrong MAC address, or a nonexistant MAC the Google API for 
-- geolocation of MAC addresses makes an IP geolocation of the host which is 
-- making the geolookup request (which is us). This IP based geolookup generates
-- a response which has an accuracy field containing a high value (meaning low 
-- accuracy). So, in order to separate the MAC-based responses from the IP-based
-- ones, we do a lookup of a non-valid MAC address "00", and compare all the 
-- results with that one: if the results match, and the accuracy is larger than 
-- 2000 (meters) then it's probably safe to say that the geolookup was made 
-- based on our IP address.
-- Google Geolocation API Protocol:
-- http://code.google.com/apis/gears/geolocation_network_protocol.html
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}
dependencies = {"snmp-interfaces"}

require "nmap"
require "stdnse"
require "http"
require "json"
require "nsedebug"

prerule = function()
	local macs = stdnse.get_script_args(SCRIPT_NAME .. ".macs")
	if macs and macs ~= "" then
		return true
	else
		stdnse.print_debug(3,
			"Skipping '%s' %s, 'mac-geolocation.macs' argument is missing.",
			SCRIPT_NAME, SCRIPT_TYPE)
		return false
	end
end

hostrule = function(host)
	if host.mac_addr or (nmap.registry[host.ip] and 
			nmap.registry[host.ip]["mac-geolocation"]) then
		return true 
	else
		return false
	end
end

--- Pipes a HTTP POST request for one MAC addres to google geo database
-- 
-- @param mac_addr The MAC address for which to retrieve the location
-- @param pipe_q The current pipeline queue
-- @returns a table containing the location lookup information
local geo_google_pipe = function(mac_addr,pipe_q)
	local postdata = [[{"version":"1.1.0","request_address":true,"wifi_towers":[{"mac_address":"]]..mac_addr..[["}]}]]
	local options = {header={['Content-Type']='application/json'}, content = postdata}
	pipe_q = http.pipeline_add("/loc/json", options, pipe_q, 'POST')
	return pipe_q
end

--- Parses the combined Google geolocation lookup response for a list of MAC addresses
-- 
-- @param mac_list a list of MAC addresses which match the response param
-- @param response matching response to the geo lookup of mac_list
-- @param mac_geo_table output table in which the parsed response is inserted
local geo_google_parse = function(mac_list,response,mac_geo_table)
-- remove the null entries,
	local mac_null
	local loc_null
	local loc_null_json = nil
	
	if nmap.registry["mac-geolocation"].null_location then
		loc_null = nmap.registry["mac-geolocation"].null_location
	else
		mac_null = table.remove(mac_list,1)
		loc_null = table.remove(response,1)
		nmap.registry["mac-geolocation"].null_location = loc_null
	end
	
-- Just in case google doesn't return our default location we insert a nil value
-- for the comparison in the loop to fail (and the whole statement to succeed)
	if (not loc_null) or (not loc_null["status-line"]) or 
		(not loc_null["status-line"]:match("HTTP/1.1 200 OK")) then
		loc_null_json = {}
		loc_null_json.location = nil
		loc_null_json.location.accuracy = 0
	else
		local stat
		stat, loc_null_json = json.parse(loc_null.body)
		if not stat then
			loc_null_json = {}
			loc_null_json.location = nil
			loc_null_json.location.accuracy = 0
		end
	end
	
	for i,mac in ipairs(mac_list) do
		if not mac_geo_table[mac] then 
			mac_geo_table[mac]={}
		end
		if response[i] and 
			response[i]["status-line"]:match("HTTP/1.1 200 OK") and
			response[i].header["content-type"]:match("application/json") 
		then
			local status, json_loc = json.parse(response[i].body)
-- Since Google returns the IP location of the origin of the request (which is us)
-- we compare it with the
			if status and json_loc.location 
			and not ( json_loc.location.longitude == loc_null_json.location.longitude
					and json_loc.location.latitude == loc_null_json.location.latitude
					and json_loc.location.accuracy > 2000) 
			then
				mac_geo_table[mac].google=json_loc["location"]
			else
-- 				mac_geo_table[mac].google = {}
			end
		else
			mac_geo_table[mac].google = {"Could not connect to API"}
		end
	end
end

--- Looks up a list of MAC addresses in the Google Geolocation database
--
-- @param mac_list a list of MAC addresses
-- @param mac_geo_table output table with the geo lookup results inserted
local geo_google = function(mac_list,mac_geo_table)
-- adding an invalid MAC address in front so we can detect locations 
-- generated by our IP address, it is removed in geo_google_parse()
	if not nmap.registry["mac-geolocation"].null_location then
		table.insert(mac_list,1,"00")
	end
	
	local pipe_q = nil
	for _,mac in ipairs(mac_list) do
		pipe_q = geo_google_pipe(mac, pipe_q)
	end
	local response = http.pipeline_go('www.google.com',443,pipe_q)
	geo_google_parse(mac_list,response,mac_geo_table)
end

local fill_output = function(src, dst, xtra)
	if src.latitude and src.longitude then
		table.insert(dst, "coordinates (lat,lon): "..src.latitude..","..src.longitude)
		
		local city = "city: "
		if src.address then
			if src.address.city then
				city = city..src.address.city
				if src.address.region then
					city = city..", "..src.address.region
				end
				if src.address.country then
					city = city..", "..src.address.country
				end
			end
			table.insert(dst,city)
			
			if xtra then
				local addr = "address: "
				if src.address.street then
					addr = addr..src.address.street
				end
				if src.address.street_number then
					addr = addr..", "..src.address.street_number
				end
				if src.address.postal_code then
					addr = addr..", "..src.address.postal_code
				end
				if src.address.county then
					addr = addr..", "..src.address.county
				end
				table.insert(dst,addr)
				
				if src.accuracy then
					table.insert(dst,"accuracy: "..src.accuracy)
				end
			end
		end
		
		return true
	end
	return false
end

action = function(host,port)
	local mac_list = {}
	local catch = function() return end
	local try = nmap.new_try(catch)
	
	if not nmap.registry["mac-geolocation"] then 
		nmap.registry["mac-geolocation"] = {}
	end
	
	if (SCRIPT_TYPE == "prerule") then
		local macs = stdnse.get_script_args(SCRIPT_NAME .. ".macs")
		mac_list = stdnse.strsplit(",",macs:upper())
	else
		if (nmap.registry[host.ip] and nmap.registry[host.ip]["mac-geolocation"]) then
			for _,mac in ipairs(nmap.registry[host.ip]["mac-geolocation"]) do
				table.insert(mac_list,mac:upper())
			end
			-- del the table once we're done with it, so it doesn't bloat the registry
			nmap.registry[host.ip]["mac-geolocation"] = nil
		end
		if host.mac_addr then
			local m = host.mac_addr
			table.insert(mac_list, (string.format( "%02x:%02x:%02x:%02x:%02x:%02x", 
					m:byte(1), m:byte(2), m:byte(3), m:byte(4), m:byte(5), m:byte(6))):upper())
		end
	end
	
	if mac_list and #mac_list>0 then		
		local extra_info = stdnse.get_script_args(SCRIPT_NAME .. ".extra_info")
		
		local mac_geo_table = {}
		
		-- Google Geolocation Database
			geo_google(mac_list,mac_geo_table)
		
		local output = {} -- table in which we insert output
		local entry_flag = false -- indicates if we should print anything (existence of atleast one entry
		
		-- lookup manufacturer table based on MAC prefix
		local mac_prefixes={}
		if nmap.registry.snmp_interfaces and nmap.registry.snmp_interfaces.mac_prefixes then
			mac_prefixes = nmap.registry.snmp_interfaces.mac_prefixes
		elseif nmap.registry["mac-geolocation"].mac_prefixes then
			mac_prefixes = nmap.registry["mac-geolocation"].mac_prefixes
		else
			nmap.registry["mac-geolocation"].mac_prefixes = try(datafiles.parse_mac_prefixes())
			mac_prefixes = nmap.registry["mac-geolocation"].mac_prefixes
		end
		
		for mac in pairs(mac_geo_table) do
			
			local tmp = {}
			local manuf = "Unknown"
			if mac_prefixes then
				local prefix = (mac:match("^(%x+:%x+:%x+).*")):gsub(":",""):upper()
				if mac_prefixes[prefix] then
					manuf = mac_prefixes[prefix]
				end
			end
			
			tmp.name = mac.." ("..manuf..")"
			
			-- only fill output if there are entries in mac_geo_table
			if mac_geo_table[mac].google then
				table.insert(tmp, {name="Google:"})
				if fill_output(mac_geo_table[mac].google, tmp[1], extra_info) then 
					entry_flag = true 
				end
			end
			
			table.insert(output,tmp)
		end
		
		if not extra_info then
			table.insert(output,"Additional geolocation info may be available through --script-args mac-geolocation.extra_info")
		end
		
		if entry_flag then
			return(stdnse.format_output(true,output))
		else 
			return
		end
	end
end
