local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Creates a reverse index at the end of scan output showing which hosts run a particular service.  This is in addition to Nmap's normal output listing the services on each host.
]]

---
-- @usage
-- nmap --script reverse-index <hosts/networks>
--
-- @output
-- Post-scan script results:
-- | reverse-index: 
-- |   22/tcp: 192.168.0.60
-- |   23/tcp: 192.168.0.100
-- |   80/tcp: 192.168.0.70
-- |   445/tcp: 192.168.0.1
-- |   53/udp: 192.168.0.105, 192.168.0.70, 192.168.0.60, 192.168.0.1
-- |_  5353/udp: 192.168.0.105, 192.168.0.70, 192.168.0.60, 192.168.0.1
--
-- @args reverse-index.mode the output display mode, can be either horizontal
--       or vertical (default: horizontal)
-- 

-- Version 0.1
-- Created 11/22/2011 - v0.1 - created by Patrik Karlsson
author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "safe" }

-- the postrule displays the reverse-index once all hosts are scanned
postrule = function() return true end

-- the hostrule iterates over open ports for the host and pushes them into the registry
hostrule = function() return true end

hostaction = function(host)
	nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
	for _, s in ipairs({"open", "open|filtered"}) do
		for _, p in ipairs({"tcp","udp"}) do
			local host, port = host, nil
			local db = nmap.registry[SCRIPT_NAME]
			while( true ) do
				port = nmap.get_ports(host, port, p, s)
				if ( not(port) ) then break	end
				db[p] = db[p] or {}
				db[p][port.number] = db[p][port.number] or {}
				table.insert(db[p][port.number], { ip = host.ip, port = port, proto = p, state = s } )
			end
		end
	end
end

--
-- Shows an index similar to the following one
-- Post-scan script results:
-- | reverse-index: 
-- |   tcp/22
-- |     192.168.0.60
-- |   tcp/23
-- |     192.168.0.100
-- |   tcp/80
-- |     192.168.0.70
-- |   tcp/445
-- |     192.168.0.1
-- |   udp/5353
-- |     192.168.0.105
-- |     192.168.0.1
-- |     192.168.0.60
-- |_    192.168.0.70
local function createVerticalResults(db)
	local results = {}
	for proto, ports in pairs(db) do
		for port, entries in pairs(ports) do
			local result_entries = {}
			for _, entry in ipairs(entries) do
				table.insert(result_entries, entry.ip)
			end
			table.sort(result_entries)
			result_entries.name = ("%d/%s"):format(port, proto)
			table.insert(results, result_entries)
			table.sort(results, 
				function(a,b)
			 		local a_port, a_proto = a.name:match("^(%d+)/(%w*)")
					local b_port, b_proto = b.name:match("^(%d+)/(%w*)")
					if ( a_proto == b_proto ) then
						return ( tonumber(a_port) ) < ( tonumber(b_port) )
					else
						return a_proto < b_proto
					end
				end 
			)
		end
	end
	return results
end

--
-- Shows an index similar to the following one
-- | reverse-index: 
-- |   tcp/22: 192.168.0.60
-- |   tcp/23: 192.168.0.100
-- |   tcp/80: 192.168.0.70
-- |   tcp/445: 192.168.0.1
-- |   udp/53: 192.168.0.105, 192.168.0.70, 192.168.0.60, 192.168.0.1
-- |_  udp/5353: 192.168.0.105, 192.168.0.70, 192.168.0.60, 192.168.0.1
local function createHorizontalResults(db)
	local results = {}
	
	for proto, ports in pairs(db) do
		for port, entries in pairs(ports) do
			local result_entries = {}
			for _, entry in ipairs(entries) do
				table.insert(result_entries, entry.ip)
			end
			local ips = stdnse.strjoin(", ", result_entries)
			local str = ("%d/%s: %s"):format(port, proto, ips)
			table.insert(results, str)
			table.sort(results, 
				function(a,b)
			 		local a_port, a_proto = a:match("^(%d+)/(%w*):")
					local b_port, b_proto = b:match("^(%d+)/(%w*):")
					if ( a_proto == b_proto ) then
						return ( tonumber(a_port) ) < ( tonumber(b_port) )
					else
						return a_proto < b_proto
					end
				end 
			)
		end
	end
	return results	
end

postaction = function()
	local db = nmap.registry[SCRIPT_NAME]
	if ( db == nil ) then
		return false
	end
  
	local results
	local mode = stdnse.get_script_args("reverse-index.mode") or "horizontal"
	
	if ( mode == 'horizontal' ) then
		results = createHorizontalResults(db)
	else
		results = createVerticalResults(db)
	end
	return stdnse.format_output(true, results)
end

local Actions = {
  hostrule = hostaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
