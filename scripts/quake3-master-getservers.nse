local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"

description = [[
Queries Quake3-style master servers for game servers (many games other than Quake 3 use this same protocol).
]]

---
-- @output
-- PORT      STATE SERVICE REASON
-- 27950/udp open  quake3-master
-- | quake3-master-getservers: 
-- |     192.0.2.22:26002 Xonotic (Xonotic 3)
-- |     203.0.113.37:26000 Nexuiz (Nexuiz 3)
-- |_    Only 2 shown. Use --script-args quake3-master-getservers.outputlimit=-1 to see all.
--
-- @args quake3-master-getservers.outputlimit If set, limits the amount of
--       hosts returned by the script. All discovered hosts are still
--       stored in the registry for other scripts to use. If set to 0 or
--       less, all files are shown. The default value is 10.

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service ({20110, 20510, 27950, 30710}, "quake3-master", {"udp"})
postrule = function()
	return (nmap.registry.q3m_servers ~= nil)
end

-- There are various sources for this information. These include:
-- - http://svn.icculus.org/twilight/trunk/dpmaster/readme.txt?view=markup
-- - http://openarena.wikia.com/wiki/Changes
-- - http://dpmaster.deathmask.net/
-- - qstat-2.11, qstat.cfg
-- - scanning master servers
-- - looking at game traffic with Wireshark
local KNOWN_PROTOCOLS = {
	["5"] = "Call of Duty",
	["10"] = "unknown",
	["43"] = "unknown",
	["48"] = "unknown",
	["50"] = "Return to Castle Wolfenstein",
	["57"] = "unknown",
	["59"] = "Return to Castle Wolfenstein",
	["60"] = "Return to Castle Wolfenstein",
	["66"] = "Quake III Arena",
	["67"] = "Quake III Arena",
	["68"] = "Quake III Arena, or Urban Terror",
	["69"] = "OpenArena, or Tremulous",
	["70"] = "unknown",
	["71"] = "OpenArena",
	["72"] = "Wolfenstein: Enemy Territory",
	["80"] = "Wolfenstein: Enemy Territory",
	["83"] = "Wolfenstein: Enemy Territory",
	["84"] = "Wolfenstein: Enemy Territory",
	["2003"] = "Soldier of Fortune II: Double Helix",
	["2004"] = "Soldier of Fortune II: Double Helix",
	["DarkPlaces-Quake 3"] = "DarkPlaces Quake",
	["Nexuiz 3"] = "Nexuiz",
	["Transfusion 3"] = "Transfusion",
	["Warsow 8"] = "Warsow",
	["Xonotic 3"] = "Xonotic",
}

local function getservers(host, port, q3protocol)
        local socket = nmap.new_socket()
	socket:set_timeout(10000)
        local status, err = socket:connect(host.ip, port.number, "udp")
	if not status then
		return {}
	end
	local probe = bin.pack("CCCCA", 0xff, 0xff, 0xff, 0xff, string.format("getservers %s empty full\n", q3protocol))
        socket:send(probe)

  local data
	status, data = socket:receive() -- get some data
	if not status then
		return {}
	end
	nmap.set_port_state(host, port, "open")

	local magic = bin.pack("CCCCA", 0xff, 0xff, 0xff, 0xff, "getserversResponse")
	local tmp
	while #data < #magic do -- get header
		status, tmp = socket:receive()
		if status then
			data = data .. tmp
		end
	end
	if string.sub(data, 1, #magic) ~= magic then -- no match
		return {}
	end

	port.version.name = "quake3-master"
        nmap.set_port_version(host, port)

	local EOT = bin.pack("ACCC", "EOT", 0, 0, 0)
	local pieces = stdnse.strsplit("\\", data)
	while pieces[#pieces] ~= EOT do -- get all data
		status, tmp = socket:receive()
		if status then
			data = data .. tmp
			pieces = stdnse.strsplit("\\", data)
		end
	end

	table.remove(pieces, 1)       --remove magic
	table.remove(pieces, #pieces) --remove EOT

	local servers = {}
	for _, value in ipairs(pieces) do
		local parts = {bin.unpack("CCCC>S", value)}
		if #parts > 5 then
			local o1 = parts[2]
			local o2 = parts[3]
			local o3 = parts[4]
			local o4 = parts[5]
			local p = parts[6]
			table.insert(servers, {string.format("%d.%d.%d.%d", o1, o2, o3, o4), p})
		end
	end
	socket:close()
	return servers
end

local function formatresult(servers, outputlimit, protocols)
	local t = tab.new()

	if not outputlimit then
		outputlimit = #servers
	end
	for i = 1, outputlimit do
		if not servers[i] then
			break
		end
		local node = servers[i]
		local protocol = node.protocol
		local ip = node.ip
		local portnum = node.port
		tab.addrow(t, string.format('%s:%d', ip, portnum), string.format('%s (%s)', protocols[protocol], protocol))
	end

	return tab.dump(t)
end

local function dropdupes(tables, stringify)
	local unique = {}
	local dupe = {}
	local s
	for _, v in ipairs(tables) do
		s = stringify(v)
		if not dupe[s] then
			table.insert(unique, v)
			dupe[s] = true
		end
	end
	return unique
end

local function scan(host, port, protocols)
	local discovered = {}
	for protocol, _ in pairs(protocols) do
		for _, node in ipairs(getservers(host, port, protocol)) do
			local entry = {
				protocol = protocol,
				ip = node[1],
				port = node[2],
				masterip = host.ip,
				masterport = port.number
			}
			table.insert(discovered, entry)
		end
	end
	return discovered
end

local function store(servers)
	if not nmap.registry.q3m_servers then
		nmap.registry.q3m_servers = {}
	end
	for _, server in ipairs(servers) do
		table.insert(nmap.registry.q3m_servers, server)
	end
end

local function protocols()
	local filter = {}
	local count = {}
	for _, advert in ipairs(nmap.registry.q3m_servers) do
		local key = stdnse.strjoin(":", {advert.ip, advert.port, advert.protocol})
		if filter[key] == nil then
			if count[advert.protocol] == nil then
				count[advert.protocol] = 0
			end
			count[advert.protocol] = count[advert.protocol] + 1
			filter[key] = true
		end
		local mkey = stdnse.strjoin(":", {advert.masterip, advert.masterport})
	end
	local sortable = {}
	for k, v in pairs(count) do
		table.insert(sortable, {k, v})
	end
	table.sort(sortable, function(a, b) return a[2] > b[2] or (a[2] == b[2] and a[1] > b[1]) end)
	local t = tab.new()
	tab.addrow(t, '#', 'PROTOCOL', 'GAME', 'SERVERS')
	for i, p in ipairs(sortable) do
		local pos = i .. '.'
		local protocol = p[1]
		count = p[2]
		local game = KNOWN_PROTOCOLS[protocol]
		if game == "unknown" then
			game = ""
		end
		tab.addrow(t, pos, protocol, game, count)
	end
	return '\n' .. tab.dump(t)
end

action = function(host, port)
	if SCRIPT_TYPE == "postrule" then
		return protocols()
	end
	local outputlimit = nmap.registry.args[SCRIPT_NAME .. ".outputlimit"]
	if not outputlimit then
		outputlimit = 10
	else
                outputlimit = tonumber(outputlimit)
	end
	if outputlimit < 1 then
		outputlimit = nil
	end
	local servers = scan(host, port, KNOWN_PROTOCOLS)
	store(servers)
	local unique = dropdupes(servers, function(t) return string.format("%s: %s:%d", t.protocol, t.ip, t.port) end)
	local formatted = formatresult(unique, outputlimit, KNOWN_PROTOCOLS)
	if #formatted < 1 then
		return
	end
	local response = {}
	table.insert(response, formatted)
	if outputlimit and outputlimit < #servers then
		table.insert(response, string.format('Only %d/%d shown. Use --script-args %s.outputlimit=-1 to see all.', outputlimit, #servers, SCRIPT_NAME))
	end
	return stdnse.format_output(true, response)
end

