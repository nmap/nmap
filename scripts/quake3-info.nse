local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Extracts information from a Quake3 game server and other games which use the same protocol.
]]

---
-- @usage
-- nmap -sU -sV -Pn --script quake3-info.nse -p <port> <target>
--
-- @output
-- PORT      STATE         SERVICE VERSION
-- 27960/udp open          quake3  Quake 3 dedicated server
-- | quake3-info:  
-- | PLAYERS:
-- |     1. cyberix (frags: 0/20, ping: 4)
-- | BASIC OPTIONS:
-- |     capturelimit: 8
-- |     dmflags: 0
-- |     elimflags: 0
-- |     fraglimit: 20
-- |     gamename: baseoa
-- |     mapname: oa_dm1
-- |     protocol: 71
-- |     timelimit: 0
-- |     version: ioq3 1.36+svn1933-1/Ubuntu linux-x86_64 Apr  4 2011
-- |     videoflags: 7
-- |     voteflags: 767
-- | OTHER OPTIONS:
-- |     bot_minplayers: 0
-- |     elimination_roundtime: 120
-- |     g_allowVote: 1
-- |     g_altExcellent: 0
-- |     g_delagHitscan: 0
-- |     g_doWarmup: 0
-- |     g_enableBreath: 0
-- |     g_enableDust: 0
-- |     g_gametype: 0
-- |     g_instantgib: 0
-- |     g_lms_mode: 0
-- |     g_maxGameClients: 0
-- |     g_needpass: 0
-- |     g_obeliskRespawnDelay: 10
-- |     g_rockets: 0
-- |     g_voteGametypes: /0/1/3/4/5/6/7/8/9/10/11/12/
-- |     g_voteMaxFraglimit: 0
-- |     g_voteMaxTimelimit: 0
-- |     g_voteMinFraglimit: 0
-- |     g_voteMinTimelimit: 0
-- |     sv_allowDownload: 0
-- |     sv_floodProtect: 1
-- |     sv_hostname: noname
-- |     sv_maxPing: 0
-- |     sv_maxRate: 0
-- |     sv_maxclients: 8
-- |     sv_minPing: 0
-- |     sv_minRate: 0
-- |_    sv_privateClients: 0

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe", "version"}


local function range(first, last)
	local list = {}
	for i = first, last do
		table.insert(list, i)
	end
	return list
end

portrule = shortport.port_or_service(range(27960, 27970), {'quake3'}, 'udp')

local function parsefields(data)
	local fields = {}
	local parts = stdnse.strsplit("\\", data)
	local nullprefix = table.remove(parts, 1)
	if nullprefix ~= "" then
		stdnse.print_debug(2, "unrecognized field format, skipping options")
		return {}
	end
	for i = 1, #parts, 2 do
		local key = parts[i]
		local value = parts[i + 1]
		fields[key] = value
	end
	return fields
end

local function parsename(data)
	local parts = stdnse.strsplit('"', data)
	if #parts ~= 3 then
		return nil
	end
	local e1 = parts[1]
	local name = parts[2]
	local e2 = parts[3]
	local extra = e1 .. e2
	if extra ~= "" then
		return nil
	end
	return name
end

local function parseplayer(data)
	local parts = stdnse.strsplit(" ", data)
	if #parts < 3 then
		stdnse.print_debug(2, "player info line is missing elements, skipping a player")
		return nil
	end
	if #parts > 3 then
		stdnse.print_debug(2, "player info line has unknown elements, skipping a player")
		return nil
	end
	local player = {}
	player.frags = parts[1]
	player.ping = parts[2]
	player.name = parsename(parts[3])
	if player.name == nil then
		stdnse.print_debug(2, "invalid player name serialization, skipping a player")
		return nil
	end
	return player
end

local function parseplayers(data)
	local players = {}
	for _, p in ipairs(data) do
		local player = parseplayer(p)
		if player then
			table.insert(players, player)
		end
	end
	return players
end

local function is_leader(a, b)
	local collide = a.name == b.name
	local even = a.frags == b.frags
	local leads = a.frags > b.frags
	local alphab = a.name > b.name
	local faster = a.ping > b.ping
	return leads or (even and alphab) or (even and collide and faster)
end

local function formatplayers(players, fraglimit)
	table.sort(players, is_leader)
	local printable = {}
	for i, player in ipairs(players) do
		local name = player.name
		local ping = player.ping
		local frags = player.frags
		if fraglimit then
			frags = string.format("%s/%s", frags, fraglimit)
		end
		table.insert(printable, string.format("%d. %s (frags: %s, ping: %s)", i, name, frags, ping))
	end
	printable["name"] = "PLAYERS:"
	return printable
end

local function formatfields(fields, title)
	local printable = {}
	for key, value in pairs(fields) do
		local kv = string.format("%s: %s", key, value)
		table.insert(printable, kv)
	end
	table.sort(printable)
	printable["name"] = title
	return printable
end

local function assorted(fields)
	local basic = {}
	local other = {}
	for key, value in pairs(fields) do
		if string.find(key, "_") == nil then
			basic[key] = value
		else
			other[key] = value
		end
	end
	return basic, other
end

action = function(host, port)
	local GETSTATUS = bin.pack("CCCCA", 0xff, 0xff, 0xff, 0xff, "getstatus\n")
	local STATUSRESP = bin.pack("CCCCA", 0xff, 0xff, 0xff, 0xff, "statusResponse")

	local status, data = comm.exchange(host, port, GETSTATUS, {["proto"] = "udp"})
	if not status then
		return
	end
	local parts = stdnse.strsplit("\n", data)
	local header = table.remove(parts, 1)
	if header ~= STATUSRESP then
		return
	end
	if #parts < 2 then
		stdnse.print_debug(2, "incomplete status response, script abort")
		return
	end
	local nullend = table.remove(parts)
	if nullend ~= "" then
		stdnse.print_debug(2, "missing terminating endline, script abort")
		return
	end
	local field_data = table.remove(parts, 1)
	local player_data = parts

	local fields = parsefields(field_data)
	local players = parseplayers(player_data)

	local basic, other = assorted(fields)

	-- Previously observed version strings:
	-- "tremulous 1.1.0 linux-x86_64 Aug  5 2010"
	-- "ioq3 1.36+svn1933-1/Ubuntu linux-x86_64 Apr  4 2011"
	local versionline = basic["version"]
	if versionline then
		local fields = stdnse.strsplit(" ", versionline)
		local product = fields[1]
		local version = fields[2]
		local osline = fields[3]
		port.version.name = "quake3"
		port.version.product = product
		port.version.version = version
		if string.find(osline, "linux") then
			port.version.ostype = "Linux"
		end
		if string.find(osline, "win") then
			port.version.ostype = "Windows"
		end
		nmap.set_port_version(host, port)
	end

	local fraglimit = fields["fraglimit"]
	if not fraglimit then
		fraglimit = "?"
	end

	local response = {}
	table.insert(response, formatplayers(players, fraglimit))
	table.insert(response, formatfields(basic, "BASIC OPTIONS:"))
	if nmap.verbosity() > 0 then
		table.insert(response, formatfields(other, "OTHER OPTIONS:"))
	end
	return stdnse.format_output(true, response)
end
