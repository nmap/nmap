local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Connects to Erlang Port Mapper Daemon (epmd) and retrieves a list of nodes with their respective port numbers.
]]

---
-- @usage
-- nmap -p 4369 --script epmd-info <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4369/tcp open  epmd
-- | epmd-info.nse: 
-- |   epmd running on port 4369
-- |   name rabbit at port 36804
-- |_  name ejabberd at port 46540

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service (4369, "epmd")

local NAMESREQ = 110

action = function(host, port)
	local socket = nmap.new_socket()
	local status, err = socket:connect(host.ip, port.number)
	if not status then
		return {}
	end
	local payload = bin.pack("C", NAMESREQ)
	local probe = bin.pack(">SA", #payload, payload)
	socket:send(probe)
	local status = true
	local data = ""
	local tmp = ""
	while status do
		data = data .. tmp
		status, tmp = socket:receive()
	end
	local pos, realport = bin.unpack(">I", data)
	local nodestring = string.sub(data, pos, -2)
	local nodes = stdnse.strsplit("\n", nodestring)
	local response = {}
	table.insert(response, 'epmd running on port ' .. realport)
	for _, node in ipairs(nodes) do
		table.insert(response, node)
	end
	return stdnse.format_output(true, response)
end
