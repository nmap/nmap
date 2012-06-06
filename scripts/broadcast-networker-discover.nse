local nmap = require "nmap"
local rpc = require "rpc"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Discovers EMC Networker backup software servers on a LAN by sending a network broadcast query.
]]

---
-- @usage nmap --script broadcast-networker-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-networker-discover: 
-- |_  10.20.30.40
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

local function Callit( host, port, program, protocol )
	
	local results = {}
	local portmap, comm = rpc.Portmap:new(), rpc.Comm:new('rpcbind', 2)

	local status, result = comm:Connect(host, port)
	if (not(status)) then
		return false, result
	end

	comm.socket:set_timeout(10000)
	status, result = portmap:Callit(comm, program, protocol, 2 )
	if ( not(status) ) then
		return false, result
	end

	while ( status ) do
		local _, rhost
		status, _, _, rhost, _ = comm:GetSocketInfo()
		if (not(status)) then
	    	return false, "Failed to get socket information"
		end
		
		if ( status ) then
			table.insert(results, rhost)
		end
	
		status, result = comm:ReceivePacket()
	end
	
	comm:Disconnect()
	return true, results
end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function()

	local results = {}
	local ip = ( nmap.address_family() == "inet" ) and "255.255.255.255" or "ff02::202"
	local iface = nmap.get_interface()
	
	-- handle problematic sends on OS X requiring the interface to be
	-- supplied as part of IPv6
	if ( iface and nmap.address_family() == "inet6" ) then
		ip = ip .. "%" .. iface
	end
	
	for _, port in ipairs({7938,111}) do
		local host, port = { ip = ip }, { number = port, protocol = "udp" }
		local status
		status, results = Callit( host, port, "nsrstat", "udp" )
		
		-- warn about problematic sends on OS X requiring the interface to be
		-- supplied as part of IPv6
		if ( not(status) and results == "Portmap.Callit: Failed to send data" ) then
			return fail("Failed sending data, try supplying the correct interface using -e")
		end
		
		if ( status ) then
			break
		end
	end
	
	if ( "table" == type(results) and 0 < #results ) then
		return stdnse.format_output(true, results)
	end
end
