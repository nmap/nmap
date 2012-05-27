local bin = require "bin"
local bit = require "bit"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers servers supporting the ATA over Ethernet protocol. ATA over Ethernet
is an ethernet protocol developed by the Brantley Coile Company and allows for
simple, high-performance access to SATA drives over Ethernet.

Discovery is performed by sending a Query Config Request to the Ethernet
broadcast address with all bits set in the major and minor fields of the
header. 
]]

---
-- @usage
-- nmap --script broadcast-ataoe-discover -e <interface>
--
-- @output
-- Pre-scan script results:
-- | broadcast-ataoe-discover: 
-- |_  Server: 08:00:27:12:34:56; Version: 1; Major: 0; Minor: 1
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

-- The minimalistic ATAoE interface
ATAoE = {
	
	-- Supported commands
	Cmd = {
		QUERY_CONFIG_INFORMATION = 1,
	},
	
	Header = {		
		-- creates a new Header instance
		new = function(self, cmd, tag)
			local o = {
				version = 1,
				flags = 0,
				major = 0xffff,
				minor = 0xff,
				error = 0,
				cmd = ATAoE.Cmd.QUERY_CONFIG_INFORMATION,
				tag = tag or createRandomTag(),					
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- parses a raw string of data and creates a new Header instance
		-- @return header new instance of header
		parse = function(data)
			local header = ATAoE.Header:new()
			local pos, verflags
			
			pos, verflags, header.error, 
				header.major, header.minor,
				header.cmd, header.tag = bin.unpack(">CCSCCI", data)		
			header.version = bit.rshift(verflags, 4)
			header.flags = bit.band(verflags, 0x0F)
			return header
		end,
		
		-- return configuration info request as string
		__tostring = function(self)
			assert(self.tag, "No tag was specified in Config Info Request")
			local verflags = bit.lshift(self.version, 4)
			return bin.pack(">CCSCCI", verflags, self.error, self.major, self.minor, self.cmd, self.tag)
		end,	
	},
	
	-- The Configuration Info Request
	ConfigInfoRequest = {
		new = function(self, tag)
			local o = { 
				header = ATAoE.Header:new(ATAoE.Cmd.QUERY_CONFIG_INFORMATION, tag)
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
			
		__tostring = function(self)
			return tostring(self.header)		
		end,
	}
}

-- Creates a random AoE header tag
function createRandomTag()
	local str = ""
	for i=1, 4 do str = str .. string.char(math.random(255)) end
	return select(2, bin.unpack(">I", str))
end

-- Send a Config Info Request to the ethernet broadcast address
-- @param iface table as returned by nmap.get_interface_info()
local function sendConfigInfoRequest(iface)
	local ETHER_BROADCAST, P_ATAOE = "ff:ff:ff:ff:ff:ff", 0x88a2
	local req = ATAoE.ConfigInfoRequest:new()
	local tag = req.tag

	local p = packet.Frame:new()
	p.mac_src = iface.mac
	p.mac_dst = packet.mactobin(ETHER_BROADCAST)
	p.ether_type = bin.pack(">S", P_ATAOE)
	p.buf = tostring(req)
	p:build_ether_frame()
	
	local dnet = nmap.new_dnet()
	dnet:ethernet_open(iface.device)
	dnet:ethernet_send(p.frame_buf)
	dnet:ethernet_close()
end

local function mactostr(bin_mac)
	return stdnse.tohex(bin_mac, { separator=":", group=2 })
end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function()

	local iname = nmap.get_interface()
	if ( not(iname) ) then
		stdnse.print_debug("%s: No interface supplied, use -e", SCRIPT_NAME)
		return
	end
		
	if ( not(nmap.is_privileged()) ) then
		stdnse.print_debug("%s: not running for lack of privileges", SCRIPT_NAME)
		return
	end
	
	local iface = nmap.get_interface_info(iname)	
	if ( not(iface) ) then
		return fail("Failed to retrieve interface information")
	end

	local pcap = nmap.new_socket()
	pcap:set_timeout(5000)
	pcap:pcap_open(iface.device, 1500, true, "ether proto 0x88a2 && !ether src " .. mactostr(iface.mac))
	
	sendConfigInfoRequest(iface)

	local result = {}
	repeat
		local status, len, l2_data, l3_data = pcap:pcap_receive()
	
		if ( status ) then
			local header = ATAoE.Header.parse(l3_data)
			local f = packet.Frame:new(l2_data)
			f:ether_parse()

			local str = ("Server: %s; Version: %d; Major: %d; Minor: %d"):format(
				mactostr(f.mac_src),
				header.version,
				header.major,
				header.minor)
			table.insert(result, str)
		end
	until( not(status) )
	pcap:pcap_close()

	if ( #result > 0 ) then
		return stdnse.format_output(true, result)
	end
end
