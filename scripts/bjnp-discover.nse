description = [[
Retrieves printer or scanner information from a remote device supporting the
BJNP protocol. The protocol is known to be supported by network based Canon
devices.
]]

---
-- @usage
-- sudo nmap -sU -p 8611,8612 --script bjnp-discover <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 8611/udp open  canon-bjnp1
-- | bjnp-discover: 
-- |   Manufacturer: Canon
-- |   Model: MG5200 series
-- |   Description: Canon MG5200 series
-- |   Firmware version: 1.050
-- |_  Command: BJL,BJRaster3,BSCCe,NCCe,IVEC,IVECPLI
-- 8612/udp open  canon-bjnp2
-- | bjnp-discover: 
-- |   Manufacturer: Canon
-- |   Model: MG5200 series
-- |   Description: Canon MG5200 series
-- |_  Command: MultiPass 2.1,IVEC
--

categories = {"safe", "discovery"}
author = "Patrik Karlsson"

local bjnp = require("bjnp")
local shortport = require("shortport")
local stdnse = require("stdnse")

portrule = shortport.portnumber({8611, 8612}, "udp")

action = function(host, port)
	local helper = bjnp.Helper:new(host, port)
	if ( not(helper:connect()) ) then
		return "\n  ERROR: Failed to connect to server"
	end
	local status, attrs
	if ( port.number == 8611 ) then
		status, attrs = helper:getPrinterIdentity()
	else
		status, attrs = helper:getScannerIdentity()
	end
	helper:close()
	return stdnse.format_output(true, attrs)
end
