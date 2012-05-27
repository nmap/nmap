local nmap = require "nmap"
local smb = require "smb"
local string = require "string"

description = [[
Checks whether or not a server is running the SMBv2 protocol. 
]]
---
--@usage
-- nmap --script smbv2-enabled.nse -p445 <host>
-- sudo nmap -sU -sS --script smbv2-enabled.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |_ smb-v2-enabled: Server supports SMBv2 protocol
--
-- Host script results:
-- |_ smb-v2-enabled: Server doesn't support SMBv2 protocol

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local function go(host)
	local status, smbstate, result
	local dialects = { "NT LM 0.12", "SMB 2.002", "SMB 2.???" }
	local overrides = {dialects=dialects}

	status, smbstate = smb.start(host)
	if(not(status)) then
		return false, "Couldn't start SMB session: " .. smbstate
	end

	status, result = smb.negotiate_protocol(smbstate, overrides)
	if(not(status)) then
		if(string.find(result, "SMBv2")) then
			return true, "Server supports SMBv2 protocol"
		end
		return false, "Couldn't negotiate protocol: " .. result
	end

	return true, "Server doesn't support SMBv2 protocol"
end

action = function(host)
	local status, result = go(host)

	if(not(status)) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result
		else
			return nil
		end
	end

	return result
end



