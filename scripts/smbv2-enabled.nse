local nmap = require "nmap"
local smb = require "smb"
local string = require "string"
local stdnse = require "stdnse"

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
--
-- @xmloutput
-- false

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
      return true, "Server supports SMBv2 protocol", true
    end
    return false, "Couldn't negotiate protocol: " .. result
  end

  return true, "Server doesn't support SMBv2 protocol", false
end

action = function(host)
  local status, result, flag = go(host)

  if(not(status)) then
    return stdnse.format_output(false, result)
  end

  return flag, result
end



