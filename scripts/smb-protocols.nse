local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Determines the supported protocols and dialects of a SMB server.
]]

---
-- @usage nmap -p 445 <target> --script=smb-double-pulsar-backdoor
--
-- @output
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "version"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local custom_dialect = stdnse.get_script_args(SCRIPT_NAME..".dialect") or nil
  local status, supported_dialects, overrides 
  local output = stdnse.output_table()
  overrides = overrides or {}
  status, supported_dialects = smb.list_dialects(host, overrides)
  if status then
    output.dialects = supported_dialects    
  end

  return output
end
