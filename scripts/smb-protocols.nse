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
-- | smb-protocols: 
-- |   dialects: 
-- |     NT LM 0.12 (SMBv1)[dangerous, but default]
-- |     2.02
-- |     2.10
-- |     3.00
-- |     3.02
-- |_    3.11
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, supported_dialects, overrides 
  local output = stdnse.output_table()
  overrides = overrides or {}
  status, supported_dialects = smb.list_dialects(host, overrides)
  if status then
    for i, v in pairs(supported_dialects) do
      if v == "NT LM 0.12" then
        supported_dialects[i] = v .. " (SMBv1) [dangerous, but default]"
      end
    end
    output.dialects = supported_dialects    
  end

  return output
end
