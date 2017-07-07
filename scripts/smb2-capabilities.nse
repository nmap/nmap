local smb = require "smb"
local smb2 = require "smb2"
local stdnse = require "stdnse"
local string = require "string"
local bit = require "bit"

description = [[
Lists the capabilities enabled in a SMBv2 server.
]]

---
-- @usage nmap -p 445 <target> --script=smb2-capabilities
--
-- @output
-- | smb2-capabilities: 
-- |   2.02:Distributed File System
-- |_  2.10:Distributed File System,Leasing,Multi-credit operations
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, smbstate, overrides 
  local output = stdnse.output_table()
  overrides = overrides or {}

  local smb2_dialects = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

  for i, dialect in pairs(smb2_dialects) do
    -- we need a clean connection for each negotiate request
    status, smbstate = smb.start(host)
    if(status == false) then
      return false, smbstate
    end
    overrides['Dialects'] = {dialect}
    status, dialect = smb2.negotiate_v2(smbstate, overrides)
    if status then
      local capabilities = {}
      stdnse.debug2("SMB2: Server capabilities: '%s'", smbstate['capabilities'])
      if ( bit.band(smbstate['capabilities'], 0x00000001) == 0x00000001) then
        table.insert(capabilities, "Distributed File System")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000002) == 0x00000002) then
        table.insert(capabilities, "Leasing")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000004) == 0x00000004) then
         table.insert(capabilities, "Multi-credit operations")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000008) == 0x00000008) then
         table.insert(capabilities, "Multiple Channel support")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000010) == 0x00000010) then
         table.insert(capabilities, "Persistent handles")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000020) == 0x00000020) then
         table.insert(capabilities, "Directory Leasing")
      end
      if ( bit.band(smbstate['capabilities'], 0x00000040) == 0x00000040) then
        table.insert(capabilities, "Encryption support")
      end
      table.insert(output, stdnse.tohex(dialect[1], {separator = ".", group = 2}) .. ":" .. stdnse.strjoin(",", capabilities))
    end

    --clean smb connection
    smb.stop(smbstate)
    status = false
  end


  return output
end
