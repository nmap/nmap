local smb = require "smb"
local smb2 = require "smb2"
local stdnse = require "stdnse"
local table = require "table"
local nmap = require "nmap"

description = [[
Attempts to list the supported capabilities in a SMBv2 server for each
 enabled dialect.

The script sends a SMB2_COM_NEGOTIATE command and parses the response
 using the SMB dialects:
* 2.02
* 2.10
* 3.00
* 3.02
* 3.11

References:
* https://msdn.microsoft.com/en-us/library/cc246561.aspx
]]

---
-- @usage nmap -p 445 --script smb2-capabilities <target>
-- @usage nmap -p 139 --script smb2-capabilities <target>
--
-- @output
-- | smb2-capabilities:
-- |   2.02:
-- |     Distributed File System
-- |   2.10:
-- |     Distributed File System
-- |     Leasing
-- |     Multi-credit operations
--
-- @xmloutput
-- <table key="2.02">
-- <elem>Distributed File System</elem>
-- </table>
-- <table key="2.10">
-- <elem>Distributed File System</elem>
-- <elem>Leasing</elem>
-- <elem>Multi-credit operations</elem>
-- </table>
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
  overrides = {}

  local smb2_dialects = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

  for i, dialect in pairs(smb2_dialects) do
    -- we need a clean connection for each negotiate request
    status, smbstate = smb.start(host)
    if(status == false) then
      stdnse.debug1("Could not establish a connection.")
      return nil
    end
    -- We set our overrides Dialects table with the dialect we are testing
    overrides['Dialects'] = {dialect}
    status = smb2.negotiate_v2(smbstate, overrides)
    if status then
      local capabilities = {}
      stdnse.debug2("SMB2: Server capabilities: '%s'", smbstate['capabilities'])

      -- We check the capabilities flags. Not all of them are supported by
      -- every dialect but we dumb check anyway.
      if smbstate['capabilities'] & 0x01 == 0x01 then
        table.insert(capabilities, "Distributed File System")
      end
      if smbstate['capabilities'] & 0x02 == 0x02 then
        table.insert(capabilities, "Leasing")
      end
      if smbstate['capabilities'] & 0x04 == 0x04 then
         table.insert(capabilities, "Multi-credit operations")
      end
      if smbstate['capabilities'] & 0x08 == 0x08 then
         table.insert(capabilities, "Multiple Channel support")
      end
      if smbstate['capabilities'] & 0x10 == 0x10 then
         table.insert(capabilities, "Persistent handles")
      end
      if smbstate['capabilities'] & 0x20 == 0x20 then
         table.insert(capabilities, "Directory Leasing")
      end
      if smbstate['capabilities'] & 0x40 == 0x40 then
        table.insert(capabilities, "Encryption")
      end
      if #capabilities<1 then
        table.insert(capabilities, "All capabilities are disabled")
      end
      output[stdnse.tohex(dialect, {separator = ".", group = 2})] = capabilities
    end
    smb.stop(smbstate)
    status = false
  end

    if #output>0 then
      return output
    else
      stdnse.debug1("No dialects were accepted.")
      if nmap.verbosity()>1 then
        return "Couldn't establish a SMBv2 connection."
      end
    end
end
