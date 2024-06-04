local smb = require "smb"
local smb2 = require "smb2"
local stdnse = require "stdnse"
local table = require "table"
local nmap = require "nmap"

description = [[
Determines the message signing configuration in SMBv2 servers
 for all supported dialects.

The script sends a SMB2_COM_NEGOTIATE request for each SMB2/SMB3 dialect
 and parses the security mode field to determine the message signing
 configuration of the SMB server.

References:
* https://msdn.microsoft.com/en-us/library/cc246561.aspx
]]

---
-- @usage nmap -p 445 --script smb2-security-mode <target>
-- @usage nmap -p 139 --script smb2-security-mode <target>
--
-- @output
-- | smb2-security-mode:
-- |   3.1.1:
-- |_    Message signing enabled but not required
--
-- @xmloutput
-- <table key="3.1.1">
-- <elem>Message signing enabled but not required</elem>
-- </table>
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local output = stdnse.output_table()

  local status, smbstate = smb.start(host)
  if(status == false) then
    return false, smbstate
  end
  --  SMB signing configuration appears to be global so
  --  there is no point of trying different dialects.
  local status, dialect = smb2.negotiate_v2(smbstate)
  if status then
    local message_signing = {}
    -- Signing configuration. SMBv2 servers support two flags:
    -- * Message signing enabled
    -- * Message signing required
    local signing_enabled, signing_required
    if smbstate['security_mode'] & 0x01 == 0x01 then
      signing_enabled = true
    end
    if smbstate['security_mode'] & 0x02 == 0x02 then
      signing_required = true
    end
    if signing_enabled and signing_required then
      table.insert(message_signing, "Message signing enabled and required")
    elseif signing_enabled and not(signing_required) then
      table.insert(message_signing, "Message signing enabled but not required")
    elseif not(signing_enabled) and not(signing_required) then
      table.insert(message_signing, "Message signing is disabled and not required!")
    elseif not(signing_enabled) and signing_required then
      table.insert(message_signing, "Message signing is disabled!")
    end
    output[smb2.dialect_name(dialect)] = message_signing
    -- We exit after first accepted dialect,
  end

  smb.stop(smbstate)
  status = false

  if #output>0 then
    return output
  else
    stdnse.debug1("No SMB2/SMB3 dialects were accepted.")
    if nmap.verbosity()>1 then
      return "Couldn't establish a SMBv2 connection."
    end
  end
end
