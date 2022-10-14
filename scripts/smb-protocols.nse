local smb = require "smb"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Attempts to list the supported protocols and dialects of a SMB server.

The script attempts to initiate a connection using the dialects:
* NT LM 0.12 (SMBv1)
* 2.0.2      (SMBv2)
* 2.1        (SMBv2)
* 3.0        (SMBv3)
* 3.0.2      (SMBv3)
* 3.1.1      (SMBv3)

Additionally if SMBv1 is found enabled, it will mark it as insecure. This
script is the successor to the (removed) smbv2-enabled script.
]]

---
-- @usage nmap -p445 --script smb-protocols <target>
-- @usage nmap -p139 --script smb-protocols <target>
--
-- @output
-- | smb-protocols:
-- |   dialects:
-- |     NT LM 0.12 (SMBv1) [dangerous, but default]
-- |     2.0.2
-- |     2.1
-- |     3.0
-- |     3.0.2
-- |_    3.1.1
--
-- @xmloutput
-- <table key="dialects">
-- <elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem>
-- <elem>2.0.2</elem>
-- <elem>2.1</elem>
-- <elem>3.0</elem>
-- <elem>3.0.2</elem>
-- <elem>3.1.1</elem>
-- </table>
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, supported_dialects = smb.list_dialects(host)
  if status then
    for i, v in pairs(supported_dialects) do -- Mark SMBv1 as insecure
      if v == "NT LM 0.12" then
        supported_dialects[i] = v .. " (SMBv1) [dangerous, but default]"
      end
    end
    if #supported_dialects > 0 then
      local output = stdnse.output_table()
      output.dialects = supported_dialects
      return output
    end
  end
  stdnse.debug1("No dialects were accepted")
  if nmap.verbosity()>1 then
    return "No dialects accepted. Something may be blocking the responses"
  end
end
