local smb = require "smb"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Attempts to list the supported protocols and dialects of a SMB server.

The script attempts to initiate a connection using the dialects:
* NT LM 0.12 (SMBv1)
* 2.02       (SMBv2)
* 2.10       (SMBv2)
* 3.00       (SMBv3)
* 3.02       (SMBv3)
* 3.11       (SMBv3)

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
-- |     2.02
-- |     2.10
-- |     3.00
-- |     3.02
-- |_    3.11
--
-- @xmloutput
-- <table key="dialects">
-- <elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem>
-- <elem>2.02</elem>
-- <elem>2.10</elem>
-- <elem>3.00</elem>
-- <elem>3.02</elem>
-- <elem>3.11</elem>
-- </table>
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
  overrides = {}
  status, supported_dialects = smb.list_dialects(host, overrides)
  if status then
    for i, v in pairs(supported_dialects) do -- Mark SMBv1 as insecure
      if v == "NT LM 0.12" then
        supported_dialects[i] = v .. " (SMBv1) [dangerous, but default]"
      end
    end
    output.dialects = supported_dialects
  end

  if #output.dialects>0 then
    return output
  else
    stdnse.debug1("No dialects were accepted")
    if nmap.verbosity()>1 then
      return "No dialects accepted. Something may be blocking the responses"
    end
  end
end
