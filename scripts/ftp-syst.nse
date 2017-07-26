local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends an FTP SYST command and returns the result.

The canonical response of "UNIX Type: L8" is stripped or ignored, since it is meaningless.

References:
* https://cr.yp.to/ftp/syst.html
]]

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- |_ftp-syst: UNIX MikroTik 6.39.2

portrule = shortport.port_or_service({21,990}, {"ftp","ftps"})

action = function(host, port)
  local socket, code, message, buffer = ftp.connect(host, port)
  if not socket then
    stdnse.debug1("Couldn't connect: %s", code or message)
    return nil
  end
  if code and code ~= 220 then
    stdnse.debug1("banner code %d %q.", code, message)
    return nil
  end

  local auth_done = false
  ::TRY_AGAIN::
  if not socket:send("SYST\r\n") then
    return nil
  end
  code, message = ftp.read_reply(buffer)
  if not code then
    stdnse.debug1("SYST error: %s", message)
    return nil
  end
  if code == 215 then
    local stripped = message:gsub("^UNIX Type: L8 *", "")
    if stripped ~= "" then
      return stripped
    else
      return nil
    end
  elseif code < 300 then
    return ("%d %s"):format(code, message)
  elseif not auth_done and -- we haven't tried logging in yet
    ( code == 503 -- Command SYST not accepted during Connected
      or code == 521 -- Not logged in - Secure authentication required
      or (code % 100) // 10 == 3 -- x3x codes are auth-related
      ) then
    -- Try logging in
    local status, code, message = ftp.auth(socket, buffer, "anonymous", "IEUser@")
    if status then
      auth_done = true
      goto TRY_AGAIN
    end
  end

  ftp.close(socket)

end
