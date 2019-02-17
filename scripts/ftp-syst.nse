local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends FTP SYST and STAT commands and returns the result.

The canonical SYST response of "UNIX Type: L8" is stripped or ignored, since it
is meaningless. Typical FTP response codes (215 for SYST and 211 for STAT) are
also hidden.

References:
* https://cr.yp.to/ftp/syst.html
]]

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- | ftp-syst:
-- |   SYST: UNIX MikroTik 6.34.3
-- |   STAT:
-- |  Enver Curri FTP server (MikroTik 6.34.3) status:
-- | Logged in as
-- | TYPE: ASCII; STRUcture: File; transfer MODE: Stream
-- | No data connection
-- |_End of status
--
-- | ftp-syst:
-- |   STAT:
-- | FTP server status:
-- |      Connected to 192.0.2.13
-- |      Logged in as ftp
-- |      TYPE: ASCII
-- |      No session bandwidth limit
-- |      Session timeout in seconds is 300
-- |      Control connection is plain text
-- |      Data connections will be plain text
-- |      At session startup, client count was 1
-- |      vsFTPd 2.0.5 - secure, fast, stable
-- |_End of status
--
-- | ftp-syst:
-- |   SYST: Version: Linux 2.6.26.8-rt16
-- |   STAT:
-- |  HES_CPE FTP server status:
-- |      ftpd (GNU inetutils) 1.4.1
-- |      Connected to 72.14.177.105
-- |      Waiting for user name
-- |      TYPE: ASCII, FORM: Nonprint; STRUcture: File; transfer MODE: Stream
-- |      No data connection
-- |_End of status
--
-- @xmloutput
-- <elem key="SYST">Version: Linux 3.10.73</elem>
-- <elem key="STAT">
--  FRITZ!Box7490 FTP server status:
--  Connected to 72.14.177.105
--  Waiting for user name
--  TYPE: ASCII, FORM: Nonprint; STRUcture: File; transfer MODE: Stream
--  No data connection
-- End of status</elem>

portrule = shortport.port_or_service({21,990}, {"ftp","ftps"})

local function do_syst(socket, buffer)
end

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

  -- SYST
  local auth_done = false
  local syst = nil
  repeat
    if not socket:send("SYST\r\n") then
      return nil
    end
    code, message = ftp.read_reply(buffer)
    if not code then
      stdnse.debug1("SYST error: %s", message)
      break
    end
    if code == 215 then
      local stripped = message:gsub("^UNIX Type: L8 *", "")
      if stripped ~= "" then
        syst = stripped
      end
      break
    elseif code < 300 then
      syst = ("%d %s"):format(code, message)
      break
    elseif not auth_done and -- we haven't tried logging in yet
      ( code == 503 -- Command SYST not accepted during Connected
        or code == 521 -- Not logged in - Secure authentication required
        or (code % 100) // 10 == 3 -- x3x codes are auth-related
        ) then
      -- Try logging in
      local status, code, message = ftp.auth(socket, buffer, "anonymous", "IEUser@")
      if status then
        auth_done = true
      end
    else
      stdnse.debug1("SYST error: %d %s", code, message)
      break
    end
  until not auth_done

  -- STAT
  if not socket:send("STAT\r\n") then
    if syst then
      return {SYST=syst}
    else
      return nil
    end
  end

  local out = stdnse.output_table()
  out.SYST = syst
  local code, stat = ftp.read_reply(buffer)

  if code then
    if code == 211 then
      out.STAT = "\n" .. stat
    elseif code < 300 then
      out.STAT = ("%d\n%s"):format(code, stat)
    end
  end

  ftp.close(socket)

  if #out > 0 then
    return out
  end
end
