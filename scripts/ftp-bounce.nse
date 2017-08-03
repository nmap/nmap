local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local ftp = require "ftp"

description=[[
Checks to see if an FTP server allows port scanning using the FTP bounce method.
]]
author = "Marek Majkowski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @args ftp-bounce.username Username to log in with. Default
-- <code>anonymous</code>.
-- @args ftp-bounce.password Password to log in with. Default
-- <code>IEUser@</code>.
-- @args ftp-bounce.checkhost Host to try connecting to with the PORT command.
--                            Default: scanme.nmap.org
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-bounce: bounce working!
--
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-bounce: server forbids bouncing to low ports <1025

categories = {"default", "safe"}

portrule = shortport.port_or_service({21, 990}, {"ftp", "ftps"})

local function get_portfmt()
  local arghost = stdnse.get_script_args(SCRIPT_NAME .. ".checkhost") or "scanme.nmap.org"
  local reg = nmap.registry[SCRIPT_NAME] or {}
  local addr = reg[arghost]
  if not addr then
    local status, addrs = nmap.resolve(arghost, "inet")
    if not status or #addrs < 1 then
      stdnse.verbose1("Couldn't resolve %s, scanning 10.0.0.1 instead.", arghost)
      addr = "10.0.0.1"
    else
      addr = addrs[1]
    end
    reg[arghost] = addr
  end
  nmap.registry[SCRIPT_NAME] = reg
  return string.format("PORT %s,%%s\r\n", (string.gsub(addr, "%.", ",")))
end

action = function(host, port)
  local user = stdnse.get_script_args(SCRIPT_NAME .. ".username") or "anonymous"
  local pass = stdnse.get_script_args(SCRIPT_NAME .. ".password") or "IEUser@"

  -- BANNER
  local socket, code, message, buffer = ftp.connect(host, port, {request_timeout=10000})
  if not socket then
    return nil
  end
  if code < 200 or code > 299 then
    socket:close()
    return nil
  end

  socket:set_timeout(5000)
  -- USER
  local status, code, message = ftp.auth(socket, buffer, user, pass)
  if not status then
    stdnse.debug1("Authentication rejected: %s %s", code or "socket", message)
    ftp.close(socket)
    return nil
  end

  -- PORT highport
  local portfmt = get_portfmt()
  -- This is actually port 256*80 + 80 = 20560
  if not socket:send(string.format(portfmt, "80,80")) then
    stdnse.debug1("Can't send PORT")
    return nil
  end
  code, message = ftp.read_reply(buffer)
  if not code then
    stdnse.debug1("Error after PORT: %s", message)
    return nil
  end
  if code < 200 or code > 299 then
    stdnse.verbose1("PORT response: %d %s", code, message)
    ftp.close(socket)
    -- return "server forbids bouncing"
    return nil
  end

  -- PORT lowport
  if not socket:send(string.format(portfmt, "0,80")) then
    stdnse.debug1("Can't send PORT")
    return nil
  end
  code, message = ftp.read_reply(buffer)
  if not code then
    stdnse.debug1("Error after PORT: %s", message)
    return nil
  end
  if code < 200 or code > 299 then
    stdnse.verbose1("PORT (low port) response: %d %s", code, message)
    ftp.close(socket)
    return "server forbids bouncing to low ports <1025"
  end

  ftp.close(socket)
  return "bounce working!"
end

