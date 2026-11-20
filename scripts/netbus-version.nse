local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Attempts to identify NetBuster 1.31 using its version-query response.
The fingerprint requires eight response bytes. An unavailable or
incomplete response does not identify the service as NetBuster.
]]

---
-- @usage
-- nmap -sV -p 12345 --script netbus-version <target>
--
-- @output
-- 12345/tcp open  netbus  NetBuster 1.31 (honeypot)

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.version_port_or_service ({}, "netbus", {"tcp"})

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local function finish(reason, err)
    socket:close()
    if err then
      stdnse.debug1("%s: %s", reason, err)
    else
      stdnse.debug1("%s", reason)
    end
    return nil
  end

  local status, response = socket:connect(host, port)
  if not status then
    return finish("connection_failed", response)
  end

  -- Unlike make_buffer, receive_buf does not return an unterminated tail
  -- as a successful record when the read fails.
  status, response = socket:receive_buf("\r", false)
  if not status then
    return finish("banner_receive_failed", response)
  end
  if not response:match("^NetBus") then
    return finish("unrelated_banner")
  end

  -- NetBus ignores nbver, but answers GetInfo (including an explicit denial
  -- when password protected). NetBuster answers the first query. Sending both
  -- avoids a timeout on NetBus without shortening the response deadline.
  status, response = socket:send("nbver\rGetInfo\r")
  if not status then
    return finish("version_send_failed", response)
  end

  -- NetBuster 1.31 replies with 1.31-<Remind>-<Times>, without a
  -- terminator. Use only its eight-byte prefix (verified on 1.31);
  -- it does not parse the full counter or infer an end from a read failure.
  status, response = socket:receive_buf(match.numbytes(8), true)
  if not status then
    return finish("version_receive_failed", response)
  end
  if not response:match("^1%.31%-[0-4]%-%d$") then
    return finish("fingerprint_mismatch")
  end

  socket:close()
  port.version.name = "netbus"
  port.version.product = "NetBuster"
  port.version.version = "1.31"
  port.version.extrainfo = "honeypot"
  nmap.set_port_version(host, port)
  return nil
end
