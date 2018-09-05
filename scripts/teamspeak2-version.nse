local comm = require "comm"
local shortport = require "shortport"
local nmap = require "nmap"
local string = require "string"

description = [[
Detects the TeamSpeak 2 voice communication server and attempts to determine
version and configuration information.

A single UDP packet (a login request) is sent. If the server does not have a
password set, the exact version, name, and OS type will also be reported on.
]]

---
-- @usage
-- nmap -sU -sV -p 8767 <target>
-- @output
-- PORT     STATE SERVICE    REASON     VERSION
-- 8767/udp open  teamspeak2 script-set TeamSpeak 2.0.23.19 (name: COWCLANS; no password)
-- Service Info: OS: Win32

author = "Marin Maržić"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "version" }

local payload = "\xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\z
\x00\x002x\xba\x85\tTeamSpeak\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x00\x00\x00\x00\nWindows XP\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00 \x00<\x00\z
\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x08nickname\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\z
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

portrule = shortport.version_port_or_service({8767}, "teamspeak2", "udp")

action = function(host, port)
  local status, result = comm.exchange(
    host, port.number, payload, { proto = "udp", timeout = 3000 })
  if not status then
    return
  end
  nmap.set_port_state(host, port, "open")

  local name, platform, version = string.match(result,
    "^\xf4\xbe\x04\0\0\0\0\0.............([^\0]*)%G+([^\0]*)\0*(........)")
  if not name then
    return
  end

  port.version.name = "teamspeak2"
  port.version.name_confidence = 10
  port.version.product = "TeamSpeak"
  if name == "" then
    port.version.version = "2"
  else
    local v_a, v_b, v_c, v_d = string.unpack("<I2 I2 I2 I2", version)
    port.version.version = v_a .. "." .. v_b .. "." .. v_c .. "." .. v_d
    port.version.extrainfo = "name: " .. name .. "; no password"
    if platform == "Win32" then
      port.version.ostype = "Windows"
    elseif platform == "Linux" then
      port.version.ostype = "Linux"
    end
  end

  nmap.set_port_version(host, port, "hardmatched")

  return
end
