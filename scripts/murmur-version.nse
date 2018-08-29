local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the Murmur service (server for the Mumble voice communication
client) versions 1.2.X.

The Murmur server listens on a TCP (control) and a UDP (voice) port
with the same port number. This script activates on both a TCP and UDP
port version scan. In both cases probe data is sent only to the UDP
port because it allows for a simple and informative ping command.

The single probe will report on the server version, current user
count, maximum users allowed on the server, and bandwidth used for
voice communication. It is used by the Mumble client to ping known
Murmur servers.

The IP address from which service detection is being ran will most
likely be temporarily banned by the target Murmur server due to
multiple incorrect handshakes (Nmap service probes). This ban makes
identifying the service via TCP impossible in practice, but does not
affect the UDP probe used by this script.

It is possible to get a corrupt user count (usually +1) when doing a
TCP service scan due to previous service probe connections affecting
the server.

See http://mumble.sourceforge.net/Protocol.
]]

---
-- @output
-- PORT      STATE SERVICE VERSION
-- 64740/tcp open  murmur  Murmur 1.2.4 (control port; users: 35; max. users: 100; bandwidth: 72000 b/s)
-- 64740/udp open  murmur  Murmur 1.2.4 (voice port; users: 35; max. users: 100; bandwidth: 72000 b/s)

author = "Marin Maržić"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "version" }

portrule = shortport.version_port_or_service({64738}, "murmur", {"tcp", "udp"})

action = function(host, port)
  local mutex = nmap.mutex("murmur-version:" .. host.ip .. ":" .. port.number)
  mutex("lock")

  if host.registry["murmur-version"] == nil then
    host.registry["murmur-version"] = {}
  end
  -- Maybe the script already ran for this port number on another protocol
  local r = host.registry["murmur-version"][port.number]
  if r == nil then
    r = {}
    host.registry["murmur-version"][port.number] = r

    local status, result = comm.exchange(
      host, port.number, "\0\0\0\0abcdefgh", { proto = "udp", timeout = 3000 })
    if not status then
      mutex("done")
      return
    end

    -- UDP port is open
    nmap.set_port_state(host, { number = port.number, protocol = "udp" }, "open")

    if not string.match(result, "^%z...abcdefgh............$") then
      mutex("done")
      return
    end

    -- Detected; extract relevant data
    r.v_a, r.v_b, r.v_c, r.users, r.maxusers, r.bandwidth =
    string.unpack(">BBB xxxxxxxx I4I4I4", result, 2)
  end

  mutex("done")

  -- If the registry is empty the port was probed but Murmur wasn't detected
  if next(r) == nil then
    return
  end

  port.version.name = "murmur"
  port.version.name_confidence = 10
  port.version.product = "Murmur"
  port.version.version = r.v_a .. "." .. r.v_b .. "." .. r.v_c
  port.version.extrainfo = "; users: " .. r.users .. "; max. users: " ..
  r.maxusers .. "; bandwidth: " .. r.bandwidth .. " b/s"
  -- Add extra info depending on protocol
  if port.protocol == "tcp" then
    port.version.extrainfo = "control port" .. port.version.extrainfo
  else
    port.version.extrainfo = "voice port" .. port.version.extrainfo
  end

  nmap.set_port_version(host, port, "hardmatched")

  return
end
