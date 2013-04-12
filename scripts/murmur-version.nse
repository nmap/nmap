local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the Murmur service (server for the Mumble voice communication
client) version 1.2.0 and above.

The Murmur server listens on a TCP (control) and an UDP (voice) port
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
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "version" }

portrule = shortport.version_port_or_service({64738, 64739, 64740, 64741, 64742}, "murmur", "udp")

action = function(host, port)
    local status, result = comm.exchange(
        host, port, "\0\0\0\0abcdefgh", { proto = "udp", timeout = 3000 })
    if (not status) then
        return
    end

    if not string.match(result, "^%z...abcdefgh............$") then
        return
    end
    -- Detected; extract relevant data
    local _, v_a, v_b, v_c, _, users, maxusers, bandwidth = bin.unpack(
        ">CCCLIII", result, 2)

    port.version.name = "murmur"
    port.version.name_confidence = 10
    port.version.product = "Murmur"
    port.version.version = v_a .. "." .. v_b .. "." .. v_c
    -- Set extra info depending on protocol and set port state to "open" if UDP
    local portinfo
    if port.protocol == "tcp" then
        portinfo = "control port"
    else
        portinfo = "voice port"
        nmap.set_port_state(host, port, "open")
    end
    port.version.extrainfo = portinfo ..
        "; users: " .. users .. "; max. users: " .. maxusers ..
        "; bandwidth: " .. bandwidth .. " b/s"

    nmap.set_port_version(host, port, "hardmatched")

    return
end
