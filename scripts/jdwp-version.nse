local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the Java Debug Wire Protocol. This protocol is used by Java programs
to be debugged via the network. It should not be open to the public Internet,
as it does not provide any security against malicious attackers who can inject
their own bytecode into the debugged process.

Documentation for JDWP is available at 
http://java.sun.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html
]]
author = "Michael Schierl <schierlm@gmx.de>" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 9999/tcp open  jdwp    Java Debug Wire Protocol (Reference Implementation) version 1.6 1.6.0_17


portrule = function(host, port)
        -- JDWP will close the port if there is no valid handshake within 2
	-- seconds, Service detection's NULL probe detects it as tcpwrapped.
        return port.service == "tcpwrapped"
               and port.protocol == "tcp" and port.state == "open"
               and not(shortport.port_is_excluded(port.number,port.protocol))
end

action = function(host, port)
        -- make sure we get at least one more packet after the JDWP-Handshake
        -- response even if there is some delay; the handshake response has 14
        -- bytes, so wait for 18 bytes here.
        local status, result = comm.exchange(host, port, "JDWP-Handshake\0\0\0\11\0\0\0\1\0\1\1", {proto="tcp", bytes=18})
        if (not status) then
                return
        end
        -- match jdwp m|JDWP-Handshake| p/$1/ v/$3/ i/$2\n$4/
        local match = {string.match(result, "^JDWP%-Handshake\0\0..\0\0\0\1\128\0\0\0\0..([^\0\n]*)\n([^\0]*)\0\0..\0\0..\0\0..([0-9._]+)\0\0..([^\0]*)")}
        if match == nil or #match == 0 then
                -- if we have one \128 (reply marker), it is at least not echo because the request did not contain \128
                if (string.match(result,"^JDWP%-Handshake\0.*\128") ~= nil) then
                    port.version.name="jdwp"
                    port.version.product="unknown"
                    nmap.set_port_version(host, port)
                end
                return
        end
        port.version.name="jdwp"
        port.version.product = match[1]
        port.version.version = match[3]
        -- port.version.extrainfo = match[2] .. "\n" .. match[4]
        nmap.set_port_version(host, port)
        return
end
