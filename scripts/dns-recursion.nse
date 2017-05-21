local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Checks if a DNS server allows queries for third-party names. It is
expected that recursion will be enabled on your own internal
nameservers.
]]

---
-- @usage
-- nmap -sU -p 53 --script=dns-recursion <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 53/udp open  domain  udp-response
-- |_dns-recursion: Recursion appears to be enabled

author = "Felix Groebert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}


portrule = shortport.portnumber(53, "udp")

action = function(host, port)

    -- generate dns query
    local request = "\xde\xad" -- Transaction-ID 0xdead
    .. "\x01\x00" -- flags (recursion desired)
    .. "\x00\x01" -- 1 question
    .. "\x00\x00" -- 0 answers
    .. "\x00\x00" -- 0 authority
    .. "\x00\x00" -- 0 additional
    .. "\x03www\x09wikipedia\x03org\x00" -- www.wikipedia.org.
    .. "\x00\x01" -- type A
    .. "\x00\x01" -- class IN

    local status, result = comm.exchange(host, port, request, {proto="udp"})

    if not status then
        return
    end

    nmap.set_port_state(host, port, "open")

    -- parse response for dns flags
    if (string.byte(result,3) & 0x80) == 0x80
        and (string.byte(result,4) & 0x85) == 0x80
    then
        return "Recursion appears to be enabled"
    end

    return
end
