local bit = require "bit"
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
-- @output
-- PORT   STATE SERVICE REASON
-- 53/udp open  domain  udp-response
-- |_dns-recursion: Recursion appears to be enabled

author = "Felix Groebert"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}


portrule = shortport.portnumber(53, "udp")

action = function(host, port)

    -- generate dns query, Transaction-ID 0xdead, www.wikipedia.org (type A, class IN)
    local request = string.char(0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03) ..  "www" .. string.char(0x09) .. "wikipedia" .. string.char(0x03) ..  "org" .. string.char(0x00, 0x00, 0x01, 0x00, 0x01)

    local status, result = comm.exchange(host, port, request, {proto="udp"})

    if not status then
        return
    end

    nmap.set_port_state(host, port, "open")

    -- parse response for dns flags
    if (bit.band(string.byte(result,3), 0x80) == 0x80
        and bit.band(string.byte(result,4), 0x85) == 0x80)
    then
        return "Recursion appears to be enabled"
    end

    return
end
