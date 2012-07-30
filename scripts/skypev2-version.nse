local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the Skype version 2 service.
]]

---
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  skype2  Skype
 
author = "Brandon Enright"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}


portrule = function(host, port)
        return (port.number == 80 or port.number == 443 or
                port.service == nil or port.service == "" or
                port.service == "unknown")
               and port.protocol == "tcp" and port.state == "open"
               and port.service ~= "http" and port.service ~= "ssl/http"
               and not(shortport.port_is_excluded(port.number,port.protocol))
end

action = function(host, port)
        local status, result = comm.exchange(host, port,
                "GET / HTTP/1.0\r\n\r\n", {bytes=26, proto=port.protocol})
        if (not status) then
                return
        end
        if (result ~= "HTTP/1.0 404 Not Found\r\n\r\n") then
                return
        end
        -- So far so good, now see if we get random data for another request
        status, result = comm.exchange(host, port,
                "random data\r\n\r\n", {bytes=15, proto=port.protocol})

        if (not status) then
                return
        end
        if string.match(result, "[^%s!-~].*[^%s!-~].*[^%s!-~]") then
                -- Detected
                port.version.name = "skype2"
                port.version.product = "Skype"
                nmap.set_port_version(host, port)
                return  
        end
        return
end
