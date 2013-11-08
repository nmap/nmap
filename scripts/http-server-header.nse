local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local nmap = require "nmap"

description = [[
Uses the HTTP Server header for missing version info. This is currently
infeasible with version probes because of the need to match non-HTTP services
correctly.
]]

---
--@output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Unidentified Server 1.0

author = "Daniel Miller" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
  -- Avoid running if -sV scan already got a match
  if type(port.version) == "table" and (port.version.name_confidence > 3 or port.version.product ~= nil) then
    return false
  end
  return shortport.http(host,port)
end

action = function(host, port)
  local status, result = comm.tryssl(host, port,
    "GET / HTTP/1.0\r\n\r\n",
    {proto=port.protocol, timeout=5000})
	
	if (not status) then
    return nil
  end

  local http_server = string.match(result, "\nServer:%s*(.-)\r?\n")
  if http_server == nil then
    return nil
  end

  port.version = port.version or {}
  
  if port.version.product == nil then
    port.version.product = http_server
  end
  nmap.set_port_version(host, port, "hardmatched")
	
	return
end
