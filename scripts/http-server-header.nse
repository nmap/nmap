local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Uses the HTTP Server header for missing version info. This is currently
infeasible with version probes because of the need to match non-HTTP services
correctly.
]]

---
--@output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Unidentified Server 1.0
--
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Unidentified Server 1.0
-- | http-server-header:
-- |_ Server: Unidentified Server 1.0
--
--@xmloutput
--<elem key="Server">Unidentified Server 1.0</elem>

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
  return (shortport.http(host,port) and nmap.version_intensity() >= 7)
end

action = function(host, port)
  local status, result = comm.tryssl(host, port, "GET / HTTP/1.0\r\n\r\n")

  if (not status) then
    return nil
  end

  port.version = port.version or {}

  if string.match(result, "^HTTP/1.[01] %d%d%d") then
    port.version.service = "http"
  else
    return nil
  end

  local http_server = string.match(result, "\nServer:%s*(.-)\r?\n")

  -- Avoid setting version info if -sV scan already got a match
  if port.version.product == nil and port.version.name_confidence <= 3 then
    port.version.product = http_server
    -- Setting "softmatched" allows the service fingerprint to be printed
    nmap.set_port_version(host, port, "softmatched")
  end

  if nmap.verbosity() > 0 and http_server then
    return {Server=http_server}
  else
    return nil
  end
end
