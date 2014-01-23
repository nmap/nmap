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
--@args
-- http-server-header.skip  If set, this script will not run. Useful for
--                          printing service fingerprints to submit to Nmap.org

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
  if stdnse.get_script_args(SCRIPT_NAME .. ".skip") then
    return false
  end
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

  port.version = port.version or {}

  if string.match(result, "^HTTP/1.[01] %d%d%d") then
    port.version.service = "http"
  else
    return nil
  end

  local http_server = string.match(result, "\nServer:%s*(.-)\r?\n")

  if port.version.product == nil then
    port.version.product = http_server
  end
  nmap.set_port_version(host, port, "hardmatched")

  if nmap.verbosity() > 0 then
    return [[
Software version grabbed from Server header.
Consider submitting a service fingerprint.
Run with --script-args http-server-header.skip
]]
  else
    return nil
  end
end
