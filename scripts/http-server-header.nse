local comm = require "comm"
local string = require "string"
local table = require "table"
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local U = require "lpeg-utility"

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
-- |_ http-server-header: Unidentified Server 1.0
--
--@xmloutput
--<table key="Server">
--  <elem>Unidentified Server 1.0</elem>
--  <elem>SomeOther Server</elem>
--</table>

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
  return (shortport.http(host,port) and nmap.version_intensity() >= 7)
end

action = function(host, port)
  local responses = {}
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match.
    -- Loop through the probes most likely to receive HTTP responses
    for _, p in ipairs({"GetRequest", "GenericLines", "HTTPOptions",
      "FourOhFourRequest", "NULL", "RTSPRequest", "Help", "SIPOptions"}) do
      responses[#responses+1] = U.get_response(port.version.service_fp, p)
    end
  end
  if #responses == 0 then
    -- Have to send the probe ourselves.
    local status, result = comm.tryssl(host, port, "GET / HTTP/1.0\r\n\r\n")

    if (not status) then
      return nil
    end
    responses[1] = result
  end

  -- Also send a probe with host header if we can. IIS reported to send
  -- different Server headers depending on presence of Host header.
  local status, result = comm.tryssl(host, port,
    ("GET / HTTP/1.1\r\nHost: %s\r\n\r\n"):format(stdnse.get_hostname(host)))
  if status then
    responses[#responses+1] = result
  end

  port.version = port.version or {}

  local headers = {}
  for _, result in ipairs(responses) do
    if string.match(result, "^HTTP/1.[01] %d%d%d") then
      port.version.service = "http"

      local http_server = string.match(result, "\n[Ss][Ee][Rr][Vv][Ee][Rr]:[ \t]*(.-)\r?\n")

      -- Avoid setting version info if -sV scan already got a match
      if port.version.product == nil and (port.version.name_confidence or 0) <= 3 then
        port.version.product = http_server
      end

      -- Setting "softmatched" allows the service fingerprint to be printed
      nmap.set_port_version(host, port, "softmatched")

      if http_server then
        headers[http_server] = true
      end
    end
  end

  local out = {}
  local out_s = {}
  for s, _ in pairs(headers) do
    out[#out+1] = s
    out_s[#out_s+1] = s == "" and "<empty>" or s
  end
  if next(out) then
    table.sort(out)
    table.sort(out_s)
    return out, ((#out > 1) and "\n  " or "") .. table.concat(out_s, "\n  ")
  end
end
