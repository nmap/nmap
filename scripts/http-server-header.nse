local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local lpeg = require "lpeg"
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

-- Cache the returned pattern
local getquote = U.escaped_quote()

-- Substitution pattern to unescape a string
local unescape = lpeg.P {
  -- Substitute captures
  lpeg.Cs((lpeg.V "simple_char" + lpeg.V "unesc")^0),
  -- Escape char is '\'
  esc = lpeg.P "\\",
  -- Simple char is anything but escape char
  simple_char = lpeg.P(1) - lpeg.V "esc",
  -- If we hit an escape, process specials or hex code, otherwise remove the escape
  unesc = (lpeg.V "esc" * lpeg.Cs( lpeg.V "specials" + lpeg.V "code" + lpeg.P(1) ))/"%1",
  -- single-char escapes. These are the only ones service_scan uses
  specials = lpeg.S "trn0" / {t="\t", r="\r", n="\n", ["0"]="\0"},
  -- hex escape: convert to char
  code = (lpeg.P "x" * lpeg.C(lpeg.S "0123456789abcdefABCDEF"^-2))/function(c)
  return string.char(tonumber(c,16)) end,
}

-- Turn the service fingerprint reply to a probe into a binary blob
local function get_response (fp, probe)
  local i, e = string.find(fp, string.format("%s,%%d+,", probe))
  if i == nil then return nil end
  return unescape:match(getquote:match(fp, e+1))
end

action = function(host, port)
  local responses = {}
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match. Unwrap the fingerprint:
    local fp = string.gsub(port.version.service_fp, "\nSF:", "")
    -- Loop through the probes most likely to receive HTTP responses
    for _, p in ipairs({"GetRequest", "GenericLines", "HTTPOptions",
      "FourOhFourRequest", "NULL", "RTSPRequest", "Help", "SIPOptions"}) do
      responses[#responses+1] = get_response(fp, p)
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

  port.version = port.version or {}

  for _, result in ipairs(responses) do
    if string.match(result, "^HTTP/1.[01] %d%d%d") then
      port.version.service = "http"

      local http_server = string.match(result, "\n[Ss][Ee][Rr][Vv][Ee][Rr]:%s*(.-)\r?\n")

      -- Avoid setting version info if -sV scan already got a match
      if port.version.product == nil and port.version.name_confidence <= 3 then
        port.version.product = http_server
        -- Setting "softmatched" allows the service fingerprint to be printed
        nmap.set_port_version(host, port, "softmatched")
      end

      if http_server then
        if nmap.verbosity() > 0 then
          return {Server=http_server}
        else
          return nil
        end
      end
    end
  end
end
