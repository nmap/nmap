local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local U = require "lpeg-utility"

description = [[
Detects the Skype version 2 service.
]]

---
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  skype2  Skype

author = "Brandon Enright"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}


portrule = function(host, port)
  return (port.number == 80 or port.number == 443 or
    port.service == nil or port.service == "" or
    port.service == "unknown")
  and port.protocol == "tcp" and port.state == "open"
  and port.version.name_confidence < 10
  and not(shortport.port_is_excluded(port.number,port.protocol))
  and nmap.version_intensity() >= 7
end

action = function(host, port)
  local result, rand
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match.
    result = U.get_response(port.version.service_fp, "GetRequest")
    -- Loop through the ASCII probes most likely to receive random response
    -- from Skype. Others will also receive this response, but are harder to
    -- distinguish from an echo service.
    for _, p in ipairs({"HTTPOptions", "RTSPRequest"}) do
      rand = U.get_response(port.version.service_fp, p)
      if rand then
        break
      end
    end
  end
  local status
  if not result then
    -- Have to send the probe ourselves.
    status, result = comm.exchange(host, port,
      "GET / HTTP/1.0\r\n\r\n", {bytes=26})

    if (not status) then
      return nil
    end
  end

  if (result ~= "HTTP/1.0 404 Not Found\r\n\r\n") then
    return
  end

  -- So far so good, now see if we get random data for another request
  if not rand then
    status, rand = comm.exchange(host, port,
      "random data\r\n\r\n", {bytes=15})

    if (not status) then
      return
    end
  end

  if string.match(rand, "[^%s!-~].*[^%s!-~].*[^%s!-~]") then
    -- Detected
    port.version.name = "skype2"
    port.version.product = "Skype"
    nmap.set_port_version(host, port)
    return
  end
  return
end
