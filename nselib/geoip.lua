local nmap = require "nmap"
local stdnse = require "stdnse"

_ENV = stdnse.module("geoip", stdnse.seeall)

---
-- Consolidation of GeoIP functions.
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

add = function(ip, lat, lon)
  if not nmap.registry.geoip then
    nmap.registry.geoip = {}
  end

  if not nmap.registry.geoip[ip] then
    nmap.registry.geoip[ip] = {}
  end

  nmap.registry.geoip[ip]["latitude"] = lat
  nmap.registry.geoip[ip]["longitude"] = lon
end

empty = function()
  return not nmap.registry.geoip
end

get_all = function()
  if empty() then
    return nil
  end

  return nmap.registry.geoip
end

return _ENV;
