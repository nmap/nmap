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

get_all_by_ip = function()
  if empty() then
    return nil
  end

  return nmap.registry.geoip
end

get_all_by_gps = function(limit)
  if empty() then
    return nil
  end

  local t = {}
  for ip, coords in pairs(get_all_by_ip()) do
    if limit and limit < #t then
      break
    end

    local key = coords["latitude"] .. "," .. coords["longitude"]
    if not t[key] then
      t[key] = {}
    end
    table.insert(t[key], ip)
  end

  return t
end

return _ENV;
