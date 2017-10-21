local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

_ENV = stdnse.module("geoip", stdnse.seeall)

---
-- Consolidation of GeoIP functions.
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

--- Add a geolocation to the registry
-- @param ip The IP that was geolocated
-- @param lat The latitude in degrees
-- @param lon The longitude in degrees
add = function(ip, lat, lon)
  local lat_n = tonumber(lat)
  if not lat_n or lat_n < -90 or lat_n > 90 then
    stdnse.debug1("Invalid latitude for %s: %s.", ip, lat)
    return
  end

  local lon_n = tonumber(lon)
  if not lat_n or lon_n < -180 or lon_n > 180 then
    stdnse.debug1("Invalid longitude for %s: %s.", ip, lon)
    return
  end

  if not nmap.registry.geoip then
    nmap.registry.geoip = {}
  end

  nmap.registry.geoip[ip] = {
    latitude = lat,
    longitude = lon
  }
end

--- Check if any coordinates have been stored in the registry
--@return True if any coordinates have been returned, false otherwise
empty = function()
  return not nmap.registry.geoip
end

--- Retrieve the table of coordinates by IP
--@return A table of coordinates keyed by IP.
get_all_by_ip = function()
  if empty() then
    return nil
  end

  return nmap.registry.geoip
end

--- Retrieve a table of IPs by coordinate
--@return A table of IPs keyed by coordinate in <code>lat,lon</code> format
get_all_by_gps = function()
  if empty() then
    return nil
  end

  local t = {}
  for ip, coords in pairs(get_all_by_ip()) do
    local key = coords["latitude"] .. "," .. coords["longitude"]
    if not t[key] then
      t[key] = {}
    end
    table.insert(t[key], ip)
  end

  return t
end

return _ENV;
