local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local coroutine = require "coroutine"

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

-- Order in which field names will be shown in XML
local field_order = {
  "latitude",
  "longitude",
  "city",
  "region",
  "country"
}

--- Location object
--
-- The object supports setting the following fields using functions like
-- <code>set_fieldname</code>:
-- * latitude
-- * longitude
-- * city
-- * region
-- * country
--
-- The location object is suitable for returning from a script, and will
-- produce appropriate string and structured XML output.
Location = {
  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Ensure fields are put in the XML in proper order
  __pairs = function(self)
    local function iterator ()
      for i, key in ipairs(field_order) do
        coroutine.yield(key, self[key])
      end
    end
    return coroutine.wrap(iterator)
  end,

  __tostring = function(self)
    local out = {
      ("coordinates: %s, %s"):format(self.latitude, self.longitude)
    }
    -- if any of these are nil, it doesn't increase #place
    local place = {self.city}
    place[#place+1] = self.region
    place[#place+1] = self.country
    if #place > 0 then
      out[#out+1] = ("location: %s"):format(table.concat(place, ", "))
    end

    return table.concat(out, "\n")
  end,
}

-- Generate setter functions
for _, field in ipairs(field_order) do
  Location["set_" .. field] = function(self, value)
    self[field] = value
  end
end

return _ENV;
