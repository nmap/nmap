local geoip = require "geoip"
local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local stdnse = require "stdnse"
local table = require "table"
local oops = require "oops"

description = [[
Tries to identify the physical location of an IP address using the
Geoplugin geolocation web service (http://www.geoplugin.com/). There
is no limit on lookups using this service.
]]

---
-- @usage
-- nmap --script ip-geolocation-geoplugin <target>
--
-- @output
-- | ip-geolocation-geoplugin:
-- | coordinates: 39.4208984375, -74.497703552246
-- |_location: New Jersey, United States
-- @xmloutput
-- <elem key="latitude">37.5605</elem>
-- <elem key="longitude">-121.9999</elem>
-- <elem key="region">California</elem>
-- <elem key="country">United States</elem>
--
-- @see ip-geolocation-ipinfodb.nse
-- @see ip-geolocation-map-bing.nse
-- @see ip-geolocation-map-google.nse
-- @see ip-geolocation-map-kml.nse
-- @see ip-geolocation-maxmind.nse

author = "Gorjan Petrovski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}


hostrule = function(host)
  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private == nil then
    stdnse.debug1("Error in Hostrule: %s.", err )
    return false
  end
  return not is_private
end

-- No limit on requests
local geoplugin = function(ip)
  local response = http.get("www.geoplugin.net", 80, "/json.gp?ip="..ip, {any_af=true})
  local stat, loc = oops.raise(
    "The geoPlugin service has likely blocked you due to excessive usage",
    json.parse(response.body))
  if not stat then
    return stat, loc
  end

  local output = geoip.Location:new()
  output:set_latitude(loc.geoplugin_latitude)
  output:set_longitude(loc.geoplugin_longitude)
  output:set_region((loc.geoplugin_regionName == json.NULL) and "Unknown" or loc.geoplugin_regionName)
  output:set_country(loc.geoplugin_countryName)

  geoip.add(ip, loc.geoplugin_latitude, loc.geoplugin_longitude)

  return true, output
end

action = function(host,port)
  return oops.output(geoplugin(host.ip))
end
