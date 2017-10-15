local geoip = require "geoip"
local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local stdnse = require "stdnse"
local table = require "table"

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
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 39.4208984375,-74.497703552246
-- |_  state: New Jersey, United States
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
  local stat, loc = json.parse(response.body)
  if not stat then
    return false, loc
  end

  local output = {}
  table.insert(output, "coordinates (lat,lon): "..loc.geoplugin_latitude..","..loc.geoplugin_longitude)
  local regionName = (loc.geoplugin_regionName == json.NULL) and "Unknown" or loc.geoplugin_regionName
  table.insert(output,"state: ".. regionName ..", ".. loc.geoplugin_countryName)

  geoip.add(ip, loc.geoplugin_latitude, loc.geoplugin_longitude)

  return true, output
end

action = function(host,port)
 local output = stdnse.output_table()

  local status, result = geoplugin(host.ip)
  if not status then
    if result == "syntax error" then
      result = "The geoPlugin service has likely blocked you due to excessive usage, but the response received was 'syntax error'."
    end
    output.ERROR = result
    return output, output.ERROR
  end

  output.name = host.ip
  if host.targetname then
    output.name = output.name.." ("..host.targetname..")"
  end

  return stdnse.format_output(true,output)
end
