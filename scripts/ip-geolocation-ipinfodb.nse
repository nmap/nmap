local geoip = require "geoip"
local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local oops = require "oops"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Tries to identify the physical location of an IP address using the
IPInfoDB geolocation web service
(http://ipinfodb.com/ip_location_api.php).

There is no limit on requests to this service. However, the API key
needs to be obtained through free registration for this service:
<code>http://ipinfodb.com/login.php</code>
]]

---
-- @usage
-- nmap --script ip-geolocation-ipinfodb <target> --script-args ip-geolocation-ipinfodb.apikey=<API_key>
--
-- @args ip-geolocation-ipinfodb.apikey A sting specifying the api-key which
--       the user wants to use to access this service
--
-- @output
-- | ip-geolocation-ipinfodb:
-- | coordinates: 37.5384, -121.99
-- |_location: FREMONT, CALIFORNIA, UNITED STATES
--
-- @xmloutput
-- <elem key="latitude">37.5384</elem>
-- <elem key="longitude">-121.99</elem>
-- <elem key="city">FREMONT</elem>
-- <elem key="region">CALIFORNIA</elem>
-- <elem key="country">UNITED STATES</elem>
--
-- @see ip-geolocation-geoplugin.nse
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
    stdnse.debug1("not running: Error in Hostrule: %s.", err )
    return false
  elseif is_private then
    stdnse.debug1("not running: Private IP address of target: %s", host.ip)
    return false
  end

  local api_key = stdnse.get_script_args(SCRIPT_NAME..".apikey")
  if not (type(api_key)=="string") then
    stdnse.debug1("not running: No IPInfoDB API key specified.")
    return false
  end

  return true
end

-- No limit on requests. A free registration for an API key is a prerequisite
local ipinfodb = function(ip)
  local api_key = stdnse.get_script_args(SCRIPT_NAME..".apikey")
  local response = http.get("api.ipinfodb.com", 80, "/v3/ip-city/?key="..api_key.."&format=json".."&ip="..ip, {any_af=true})
  local stat, loc = oops.raise(
    "Unable to parse ipinfodb.com response",
    json.parse(response.body))
  if not stat then
    return stat, loc
  end
  if loc.statusMessage and loc.statusMessage == "Invalid API key." then
    return false, oops.err(loc.statusMessage)
  end

  local output = geoip.Location:new()
  output:set_latitude(loc.latitude)
  output:set_longitude(loc.longitude)
  output:set_city(loc.cityName)
  output:set_region(loc.regionName)
  output:set_country(loc.countryName)

  geoip.add(ip, loc.latitude, loc.longitude)

  return true, output
end

action = function(host,port)
  return oops.output(ipinfodb(host.ip))
end
