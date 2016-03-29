local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Tries to identify the physical location of an IP address using the
Geobytes geolocation web service
(http://www.geobytes.com/iplocator.htm). The limit of lookups using
this service is 20 requests per hour. Once the limit is reached, an
nmap.registry["ip-geolocation-geobytes"].blocked boolean is set so no
further requests are made during a scan.
]]

---
-- @usage
-- nmap --script ip-geolocation-geobytes <target>
--
-- @output
-- | ip-geolocation-geobytes:
-- |   latitude: 43.667
-- |   longitude: -79.417
-- |   city: Toronto
-- |   region: Ontario
-- |_  country: Canada
--
-- @xmloutput
-- <elem key="latitude">43.667</elem>
-- <elem key="longitude">-79.417</elem>
-- <elem key="city">Toronto</elem>
-- <elem key="region">Ontario</elem>
-- <elem key="country">Canada</elem>

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

-- Limit is 20 request per hour per requesting host, when reached all table
-- values are filled with a "Limit Exceeded" value. A record in the registry is
-- made so no more requests are made to the server during one scan
action = function(host)
  if nmap.registry["ip-geolocation-geobytes"] and nmap.registry["ip-geolocation-geobytes"].blocked then
    stdnse.debug1("20 requests per hour Limit Exceeded")
    return nil
  end
  local response = http.get("www.geobytes.com", 80, "/IpLocator.htm?GetLocation&template=json.txt&IpAddress="..host.ip, {any_af=true})
  local stat, out = json.parse(response.body)
  if stat then
    local loc = out.geobytes
    local output=stdnse.output_table()
    if loc.city and loc.city == "Limit Exceeded" then
      if not nmap.registry["ip-geolocation-geobytes"] then nmap.registry["ip-geolocation-geobytes"]={} end
      nmap.registry["ip-geolocation-geobytes"].blocked = true
      stdnse.debug1("20 requests per hour Limit Exceeded")
      return nil
    end
    -- Process output
    -- an empty table is returned when latitude and longitude can not be determined
    if ( "table" == type(loc.latitude) or "table" == type(loc.longitude) ) then
      return "Could not determine location for IP"
    end
    output["latitude"] = loc.latitude
    output["longitude"] = loc.longitude
    output["city"] = loc.city
    output["region"] = loc.region
    output["country"] = loc.country
    return output
  elseif response.body:match("Limit Exceeded") then
    if not nmap.registry["ip-geolocation-geobytes"] then nmap.registry["ip-geolocation-geobytes"]={} end
    nmap.registry["ip-geolocation-geobytes"].blocked = true
    stdnse.debug1("20 requests per hour Limit Exceeded")
    return nil
  end
  return nil
end
