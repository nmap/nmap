local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
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
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 37.5384,-121.99
-- |_  city: FREMONT, CALIFORNIA, UNITED STATES
--

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
  local stat, loc = json.parse(response.body)
  if not stat then
    stdnse.debug1("No response, possibly a network problem.")
    return nil
  end
  if loc.statusMessage and loc.statusMessage == "Invalid API key." then
    stdnse.debug1(loc.statusMessage)
    return nil
  end

  local output = {}
  table.insert(output, "coordinates (lat,lon): "..loc.latitude..","..loc.longitude)
  table.insert(output,"city: ".. loc.cityName..", ".. loc.regionName..", ".. loc.countryName)

  return output
end

action = function(host,port)
  local output = ipinfodb(host.ip)

  if(#output~=0) then
    output.name = host.ip
    if host.targetname then
      output.name = output.name.." ("..host.targetname..")"
    end
  end

  return stdnse.format_output(true,output)
end
