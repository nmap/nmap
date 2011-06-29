description = [[
Tries to identify the physical location of an IP address using the
IPInfoDB geolocation web service
(http://ipinfodb.com/ip_location_api.php).

There is no limit on requests to this service. However, the API key
used was obtained through a free registration with the service.
]]

---
-- @usage
-- nmap --script ip-geolocation-ipinfodb <target>
--
-- @output
-- | ip-geolocation-ipinfodb:
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 37.5384,-121.99
-- |_  city: FREMONT, CALIFORNIA, UNITED STATES
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}

require "stdnse"
require "ipOps"
require "json"
require "http"

hostrule = function(host)
	local is_private, err = ipOps.isPrivate( host.ip )
    if is_private == nil then
      stdnse.print_debug( "%s Error in Hostrule: %s.", SCRIPT_NAME, err )
      return false
    end
    return not is_private
end

-- No limit on requests. A free registration for an API key is a prerequisite
local ipinfodb = function(ip)
	local api_key = "430ff90c5bf74d71db87f156837ffd7c67725927271c95f650a6ae994342b57f"
	local response = http.get("api.ipinfodb.com", 80, "/v3/ip-city/?key="..api_key.."&format=json".."&ip="..ip, nil)
	local stat, loc = json.parse(response.body)
	if not stat then return nil end
	
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
