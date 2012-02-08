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
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 43.667,-79.417
-- |_  city: Toronto, Ontario, Canada
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}

require "nmap"
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

-- Limit is 20 request per hour per requesting host, when reached all table 
-- values are filled with a "Limit Exceeded" value. A record in the registry is 
-- made so no more requests are made to the server during one scan
local geobytes = function(ip)
	if nmap.registry["ip-geolocation-geobytes"] and nmap.registry["ip-geolocation-geobytes"].blocked then
		return nil
	end
	local response = http.get("www.geobytes.com", 80, "/IpLocator.htm?GetLocation&template=json.txt&IpAddress="..ip, nil)
	local stat, out = json.parse(response.body)
	local loc = out.geobytes
	local output={}
	if stat then
		if loc.city and loc.city == "Limit Exceeded" then
			if not nmap.registry["ip-geolocation-geobytes"] then nmap.registry["ip-geolocation-geobytes"]={} end
			nmap.registry["ip-geolocation-geobytes"].blocked = true
			return nil
		end
		-- Process output
		table.insert(output, "coordinates (lat,lon): " .. loc.latitude .. "," .. loc.longitude)
		table.insert(output,"city: ".. loc.city..", ".. loc.region..", ".. loc.country)
		return output
	end
	return nil
end

action = function(host,port)
	local output = geobytes(host.ip)
		
	if(#output~=0) then 
		output.name = host.ip 
		if host.targetname then
			output.name = output.name.." ("..host.targetname..")" 
		end
	end
	
	return stdnse.format_output(true,output)
end
