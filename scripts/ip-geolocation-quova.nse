description = [[
Tries to identify the physical location of an IP address using the
Quova geolocation web service (http://www.quova.com/).

It uses three API keys obtained through a free registration. The limit
on lookups is 1000 per API key per day, and 2 per API key per second.
]]

---
-- @usage
-- nmap --script ip-geolocation-quova <target>
--
-- @output
-- | ip-geolocation-quova:
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 37.56699,-121.98266
-- |_  city: fremont, california, united states
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}

require "stdnse"
require "ipOps"
require "json"
require "http"
require "openssl"

hostrule = function(host)
	local is_private, err = ipOps.isPrivate( host.ip )
    if is_private == nil then
      stdnse.print_debug( "%s Error in Hostrule: %s.", SCRIPT_NAME, err )
      return false
    end
    return not is_private
end

-- A free registration for an API key is required. Limit is 1000 requests per 
-- API per day, 2 requests per API per second 
local quova = function(ip)
	local api_keys = {"100.9fjahzuxgtwmzfdztd8g","100.t9e4u6pgtdpf84xenv2y","100.8pf9xxzxt4sxuu7ephdn"}
	local secret_codes = {"2YY39UGm", "haBZaVfj", "MtFMZuHH"}
	local secret = nil
	local timestamp = nil
	local sig = nil
	local response = nil
	
	for i,api_key in ipairs(api_keys) do
		timestamp = os.time(os.date("!*t"))
		secret = secret_codes[i]
		sig = stdnse.tohex(openssl.md5(api_key .. secret .. timestamp))
		
		response = http.get("api.quova.com", 80, "/v1/ipinfo/" .. ip .. "?apikey=" ..api_key.."&sig="..sig.."&format=json", nil)
		
		if response.status == 200 then break end
		if response.status ~= 403 then 
			stdnse.print_debug("Quova API is malfunctioning.")
			return nil
		end
		if response.status == 403 and response.header["x-mashery-error-code"]~= "ERR_403_DEVELOPER_OVER_QPS" then
			return nil
		end
	end
	
	local stat,obj_json = json.parse(response.body)
	if not stat then return nil end
	
	loc = obj_json.ipinfo.Location
	
	local output = {}
	table.insert(output,"coordinates (lat,lon): "..loc.latitude..","..loc.longitude)
	table.insert(output,"city: ".. loc.CityData.city..", ".. loc.StateData.state..", ".. loc.CountryData.country)
	
	return output
end
	
action = function(host,port)
	local output = quova(host.ip)
	
	if output and(#output~=0) then 
		output.name = host.ip 
		if host.targetname then
			output.name = output.name.." ("..host.targetname..")" 
		end
		return stdnse.format_output(true,output)
	end
	
end
