description = [[
Queries HPE OneView server API to extract the API version information.

For more information see:

https://techlibrary.hpe.com/docs/enterprise/servers/oneview5.0/cicf-api/en/index.html#rest/version

]]

---
-- @usage
-- nmap --script hpe-oneview-api--version -p 443 <host>
--
-- @output
-- | hpe-oneview-api-version:
-- |   Current version: 4800
-- |_  Minimum version: 120
-- Service Info: CPE: Version: 4800
----------------------------------------------------------

author = "Robin Wood - Digininja"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local json = require "json"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

portrule = function (host, port)
  if nmap.version_intensity() < 7 or nmap.port_is_excluded(port.number, port.protocol) then
    return false
  end
  return shortport.http(host, port)
end

local function get_version(host, port)
  local path = "/rest/version"

  local response = http.get( host, port, path)

  if(response['status'] ~= 200 or response['content-length'] == 0) then
    return false, "Version endpoint not found"
  end

  if ( response.header and response.header["content-type"] ) then
    if ( not string.find(response.header["content-type"], "application/json" ) ) then
	  return false, "Wrong content type returned " .. response.header["content-type"]
    end
  else
  	return false, "No content type returned"
  end

  return true, response.body
end

action = function(host, port)

  local result, body = get_version(host, port)

  if(not(result)) then
    stdnse.debug1("%s", body)
    return nil
  end

  local status, json_data = json.parse(body)
  if ( not(status) ) then
    return false, "Failed to parse JSON response"
  end

  local current_version = json_data['currentVersion']
  local minimum_version = json_data['minimumVersion']

  if (current_version == nil or minimum_version == nil) then
    stdnse.debug1("API did not return the expected data")
    return nil
  end
    

  table.insert(port.version.cpe, ("Version: %s"):format(current_version))

  nmap.set_port_version(host, port, "hardmatched")

  local response = stdnse.output_table()

  response["Current API Version"] = ("%s"):format(current_version)
  response["Minimum API Version"] = ("%s"):format(minimum_version)

  return response
end
