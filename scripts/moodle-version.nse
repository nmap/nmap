description = [[
Uses the version number disclosed in an API error message to get an idea of the Moodle version
installed on the server.
]]

---
-- @usage
-- nmap --script moodle-version -p443 <host>
--
-- @output
-- | moodle-version:
-- |   Moodle version: 403
----------------------------------------------------------

author = "Robin Wood"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local json = require "json"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

local version_mappings = stdnse.output_table()

version_mappings["400"] = "4.0.x"
version_mappings["401"] = "4.1.x"
version_mappings["402"] = "4.2.x"
version_mappings["403"] = "4.3.x"

portrule = function (host, port)
  if nmap.version_intensity() < 7 or nmap.port_is_excluded(port.number, port.protocol) then
    return false
  end
  return shortport.http(host, port)
end

local function get_file(host, port, path)
  local req
  req='[{"index":0,"methodname":"core_session_touch"}]'

  local result = http.post( host, port, path, nil, nil, req)
  if(result['status'] ~= 200 or result['content-length'] == 0) then
    return false, "Couldn't download file: " .. path
  end

  return true, result.body
end

action = function(host, port)
  local result, body = get_file(host, port, "/lib/ajax/service.php")

  if(not(result)) then
    stdnse.debug1("%s", body)
    return nil
  end

  local version
  local ok_json, response = json.parse(body)
  local moreinfourl = response[1]['exception']['moreinfourl']

  if ok_json and moreinfourl then
    version = moreinfourl:match (".*/([0-9]*)/en/error")
  end

  if not version then
    stdnse.debug1("Could not find more info URL.")
    return nil
  end

  if version_mappings[version] then
    version = version_mappings[version]
  end

  if not port.version.version then
    port.version.version = version
  end
  
  nmap.set_port_version(host, port, "hardmatched")

  local response = stdnse.output_table()

  response["Moodle version"] = ("%s"):format(version)

  return response
end
