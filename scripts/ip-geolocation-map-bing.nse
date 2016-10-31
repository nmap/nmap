local http = require "http"
local geoip = require "geoip"
local io = require "io"
local stdnse = require "stdnse"
local table = require "table"

description = [[
]]

---
-- @usage
-- nmap -sn -Pn --script ip-geolocation-geoplugin,ip-geolocation-map-bing --script-args ip-geolocation-map-bing.api_key=[redacted],ip-geolocation-map-bing.map_path=map.png <target>
--
-- @output
-- | ip-geolocation-map-bing:
-- |_  The map has been saved at 'nmap.png'.
--
-- @args ip-geolocation-map-bing.api_key (REQUIRED)
-- @args ip-geolocation-map-bing.center
-- @args ip-geolocation-map-bing.format
-- @args ip-geolocation-map-bing.language
-- @args ip-geolocation-map-bing.layer
-- @args ip-geolocation-map-bing.map_path (REQUIRED)
-- @args ip-geolocation-map-bing.marker_style
-- @args ip-geolocation-map-bing.scale
-- @args ip-geolocation-map-bing.size

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

local render = function(query, body, path)
  local options = {
    ["header"] = {
      ["Content-Type"] = "text/plain; charset=utf-8"
    }
  }

  local res = http.post("dev.virtualearth.net", 80, query, options, nil, body)
  if not res or res.status ~= 200 then
    stdnse.debug1("Error %d from API: %s", res.status, res.body)
    return false, ("Failed to recieve map using query '%s'."):format(query)
  end

  local f = io.open(path, "w")
  if not f then
    return false, ("Failed to open file '%s'."):format(path)
  end

  if not f:write(res.body) then
    return false, ("Failed to write file '%s'."):format(path)
  end

  f:close()

  return true, ("The map has been saved at '%s'."):format(path)
end

local parse_args = function()
  local query = "/REST/v1/Imagery/Map/"

  local layer = stdnse.get_script_args(SCRIPT_NAME .. "layer")
  if not layer then
    layer = "Road"
  end
  query = query .. layer .. "?"

  local api_key = stdnse.get_script_args(SCRIPT_NAME .. '.api_key')
  if not api_key then
    return false, "Need to specify an API key, get one at https://www.bingmapsportal.com/."
  end
  query = query .. "key=" .. api_key

  local center = stdnse.get_script_args(SCRIPT_NAME .. "center")
  if center then
    query = query .. "&center=" .. center
  end

  local format = stdnse.get_script_args(SCRIPT_NAME .. "format")
  if format then
    query = query .. "&fmt=" .. format
  end

  local language = stdnse.get_script_args(SCRIPT_NAME .. "language")
  if language then
    query = query .. "&language=" .. language
  end

  local map_path = stdnse.get_script_args(SCRIPT_NAME .. '.map_path')
  if not map_path then
    return false, "Need to specify a path for the map."
  end

  local scale = stdnse.get_script_args(SCRIPT_NAME .. "scale")
  if scale then
    query = query .. "&scale=" .. scale
  end

  local size = stdnse.get_script_args(SCRIPT_NAME .. "size")
  if not size then
    size = "1280x1280"
  end
  size = string.gsub(size, "x", ",")
  query = query .. "&mapSize=" .. size

  -- Add in a pushpin for each host.
  pushpins = {}
  for ip, coords in pairs(geoip.get_all()) do
    table.insert(pushpins, "pp=" .. coords["latitude"] .. "," .. coords["longitude"])

    -- The API allows up to 100 pushpins with the POST method.
    if #pushpins >= 100 then
      break
    end
  end
  body = table.concat(pushpins, "&")

  return true, query, body, map_path
end

postrule = function()
  return not geoip.empty()
end

action = function()
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, query, body, path = parse_args()
  if not status then
    output.ERROR = query
    return output, output.ERROR
  end

  -- Render the map.
  local status, msg = render(query, body, path)
  if not status then
    output.ERROR = msg
    return output, output.ERROR
  end

  return output, stdnse.format_output(true, msg)
end
