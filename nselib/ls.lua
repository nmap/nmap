---
-- Implements reports of file listings.
--
-- TODO: report files as structured data with the same human readable
-- output.
--
-- Scripts that use this module can use the script arguments listed below:
-- @args ls.maxdepth [optional] the maximum depth to recurse into a directory
--                   (default: no recursion).
-- @args ls.maxfiles [optional] the maximum number of files to return
--                   (default: 1, no recursion).
-- @args ls.pattern  [optional] return only files that match the given pattern
-- @args ls.checksum [optional] download each file and calculate a SHA1 checksum
-- @args ls.errors   [optional] report errors
-- @args ls.empty    [optional] report empty volumes (with no information
--                   or error)
--
-- These arguments can either be set for all the scripts using this
-- module (--script-args ls.arg=value) or for one particular script
-- (--script-args afp-ls.arg=value). If both are specified for the
-- same argument, the script-specific value is used.
--
-- @author Pierre Lalet <pierre@droids-corp.org>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-----------------------------------------------------------------------

local LIBRARY_NAME = "ls"

local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

_ENV = stdnse.module("ls", stdnse.seeall)

local config_values = {
  ["maxdepth"] = 1,
  ["maxfiles"] = 10,
  ["pattern"] = "*",
  ["checksum"] = false,
  ["errors"] = false,
  ["empty"] = false,
  ["human"] = false,
}

local function convert_arg(argval, argtype)
  if argtype == "number" then
    return tonumber(argval)
  elseif argtype == "boolean" then
    if argval == "true" or argval == "yes" then
      return true
    else
      return false
    end
  end
  return argval
end

for argname, argvalue in pairs(config_values) do
  local argval = stdnse.get_script_args(LIBRARY_NAME .. "." .. argname)
  if argval ~= nil then
    config_values[argname] = convert_arg(argval, type(argvalue))
  end
end

function config(argname)
  -- get a config value from (by order or priority):
  --   1. a script-specific argument (e.g., http-ls.*)
  --   2. a module argument (ls.*)
  --   3. the default value
  local argval = stdnse.get_script_args(stdnse.getid() .. "." .. argname)
  if argval == nil then
    return config_values[argname]
  else
    return convert_arg(argval, type(config_values[argname]))
  end
end

function new_listing()
  local output = {}
  output['curvol'] = nil
  output['volumes'] = {}
  output['errors'] = {}
  output['info'] = {}
  output['total'] = {
    ['files'] = 0,
    ['bytes'] = 0,
  }
  return output
end

function new_vol(output, name, hasperms)
  local curvol = {}
  local files = tab.new()
  local i = 1
  if hasperms then
     tab.add(files, 1, "PERMISSION")
     tab.add(files, 2, "UID")
     tab.add(files, 3, "GID")
     i = 4
  end
  tab.add(files, i, "SIZE")
  tab.add(files, i + 1, "TIME")
  tab.add(files, i + 2, "FILENAME")
  if config("checksum") then
    tab.add(files, i + 3, "CHECKSUM")
  end
  tab.nextrow(files)
  curvol['files'] = files
  curvol['name'] = name
  curvol['count'] = 0
  curvol['bytes'] = 0
  curvol['errors'] = {}
  curvol['info'] = {}
  curvol['hasperms'] = hasperms
  output['curvol'] = curvol
end

function report_error(output, err)
  if output["curvol"] == nil then
    stdnse.debug1("error: " .. err)
  else
    stdnse.debug1("error [" .. output["curvol"]["name"] .. "]: " .. err)
  end
  if config('errors') then
    if output["curvol"] == nil then
      table.insert(output["errors"], err)
    else
      table.insert(output["curvol"]["errors"], err)
    end
  end
end

function report_info(output, info)
  if output["curvol"] == nil then
    stdnse.debug1("info: " .. info)
    table.insert(output["info"], info)
  else
    stdnse.debug1("info [" .. output["curvol"]["name"] .. "]: " .. info)
    table.insert(output["curvol"]["info"], info)
  end
end

local units = {
  ["k"] = 1024,
  ["m"] = 1048576,
  ["g"] = 1073741824,
  ["t"] = 1099511627776,
}

function add_file(output, file)
  -- returns true iff script should continue
  local files = output["curvol"]["files"]
  local size, bsize
  for i, info in ipairs(file) do
    if type(info) == "number" then
      tab.add(files, i, tostring(info))
    else
      tab.add(files, i, info)
    end
  end
  tab.nextrow(files)
  output["curvol"]["count"] = output["curvol"]["count"] + 1
  if output["curvol"]["hasperms"] then
    size = file[4]
  else
    size = file[1]
  end
  bsize = tonumber(size)
  if bsize == nil then
    local unit = string.lower(string.sub(size, -1, -1))
    bsize = tonumber(string.sub(size, 0, -2))
    if units[unit] ~= nil and bsize ~= nil then
      bsize = bsize * units[unit]
    else
      bsize = 0
    end
  end
  output["curvol"]["bytes"] = output["curvol"]["bytes"] + bsize
  return (config("maxfiles") == 0 or config("maxfiles") == nil
	    or config("maxfiles") > output["curvol"]["count"])
end

function end_vol(output)
  local vol = {["volume"] = output["curvol"]["name"]}
  local empty = true
  if #output["curvol"]["files"] ~= 1 then
    vol["files"] = "\n" .. tab.dump(output["curvol"]["files"])
    empty = false
  end
  if #output["curvol"]["errors"] ~= 0 then
    vol["errors"] = output["curvol"]["errors"]
    empty = false
  end
  if #output["curvol"]["info"] ~= 0 then
    vol["info"] = output["curvol"]["info"]
    empty = false
  end
  if config("empty") or not empty then
    table.insert(output["volumes"], vol)
  end
  output["total"]["files"] = output["total"]["files"] + output["curvol"]["count"]
  output["total"]["bytes"] = output["total"]["bytes"] + output["curvol"]["bytes"]
  output["curvol"] = nil
end

function end_listing(output)
  if #output["errors"] == 0 then
    output["errors"] = nil
  end
  if #output["info"] == 0 then
    output["info"] = nil
  end
end

return _ENV
