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
-- @args ls.errors   [optional] report connection errors
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
}
local config_types = {
  ["pattern"] = "string",
  ["maxdepth"] = "number",
  ["maxfiles"] = "number",
  ["checksum"] = "boolean",
  ["errors"] = "boolean",
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

for argname, argtype in pairs(config_types) do
  local argval = stdnse.get_script_args(LIBRARY_NAME .. "." .. argname)
  if argval ~= nil then
    config_values[argname] = convert_arg(argval, argtype)
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
    return convert_arg(argval, config_types[argname])
  end
end

function new_listing()
  local output = {}
  output['curvol'] = nil
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
  curvol['errors'] = {}
  output['curvol'] = curvol
end

function report_error(output, err)
  stdnse.debug1(err)
  if config('errors') then
    if output["curvol"] == nil then
      table.insert(output, err)
    else
       table.insert(output["curvol"]["errors"], err)
    end
  end
end

function report_info(output, info)
  stdnse.debug1(info)
  if output["curvol"] == nil then
    table.insert(output, info)
  else
    table.insert(output["curvol"]["info"], info)
  end
end

function add_file(output, file)
  -- returns true iff script should continue
  local files = output["curvol"]["files"]
  for i, info in ipairs(file) do
    tab.add(files, i, info)
  end
  output["curvol"]["count"] = output["curvol"]["count"] + 1
  tab.nextrow(files)
  return (config("maxfiles") == 0 or config("maxfiles") == nil
	    or config("maxfiles") > output["curvol"]["count"])
end

function end_vol(output)
  local vol = {volume = output["curvol"]["name"],
	       files = "\n" .. tab.dump(output["curvol"]["files"])}
  if #output["curvol"]["errors"] ~= 0 then
    vol["error"] = output["curvol"]["errors"]
  end
  if #output["curvol"]["info"] ~= 0 then
    vol["info"] = output["curvol"]["info"]
  end
  table.insert(output, vol)
  output["curvol"] = nil
end

return _ENV
