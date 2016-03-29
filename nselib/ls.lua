---
-- Report file and directory listings.
--
-- For scripts that gather and report directory listings, this script provides
-- a common output format and helpful script arguments.
--
-- The arguments can either be set for all the scripts using this
-- module (--script-args ls.arg=value) or for one particular script
-- (--script-args afp-ls.arg=value). If both are specified for the
-- same argument, the script-specific value is used.
--
-- @args ls.maxdepth The maximum depth to recurse into a directory. If less
--                   than 0 (e.g. -1) then recursion is unlimited.
--                   (default: 0, no recursion).
-- @args ls.maxfiles The maximum number of files to return. Set to 0 or less to
--                   disable this limit. (default: 10).
-- @args ls.checksum (boolean) Download each file and calculate a
--                   SHA1 checksum. Although this is a module
--                   argument, the implementation is done in each
--                   script and is currently only supported by smb-ls
--                   and http-ls
-- @args ls.errors   (boolean) Report errors
-- @args ls.empty    (boolean) Report empty volumes (with no information
--                   or error)
-- @args ls.human    (boolean) Show file sizes in human-readable format with K,
--                   M, G, T, P suffixes. Some services return human-readable
--                   sizes natively; in these cases, the size is reported as
--                   given.
--
-- @author Pierre Lalet <pierre@droids-corp.org>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-----------------------------------------------------------------------

local LIBRARY_NAME = "ls"

local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"

_ENV = stdnse.module("ls", stdnse.seeall)

local config_values = {
  ["maxdepth"] = 1,
  ["maxfiles"] = 10,
  ["checksum"] = false,
  ["errors"] = false,
  ["empty"] = false,
  ["human"] = false,
}

--- Convert an argument to its expected type
local function convert_arg(argval, argtype)
  if argtype == "number" then
    return tonumber(argval)
  elseif argtype == "boolean" then
    if argval == "false" or argval == "no" or argval == "0" then
      return false
    else
      return true
    end
  end
  return argval
end

--- Update config_values using module arguments ("ls.argname", as
-- opposed to script-specific arguments, "http-ls.argname")
for argname, argvalue in pairs(config_values) do
  local argval = stdnse.get_script_args(LIBRARY_NAME .. "." .. argname)
  if argval ~= nil then
    config_values[argname] = convert_arg(argval, type(argvalue))
  end
end

--- Get a config value from (by order or priority):
-- 1. a script-specific argument (e.g., http-ls.argname)
-- 2. a module argument (ls.argname)
-- 3. the default value
-- @param argname The name of the configuration parameter
-- @return The configuration value
function config(argname)
  local argval = stdnse.get_script_args(stdnse.getid() .. "." .. argname)
  if argval == nil then
    return config_values[argname]
  else
    return convert_arg(argval, type(config_values[argname]))
  end
end

--- Create a new script output.
-- @return The ls output object to be passed to other functions
function new_listing()
  local output = stdnse.output_table()
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

--- Create a new volume within the provided output
-- @param output The ls output object, from new_listing()
-- @param name The name of the volume
-- @param hasperms Boolean true if the volume listing will include permissions
function new_vol(output, name, hasperms)
  local curvol = stdnse.output_table()
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
  curvol['name'] = name
  curvol['files'] = files
  curvol['count'] = 0
  curvol['bytes'] = 0
  curvol['errors'] = {}
  curvol['info'] = {}
  curvol['hasperms'] = hasperms
  output['curvol'] = curvol
end

--- Report an error, using stdnse.debug() and (depending on the
-- configuration settings) adding the error message to the output.
-- @param output The ls output object, from new_listing()
-- @param err The error message to report
-- @param level The debug level (default: 1)
function report_error(output, err, level)
  level = level or 1
  if output["curvol"] == nil then
    stdnse.debug(level, string.format("error: %s", err))
  else
    stdnse.debug(level, string.format("error [%s]: %s",
      output["curvol"]["name"], err))
  end
  if config('errors') then
    if output["curvol"] == nil then
      table.insert(output["errors"], err)
    else
      table.insert(output["curvol"]["errors"], err)
    end
  end
end

--- Report information, using stdnse.debug() and adding the message
-- to the output.
-- @param output The ls output object, from new_listing()
-- @param info The info message to report
-- @param level The debug level (default: 1)
function report_info(output, info, level)
  level = level or 1
  if output["curvol"] == nil then
    stdnse.debug(level, string.format("info: %s", info))
    table.insert(output["info"], info)
  else
    stdnse.debug(level, string.format("info [%s]: %s",
      output["curvol"]["name"],  info))
    table.insert(output["curvol"]["info"], info)
  end
end

local units = {
  ["k"] = 1024,
  ["m"] = 1024^2,
  ["g"] = 1024^3,
  ["t"] = 1024^4,
  ["p"] = 1024^5,
}

--- Get a size as an integer from a (possibly) human readable input.
local function get_size(size)
  local bsize = tonumber(size)
  if bsize == nil then
    local unit = string.lower(string.sub(size, -1, -1))
    bsize = tonumber(string.sub(size, 0, -2))
    if units[unit] ~= nil and bsize ~= nil then
      bsize = bsize * units[unit]
      local sigfigs = #(string.match(size, "[0-9.]+"))
      if string.find(size, "%.") then
        sigfigs = sigfigs - 1
      end
      local d = math.ceil(math.log(bsize, 10))
      local power = sigfigs - d
      local magnitude = 10^power
      local shifted = math.floor(bsize * magnitude)
      bsize = math.floor(shifted / magnitude)
    else
      bsize = nil
    end
  end
  return bsize
end

--- Add a new file to the current volume.
-- @param output The ls output object, from new_listing()
-- @param file A table containing the information about the file
-- @return Boolean true if the script may continue adding files, false if
--         maxfiles has been reached.
function add_file(output, file)
  local curvol = output.curvol
  local files = curvol["files"]
  for i, info in ipairs(file) do
    tab.add(files, i, tostring(info))
  end
  local size = get_size(file[curvol.hasperms and 4 or 1])
  if size then
    curvol["bytes"] = curvol["bytes"] + size
  end
  tab.nextrow(files)
  curvol["count"] = curvol["count"] + 1
  return (config("maxfiles") == 0 or config("maxfiles") == nil
    or config("maxfiles") > curvol["count"])
end

--- Close the current volume. It is mandatory to call this function
-- before calling new_vol() again or before calling end_listing().
-- @param output The ls output object, from new_listing()
function end_vol(output)
  local curvol = output.curvol
  local vol = {["volume"] = curvol["name"]}
  local empty = true
  -- "files" is a tab.lua table, so row 1 is the table heading
  if #curvol["files"] ~= 1 then
    vol["files"] = curvol["files"]
    empty = false
  end
  if #curvol["errors"] ~= 0 then
    vol["errors"] = curvol["errors"]
    empty = false
  end
  if #curvol["info"] ~= 0 then
    vol["info"] = curvol["info"]
    empty = false
  end
  if not empty or config("empty") then
    table.insert(output["volumes"], vol)
  end
  output["total"]["files"] = output["total"]["files"] + curvol["count"]
  output["total"]["bytes"] = output["total"]["bytes"] + curvol["bytes"]
  output["curvol"] = nil
end

--- Convert a files table to structured data.
local function files_to_structured(files)
  local result = {}
  local fields = table.remove(files, 1)
  for i=1, #fields do
    fields[i] = string.lower(fields[i])
  end
  for i, file in ipairs(files) do
    result[i] = {}
    for j, value in ipairs(file) do
      result[i][fields[j]] = value
    end
  end
  return result
end

--- Convert a files table to human readable data.
local function files_to_readable(files)
  local outtab = tab.new()
  local fields = files[1]
  local isize
  tab.addrow(outtab, table.unpack(fields))
  for i, field in ipairs(fields) do
    if string.lower(field) == "size" then
      isize = i
      break
    end
  end
  local units = {"K", "M", "G", "T", "P"}
  for i = 2, #files do
    local outfile = {}
    for j, value in ipairs(files[i]) do
      outfile[j] = value
    end
    if config("human") then
      local size = tonumber(outfile[isize])
      -- If tonumber didn't work, it's already in human-readable format
      if size ~= nil then
        local iunit = 0
        while size > 1024 and units[iunit+1] do
          size = size / 1024
          iunit = iunit + 1
        end
        if units[iunit] then
          outfile[isize] = string.format("%.1f %s", size, units[iunit])
        else
          outfile[isize] = tostring(size)
        end
      end
    end
    tab.addrow(outtab, table.unpack(outfile))
  end
  return tab.dump(outtab)
end

--- Close current listing. Return both the structured and the human
--  readable outputs.
-- @param output The ls output object, from new_listing()
-- @return Structured output
-- @return Human readable output
function end_listing(output)
  assert(output["curvol"] == nil)
  local text = {}
  local empty = true
  if #output["info"] == 0 then
    output["info"] = nil
  else
    for _, line in ipairs(output["info"]) do
      text[#text + 1] = line
    end
    empty = false
  end
  if #output["errors"] == 0 then
    output["errors"] = nil
  else
    for _, line in ipairs(output["errors"]) do
      text[#text + 1] = string.format("ERROR: %s", line)
    end
    empty = false
  end
  if #output["volumes"] == 0 then
    output["volumes"] = nil
    output["total"] = nil
  else
    for _, volume in ipairs(output["volumes"]) do
      text[#text + 1] = string.format("Volume %s", volume["volume"])
      if volume["info"] then
        for _, line in ipairs(volume["info"]) do
          text[#text + 1] = string.format("  %s", line)
        end
      end
      if volume["errors"] then
        for _, line in ipairs(volume["errors"]) do
          text[#text + 1] = string.format("  ERROR: %s", line)
        end
      end
      if volume["files"] then
        text[#text + 1] = files_to_readable(volume["files"])
        volume["files"] = files_to_structured(volume["files"])
      end
      text[#text + 1] = ""
    end
    empty = false
  end
  if empty then
    return nil
  else
    return output, table.concat(text, "\n")
  end
end

return _ENV
