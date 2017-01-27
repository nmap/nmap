---
-- Read and parse some of Nmap's data files: <code>nmap-protocols</code>,
-- <code>nmap-rpc</code>, <code>nmap-services</code>, and
-- <code>nmap-mac-prefixes</code>.
--
-- The functions in this module return values appropriate for use with exception
-- handling via <code>nmap.new_try</code>. On success, they return true and
-- the function result. On failure, they return false and an error message.
-- @author Kris Katterjohn 03/2008
-- @author jah 08/2008
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("datafiles", stdnse.seeall)


---
-- Capture patterns for common data files, indexed by filename.
-- @class table
-- @name common_files
-- @see parse_file
local common_files = {
  ["nmap-rpc"]       = { [function(ln) return tonumber( ln:match( "^%s*[^%s#]+%s+(%d+)" ) ) end] = "^%s*([^%s#]+)%s+%d+" },
  ["nmap-protocols"] = { [function(ln) return tonumber( ln:match( "^%s*[^%s#]+%s+(%d+)" ) ) end] = "^%s*([^%s#]+)%s+%d+" },
  ["nmap-services"]  = { ["tcp"] = { [function(ln) return tonumber( ln:match( "^%s*[^%s#]+%s+(%d+)/tcp" ) ) end] = "^%s*([^%s#]+)%s+%d+/tcp" },
    ["udp"] = { [function(ln) return tonumber( ln:match( "^%s*[^%s#]+%s+(%d+)/udp" ) ) end] = "^%s*([^%s#]+)%s+%d+/udp" }
  },
  ["nmap-mac-prefixes"] = { [ "^%s*(%w+)%s+[^#]+" ] = "^%s*%w+%s+([^#]+)" }

}

-- Helper for parse_* functions
local parse_and_cache = function(filename)
  nmap.registry.datafiles = nmap.registry.datafiles or {}
  if not nmap.registry.datafiles[filename] then
    local status
    status, nmap.registry.datafiles[filename] = parse_file(filename)
    if not status then
      return false, string.format("Error parsing %s", filename)
    end
  end

  return true, nmap.registry.datafiles[filename]
end


---
-- Read and parse <code>nmap-protocols</code>.
--
-- On success, return true and a table mapping protocol numbers to protocol
-- names.
-- @return Status (true or false).
-- @return Table (if status is true) or error string (if status is false).
-- @see parse_file
parse_protocols = function()
  return parse_and_cache("nmap-protocols")
end


---
-- Read and parse <code>nmap-rpc</code>.
--
-- On success, return true and a table mapping RPC numbers to RPC names.
-- @return Status (true or false).
-- @return Table (if status is true) or error string (if status is false).
-- @see parse_file
parse_rpc = function()
  return parse_and_cache("nmap-rpc")
end


---
-- Read and parse <code>nmap-services</code>.
--
-- On success, return true and a table containing two subtables, indexed by the
-- keys "tcp" and "udp". The <code>tcp</code> subtable maps TCP port numbers to
-- service names, and the <code>udp</code> subtable is the same for UDP. You can
-- pass "tcp" or "udp" as an argument to <code>parse_services</code> to get
-- only one of the results tables.
-- @param protocol The protocol table to return (<code>"tcp"</code> or
-- <code>"udp"</code>).
-- @return Status (true or false).
-- @return Table (if status is true) or error string (if status is false).
-- @see parse_file
parse_services = function(protocol)
  if protocol and protocol ~= "tcp" and protocol ~= "udp" then
    return false, "Bad protocol for nmap-services: use tcp or udp"
  end

  local services_table
  nmap.registry.datafiles = nmap.registry.datafiles or {}
  nmap.registry.datafiles.services = nmap.registry.datafiles.services or {}
  if protocol then
    if not nmap.registry.datafiles.services[protocol] then
      local status
      status, nmap.registry.datafiles.services[protocol] = parse_file("nmap-services", protocol)
      if not status then
        return false, "Error parsing nmap-services"
      end
    end
    services_table = nmap.registry.datafiles.services[protocol]
  else
    local status
    status, nmap.registry.datafiles.services = parse_file("nmap-services")
    if not status then
      return false, "Error parsing nmap-services"
    end
    services_table = nmap.registry.datafiles.services
  end

  return true, services_table
end


---
-- Read and parse <code>nmap-mac-prefixes</code>.
--
-- On success, return true and a table mapping 3 byte MAC prefixes to manufacturer names.
-- @return Status (true or false).
-- @return Table (if status is true) or error string (if status is false).
-- @see parse_file
parse_mac_prefixes = function()
  return parse_and_cache("nmap-mac-prefixes")
end


---
-- Read and parse a generic data file. The other parse functions are
-- defined in terms of this one.
--
-- If filename is a key in <code>common_files</code>, use the corresponding
-- capture pattern. Otherwise the second argument must be a table of the kind
-- taken by <code>parse_lines</code>.
-- @param filename Name of the file to parse.
-- @param ... A table of capture patterns.
-- @return Boolean status, false on failure
-- @return A table whose structure mirrors that of the capture table,
-- filled in with captured values.
function parse_file(filename, ...)

  local data_struct

  -- must have a filename
  if type( filename ) ~= "string" or filename == "" then
    return false, "Error in datafiles.parse_file: No file to parse."
  end

  -- is filename a member of common_files? is second parameter a key in common_files or is it a table?
  if common_files[filename] and type( (...) ) == "string" and common_files[filename][(...)] then
    data_struct = { common_files[filename][(...)] }
  elseif common_files[filename] and select("#", ...) == 0 then
    data_struct = { common_files[filename] }
  elseif type( (...) ) == "table" then
    data_struct = {...}
  elseif type( (...) ) ~= "table" then
    return false, "Error in datafiles.parse_file: Expected second parameter as table."
  end

  if type( data_struct ) == "table" then
    for i, struc in ipairs( data_struct ) do
      -- check that all varargs are tables
      if type( struc ) ~= "table" then return false, "Error in datafiles.parse_file: Bad Parameter." end
      -- allow empty table as sugar for ^(.+)$ capture the whole line
      if not next( struc ) and #struc == 0 then data_struct[i] = { "^(.+)$" } end
    end
    if #data_struct == 0 then
      return false, "Error in datafiles.parse_file: I've no idea how you want your data."
    end
  end

  -- get a table of lines
  local status, lines = read_from_file( filename )
  if not status then
    return false, ( "Error in datafiles.parse_file: %s could not be read: %s." ):format( filename, lines )
  end

  -- do the actual parsing
  local ret = {}
  for _, ds in ipairs( data_struct ) do
    status, ret[#ret+1] = parse_lines( lines, ds )
    -- hmmm should we fail all if there are any failures? yes? ok
    if not status then return false, ret[#ret] end
  end

  return true, table.unpack( ret )

end


---
-- Generic parsing of an array of strings.
-- @param lines An array of strings to operate on.
-- @param data_struct A table containing capture patterns to be applied
-- to each string in the array. A capture will be applied to each string
-- using <code>string.match</code> and may also be enclosed within a table or
-- a function. If a function, it must accept a string as its parameter and
-- should return one value derived from that string.
-- @return A table whose structure mirrors that of the capture table,
-- filled in with captured values.
function parse_lines(lines, data_struct)

  if type( lines ) ~= "table" or #lines < 1 then
    return false, "Error in datafiles.parse_lines: No lines to parse."
  end

  if type( data_struct ) ~= "table" or not next( data_struct ) then
    return false, "Error in datafiles.parse_lines: Expected second parameter as a non-empty table."
  end

  local ret = {}

  -- traverse data_struct and enforce sensible index-value pairs.  Call functions to process the members of lines.
  for index, value in pairs( data_struct ) do
    if type(index) == nil then return false, "Error in datafiles.parse_lines: Invalid index." end
    if type(index) == "number" or type(value) == "table" then
      if type(value) == "number" then
        return false, "Error in datafiles.parse_lines: No patterns for data capture."
      elseif type(value) == "string" or type(value) == "function" then
        ret = get_array( lines, value )
      elseif type(value) == "table" then
        local _
        _, ret[index] = parse_lines( lines, value )
      else
        -- TEMP
        stdnse.debug1("Error in datafiles.parse_lines: Index with type %s has unexpected value %s", type(index), type(value))
      end
    elseif type(index) == "string" or type(index) == "function"  then
      if type( value ) == "string" or type( value ) == "function" then
        ret = get_assoc_array( lines, index, value )
      else
        return false, ( "Error in datafiles.parse_lines: Invalid value for index %s." ):format( index )
      end
    else
      -- TEMP
      stdnse.debug1("Error in datafiles.parse_lines: Index with type %s has unexpected value %s", type(index), type(value))
    end
  end

  return true, ret

end


---
-- Read a file, line by line, into a table.
-- @param file String with the name of the file to read.
-- @return Status (true or false).
-- @return Array of lines read from the file (if status is true) or error
-- message (if status is false).
function read_from_file( file )

  -- get path to file
  local filepath = nmap.fetchfile( file )
  if not filepath then
    return false, ( "Error in nmap.fetchfile: Could not find file %s." ):format( file )
  end

  local f, err, _ = io.open( filepath, "r" )
  if not f then
    return false, ( "Error in datafiles.read_from_file: Cannot open %s for reading: %s" ):format( filepath, err )
  end

  local ret = {}
  for line in f:lines() do
    ret[#ret+1] = line
  end

  f:close()

  return true, ret

end


---
-- Return an array-like table of values captured from each line.
-- @param lines Table of strings containing the lines to process.
-- @param v_pattern Pattern to use on the lines to produce the value for the
-- array.
get_array = function(lines, v_pattern)
  local ret = {}
  for _, line in ipairs( lines ) do
    assert( type( line ) == "string" )
    local captured
    if type( v_pattern ) == "function" then
      captured = v_pattern( line )
    else
      captured = line:match( v_pattern )
    end
    table.insert( ret, captured )
  end
  return ret
end


---
-- Return a table of index-value pairs captured from each line.
-- @param lines Table of strings containing the lines to process.
-- @param i_pattern Pattern to use on the lines to produce the key for the
-- associative array.
-- @param v_pattern Pattern to use on the lines to produce the value for the
-- associative array.
get_assoc_array = function(lines, i_pattern, v_pattern)
  local ret = {}
  for _, line in ipairs(lines) do
    assert( type( line ) == "string" )
    local index
    if type(i_pattern) == "function" then
      index = i_pattern(line)
    else
      index = line:match(i_pattern)
    end
    if index and type(v_pattern) == "function" then
      local m = v_pattern(line)
      if m then ret[index] = m end
    elseif index then
      local m = line:match(v_pattern)
      if m then ret[index] = m end
    end
  end
  return ret
end

return _ENV;
