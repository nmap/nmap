--- Client-side HTTP library.
-- \n\n
-- The return value of each function in this module is a table with the
-- following keys: status, status-line, header, and body. status is a number
-- representing the HTTP status code returned in response to the HTTP
-- request. In case of an unhandled error, status is nil. status-line is
-- the entire status message which includes the HTTP version, status code
-- and reason phrase. The header value is a table containing key-value
-- pairs of HTTP headers received in response to the request. The header
-- names are in lower-case and are the keys to their corresponding header
-- values (e.g. header.location = "http://nmap.org/").
-- Multiple headers of the same name are concatenated and separated by
-- commas. The body value is a string containing the body of the HTTP
-- response.
-- @copyright See nmaps COPYING for licence

module(... or "http",package.seeall)

local url    = require 'url'
local stdnse = require 'stdnse'

--
-- http.get( host, port, path, options )
-- http.request( host, port, request, options )
-- http.get_url( url, options )
--
-- host may either be a string or table
-- port may either be a number or a table
--
-- the format of the return value is a table with the following structure:
-- {status = 200, status-line = "HTTP/1.1 200 OK", header = {}, body ="<html>...</html>"}
-- the header table has an entry for each received header with the header name being the key
-- the table also has an entry named "status" which contains the http status code of the request
-- in case of an error status is nil


--- Fetches a resource with a GET request. The first argument is either a
-- string with the hostname or a table like the host table passed by nmap.
-- The second argument is either the port number or a table like the port
-- table passed by nmap. The third argument is the path of the resource.
-- The fourth argument is a table for further options. The table may have
-- 2 keys: timeout and header. timeout is the timeout used for the socket
-- operations. header is a table with additional headers to be used for
-- the request. The function builds the request and calls http.request.
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options. See function description.
-- @return table
get = function( host, port, path, options )
  options = options or {}
  local presets = {Host=host,Connection="close",['User-Agent']="Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"}
  if type(host) == 'table' then
    presets['Host'] = host.targetname or ( host.name ~= '' and host.name ) or host.ip
  end

  local header = options.header or {}
  for key,value in pairs(presets) do
    header[key] = header[key] or value
  end

  local data = "GET "..path.." HTTP/1.1\r\n"
  for key,value in pairs(header) do
    data = data .. key .. ": " .. value .. "\r\n"
  end
  data = data .. "\r\n"

  return request( host, port, data, options )
end

--- Parses url and calls http.get with the result. The second argument
-- is a table for further options. The table may have 2 keys: timeout
-- and header. timeout is the timeout used for the socket operations.
-- header is a table with additional headers to be used for the request. 
-- @param url The url of the host.
-- @param options Options passed to http.get.
-- @see http.get
get_url = function( u, options )
  local parsed = url.parse( u )
  local port = {}

  port.service = parsed.scheme
  port.number = parsed.port

  if not port.number then
    if parsed.scheme == 'https' then
      port.number = 443
    else
      port.number = 80
    end
  end

  local path = parsed.path or "/"
  if parsed.query then
    path = path .. "?" .. parsed.query
  end

  return get( parsed.host, port, path, options )
end

--- Sends request to host:port and parses the answer. The first argument
-- is either a string with the hostname or a table like the host table
-- passed by nmap. The second argument is either the port number or a
-- table like the port table passed by nmap. SSL is used for the request
-- if either port.service  equals https or port.version.service_tunnel
-- equals ssl. The third argument is the request. The fourth argument is
-- a table for further options. You can specify a timeout for the socket
-- operations with the timeout key. 
-- @param host The host to query.
-- @param port The port on the host.
-- @param data Data to send initially to the host.
-- @param options Table of options.
-- @see http.get
request = function( host, port, data, options )
  options = options or {}

  if type(host) == 'table' then
    host = host.ip
  end

  local protocol = 'tcp'
  if type(port) == 'table' then
    if port.service == 'https' or ( port.version and port.version.service_tunnel == 'ssl' ) then
      protocol = 'ssl'
    end
    port = port.number
  end

  local result = {status=nil,["status-line"]=nil,header={},body=""}
  local socket = nmap.new_socket()
  local default_timeout = {}
  if options.timeout then
    socket:set_timeout( options.timeout )
  else
    default_timeout = get_default_timeout( nmap.timing_level() )
    socket:set_timeout( default_timeout.connect )
  end

  if not socket:connect( host, port, protocol ) then
    return result
  end

  if not options.timeout then
    socket:set_timeout( default_timeout.request )
  end

  if not socket:send( data ) then
    return result
  end

  -- no buffer - we want everything now!
  local response = {}
  while true do
    local status, part = socket:receive()
    if not status then
      break
    else
      response[#response+1] = part
    end
  end

  socket:close()

  response = table.concat( response )

  -- try and separate the head from the body
  local header, body
  if response:match( "\r?\n\r?\n" ) then
    header, body = response:match( "^(.-)\r?\n\r?\n(.*)$" )
  else
    header, body = "", response
  end

  header = stdnse.strsplit( "\r?\n", header )

  local line, _

  -- build nicer table for header
  local last_header, match
  for number, line in ipairs( header or {} ) do
    if number == 1 then
      local code
      _, _, code = string.find( line, "HTTP/%d\.%d (%d+)")
      result.status = tonumber(code)
      if code then result["status-line"] = line end
    else
      match, _, key, value = string.find( line, "(.+): (.*)" )
      if match and key and value then
        key = key:lower()
        if result.header[key] then
          result.header[key] = result.header[key] .. ',' .. value
        else
          result.header[key] = value
        end
        last_header = key
      else
        match, _, value = string.find( line, " +(.*)" )
        if match and value and last_header then
          result.header[last_header] = result.header[last_header] .. ',' .. value
        end
      end
    end
  end

  body_delim = ( body:match( "\r\n" ) and "\r\n" )  or
               ( body:match( "\n" )   and "\n" ) or nil

  -- handle chunked encoding
  if result.header['transfer-encoding'] == 'chunked' and type( body_delim ) == "string" then
    body = body_delim .. body
    local b = {}
    local start, ptr = 1, 1
    local chunk_len
    local pattern = ("%s([^%s]+)%s"):format( body_delim, body_delim, body_delim )
    while ( ptr < ( type( body ) == "string" and body:len() ) or 1 ) do
      local hex = body:match( pattern, ptr )
      if not hex then break end
      chunk_len = tonumber( hex or 0, 16 ) or nil
      if chunk_len then
        start = ptr + hex:len() + 2*body_delim:len()
        ptr = start + chunk_len
        b[#b+1] = body:sub( start, ptr-1 )
      end
    end
    body = table.concat( b )
  end

  -- special case for conjoined header and body
  if type( result.status ) ~= "number" and type( body ) == "string" then
    local code, remainder = body:match( "HTTP/%d\.%d (%d+)(.*)") -- The Reason-Phrase will be prepended to the body :(
    if code then
      stdnse.print_debug( "Interesting variation on the HTTP standard.  Please submit a --script-trace output for this host (%s) to nmap-dev[at]insecure.org.", host )
      result.status = tonumber(code)
      body = remainder or body
    end
  end

  result.body = body

  return result

end

get_default_timeout = function( nmap_timing )
  local timeout = {}
  if nmap_timing >= 0 and nmap_timing <= 3 then
    timeout.connect = 10000
    timeout.request = 15000
  end
  if nmap_timing >= 4 then
    timeout.connect = 5000
    timeout.request = 10000
  end
  if nmap_timing >= 5 then
    timeout.request = 7000
  end
  return timeout
end
