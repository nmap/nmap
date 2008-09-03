--- The http module provides functions for dealing with the client side
-- of the http protocol. The functions reside inside the http namespace.
-- The return value of each function in this module is a table with the
-- following keys: status, header and body. status is a number representing
-- the HTTP status code returned in response to the HTTP request. In case
-- of an unhandled error, status is nil. The header value is a table
-- containing key-value pairs of HTTP headers received in response to the
-- request. The header names are in lower-case and are the keys to their
-- corresponding header values (e.g. header.location = "http://nmap.org/").
-- Multiple headers of the same name are concatenated and separated by
-- commas. The body value is a string containing the body of the HTTP
-- response.
-- @copyright See nmaps COPYING for licence

module(... or "http",package.seeall)

require 'stdnse'
require 'url'

--
-- http.get( host, port, path, options )
-- http.request( host, port, request, options )
-- http.get_url( url, options )
--
-- host may either be a string or table
-- port may either be a number or a table
--
-- the format of the return value is a table with the following structure:
-- {status = 200, header = {}, body ="<html>...</html>"}
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
-- @param options A table of optoins. See function description.
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

  local result = {status=nil,header={},body=""}
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

  local buffer = stdnse.make_buffer( socket, "\r\n" )

  local line, _
  local header, body = {}, {}

  -- header loop
  while true do
    line = buffer()
    if (not line or line == "") then break end
    table.insert(header,line)
  end

  -- build nicer table for header
  local last_header, match
  for number, line in ipairs( header ) do
    if number == 1 then
      local code
      _, _, code = string.find( line, "HTTP/%d\.%d (%d+)")
      result.status = tonumber(code)
      if not result.status then table.insert(body,line) end
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
        elseif match and value then
          table.insert(body,line)
        end
      end
    end
  end

  -- handle body
  if result.header['transfer-encoding'] == 'chunked' then
    -- if the server used chunked encoding we have to 'dechunk' the answer
    local counter, chunk_size
    counter = 0; chunk_size = 0
    while true do
      if counter >= chunk_size then
        counter = 0
        chunk_size = tonumber( buffer(), 16 )
        if chunk_size == 0 or not chunk_size then break end
      end
      line = buffer()
      if not line then break end
      counter = counter + #line + 2
      table.insert(body,line)
    end
  else
    while true do
      line = buffer()
      if not line then break end
      table.insert(body,line)
    end
  end

  socket:close()
  result.body = table.concat( body, "\r\n" )

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
