-- See nmaps COPYING for licence
module(...,package.seeall)

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


-- fetch relative URL with get request
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

-- fetch URL with get request
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

-- send http request and return the result as table
-- host may be a table or the hostname
-- port may be a table or the portnumber
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

  local buffer = stdnse.make_buffer( socket, "\r?\n" )

  local status, line, _
  local header, body = {}, {}

  -- header loop
  while true do
    status, line = buffer()
    if (not status or line == "") then break end
    table.insert(header,line)
  end

  -- build nicer table for header
  local last_header, match
  for number, line in pairs( header ) do
    if number == 1 then
      local code
      _, _, code = string.find( line, "HTTP/%d\.%d (%d+)")
      result.status = tonumber(code)
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
        if match and value then
          result.header[last_header] = result.header[last_header] .. ',' .. value
        end
      end
    end
  end

  -- body loop
  while true do
    status, line = buffer()
    if (not status) then break end
    table.insert(body,line)
  end

  socket:close()
  result.body = table.concat( body, "\n" )

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