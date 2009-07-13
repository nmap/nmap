--- Client-side HTTP library.
--
-- The return value of each function in this module is a table with the
-- following keys: <code>status</code>, <code>status-line</code>,
-- <code>header</code>, and <code>body</code>. <code>status</code> is a number
-- representing the HTTP status code returned in response to the HTTP request.
-- In case of an unhandled error, <code>status</code> is <code>nil</code>.
-- <code>status-line</code> is the entire status message which includes the HTTP
-- version, status code, and reason phrase. The <code>header</code> value is a
-- table containing key-value pairs of HTTP headers received in response to the
-- request. The header names are in lower-case and are the keys to their
-- corresponding header values (e.g. <code>header.location</code> =
-- <code>"http://nmap.org/"</code>). Multiple headers of the same name are
-- concatenated and separated by commas. The <code>body</code> value is a string
-- containing the body of the HTTP response.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "http",package.seeall)

local url    = require 'url'
local stdnse = require 'stdnse'
local comm   = require 'comm'

-- Skip *( SP | HT ) starting at offset. See RFC 2616, section 2.2.
-- @return the first index following the spaces.
-- @return the spaces skipped over.
local function skip_space(s, offset)
  local _, i, space = s:find("^([ \t]*)", offset)
  return i + 1, space
end

-- Get a token starting at offset. See RFC 2616, section 2.2.
-- @return the first index following the token, or nil if no token was found.
-- @return the token.
local function get_token(s, offset)
  -- All characters except CTL and separators.
  local _, i, token = s:find("^([^()<>@,;:\\\"/%[%]?={} %z\001-\031\127]+)", offset)
  if i then
    return i + 1, token
  else
    return nil
  end
end

-- Get a quoted-string starting at offset. See RFC 2616, section 2.2. crlf is
-- used as the definition for CRLF in the case of LWS within the string.
-- @return the first index following the quoted-string, or nil if no
-- quoted-string was found.
-- @return the contents of the quoted-string, without quotes or backslash
-- escapes.
local function get_quoted_string(s, offset, crlf)
  local result = {}
  local i = offset
  assert(s:sub(i, i) == "\"")
  i = i + 1
  while i <= s:len() do
    local c = s:sub(i, i)
    if c == "\"" then
      -- Found the closing quote, done.
      return i + 1, table.concat(result)
    elseif c == "\\" then
      -- This is a quoted-pair ("\" CHAR).
      i = i + 1
      c = s:sub(i, i)
      if c == "" then
        -- No character following.
        error(string.format("\\ escape at end of input while parsing quoted-string."))
      end
      -- Only CHAR may follow a backslash.
      if c:byte(1) > 127 then
        error(string.format("Unexpected character with value > 127 (0x%02X) in quoted-string.", c:byte(1)))
      end
    else
      -- This is qdtext, which is TEXT except for '"'.
      -- TEXT is "any OCTET except CTLs, but including LWS," however "a CRLF is
      -- allowed in the definition of TEXT only as part of a header field
      -- continuation." So there are really two definitions of quoted-string,
      -- depending on whether it's in a header field or not. This function does
      -- not allow CRLF.
      c = s:sub(i, i)
      if c ~= "\t" and c:match("^[%z\001-\031\127]$") then
        error(string.format("Unexpected control character in quoted-string: 0x%02X.", c:byte(1)))
      end
    end
    result[#result + 1] = c
    i = i + 1
  end
  return nil
end

-- Get a ( token | quoted-string ) starting at offset.
-- @return the first index following the token or quoted-string, or nil if
-- nothing was found.
-- @return the token or quoted-string.
local function get_token_or_quoted_string(s, offset, crlf)
  if s:sub(offset, offset) == "\"" then
    return get_quoted_string(s, offset)
  else
    return get_token(s, offset)
  end
end

-- This is an interator that breaks a "chunked"-encoded string into its chunks.
-- Each iteration produces one of the chunks.
local function get_chunks(s, offset, crlf)
  local finished_flag = false

  return function()
    if finished_flag then
      -- The previous iteration found the 0 chunk.
      return nil
    end

    offset = skip_space(s, offset)

    -- Get the chunk-size.
    local _, i, hex
    _, i, hex = s:find("^([%x]+)", offset)
    if not i then
      error(string.format("Chunked encoding didn't find hex at position %d; got %q.", offset, s:sub(offset, offset + 10)))
    end
    offset = i + 1

    local chunk_size = tonumber(hex, 16)
    if chunk_size == 0 then
      -- Process this chunk so the caller gets the following offset, but halt
      -- the iteration on the next round.
      finished_flag = true
    end

    -- Ignore chunk-extensions.
    -- RFC 2616, section 2.1 ("Implied *LWS") seems to allow *LWS between the
    -- parts of a chunk-extension, but that is ambiguous. Consider this case:
    -- "1234;a\r\n =1\r\n...". It could be an extension with a chunk-ext-name
    -- of "a" (and no value), and a chunk-data beginning with " =", or it could
    -- be a chunk-ext-name of "a" with a value of "1", and a chunk-data
    -- starting with "...". We don't allow *LWS here, only ( SP | HT ), so the
    -- first interpretation will prevail.
    offset = skip_space(s, offset)
    while s:sub(offset, offset) == ";" do
      local token
      offset = offset + 1
      offset = skip_space(s, offset)
      i, token = get_token(s, offset)
      if not token then
        error(string.format("chunk-ext-name missing at position %d; got %q.", offset, s:sub(offset, offset + 10)))
      end
      offset = i
      offset = skip_space(s, offset)
      if s:sub(offset, offset) == "=" then
        offset = offset + 1
        offset = skip_space(s, offset)
        i, token = get_token_or_quoted_string(s, offset)
        if not token then
          error(string.format("chunk-ext-name missing at position %d; got %q.", offset, s:sub(offset, offset + 10)))
        end
      end
      offset = i
      offset = skip_space(s, offset)
    end

    _, i = s:find("^" .. crlf, offset)
    if not i then
      error(string.format("Didn't find CRLF after chunk-size [ chunk-extension ] at position %d; got %q.", offset, s:sub(offset, offset + 10)))
    end
    offset = i + 1

    -- Now get the chunk-data.
    local chunk = s:sub(offset, offset + chunk_size - 1)
    if chunk:len() ~= chunk_size then
      error(string.format("Chunk starting at position %d was only %d bytes, not %d as expected.", offset, chunk:len(), chunk_size))
    end
    offset = offset + chunk_size

    if chunk_size > 0 then
      _, i = s:find("^" .. crlf, offset)
      if not i then
        error(string.format("Didn't find CRLF after chunk-data at position %d; got %q.", offset, s:sub(offset, offset + 10)))
      end
      offset = i + 1
    end

    -- print(string.format("chunk %d %d", offset, chunk_size))

    return offset, chunk
  end
end

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

--- Recursively copy into a table any elements from another table whose key it
-- doesn't have.
local function table_augment(to, from)
  for k, v in pairs(from) do
    if type( to[k] ) == 'table' then
      table_augment(to[k], from[k])
    else
      to[k] = from[k]
    end
  end
end

--- Get a suitable hostname string from the argument, which may be either a
-- string or a host table.
local function get_hostname(host)
  if type(host) == "table" then
    return host.targetname or ( host.name ~= '' and host.name ) or host.ip
  else
    return host
  end
end

--- Fetches a resource with a GET request.
--
-- The first argument is either a string with the hostname or a table like the
-- host table passed to a portrule or hostrule. The second argument is either
-- the port number or a table like the port table passed to a portrule or
-- hostrule. The third argument is the path of the resource. The fourth argument
-- is a table for further options. The function builds the request and calls
-- <code>http.request</code>.
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @return Table as described in the module description.
-- @see http.request
get = function( host, port, path, options )
  options = options or {}

  -- Private copy of the options table, used to add default header fields.
  local mod_options = {
    header = {
      Host = get_hostname(host),
      Connection = "close",
      ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"
    }
  }
  -- Add any other options into the local copy.
  table_augment(mod_options, options)

  local data = "GET " .. path .. " HTTP/1.1\r\n"

  return request( host, port, data, mod_options )
end

--- Parses a URL and calls <code>http.get</code> with the result.
--
-- The second argument is a table for further options.
-- @param u The URL of the host.
-- @param options A table of options, as with <code>http.request</code>.
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

--- Sends request to host:port and parses the answer.
--
-- The first argument is either a string with the hostname or a table like the
-- host table passed to a portrule or hostrule. The second argument is either
-- the port number or a table like the port table passed to a portrule or
-- hostrule. SSL is used for the request if <code>port.service</code> is
-- <code>"https"</code> or <code>"https-alt"</code> or
-- <code>port.version.service_tunnel</code> is <code>"ssl"</code>.
-- The third argument is the request. The fourth argument is
-- a table for further options.
-- @param host The host to query.
-- @param port The port on the host.
-- @param data Data to send initially to the host, like a <code>GET</code> line.
-- Should end in a single <code>\r\n</code>.
-- @param options A table of options. It may have any of these fields:
-- * <code>timeout</code>: A timeout used for socket operations.
-- * <code>header</code>: A table containing additional headers to be used for the request.
-- * <code>content</code>: The content of the message (content-length will be added -- set header['Content-Length'] to override)
request = function( host, port, data, options )
  options = options or {}

  if type(host) == 'table' then
    host = host.ip
  end

  if type(port) == 'table' then
    if port.protocol and port.protocol ~= 'tcp' then
      stdnse.print_debug(1, "http.request() supports the TCP protocol only, your request to %s cannot be completed.", host)
      return nil
    end
  end

  -- Build the header.
  for key, value in pairs(options.header or {}) do
    data = data .. key .. ": " .. value .. "\r\n"
  end
  if(options.content ~= nil and options.header['Content-Length'] == nil) then
    data = data .. "Content-Length: " .. string.len(options.content) .. "\r\n"
  end
  data = data .. "\r\n"

  if(options.content ~= nil) then
    data = data .. options.content
  end

  if options.timeout then
    local opts = {timeout=options.timeout, recv_before=false}
  else
    local df_timeout = get_default_timeout( nmap.timing_level() )
    local opts = {connect_timeout=df_timeout.connect, request_timeout = df_timeout.request, recv_before=false}
  end

  local response = {}
  local result = {status=nil,["status-line"]=nil,header={},body=""}
  local socket, bopt

  socket, response[1], bopt = comm.tryssl(host, port, data, opts)

  if not socket or not response then
    return result
  end

  -- no buffer - we want everything now!
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

  local line, _, value

  -- build nicer table for header
  local last_header, match, key
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

  local body_delim = ( body:match( "\r\n" ) and "\r\n" )  or
                     ( body:match( "\n" )   and "\n" ) or nil

  -- handle chunked encoding
  if result.header['transfer-encoding'] == 'chunked' then
    local _, chunk
    local chunks = {}
    for _, chunk in get_chunks(body, 1, body_delim) do
      chunks[#chunks + 1] = chunk
    end
    body = table.concat(chunks)
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
