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
--


module(... or "http",package.seeall)

local url    = require 'url'
local stdnse = require 'stdnse'
local comm   = require 'comm'

---Use ssl if we have it
local have_ssl = (nmap.have_ssl() and pcall(require, "openssl"))

-- The 404 used for URL checks
local URL_404 = '/Nmap404Check' .. os.time(os.date('*t'))

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

--- Parses a response header and return a table with cookie jar
--
--  The cookie attributes can be accessed by:
--  cookie_table[1]['name']
--  cookie_table[1]['value']  
--  cookie_table[1]['attr']
--
--  Where attr is the attribute name, like expires or path.
--  Attributes without a value, are considered boolean (like http-only)
--
--  @param header The response header
--  @return cookie_table A table with all the cookies
local function parseCookies(header)
  local lines = stdnse.strsplit("\r?\n", header)
  local i = 1
  local n = table.getn(lines)
  local cookie_table = {}
  local cookie_attrs
  while i <= n do
    if string.match(lines[i]:lower(), "set%-cookie:") then
      local cookie = {}
      local _, cookie_attrs = string.match(lines[i], "(.+): (.*)")
      cookie_attrs = stdnse.strsplit(";",cookie_attrs)
      cookie['name'], cookie['value'] = string.match(cookie_attrs[1],"(.*)=(.*)")
      local j = 2
      while j <= #cookie_attrs do
        local attr = string.match(cookie_attrs[j],"^%s-(.*)=")
        local value = string.match(cookie_attrs[j],"=(.*)$")
        if attr and value then 
          local attr = string.gsub(attr, " ", "")
          cookie[attr] = value
        else
          cookie[string.gsub(cookie_attrs[j]:lower()," ","")] = true
        end
        j = j + 1
      end
    table.insert(cookie_table, cookie)
    end
    i = i + 1
  end
  return cookie_table
end

--- Tries to extract the max number of requests that should be made on
--  a keep-alive connection based on "Keep-Alive: timeout=xx,max=yy" response
--  header.
--
--  If the value is not available, an arbitrary value is used. If the connection
--  is not explicitly closed by the server, this same value is attempted.
--
--  @param response The http response - Might be a table or a raw response
--  @return The max number of requests on a keep-alive connection
local function getPipelineMax( response )
  if response then
    if type(response) ~= "table" then response = parseResult( response ) end
    if response.header and response.header.connection ~= "close" then
      if response.header["keep-alive"] then
        local max = string.match( response.header["keep-alive"], "max\=(%d*)")
        if(max == nil) then
          return 40
        end
        return max
      else return 40 end
    end
  end
  return 1
end

--- Sets all the values and options for a get request and than calls buildRequest to
--  create a string to be sent to the server as a resquest
--
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @return Request String 
local buildGet = function( host, port, path, options, cookies )
  options = options or {}

  -- Private copy of the options table, used to add default header fields.
  local mod_options = {
    header = {
      Host = get_hostname(host),
      ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"
    }
  }
  if cookies then
    local cookies = buildCookies(cookies, path)
    if #cookies > 0 then mod_options["header"]["Cookies"] = cookies end
  end

  if options and options.connection 
    then mod_options["header"]["Connection"] = options.connection
    else mod_options["header"]["Connection"] = "Close" end

  -- Add any other options into the local copy.
  table_augment(mod_options, options)

  local data = "GET " .. path .. " HTTP/1.1\r\n"
  return data, mod_options
end

--- Sets all the values and options for a head request and than calls buildRequest to
--  create a string to be sent to the server as a resquest
--
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @return Request String 
local buildHead = function( host, port, path, options, cookies )
  local options = options or {}

  -- Private copy of the options table, used to add default header fields.
  local mod_options = {
    header = {
      Host = get_hostname(host),
      ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"
    }
  }
  if cookies then
    local cookies = buildCookies(cookies, path)
    if #cookies > 0 then mod_options["header"]["Cookies"] = cookies end
  end
  if options and options.connection 
    then mod_options["header"]["Connection"] = options.connection
    else mod_options["header"]["Connection"] = "Close" end

  -- Add any other options into the local copy.
  table_augment(mod_options, options)

  local data = "HEAD " .. path .. " HTTP/1.1\r\n"
  return data, mod_options
end

--- Sets all the values and options for a post request and than calls buildRequest to
--  create a string to be sent to the server as a resquest
--
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @return Request String 
local buildPost = function( host, port, path, options, cookies, postdata)
  local options = options or {}
  local content = ""

  if postdata and type(postdata) == "table" then
    local k, v
    for k, v in pairs(postdata) do
      content = content .. k .. "=" .. url.escape(v) .. "&"
    end
    content = string.gsub(content, "%%20","+") 
    content = string.sub(content, 1, string.len(content)-1)
  elseif postdata and type(postdata) == "string" then
    content = postdata
    content = string.gsub(content, " ","+")
  end

  local mod_options = {
    header = {
      Host = get_hostname(host),
      Connection = "close",
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"
    },
    content = content
  }
  if cookies then
    local cookies = buildCookies(cookies, path)
    if #cookies > 0 then mod_options["header"]["Cookies"] = cookies end
  end

  table_augment(mod_options, options)

  local data = "POST " .. path .. " HTTP/1.1\r\n"

  return data, mod_options
end

--- Parses all options from a request and creates the string
--  to be sent to the server
--
--  @param data 
--  @param options
--  @return A string ready to be sent to the server
local buildRequest = function (data, options) 
  options = options or {} 

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

  return data
end

--- Transforms multiple raw responses from a pipeline request
--  (a single and long string with all the responses) into a table
--  containing one response in each field.
--
--  @param response The raw multiple response
--  @return Table with one response in each field
local function splitResults( response )
  local tmp
  local i
  local results = {}

  response = stdnse.strsplit("\n", response)

  --Index adjustment based on response.
  if(string.match(response[1], "HTTP/%d\.%d %d+"))
    then i = 0
    else i = 1; results[1] = ""
  end

  for _, line in ipairs( response or {} ) do
    if(string.match(line, "HTTP/%d\.%d %d+")) then
      i = i + 1
      results[i] = ""
    end
    results[i] = results[i] .. line .. "\n"
  end
  return results 
end

--- Builds a string to be added to the request mod_options table
-- 
--  @param cookies A cookie jar just like the table returned by parseCookies
--  @param path If the argument exists, only cookies with this path are included to the request
--  @return A string to be added to the mod_options table
function buildCookies(cookies, path)
  local cookie = ""
  if type(cookies) == 'string' then return cookies end 
  for i, ck in ipairs(cookies or {}) do
    if not path or string.match(ck["path"],".*" .. path .. ".*") then
      if i ~= 1 then cookie = cookie .. " " end
      cookie = cookie .. ck["name"] .. "=" .. ck["value"] .. ";"
    end
  end
  return cookie
end

--- Fetches a resource with a GET request.
--
-- The first argument is either a string with the hostname or a table like the
-- host table passed to a portrule or hostrule. The second argument is either
-- the port number or a table like the port table passed to a portrule or
-- hostrule. The third argument is the path of the resource. The fourth argument
-- is a table for further options. The fifth argument is a cookie table.
-- The function calls buildGet to build the request, calls request to send it 
-- and than parses the result calling parseResult
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @return Table as described in the module description.
-- @see http.parseResult
get = function( host, port, path, options, cookies )
  local data, mod_options = buildGet(host, port, path, options, cookies)
  data = buildRequest(data, mod_options)
  local response = request(host, port, data)
  return parseResult(response)
end

--- Fetches a resource with a HEAD request.
--
-- The first argument is either a string with the hostname or a table like the
-- host table passed to a portrule or hostrule. The second argument is either
-- the port number or a table like the port table passed to a portrule or
-- hostrule. The third argument is the path of the resource. The fourth argument
-- is a table for further options. The fifth argument is a cookie table.
-- The function calls buildHead to build the request, calls request to send it 
-- and than parses the result calling parseResult.
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @return Table as described in the module description.
-- @see http.parseResult
head = function( host, port, path, options, cookies )
  local data, mod_options = buildHead(host, port, path, options, cookies)
  data = buildRequest(data, mod_options)
  local response = request(host, port, data)
  return parseResult(response)
end

--- Fetches a resource with a POST request.
--
-- The first argument is either a string with the hostname or a table like the
-- host table passed to a portrule or hostrule. The second argument is either
-- the port number or a table like the port table passed to a portrule or
-- hostrule. The third argument is the path of the resource. The fourth argument
-- is a table for further options. The fifth argument is a cookie table. The sixth 
-- argument is a table with data to be posted. 
-- The function calls buildHead to build the request, calls request to send it 
-- and than parses the result calling parseResult.
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @param postada A table of data to be posted
-- @return Table as described in the module description.
-- @see http.parseResult
post = function( host, port, path, options, cookies , postdata )
  local data, mod_options = buildPost(host, port, path, options, cookies, postdata)
  data = buildRequest(data, mod_options)
  local response = request(host, port, data)
  return parseResult(response)
end

--- Builds a get request to be used in a pipeline request
--
--  Calls buildGet to build a get request
--
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @param allReqs A table with all the pipeline requests
-- @return Table with the pipeline get requests (plus this new one)
function pGet( host, port, path, options, cookies, allReqs )
  local req = {}
  if not allReqs then allReqs = {} end
  if not options then options = {} end
  local object = {data="", opts=""}
  options.connection = "Keep-alive"
  object["data"], object["opts"] =  buildGet(host, port, path, options, cookies)
  allReqs[#allReqs + 1] =  object
  return allReqs
end

--- Builds a Head request to be used in a pipeline request
--
--  Calls buildHead to build a get request
--
-- @param host The host to query.
-- @param port The port for the host.
-- @param path The path of the resource.
-- @param options A table of options, as with <code>http.request</code>.
-- @param cookies A table with cookies
-- @param allReqs A table with all the pipeline requests
-- @return Table with the pipeline get requests (plus this new one)
function pHead( host, port, path, options, cookies, allReqs )
  local req = {}
  if not allReqs then allReqs = {} end
  if not options then options = {} end
  local object = {data="", opts=""}
  options.connection = "Keep-alive"
  object["data"], object["opts"] =  buildHead(host, port, path, options, cookies)
  allReqs[#allReqs + 1] =  object
  return allReqs
end


--- Performs pipelined that are in allReqs to the resource.
--  After requesting it will call splitResults to split the multiple responses
--  from the server, and than call parseResult to create the http response table
--
--  Possible options are:
--  raw:
--  - false, result is parsed as http response tables.
--  - true, result is only splited in different tables by request.
--
--  @param host The host to query.
--  @param port The port for the host.
--  @param allReqs A table with all the previously built pipeline requests
--  @param options A table with options to configure the pipeline request
--  @return A table with multiple http response tables
pipeline = function(host, port, allReqs, options)
  stdnse.print_debug("Total number of pipelined requests: " .. #allReqs)
  local response = {}
  local response_tmp
  local response_tmp_table = {}
  local requests = ""
  local response_raw
  local response_splitted = {}
  local i = 2
  local j, opts
  local opts
  local recv_status = true

  -- Check for an empty request
  if(#allReqs == 0) then
    stdnse.print_debug(1, "Warning: empty set of requests passed to http.pipeline()")
    return {}
  end
  
  opts = {connect_timeout=5000, request_timeout=3000, recv_before=false}

  local socket, bopt

  -- We'll try a first request with keep-alive, just to check if the server
  -- supports and how many requests we can send into one socket!
  socket, response_raw, bopt = comm.tryssl(host, port, buildRequest(allReqs[1]["data"], allReqs[1]["opts"]), opts)
  if not socket or not response_raw then return response_raw end
  response_splitted[1] = response_raw
  local limit = tonumber(getPipelineMax(response_raw))
  stdnse.print_debug("Number of requests allowed by pipeline: " .. limit)

  while i <= #allReqs do
    -- we build a big request with many requests, upper limited by the var "limit"

    j = i
    while j < i + limit and j <= #allReqs do
      if j + 1 == i + limit or j == #allReqs then
        allReqs[j]["opts"]["header"]["Connection"] = "Close"
      end
      requests = requests .. buildRequest(allReqs[j]["data"], allReqs[j]["opts"])
      j = j + 1
    end

    -- Connect to host and send all the requests at once!

    if not socket:get_info() then socket:connect(host.ip, port.number, bopt) end
    socket:set_timeout(10000)
    socket:send(requests)
    response_raw = ""
    while recv_status do
      recv_status, response_tmp = socket:receive()
      if recv_status then response_raw = response_raw .. response_tmp end
    end

    -- Transform the raw response we received in a table of responses and
    -- count the number of responses for pipeline control

    response_tmp_table = splitResults(response_raw)
    for _, v in ipairs(response_tmp_table) do
      response_splitted[#response_splitted + 1] = v
    end

    -- We check if we received all the requests we sent
    -- if we didn't, reduce the number of requests (server might be overloaded)

    i = i + #response_tmp_table
    if(#response_tmp_table < limit and i <= #allReqs) then
      limit = #response_tmp_table
      stdnse.print_debug("Didn't receive all expected responses.\nDecreasing max pipelined requests to " .. limit )
    end
    recv_status = true
    socket:close()
    requests = ""
  end

  -- Prepare responses and return it!

  stdnse.print_debug("Number of received responses: " .. #response_splitted)
  if options and options.raw then
    response = response_splitted
  else
    for _, value in ipairs(response_splitted) do
      response[#response + 1] = parseResult(value)
    end
  end
  return(response)
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
request = function( host, port, data )
  local opts
  
  if type(host) == 'table' then
    host = host.ip
  end

  if type(port) == 'table' then
    if port.protocol and port.protocol ~= 'tcp' then
      stdnse.print_debug(1, "http.request() supports the TCP protocol only, your request to %s cannot be completed.", host)
      return nil
    end
  end

  local response = {}
  local result = {status=nil,["status-line"]=nil,header={},body=""}
  local socket

  socket, response[1] = comm.tryssl(host, port, data, opts)

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

  return response
end


--- Parses a simple response and creates a default http response table
--  splitting header, cookies and body.
--
--  @param response A response received from the server for a request
--  @return A table with the values received from the server
function parseResult( response )
  if type(response) ~= "string" then return response end
  local result = {status=nil,["status-line"]=nil,header={},body=""}

  -- try and separate the head from the body
  local header, body
  if response and response:match( "\r?\n\r?\n" ) then
    header, body = response:match( "^(.-)\r?\n\r?\n(.*)$" )
  else
    header, body = "", response
  end

  result.cookies = parseCookies(header)

  header = stdnse.strsplit( "\r?\n", header )

  local line, _, value

  -- build nicer table for header
  local last_header, match, key
  for number, line in ipairs( header or {} ) do
    if number == 1 then
      local code = line:match "HTTP/%d%.%d (%d+)";
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
      stdnse.print_debug( "Interesting variation on the HTTP standard.  Please submit a --script-trace output for this host to nmap-dev[at]insecure.org.")
      result.status = tonumber(code)
      body = remainder or body
    end
  end

  result.body = body

  return result

end

local MONTH_MAP = {
  Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
  Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12
}

--- Parses an HTTP date string, in any of the following formats from section
-- 3.3.1 of RFC 2616:
-- * Sun, 06 Nov 1994 08:49:37 GMT  (RFC 822, updated by RFC 1123)
-- * Sunday, 06-Nov-94 08:49:37 GMT (RFC 850, obsoleted by RFC 1036)
-- * Sun Nov  6 08:49:37 1994       (ANSI C's <code>asctime()</code> format)
-- @arg s the date string.
-- @return a table with keys <code>year</code>, <code>month</code>,
-- <code>day</code>, <code>hour</code>, <code>min</code>, <code>sec</code>, and
-- <code>isdst</code>, relative to GMT, suitable for input to
-- <code>os.time</code>.
function parse_date(s)
  local day, month, year, hour, min, sec, tz, month_name
  -- RFC 2616, section 3.3.1:

  -- Handle RFC 1123 and 1036 at once.
  day, month_name, year, hour, min, sec, tz = s:match("^%w+, (%d+)[- ](%w+)[- ](%d+) (%d+):(%d+):(%d+) (%w+)$")
  if not day then
    month_name, day, hour, min, sec, year = s:match("%w+ (%w+)  ?(%d+) (%d+):(%d+):(%d+) (%d+)")
    tz = "GMT"
  end
  if not day then
    stdnse.print_debug(1, "http.parse_date: can't parse date \"%s\": unknown format.", s)
    return nil
  end
  -- Look up the numeric code for month.
  month = MONTH_MAP[month_name]
  if not month then
    stdnse.print_debug(1, "http.parse_date: unknown month name \"%s\".", month_name)
    return nil
  end
  if tz ~= "GMT" then
    stdnse.print_debug(1, "http.parse_date: don't know time zone \"%s\", only \"GMT\".", tz)
    return nil
  end
  day = tonumber(day)
  year = tonumber(year)
  hour = tonumber(hour)
  min = tonumber(min)
  sec = tonumber(sec)

  if year < 100 then
    -- Two-digit year. Make a guess.
    if year < 70 then
      year = year + 2000
    else
      year = year + 1900
    end
  end

  return { year = year, month = month, day = day, hour = hour, min = min, sec = sec, isdst = false }
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

---Take the data returned from a HTTP request and return the status string. Useful 
-- for <code>print_debug</code> messaes and even for advanced output. 
--
--@param data The data returned by a HTTP request (can be nil or empty)
--@return The status string, the status code, or "<unknown status>". 
local function get_status_string(data)
	-- Make sure we have valid data
	if(data == nil) then
		return "<unknown status>"
	elseif(data['status-line'] == nil) then
		if(data['status'] ~= nil) then
			return data['status']
		end

		return "<unknown status>"
	end

	-- We basically want everything after the space
	local space = string.find(data['status-line'], ' ')
	if(space == nil) then
		return data['status-line']
	else
		return string.sub(data['status-line'], space + 1)
	end
end

---Determine whether or not the server supports HEAD by requesting '/' and verifying that it returns 
-- 200, and doesn't return data. We implement the check like this because can't always rely on OPTIONS to 
-- tell the truth. 
--
--Note: If <code>identify_404</code> returns a 200 status, HEAD requests should be disabled. 
--
--@param host The host object. 
--@param port The port to use -- note that SSL will automatically be used, if necessary. 
--@param result_404 [optional] The result when an unknown page is requested. This is returned by <code>identify_404</code>. 
--                  If the 404 page returns a '200' code, then we disable HEAD requests. 
--@return A boolean value: true if HEAD is usable, false otherwise. 
function can_use_head(host, port, result_404)
	-- If the 404 result is 200, don't use HEAD. 
	if(result_404 == 200) then
		return false
	end

	-- Perform a HEAD request and see what happens. 
	local data = http.head( host, port, '/' )
	if data then
		if data.status and data.status == 302 and data.header and data.header.location then
			stdnse.print_debug(1, "http-enum.nse: Warning: Host returned 302 and not 200 when performing HEAD.")
			return false
		end

		if data.status and data.status == 200 and data.header then
			-- check that a body wasn't returned
			if string.len(data.body) > 0 then
				stdnse.print_debug(1, "http-enum.nse: Warning: Host returned data when performing HEAD.")
				return false
			end

			stdnse.print_debug(1, "http-enum.nse: Host supports HEAD.")
			return true
		end

		stdnse.print_debug(1, "http-enum.nse: Didn't receive expected response to HEAD request (got %s).", get_status_string(data))
		return false
	end

	stdnse.print_debug(1, "http-enum.nse: HEAD request completely failed.")
	return false
end

---Request the root folder, "/", in order to determine if we can use a GET request against this server. If the server returns
-- 301 Moved Permanently or 401 Authentication Required, then tests against this server will most likely fail. 
--
-- TODO: It's probably worthwhile adding a script-arg that will ignore the output of this function and always scan servers. 
--
--@param host The host object. 
--@param port The port to use -- note that SSL will automatically be used, if necessary. 
--@return (result, message) result is a boolean: true means we're good to go, false means there's an error.
--        The error is returned in message. 
function can_use_get(host, port)
	stdnse.print_debug(1, "Checking if a GET request is going to work out")

	-- Try getting the root directory
	local data = http.get( host, port, '/' )
	if(data == nil) then
		return false, "GET request returned nil. Is the server still up?"
	end

	-- If the root directory is a permanent redirect, we're going to run into troubles
	if(data.status == 301) then
		if(data.header and data.header.location) then
			return false, string.format("GET request returned %s -- try scanning %s instead, if possible", get_status_string(data), data.header.location)
		else
			return false, string.format("GET request returned %s -- site is trying to redirect us, but didn't say where", get_status_string(data))
		end
	end

	-- If the root directory requires authentication, we're outta luck
	if(data.status == 401) then
		return false, string.format("Root directory required authentication -- giving up (%s)", get_status_string(data))
	end

	stdnse.print_debug(1, "It appears that the GET request will work")

	return true
end

---Try and remove anything that might change within a 404. For example:
-- * A file path (includes URI)
-- * A time
-- * A date
-- * An execution time (numbers in general, really)
--
-- The intention is that two 404 pages from different URIs and taken hours apart should, whenever
-- possible, look the same. 
--
-- During this function, we're likely going to over-trim things. This is fine -- we want enough to match on that it'll a) be unique, 
-- and b) have the best chance of not changing. Even if we remove bits and pieces from the file, as long as it isn't a significant
-- amount, it'll remain unique. 
--
-- One case this doesn't cover is if the server generates a random haiku for the user. 
--
--@param body The body of the page. 
--@param uri  The URI that the page came from. 
local function clean_404(body)

	-- Remove anything that looks like time 
	body = string.gsub(body, '%d?%d:%d%d:%d%d', "")
	body = string.gsub(body, '%d%d:%d%d', "")
	body = string.gsub(body, 'AM', "")
	body = string.gsub(body, 'am', "")
	body = string.gsub(body, 'PM', "")
	body = string.gsub(body, 'pm', "")

	-- Remove anything that looks like a date (this includes 6 and 8 digit numbers)
	-- (this is probably unnecessary, but it's getting pretty close to 11:59 right now, so you never know!)
	body = string.gsub(body, '%d%d%d%d%d%d%d%d', "") -- 4-digit year (has to go first, because it overlaps 2-digit year)
	body = string.gsub(body, '%d%d%d%d%-%d%d%-%d%d', "")
	body = string.gsub(body, '%d%d%d%d/%d%d/%d%d', "")
	body = string.gsub(body, '%d%d%-%d%d%-%d%d%d%d', "")
	body = string.gsub(body, '%d%d%/%d%d%/%d%d%d%d', "")

	body = string.gsub(body, '%d%d%d%d%d%d', "") -- 2-digit year
	body = string.gsub(body, '%d%d%-%d%d%-%d%d', "")
	body = string.gsub(body, '%d%d%/%d%d%/%d%d', "")

	-- Remove anything that looks like a path (note: this will get the URI too) (note2: this interferes with the date removal above, so it can't be moved up)
	body = string.gsub(body, "/[^ ]+", "") -- Unix - remove everything from a slash till the next space
	body = string.gsub(body, "[a-zA-Z]:\\[^ ]+", "") -- Windows - remove everything from a "x:\" pattern till the next space

	-- If we have SSL available, save us a lot of memory by hashing the page (if SSL isn't available, this will work fine, but
	-- take up more memory). If we're debugging, don't hash (it makes things far harder to debug). 
	if(have_ssl and nmap.debugging() == 0) then
		return openssl.md5(body)
	end

	return body
end

---Try requesting a non-existent file to determine how the server responds to unknown pages ("404 pages"), which a) 
-- tells us what to expect when a non-existent page is requested, and b) tells us if the server will be impossible to
-- scan. If the server responds with a 404 status code, as it is supposed to, then this function simply returns 404. If it 
-- contains one of a series of common status codes, including unauthorized, moved, and others, it is returned like a 404. 
--
-- If, however, the 404 page returns a 200 status code, it gets interesting. First, it attempts to clean the returned
-- body (see <code>clean_404</code> for details). Once any dynamic-looking data has been removed from the string, another
-- 404 page is requested. If the response isn't identical to the first 404 page, an error is returned. The reason is, 
-- obviously, because we now have no way to tell a valid page from an invalid one. 
--
--@param host The host object.
--@param port The port to which we are establishing the connection. 
--@return (status, result, body) If status is false, result is an error message. Otherwise, result is the code to expect and 
--        body is the cleaned-up body (or a hash of the cleaned-up body). 
function identify_404(host, port)
	local data
	local bad_responses = { 301, 302, 401, 403, 499, 501 }

	data = http.get(host, port, URL_404)

	if(data == nil) then
		stdnse.print_debug(1, "http-enum.nse: Failed while testing for 404 status code")
		return false, "Failed while testing for 404 error message"
	end

	if(data.status and data.status == 404) then
		stdnse.print_debug(1, "http-enum.nse: Host returns proper 404 result.")
		return true, 404
	end

	if(data.status and data.status == 200) then
		stdnse.print_debug(1, "http-enum.nse: Host returns 200 instead of 404.")

		-- Clean up the body (for example, remove the URI). This makes it easier to validate later
		if(data.body) then
			-- Obtain another 404, with a different URI, to make sure things are consistent -- if they aren't, there's little hope
			local data2 = http.get(host, port, URL_404 .. "-2")
			if(data2 == nil) then
				stdnse.print_debug(1, "http-enum.nse: Failed while testing for second 404 error message")
				return false, "Failed while testing for second 404 error message"
			end

			-- Check if the return code became something other than 200
			if(data2.status ~= 200) then
				if(data2.status == nil) then
					data2.status = "<unknown>"
				end
				stdnse.print_debug(1, "http-enum.nse: HTTP 404 status changed during request (become %d; server is acting very strange).", data2.status)
				return false, string.format("HTTP 404 status changed during request (became %d; server is acting very strange).", data2.status)
			end

			-- Check if the returned body (once cleaned up) matches the first returned body
			local clean_body  = clean_404(data.body)
			local clean_body2 = clean_404(data2.body)
			if(clean_body ~= clean_body2) then
				stdnse.print_debug(1, "http-enum.nse: Two known 404 pages returned valid and different pages; unable to identify valid response.")
				stdnse.print_debug(1, "http-enum.nse: If you investigate the server and it's possible to clean up the pages, please post to nmap-dev mailing list.")
				return false, string.format("Two known 404 pages returned valid and different pages; unable to identify valid response.")
			end

			return true, 200, clean_body
		end

		stdnse.print_debug(1, "http-enum.nse: The 200 response didn't contain a body.")
		return true, 200
	end

	-- Loop through any expected error codes
	for _,code in pairs(bad_responses) do
		if(data.status and data.status == code) then
			stdnse.print_debug(1, "http-enum.nse: Host returns %s instead of 404 File Not Found.", get_status_string(data))
			return true, code
		end
	end

	stdnse.print_debug(1,  "Unexpected response returned for 404 check: %s", get_status_string(data))
--	io.write("\n\n" .. nsedebug.tostr(data) .. "\n\n")

	return false, string.format("Unexpected response returned for 404 check: %s", get_status_string(data))
end

---Determine whether or not the page that was returned is a 404 page. This is actually a pretty simple function, 
-- but it's best to keep this logic close to <code>identify_404</code>, since they will generally be used 
-- together. 
--
--@param data The data returned by the HTTP request
--@param result_404 The status code to expect for non-existent pages. This is returned by <code>identify_404</code>. 
--@param known_404  The 404 page itself, if <code>result_404</code> is 200. If <code>result_404</code> is something
--                  else, this parameter is ignored and can be set to <code>nil</code>. This is returned by 
--                  <code>identfy_404</code>. 
--@param page       The page being requested (used in error messages). 
--@param displayall [optional] If set to true, "true", or "1", displays all error codes that don't look like a 404 instead
--                  of just 200 OK and 401 Authentication Required. 
--@return A boolean value: true if the page appears to exist, and false if it does not. 
function page_exists(data, result_404, known_404, page, displayall)
	if(data and data.status) then
		-- Handle the most complicated case first: the "200 Ok" response
		if(data.status == 200) then
			if(result_404 == 200) then
				-- If the 404 response is also "200", deal with it (check if the body matches)
				if(clean_404(data.body) ~= known_404) then
					stdnse.print_debug(1, "http-enum.nse: Page returned a body that doesn't match known 404 body, therefore it exists (%s)", page)
					return true
				else
					return false
				end
			else
				-- If 404s return something other than 200, and we got a 200, we're good to go
				stdnse.print_debug(1, "http-enum.nse: Page was '%s', it exists! (%s)", get_status_string(data), page)
				return true
			end
		else
			-- If the result isn't a 200, check if it's a 404 or returns the same code as a 404 returned
			if(data.status ~= 404 and data.status ~= result_404) then
				-- If this check succeeded, then the page isn't a standard 404 -- it could be a redirect, authentication request, etc. Unless the user
				-- asks for everything (with a script argument), only display 401 Authentication Required here.
				stdnse.print_debug(1, "http-enum.nse: Page didn't match the 404 response (%s) (%s)", get_status_string(data), page)

				if(data.status == 401) then -- "Authentication Required"
					return true
				elseif(displayall == true or displayall == '1' or displayall == "true") then
					return true
				end

				return false
			else
				-- Page was a 404, or looked like a 404
				return false
			end
		end
	else
		stdnse.print_debug(1, "http-enum.nse: HTTP request failed (is the host still up?)")
		return false
	end
end


