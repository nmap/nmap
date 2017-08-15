---Implements the HTTP client protocol in a standard form that Nmap scripts can
-- take advantage of.
--
-- Because HTTP has so many uses, there are a number of interfaces to this
-- library.
--
-- The most obvious and common ones are simply <code>get</code>,
-- <code>post</code>, and <code>head</code>; or, if more control is required,
-- <code>generic_request</code> can be used. These functions take host and port
-- as their main parameters and they do what one would expect. The
-- <code>get_url</code> helper function can be used to parse and retrieve a full
-- URL.
--
-- HTTPS support is transparent. The library uses <code>comm.tryssl</code> to
-- determine whether SSL is required for a request.
--
-- These functions return a table of values, including:
-- * <code>status-line</code> - A string representing the status, such as "HTTP/1.1 200 OK", followed by a newline. In case of an error, a description will be provided in this line.
-- * <code>status</code> - The HTTP status value; for example, "200". If an error occurs during a request, then this value is going to be nil.
-- * <code>version</code> - HTTP protocol version string, as stated in the status line. Example: "1.1"
-- * <code>header</code> - An associative array representing the header. Keys are all lowercase, and standard headers, such as 'date', 'content-length', etc. will typically be present.
-- * <code>rawheader</code> - A numbered array of the headers, exactly as the server sent them. While header['content-type'] might be 'text/html', rawheader[3] might be 'Content-type: text/html'.
-- * <code>cookies</code> - A numbered array of the cookies the server sent. Each cookie is a table with the expected keys, such as <code>name</code>, <code>value</code>, <code>path</code>, <code>domain</code>, and <code>expires</code>. This table can be sent to the server in subsequent responses in the <code>options</code> table to any function (see below).
-- * <code>body</code> - The full body, as returned by the server. Chunked encoding is handled transparently.
-- * <code>fragment</code> - Partially received body (if any), in case of an error.
-- * <code>location</code> - A numbered array of the locations of redirects that were followed.
--
-- Many of the functions optionally allow an "options" input table, which can
-- modify the HTTP request or its processing in many ways like adding headers or
-- setting the timeout. The following are valid keys in "options"
-- (note: not all options will necessarily affect every function):
-- * <code>timeout</code>: A timeout used for socket operations.
-- * <code>header</code>: A table containing additional headers to be used for the request. For example, <code>options['header']['Content-Type'] = 'text/xml'</code>
-- * <code>content</code>: The content of the message. This can be either a string, which will be directly added as the body of the message, or a table, which will have each key=value pair added (like a normal POST request). (A corresponding Content-Length header will be added automatically. Set header['Content-Length'] to override it).
-- * <code>cookies</code>: A list of cookies as either a string, which will be directly sent, or a table. If it's a table, the following fields are recognized: <code>name</code>, <code>value</code> and <code>path</code>. Only <code>name</code> and <code>value</code> fields are required.
-- * <code>auth</code>: A table containing the keys <code>username</code> and <code>password</code>, which will be used for HTTP Basic authentication.
--   If a server requires HTTP Digest authentication, then there must also be a key <code>digest</code>, with value <code>true</code>.
--   If a server requires NTLM authentication, then there must also be a key <code>ntlm</code>, with value <code>true</code>.
-- * <code>bypass_cache</code>: Do not perform a lookup in the local HTTP cache.
-- * <code>no_cache</code>: Do not save the result of this request to the local HTTP cache.
-- * <code>no_cache_body</code>: Do not save the body of the response to the local HTTP cache.
-- * <code>any_af</code>: Allow connecting to any address family, inet or inet6. By default, these functions will only use the same AF as nmap.address_family to resolve names. (This option is a straight pass-thru to <code>comm.lua</code> functions.)
-- * <code>redirect_ok</code>: Closure that overrides the default redirect_ok used to validate whether to follow HTTP redirects or not. False, if no HTTP redirects should be followed. Alternatively, a number may be passed to change the number of redirects to follow.
--   The following example shows how to write a custom closure that follows 5 consecutive redirects, without the safety checks in the default redirect_ok:
--   <code>
--   redirect_ok = function(host,port)
--     local c = 5
--     return function(url)
--       if ( c==0 ) then return false end
--       c = c - 1
--       return true
--     end
--   end
--   </code>
--
-- If a script is planning on making a lot of requests, the pipelining functions
-- can be helpful. <code>pipeline_add</code> queues requests in a table, and
-- <code>pipeline_go</code> performs the requests, returning the results as an
-- array, with the responses in the same order as the requests were added.
-- As a simple example:
--<code>
--  -- Start by defining the 'all' variable as nil
--  local all = nil
--
--  -- Add two GET requests and one HEAD to the queue but these requests are
--  -- not performed yet. The second parameter represents the "options" table
--  -- (which we don't need in this example).
--  all = http.pipeline_add('/book',    nil, all)
--  all = http.pipeline_add('/test',    nil, all)
--  all = http.pipeline_add('/monkeys', nil, all, 'HEAD')
--
--  -- Perform all three requests as parallel as Nmap is able to
--  local results = http.pipeline_go('nmap.org', 80, all)
--</code>
--
-- At this point, <code>results</code> is an array with three elements.
-- Each element is a table containing the HTTP result, as discussed above.
--
-- One more interface provided by the HTTP library helps scripts determine
-- whether or not a page exists. The <code>identify_404</code> function will
-- try several URLs on the server to determine what the server's 404 pages look
-- like. It will attempt to identify customized 404 pages that may not return
-- the actual status code 404. If successful, the function
-- <code>page_exists</code> can then be used to determine whether or not a page
-- exists.
--
-- Some other miscellaneous functions that can come in handy are
-- <code>response_contains</code>, <code>can_use_head</code>, and
-- <code>save_path</code>. See the appropriate documentation for details.
--
-- @args http.max-cache-size The maximum memory size (in bytes) of the cache.
--
-- @args http.useragent The value of the User-Agent header field sent with
-- requests. By default it is
-- <code>"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"</code>.
-- A value of the empty string disables sending the User-Agent header field.
--
-- @args http.pipeline If set, it represents the number of HTTP requests that'll be
-- sent on one connection. This can be set low to make debugging easier, or it
-- can be set high to test how a server reacts (its chosen max is ignored).
-- @args http.max-pipeline If set, it represents the number of outstanding  HTTP requests
-- that should be pipelined. Defaults to <code>http.pipeline</code> (if set), or to what
-- <code>getPipelineMax</code> function returns.
--
-- TODO
-- Implement cache system for http pipelines
--


local base64 = require "base64"
local bin = require "bin"
local bit = require "bit"
local comm = require "comm"
local coroutine = require "coroutine"
local nmap = require "nmap"
local os = require "os"
local sasl = require "sasl"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local smbauth = require "smbauth"
local unicode = require "unicode"

_ENV = stdnse.module("http", stdnse.seeall)

--Use ssl if we have it
local have_ssl, openssl = pcall(require,'openssl')

USER_AGENT = stdnse.get_script_args('http.useragent') or "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
local MAX_REDIRECT_COUNT = 5

-- Recursively copy a table.
-- Only recurs when a value is a table, other values are copied by assignment.
local function tcopy (t)
  local tc = {};
  for k,v in pairs(t) do
    if type(v) == "table" then
      tc[k] = tcopy(v);
    else
      tc[k] = v;
    end
  end
  return tc;
end

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

--- Provide the default port for a given scheme.
-- The localization is necessary because functions in http.lua like to use
-- "url" as a local parameter
local get_default_port = url.get_default_port

--- Get a value suitable for the Host header field.
-- See RFC 2616 sections 14.23 and 5.2.
local function get_host_field(host, port)
  if not host then return nil end
  if type(port) == "number" then
    port = {number=port, protocol="tcp", state="open", version={}}
  end
  local scheme = shortport.ssl(host, port) and "https" or "http"
  if port.number == get_default_port(scheme) then
    return stdnse.get_hostname(host)
  else
    return stdnse.get_hostname(host) .. ":" .. port.number
  end
end

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
  local _, i, token = s:find("^([^()<>@,;:\\\"/%[%]?={} \0\001-\031\127]+)", offset)
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
        error("\\ escape at end of input while parsing quoted-string.")
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
      if c ~= "\t" and c:match("^[\0\001-\031\127]$") then
        error(string.format("Unexpected control character in quoted-string: 0x%02X.", c:byte(1)))
      end
    end
    result[#result + 1] = c
    i = i + 1
  end
  return nil
end

-- Returns the index just past the end of LWS.
local function skip_lws(s, pos)
  local _, e

  while true do
    while string.match(s, "^[ \t]", pos) do
      pos = pos + 1
    end
    _, e = string.find(s, "^\r?\n[ \t]", pos)
    if not e then
      return pos
    end
    pos = e + 1
  end
end


---Validate an 'options' table, which is passed to a number of the HTTP functions. It is
-- often difficult to track down a mistake in the options table, and requires fiddling
-- with the http.lua source, but this should make that a lot easier.
local function validate_options(options)
  local bad = false

  if(options == nil) then
    return true
  end

  for key, value in pairs(options) do
    if(key == 'timeout') then
      if(type(tonumber(value)) ~= 'number') then
        stdnse.debug1('http: options.timeout contains a non-numeric value')
        bad = true
      end
    elseif(key == 'header') then
      if(type(value) ~= 'table') then
        stdnse.debug1("http: options.header should be a table")
        bad = true
      end
    elseif(key == 'content') then
      if(type(value) ~= 'string' and type(value) ~= 'table') then
        stdnse.debug1("http: options.content should be a string or a table")
        bad = true
      end
    elseif(key == 'cookies') then
      if(type(value) == 'table') then
        for _, cookie in ipairs(value) do
          for cookie_key, cookie_value in pairs(cookie) do
            if(cookie_key == 'name') then
              if(type(cookie_value) ~= 'string') then
                stdnse.debug1("http: options.cookies[i].name should be a string")
                bad = true
              end
            elseif(cookie_key == 'value') then
              if(type(cookie_value) ~= 'string') then
                stdnse.debug1("http: options.cookies[i].value should be a string")
                bad = true
              end
            elseif(cookie_key == 'path') then
              if(type(cookie_value) ~= 'string') then
                stdnse.debug1("http: options.cookies[i].path should be a string")
                bad = true
              end
            elseif(cookie_key == 'expires') then
              if(type(cookie_value) ~= 'string') then
                stdnse.debug1("http: options.cookies[i].expires should be a string")
                bad = true
              end
            elseif(cookie_key == 'max-age') then
              if(type(cookie_value) ~= 'string') then
                stdnse.debug1("http: options.cookies[i].max-age should be a string")
                bad = true
              end
            elseif not (cookie_key == 'httponly' or cookie_key == 'secure') then
              stdnse.debug1("http: Unknown field in cookie table: %s", cookie_key)
              -- Ignore unrecognized attributes (per RFC 6265, Section 5.2)
            end
          end
        end
      elseif(type(value) ~= 'string') then
        stdnse.debug1("http: options.cookies should be a table or a string")
        bad = true
      end
    elseif(key == 'auth') then
      if(type(value) == 'table') then
        if(value['username'] == nil or value['password'] == nil) then
          stdnse.debug1("http: options.auth should contain both a 'username' and a 'password' key")
          bad = true
        end
      else
        stdnse.debug1("http: options.auth should be a table")
        bad = true
      end
    elseif (key == 'digestauth') then
      if(type(value) == 'table') then
        local req_keys = {"username","realm","nonce","digest-uri","response"}
        for _,k in ipairs(req_keys) do
          if not value[k] then
            stdnse.debug1("http: options.digestauth missing key: %s",k)
            bad = true
            break
          end
        end
      else
        bad = true
        stdnse.debug1("http: options.digestauth should be a table")
      end
    elseif (key == 'ntlmauth') then
      stdnse.debug1("Proceeding with ntlm message")
    elseif(key == 'bypass_cache' or key == 'no_cache' or key == 'no_cache_body' or key == 'any_af') then
      if(type(value) ~= 'boolean') then
        stdnse.debug1("http: options.%s must be a boolean value", key)
        bad = true
      end
    elseif(key == 'redirect_ok') then
      if(type(value)~= 'function' and type(value)~='boolean' and type(value) ~= 'number') then
        stdnse.debug1("http: options.redirect_ok must be a function or boolean or number")
        bad = true
      end
    else
      stdnse.debug1("http: Unknown key in the options table: %s", key)
    end
  end

  return not(bad)
end


-- The following recv functions, and the function <code>next_response</code>
-- follow a common pattern. They each take a <code>partial</code> argument
-- whose value is data that has been read from the socket but not yet used in
-- parsing, and they return as their second return value a new value for
-- <code>partial</code>. The idea is that, for example, in reading from the
-- socket to get the Status-Line, you will probably read too much and read part
-- of the header. That part (the "partial") has to be retained when you go to
-- parse the header. The common use pattern is this:
-- <code>
-- local partial
-- status_line, partial = recv_line(socket, partial)
-- ...
-- header, partial = recv_header(socket, partial)
-- ...
-- </code>
-- On error, the functions return <code>nil</code>, the second return value
-- is an error message, and the third value is an unfinished fragment of
-- the response body (if any):
-- <code>
-- body, partial, fragment = recv_body(socket, partial)
-- if not body then
--   stdnse.debug1("Error encountered: %s", partial)
--   stdnse.debug1("Only %d bytes of the body received", (#fragment or 0))
-- end
-- ...
-- </code>

-- Receive a single line (up to <code>\n</code>).
local function recv_line(s, partial)
  local _, e
  local status, data
  local pos

  partial = partial or ""

  pos = 1
  while true do
    _, e = string.find(partial, "\n", pos, true)
    if e then
      break
    end
    status, data = s:receive()
    if not status then
      return status, data
    end
    pos = #partial
    partial = partial .. data
  end

  return string.sub(partial, 1, e), string.sub(partial, e + 1)
end

local function line_is_empty(line)
  return line == "\r\n" or line == "\n"
end

-- Receive up to and including the first blank line, but return everything up
-- to and not including the final blank line.
local function recv_header(s, partial)
  local lines = {}

  partial = partial or ""

  while true do
    local line
    line, partial = recv_line(s, partial)
    if not line then
      return line, partial
    end
    if line_is_empty(line) then
      break
    end
    lines[#lines + 1] = line
  end

  return table.concat(lines), partial
end

-- Receive until the connection is closed.
local function recv_all(s, partial)
  local parts

  partial = partial or ""

  parts = {partial}
  while true do
    local status, part = s:receive()
    if not status then
      break
    else
      parts[#parts + 1] = part
    end
  end

  return table.concat(parts), ""
end

-- Receive exactly <code>length</code> bytes. Returns <code>nil</code> if that
-- many aren't available.
local function recv_length(s, length, partial)
  local parts, last

  partial = partial or ""

  parts = {}
  last = partial
  length = length - #last
  while length > 0 do
    local status

    parts[#parts + 1] = last
    status, last = s:receive()
    if not status then
      return nil, last, table.concat(parts)
    end
    length = length - #last
  end

  -- At this point length is 0 or negative, and indicates the degree to which
  -- the last read "overshot" the desired length.

  if length == 0 then
    return table.concat(parts) .. last, ""
  else
    return table.concat(parts) .. string.sub(last, 1, length - 1), string.sub(last, length)
  end
end

-- Receive until the end of a chunked message body, and return the dechunked
-- body.
local function recv_chunked(s, partial)
  local chunks, chunk, fragment
  local chunk_size
  local pos

  chunks = {}
  repeat
    local line, hex, _, i

    line, partial = recv_line(s, partial)
    if not line then
      return nil, "Chunk size not received; " .. partial, table.concat(chunks)
    end

    pos = 1
    pos = skip_space(line, pos)

    -- Get the chunk-size.
    _, i, hex = string.find(line, "^([%x]+)", pos)
    if not i then
      return nil,
            ("Chunked encoding didn't find hex; got %q."):format(line:sub(pos, pos + 10)),
            table.concat(chunks)
    end
    pos = i + 1

    chunk_size = tonumber(hex, 16)

    -- Ignore chunk-extensions that may follow here.
    -- RFC 2616, section 2.1 ("Implied *LWS") seems to allow *LWS between the
    -- parts of a chunk-extension, but that is ambiguous. Consider this case:
    -- "1234;a\r\n =1\r\n...". It could be an extension with a chunk-ext-name
    -- of "a" (and no value), and a chunk-data beginning with " =", or it could
    -- be a chunk-ext-name of "a" with a value of "1", and a chunk-data
    -- starting with "...". We don't allow *LWS here, only ( SP | HT ), so the
    -- first interpretation will prevail.

    chunk, partial, fragment = recv_length(s, chunk_size, partial)
    if not chunk then
      return nil,
             "Incomplete chunk; " .. partial,
             table.concat(chunks) .. fragment
    end
    chunks[#chunks + 1] = chunk

    line, partial = recv_line(s, partial)
    if not line then
      -- this warning message was initially an error but was adapted
      -- to support broken servers, such as the Citrix XML Service
      stdnse.debug2("Didn't find CRLF after chunk-data.")
    elseif not string.match(line, "^\r?\n") then
      return nil,
             ("Didn't find CRLF after chunk-data; got %q."):format(line),
             table.concat(chunks)
    end
  until chunk_size == 0

  return table.concat(chunks), partial
end

-- Receive a message body, assuming that the header has already been read by
-- <code>recv_header</code>. The handling is sensitive to the request method
-- and the status code of the response.
local function recv_body(s, response, method, partial)
  local connection_close, connection_keepalive
  local transfer_encoding
  local content_length
  local err

  partial = partial or ""

  -- First check for Connection: close and Connection: keep-alive. This is
  -- necessary to handle some servers that don't follow the protocol.
  connection_close = false
  connection_keepalive = false
  if response.header.connection then
    local offset, token
    offset = 0
    while true do
      offset, token = get_token(response.header.connection, offset + 1)
      if not offset then
        break
      end
      if string.lower(token) == "close" then
        connection_close = true
      elseif string.lower(token) == "keep-alive" then
        connection_keepalive = true
      end
    end
  end

  -- See RFC 2616, section 4.4 "Message Length".

  -- 1. Any response message which "MUST NOT" include a message-body (such as
  --    the 1xx, 204, and 304 responses and any response to a HEAD request) is
  --    always terminated by the first empty line after the header fields...
  --
  -- Despite the above, some servers return a body with response to a HEAD
  -- request. So if an HTTP/1.0 server returns a response without Connection:
  -- keep-alive, or any server returns a response with Connection: close, read
  -- whatever's left on the socket (should be zero bytes).
  if string.upper(method) == "HEAD"
    or (response.status >= 100 and response.status <= 199)
    or response.status == 204 or response.status == 304 then
    if connection_close or (response.version == "1.0" and not connection_keepalive) then
      return recv_all(s, partial)
    else
      return "", partial
    end
  end

  -- 2. If a Transfer-Encoding header field (section 14.41) is present and has
  --    any value other than "identity", then the transfer-length is defined by
  --    use of the "chunked" transfer-coding (section 3.6), unless the message
  --    is terminated by closing the connection.
  if response.header["transfer-encoding"]
    and response.header["transfer-encoding"] ~= "identity" then
    return recv_chunked(s, partial)
  end
  -- The Citrix XML Service sends a wrong "Transfer-Coding" instead of
  -- "Transfer-Encoding".
  if response.header["transfer-coding"]
    and response.header["transfer-coding"] ~= "identity" then
    return recv_chunked(s, partial)
  end

  -- 3. If a Content-Length header field (section 14.13) is present, its decimal
  --    value in OCTETs represents both the entity-length and the
  --    transfer-length. The Content-Length header field MUST NOT be sent if
  --    these two lengths are different (i.e., if a Transfer-Encoding header
  --    field is present). If a message is received with both a
  --    Transfer-Encoding header field and a Content-Length header field, the
  --    latter MUST be ignored.
  if response.header["content-length"]  and not response.header["transfer-encoding"] then
    content_length = tonumber(response.header["content-length"])
    if not content_length then
      return nil, string.format("Content-Length %q is non-numeric", response.header["content-length"])
    end
    return recv_length(s, content_length, partial)
  end

  -- 4. If the message uses the media type "multipart/byteranges", and the
  --    transfer-length is not otherwise specified, then this self-delimiting
  --    media type defines the transfer-length. [sic]

  -- Case 4 is unhandled.

  -- 5. By the server closing the connection.
  return recv_all(s, partial)
end

-- Sets response["status-line"], response.status, and response.version.
local function parse_status_line(status_line, response)
  response["status-line"] = status_line
  local version, status, reason_phrase = string.match(status_line,
    "^HTTP/(%d+%.%d+) +(%d+) +(.-)\r?\n$")
  if not version then
    return nil, string.format("Error parsing status-line %q.", status_line)
  end
  -- We don't have a use for the reason_phrase; ignore it.
  response.version = version
  response.status = tonumber(status)
  if not response.status then
    return nil, string.format("Status code is not numeric: %s", status)
  end

  return true
end

local parse_set_cookie -- defined farther down

-- Sets response.header and response.rawheader.
local function parse_header(header, response)
  local pos
  local name, words
  local s, e

  response.header = {}
  response.rawheader = stdnse.strsplit("\r?\n", header)
  pos = 1
  while pos <= #header do
    -- Get the field name.
    e, name = get_token(header, pos)
    -- Do not bail out if the header is malformed. Consume the header line
    -- anyway, getting to the next header, but do not create a new entry in
    -- the "header" table.
    if e then
      if header:sub(e, e) ~= ":" then
        name = nil
      end
      pos = e + 1
    end

    -- Skip initial space.
    pos = skip_lws(header, pos)
    -- Get non-space words separated by LWS, then join them with a single space.
    words = {}
    while pos <= #header and not string.match(header, "^\r?\n", pos) do
      s = pos
      while not string.match(header, "^[ \t]", pos) and
        not string.match(header, "^\r?\n", pos) do
        pos = pos + 1
      end
      words[#words + 1] = string.sub(header, s, pos - 1)
      pos = skip_lws(header, pos)
    end

    if name then
      -- Set it in our table.
      name = string.lower(name)
      local value = table.concat(words, " ")
      if response.header[name] then
        -- TODO: delay concatenation until return to avoid resource exhaustion
        response.header[name] = response.header[name] .. ", " .. value
      else
        response.header[name] = value
      end

      -- Update the cookie table if this is a Set-Cookie header
      if name == "set-cookie" then
        local cookie, err = parse_set_cookie(value)
        if cookie then
          response.cookies[#response.cookies + 1] = cookie
        else
          -- Ignore any cookie parsing error
        end
      end
    end

    -- Next field, or end of string. (If not it's an error.)
    s, e = string.find(header, "^\r?\n", pos)
    if not e then
      return nil, string.format("Header field named %q didn't end with CRLF", name)
    end
    pos = e + 1
  end

  return true
end

-- Parse the contents of a Set-Cookie header field.
-- The result is a table of the form
--
-- { name = "NAME", value = "VALUE", Comment = "...", Domain = "...", ... }
--
-- Every key except "name" and "value" is optional.
--
-- This function attempts to support the header parser defined in RFC 6265,
-- Section 5.2. Values need not be quoted, but if they start with a quote they
-- will be interpreted as a quoted string.
parse_set_cookie = function (s)
  local name, value
  local _

  local cookie = {}

  -- Get the NAME=VALUE part.
  local pos
  _, pos, cookie.name = s:find("^[ \t]*(.-)[ \t]*=[ \t]*")
  if not (cookie.name or ""):find("^[^;]+$") then
    return nil, "Can't get cookie name."
  end
  pos = pos + 1
  if s:sub(pos, pos) == "\"" then
    pos, cookie.value = get_quoted_string(s, pos)
    if not cookie.value then
      return nil, string.format("Can't get value of cookie named \"%s\".", cookie.name)
    end
    pos = skip_space(s, pos)
  else
    _, pos, cookie.value = s:find("^(.-)[ \t]*%f[;\0]", pos)
    pos = pos + 1
  end

  -- Loop over the attributes.
  while s:sub(pos, pos) == ";" do
    pos = pos + 1
    pos = skip_space(s, pos)
    if pos > #s then
      break
    end
    pos, name = get_token(s, pos)
    if not name then
      return nil, string.format("Can't get attribute name of cookie \"%s\".", cookie.name)
    end
    pos = skip_space(s, pos)
    if s:sub(pos, pos) == "=" then
      pos = pos + 1
      pos = skip_space(s, pos)
      if s:sub(pos, pos) == "\"" then
        pos, value = get_quoted_string(s, pos)
      else
        _, pos, value = s:find("([^;]*)", pos)
        value = value:match("(.-)[ \t]*$")
        pos = pos + 1
      end
      if not value then
        return nil, string.format("Can't get value of cookie attribute \"%s\".", name)
      end
    else
      value = true
    end
    cookie[name:lower()] = value
    pos = skip_space(s, pos)
  end

  return cookie
end

-- Read one response from the socket <code>s</code> and return it after
-- parsing.
--
-- In case of an error, a partially received response body (if any) is captured
-- and preserved in the response object. A future possible enhancement is to
-- extend this feature to also cover the response status line and headers.
-- One way to implement it would be to repurpose the current third returned
-- value from next_response() to be the partially built-up HTTP response
-- object, not just a string representing the body fragment.

local function next_response(s, method, partial)
  local response
  local status_line, header, body, fragment
  local status, err

  partial = partial or ""
  response = {
    status=nil,
    ["status-line"]=nil,
    header={},
    rawheader={},
    cookies={},
    body=""
  }

  status_line, partial = recv_line(s, partial)
  if not status_line then
    return nil, partial
  end
  status, err = parse_status_line(status_line, response)
  if not status then
    return nil, err
  end

  header, partial = recv_header(s, partial)
  if not header then
    return nil, partial
  end
  status, err = parse_header(header, response)
  if not status then
    return nil, err
  end

  body, partial, fragment = recv_body(s, response, method, partial)
  if not body then
    return nil, partial, fragment
  end
  response.body = body

  return response, partial
end

--- Tries to extract the max number of requests that should be made on
--  a keep-alive connection based on "Keep-Alive: timeout=xx,max=yy" response
--  header.
--
--  If the value is not available, an arbitrary value is used. If the connection
--  is not explicitly closed by the server, this same value is attempted.
--
--  @param response The HTTP response table
--  @return The max number of requests on a keep-alive connection
local function getPipelineMax(response)
  -- Allow users to override this with a script-arg
  local pipeline = stdnse.get_script_args({'http.pipeline', 'pipeline'})

  if(pipeline) then
    return tonumber(pipeline)
  end

  if response then
    local hdr = response.header or {}
    local opts = stdnse.strsplit("%s+", (hdr.connection or ""):lower())
    if stdnse.contains(opts, "close") then return 1 end
    if response.version >= "1.1" or stdnse.contains(opts, "keep-alive") then
      return tonumber((hdr["keep-alive"] or ""):match("max=(%d+)")) or 40
    end
  end
  return 1
end

--- Builds a string to be added to the request mod_options table
--
--  @param cookies A cookie jar just like the table returned by parse_set_cookie.
--  @param path If the argument exists, only cookies with this path are included in the request
--  @return A string to be added to the mod_options table
local function buildCookies(cookies, path)
  if type(cookies) == 'string' then return cookies end
  local cookie = {}
  for _, ck in ipairs(cookies or {}) do
    local ckpath = ck["path"]
    if not path or not ckpath
      or ckpath == path
      or ckpath:sub(-1) == "/" and ckpath == path:sub(1, ckpath:len())
      or ckpath .. "/" == path:sub(1, ckpath:len()+1)
      then
        cookie[#cookie+1] = ck["name"] .. "=" .. ck["value"]
      end
    end
  return table.concat(cookie, "; ")
end

-- HTTP cache.
-- Cache of GET and HEAD requests. Uses <"host:port:path", record>.
-- record is in the format:
--   result: The result from http.get or http.head
--   last_used: The time the record was last accessed or made.
--   get: Was the result received from a request to get or recently wiped?
--   size: The size of the record, equal to #record.result.body.
local cache = {size = 0};

local function check_size (cache)
  local max_size = tonumber(stdnse.get_script_args({'http.max-cache-size', 'http-max-cache-size'}) or 1e6);

  local size = cache.size;

  if size > max_size then
    stdnse.debug1(
        "Current http cache size (%d bytes) exceeds max size of %d",
        size, max_size);
    table.sort(cache, function(r1, r2)
      return (r1.last_used or 0) < (r2.last_used or 0);
    end);

    for i, record in ipairs(cache) do
      if size <= max_size then break end
      local result = record.result;
      if type(result.body) == "string" then
        size = size - record.size;
        record.size, record.get, result.body = 0, false, "";
      end
    end
    cache.size = size;
  end
  stdnse.debug2("Final http cache size (%d bytes) of max size of %d",
      size, max_size);
  return size;
end

-- Unique value to signal value is being retrieved.
-- Also holds <mutex, thread> pairs, working thread is value
local WORKING = setmetatable({}, {__mode = "v"});

local function lookup_cache (method, host, port, path, options)
  if(not(validate_options(options))) then
    return nil
  end

  options = options or {};
  local bypass_cache = options.bypass_cache; -- do not lookup
  local no_cache = options.no_cache; -- do not save result
  local no_cache_body = options.no_cache_body; -- do not save body

  if type(port) == "table" then port = port.number end

  local key = stdnse.get_hostname(host)..":"..port..":"..path;
  local mutex = nmap.mutex(tostring(lookup_cache)..key);

  local state = {
    mutex = mutex,
    key = key,
    method = method,
    bypass_cache = bypass_cache,
    no_cache = no_cache,
    no_cache_body = no_cache_body,
  };

  while true do
    mutex "lock";
    local record = cache[key];
    if bypass_cache or record == nil or method ~= record.method then
      WORKING[mutex] = coroutine.running();
      cache[key], state.old_record = WORKING, record;
      return nil, state;
    elseif record == WORKING then
      local working = WORKING[mutex];
      if working == nil or coroutine.status(working) == "dead" then
        -- thread died before insert_cache could be called
        cache[key] = nil; -- reset
      end
      mutex "done";
    else
      mutex "done";
      record.last_used = os.time();
      return tcopy(record.result), state;
    end
  end
end

local function response_is_cacheable(response)
  -- if response.status is nil, then an error must have occurred during the request
  -- and we probably don't want to cache the response
  if not response.status then
    return false
  end

  -- 206 Partial Content. RFC 2616, 1.34: "...a cache that does not support the
  -- Range and Content-Range headers MUST NOT cache 206 (Partial Content)
  -- responses."
  if response.status == 206 then
    return false
  end

  -- RFC 2616, 13.4. "A response received with any [status code other than 200,
  -- 203, 206, 300, 301 or 410] (e.g. status codes 302 and 307) MUST NOT be
  -- returned in a reply to a subsequent request unless there are cache-control
  -- directives or another header(s) that explicitly allow it."
  -- We violate the standard here and allow these other codes to be cached,
  -- with the exceptions listed below.

  -- 401 Unauthorized. Caching this would prevent us from retrieving it later
  -- with the correct credentials.
  if response.status == 401 then
    return false
  end

  return true
end

local function insert_cache (state, response)
  local key = assert(state.key);
  local mutex = assert(state.mutex);

  if response == nil or state.no_cache or not response_is_cacheable(response) then
    cache[key] = state.old_record;
  else
    local record = {
      result = tcopy(response),
      last_used = os.time(),
      method = state.method,
      size = type(response.body) == "string" and #response.body or 0,
    };
    response = record.result; -- only modify copy
    cache[key], cache[#cache+1] = record, record;
    if state.no_cache_body then
      response.body = "";
    end
    if type(response.body) == "string" then
      cache.size = cache.size + #response.body;
      check_size(cache);
    end
  end
  mutex "done";
end

-- Return true if the given method requires a body in the request. In case no
-- body was supplied we must send "Content-Length: 0".
local function request_method_needs_content_length(method)
  return method == "POST"
end

-- For each of the following request functions, <code>host</code> may either be
-- a string or a table, and <code>port</code> may either be a number or a
-- table.
--
-- The format of the return value is a table with the following structure:
-- {status = 200, status-line = "HTTP/1.1 200 OK", header = {}, rawheader = {}, body ="<html>...</html>"}
-- The header table has an entry for each received header with the header name
-- being the key. The table also has an entry named "status" which contains the
-- http status code of the request.
-- In case of an error, the status is nil, status-line describes the problem,
-- and fragment contains a partially received response body (if any).

local function http_error(status_line, fragment)
  return {
    status = nil,
    ["status-line"] = status_line,
    header = {},
    rawheader = {},
    body = nil,
    fragment = fragment
  }
end

--- Build an HTTP request from parameters and return it as a string.
--
-- @param host The host this request is intended for.
-- @param port The port this request is intended for.
-- @param method The method to use.
-- @param path The path for the request.
-- @param options A table of options, which may include the keys:
-- * <code>header</code>: A table containing additional headers to be used for the request.
-- * <code>content</code>: The content of the message (content-length will be added -- set header['Content-Length'] to override)
-- * <code>cookies</code>: A table of cookies in the form returned by <code>parse_set_cookie</code>.
-- * <code>auth</code>: A table containing the keys <code>username</code> and <code>password</code>.
-- @return A request string.
-- @see generic_request
local function build_request(host, port, method, path, options)
  if(not(validate_options(options))) then
    return nil
  end
  options = options or {}

  -- Private copy of the options table, used to add default header fields.
  local mod_options = {
    header = {
      Connection = "close",
      Host = get_host_field(host, port),
      ["User-Agent"]  = USER_AGENT
    }
  }

  if options.cookies then
    local cookies = buildCookies(options.cookies, path)
    if #cookies > 0 then
      mod_options.header["Cookie"] = cookies
    end
  end

  if options.auth and not (options.auth.digest or options.auth.ntlm) then
    local username = options.auth.username
    local password = options.auth.password
    local credentials = "Basic " .. base64.enc(username .. ":" .. password)
    mod_options.header["Authorization"] = credentials
  end

  if options.digestauth then
    local order = {"username", "realm", "nonce", "digest-uri", "algorithm", "response", "qop", "nc", "cnonce"}
    local no_quote = {algorithm=true, qop=true, nc=true}
    local creds = {}
    for _,k in ipairs(order) do
      local v = options.digestauth[k]
      if v then
        if no_quote[k] then
          table.insert(creds, ("%s=%s"):format(k,v))
        else
          if k == "digest-uri" then
            table.insert(creds, ('%s="%s"'):format("uri",v))
          else
            table.insert(creds, ('%s="%s"'):format(k,v))
          end
        end
      end
    end
    local credentials = "Digest "..table.concat(creds, ", ")
    mod_options.header["Authorization"] = credentials
  end

  if options.ntlmauth then
    mod_options.header["Authorization"] = "NTLM " .. base64.enc(options.ntlmauth)
  end


  local body
  -- Build a form submission from a table, like "k1=v1&k2=v2".
  if type(options.content) == "table" then
    local parts = {}
    local k, v
    for k, v in pairs(options.content) do
      parts[#parts + 1] = url.escape(k) .. "=" .. url.escape(v)
    end
    body = table.concat(parts, "&")
    mod_options.header["Content-Type"] = "application/x-www-form-urlencoded"
  elseif options.content then
    body = options.content
  elseif request_method_needs_content_length(method) then
    body = ""
  end
  if body then
    mod_options.header["Content-Length"] = #body
  end

  -- Add any other header fields into the local copy.
  table_augment(mod_options, options)
  -- We concat this string manually to allow null bytes in requests
  local request_line = method.." "..path.." HTTP/1.1"
  local header = {}
  for name, value in pairs(mod_options.header) do
    -- we concat this string manually to allow null bytes in requests
    header[#header + 1] = name..": "..value
  end

  return request_line .. "\r\n" .. stdnse.strjoin("\r\n", header) .. "\r\n\r\n" .. (body or "")
end

--- Send a string to a host and port and return the HTTP result. This function
-- is like <code>generic_request</code>, to be used when you have a ready-made
-- request, not a collection of request parameters.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param options A table of other parameters. It may have any of these fields:
-- * <code>timeout</code>: A timeout used for socket operations.
-- * <code>header</code>: A table containing additional headers to be used for the request.
-- * <code>content</code>: The content of the message (content-length will be added -- set header['Content-Length'] to override)
-- * <code>cookies</code>: A table of cookies in the form returned by <code>parse_set_cookie</code>.
-- * <code>auth</code>: A table containing the keys <code>username</code> and <code>password</code>.
-- @return A response table, see module documentation for description.
-- @see generic_request
local function request(host, port, data, options)
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  local method
  local header
  local response

  options = options or {}

  if type(port) == 'table' then
    if port.protocol and port.protocol ~= 'tcp' then
      stdnse.debug1("http.request() supports the TCP protocol only, your request to %s cannot be completed.", host)
      return http_error("Unsupported protocol.")
    end
  end

  method = string.match(data, "^(%S+)")

  local socket, partial, opts = comm.tryssl(host, port, data, {timeout = options.timeout, any_af = options.any_af})

  if not socket then
    stdnse.debug1("http.request socket error: %s", partial)
    return http_error("Error creating socket.")
  end

  repeat
    local fragment
    response, partial, fragment = next_response(socket, method, partial)
    if not response then
      return http_error("Error in next_response function; " .. partial, fragment)
    end
    -- See RFC 2616, sections 8.2.3 and 10.1.1, for the 100 Continue status.
    -- Sometimes a server will tell us to "go ahead" with a POST body before
    -- sending the real response. If we got one of those, skip over it.
  until not (response.status >= 100 and response.status <= 199)

  socket:close()

  -- if SSL was used to retrieve the URL mark this in the response
  response.ssl = ( opts == 'ssl' )

  return response
end

---Do a single request with a given method. The response is returned as the standard
-- response table (see the module documentation).
--
-- The <code>get</code>, <code>head</code>, and <code>post</code> functions are simple
-- wrappers around <code>generic_request</code>.
--
-- Any 1XX (informational) responses are discarded.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param method The method to use; for example, 'GET', 'HEAD', etc.
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket timeouts, HTTP headers, and other parameters. For full documentation, see the module documentation (above).
-- @return A response table, see module documentation for description.
-- @see request
function generic_request(host, port, method, path, options)
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end

  local digest_auth = options and options.auth and options.auth.digest
  local ntlm_auth = options and options.auth and options.auth.ntlm

  if (digest_auth or ntlm_auth) and not have_ssl then
    stdnse.debug1("http: digest and ntlm auth require openssl.")
  end

  if digest_auth and have_ssl then
    -- If we want to do digest authentication, we have to make an initial
    -- request to get realm, nonce and other fields.
    local options_with_auth_removed = tcopy(options)
    options_with_auth_removed["auth"] = nil
    local r = generic_request(host, port, method, path, options_with_auth_removed)
    local h = r.header['www-authenticate']
    if not r.status or (h and not string.find(h:lower(), "digest.-realm")) then
      stdnse.debug1("http: the target doesn't support digest auth or there was an error during request.")
      return http_error("The target doesn't support digest auth or there was an error during request.")
    end
    -- Compute the response hash
    local dmd5 = sasl.DigestMD5:new(h, options.auth.username, options.auth.password, method, path)
    local _, digest_table = dmd5:calcDigest()
    options.digestauth = digest_table
  end

  if ntlm_auth and have_ssl then

    local custom_options = tcopy(options) -- to be sent with the type 1 request
    custom_options["auth"] = nil -- removing the auth options
    -- let's check if the target supports ntlm with a simple get request.
    -- Setting a timeout here other than nil messes up the authentication if this is the first device sending
    -- a request to the server. Don't know why.
    custom_options.timeout = nil
    local response = generic_request(host, port, method, path, custom_options)
    local authentication_header = response.header['www-authenticate']
    -- get back the timeout option.
    custom_options.timeout = options.timeout
    custom_options.header = options.header or {}
    custom_options.header["Connection"] = "Keep-Alive" -- Keep-Alive headers are needed for authentication.

    if (not authentication_header) or (not response.status) or (not string.find(authentication_header:lower(), "ntlm")) then
      stdnse.debug1("http: the target doesn't support NTLM or there was an error during request.")
      return http_error("The target doesn't support NTLM or there was an error during request.")
    end

    -- ntlm works with three messages. we send a request, it sends
    -- a challenge, we respond to the challenge.
    local hostname = options.auth.hostname or "localhost" -- the hostname to be sent
    local workstation_name = options.auth.workstation_name or "NMAP" -- the workstation name to be sent
    local username = options.auth.username -- the username as specified

    local auth_blob = "NTLMSSP\x00" .. -- NTLM signature
    "\x01\x00\x00\x00" .. -- NTLM Type 1 message
    bin.pack("<I", 0xa208b207) .. -- flags 56, 128, Version, Extended Security, Always Sign, Workstation supplied, Domain Supplied, NTLM Key, OEM, Unicode
    bin.pack("<SSISSI",#workstation_name, #workstation_name, 40 + #hostname, #hostname, #hostname, 40) .. -- Supplied Domain and Workstation
    bin.pack("CC<S", -- OS version info
    5, 1, 2600) .. -- 5.1.2600
    "\x00\x00\x00\x0f" .. -- OS version info end (static 0x0000000f)
    hostname.. -- HOST NAME
    workstation_name --WORKSTATION name

    custom_options.ntlmauth = auth_blob

    -- check if the protocol is tcp
    if type(port) == 'table' then
      if port.protocol and port.protocol ~= 'tcp' then
        stdnse.debug1("NTLM authentication supports the TCP protocol only, your request to %s cannot be completed.", host)
        return http_error("Unsupported protocol.")
      end
    end

    -- tryssl uses ssl if needed. sends the type 1 message.
    local socket, partial, opts = comm.tryssl(host, port, build_request(host, port, method, path, custom_options), { timeout = options.timeout })

    if not socket then
      return http_error("Could not create socket to send type 1 message.")
    end

    repeat
      local fragment
      response, partial, fragment = next_response(socket, method, partial)
      if not response then
        return http_error("There was error in receiving response of type 1 message; " .. partial, fragment)
      end
    until not (response.status >= 100 and response.status <= 199)

    authentication_header = response.header['www-authenticate']
    -- take out the challenge
    local type2_response = authentication_header:sub(authentication_header:find(' ')+1, -1)
    local _, _, message_type, _, _, _, flags_received, challenge= bin.unpack("<A8ISSIIA8", base64.dec(type2_response))
    -- check if the response is a type 2 message.
    if message_type ~= 0x02 then
      stdnse.debug1("Expected type 2 message as response.")
      return
    end

    local is_unicode  = (bit.band(flags_received, 0x00000001) == 0x00000001) -- 0x00000001 UNICODE Flag
    local is_extended = (bit.band(flags_received, 0x00080000) == 0x00080000) -- 0x00080000 Extended Security Flag
    local type_3_flags = 0xa2888206 -- flags 56, 128, Version, Target Info, Extended Security, Always Sign, NTLM Key, OEM

    local lanman, ntlm
    if is_extended then
    -- this essentially calls the new ntlmv2_session_response function in smbauth.lua and returns whatever it returns
      lanman, ntlm = smbauth.get_password_response(nil, username, "", options.auth.password, nil, "ntlmv2_session", challenge, true)
    else
      lanman, ntlm = smbauth.get_password_response(nil, username, "", options.auth.password, nil, "ntlm", challenge, false)
      type_3_flags = type_3_flags - 0x00080000 -- Removing the Extended Security Flag as server doesn't support it.
    end

    local domain = ""
    local session_key = ""

    -- if server supports unicode, then strings are sent in unicode format.
    if is_unicode then
      username = unicode.utf8to16(username)
      hostname = unicode.utf8to16(hostname)
      type_3_flags = type_3_flags - 0x00000001 -- OEM flag is 0x00000002. removing 0x00000001 results in UNICODE flag.
    end

    local BASE_OFFSET = 72 -- Version 3 -- The Session Key<empty in our case>, flags, and OS Version structure are all present.

    auth_blob = bin.pack("<zISSISSISSISSISSISSIICCSAAAAA",
      "NTLMSSP",
      0x00000003,
      #lanman,
      #lanman,
      BASE_OFFSET + #username + #hostname,
      ( #ntlm ),
      ( #ntlm ),
      BASE_OFFSET + #username + #hostname + #lanman,
      #domain,
      #domain,
      BASE_OFFSET,
      #username,
      #username,
      BASE_OFFSET,
      #hostname,
      #hostname,
      BASE_OFFSET + #username,
      #session_key,
      #session_key,
      BASE_OFFSET + #username + #hostname + #lanman + #ntlm,
      type_3_flags,
      5,
      1,
      2600,
      "\x00\x00\x00\x0f",
      username,
      hostname,
      lanman,
      ntlm)

    custom_options.ntlmauth = auth_blob
    socket:send(build_request(host, port, method, path, custom_options))

    repeat
      local fragment
      response, partial, fragment = next_response(socket, method, partial)
      if not response then
        return http_error("There was error in receiving response of type 3 message; " .. partial, fragment)
      end
    until not (response.status >= 100 and response.status <= 199)

    socket:close()
    response.ssl = ( opts == 'ssl' )

    return response
  end

  return request(host, port, build_request(host, port, method, path, options), options)
end

---Uploads a file using the PUT method and returns a result table. This is a simple wrapper
-- around <code>generic_request</code>
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket timeouts, HTTP headers, and other parameters. For full documentation, see the module documentation (above).
-- @param putdata The contents of the file to upload
-- @return A response table, see module documentation for description.
-- @see http.generic_request
function put(host, port, path, options, putdata)
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  if ( not(putdata) ) then
    return http_error("No file to PUT.")
  end
  local mod_options = {
    content = putdata,
  }
  table_augment(mod_options, options or {})
  return generic_request(host, port, "PUT", path, mod_options)
end

-- A battery of tests a URL is subjected to in order to decide if it may be
-- redirected to.
local redirect_ok_rules = {

  -- Check if there's any credentials in the url
  function (url, host, port)
    -- bail if userinfo is present
    return not url.userinfo
  end,

  -- Check if the location is within the domain or host
  --
  -- Notes:
  -- * A domain match must be exact and at least a second-level domain
  -- * ccTLDs are not treated as such. The rule will not stop a redirect
  --   from foo.co.uk to bar.co.uk even though it logically should.
  function (url, host, port)
    local hostname = stdnse.get_hostname(host)
    if hostname == host.ip then
      return url.host == hostname
    end
    local domain = function (h) return (h:match("%..+%..+") or h):lower() end
    return domain(hostname) == domain(url.host)
  end,

  -- Check whether the new location has the same port number
  function (url, host, port)
    -- port fixup, adds default ports 80 and 443 in case no url.port was
    -- defined, we do this based on the url scheme
    local url_port = url.port or get_default_port(url.scheme)
    if not url_port or url_port == port.number then
      return true
    end
    return false
  end,

  -- Check whether the url.scheme matches the port.service
  function (url, host, port)
    -- if url.scheme is present then it must match the scanned port
    if url.scheme and url.port then return true end
    if url.scheme and url.scheme ~= port.service then return false end
    return true
  end,

  -- make sure we're actually being redirected somewhere and not to the same url
  function (url, host, port)
    -- url.path must be set if returning true
    -- path cannot be unchanged unless host has changed
    -- TODO: Since we do not know here what the actual old path was then
    --       the effectiveness of this code is a bit unclear.
    if not url.path then return false end
    if url.path == "/" and url.host == (host.targetname or host.ip) then return false end
    return true
  end,
}

--- Provides the default behavior for HTTP redirects.
--
-- Redirects will be followed unless they:
-- * contain credentials
-- * are on a different domain or host
-- * have a different port number or URI scheme
-- * redirect to the same URI
-- * exceed the maximum number of redirects specified
-- @param host table as received by the action function
-- @param port table as received by the action function
-- @param counter number of redirects to follow.
-- @return a default closure suitable for option "redirect_ok"
function redirect_ok(host, port, counter)
  -- convert a numeric port to a table
  if ( "number" == type(port) ) then
    port = { number = port }
  end
  return function(url)
    if ( counter == 0 ) then return false end
    counter = counter - 1
    for i, rule in ipairs( redirect_ok_rules ) do
      if ( not(rule( url, host, port )) ) then
        --stdnse.debug1("Rule failed: %d", i)
        return false
      end
    end
    return true
  end
end

--- Handles a HTTP redirect
-- @param host table as received by the script action function
-- @param port table as received by the script action function
-- @param path string
-- @param response table as returned by http.get or http.head
-- @return url table as returned by <code>url.parse</code> or nil if there's no
--         redirect taking place
function parse_redirect(host, port, path, response)
  if ( not(tostring(response.status):match("^30[01237]$")) or
       not(response.header) or
       not(response.header.location) ) then
    return nil
  end
  port = ( "number" == type(port) ) and { number = port } or port
  local u = url.parse(response.header.location)
  if ( not(u.host) ) then
    -- we're dealing with a relative url
    u.host = stdnse.get_hostname(host)
  end
  -- do port fixup
  u.port = u.port or get_default_port(u.scheme) or port.number
  if ( not(u.path) ) then
    u.path = "/"
  end
  u.path = url.absolute(path, u.path)
  if ( u.query ) then
    u.path = ("%s?%s"):format( u.path, u.query )
  end
  return u
end

-- Retrieves the correct function to use to validate HTTP redirects
-- @param host table as received by the action function
-- @param port table as received by the action function
-- @param options table as passed to http.get or http.head
-- @return redirect_ok function used to validate HTTP redirects
local function get_redirect_ok(host, port, options)
  if ( options ) then
    if ( options.redirect_ok == false ) then
      return function() return false end
    elseif( "function" == type(options.redirect_ok) ) then
      return options.redirect_ok(host, port)
    elseif( type(options.redirect_ok) == "number") then
      return redirect_ok(host, port, options.redirect_ok)
    else
      return redirect_ok(host, port, MAX_REDIRECT_COUNT)
    end
  else
    return redirect_ok(host, port, MAX_REDIRECT_COUNT)
  end
end

---Fetches a resource with a GET request and returns the result as a table.
--
-- This is a simple wrapper around <code>generic_request</code>, with the added
-- benefit of having local caching and support for HTTP redirects. Redirects
-- are followed only if they pass all the validation rules of the redirect_ok
-- function. This function may be overridden by supplying a custom function in
-- the <code>redirect_ok</code> field of the options array. The default
-- function redirects the request if the destination is:
-- * Within the same host or domain
-- * Has the same port number
-- * Stays within the current scheme
-- * Does not exceed <code>MAX_REDIRECT_COUNT</code> count of redirects
--
-- Caching and redirects can be controlled in the <code>options</code> array,
-- see module documentation for more information.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket
--                timeouts, HTTP headers, and other parameters. For full
--                documentation, see the module documentation (above).
-- @return A response table, see module documentation for description.
-- @see http.generic_request
function get(host, port, path, options)
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  local redir_check = get_redirect_ok(host, port, options)
  local response, state, location
  local u = { host = host, port = port, path = path }
  repeat
    response, state = lookup_cache("GET", u.host, u.port, u.path, options);
    if ( response == nil ) then
      response = generic_request(u.host, u.port, "GET", u.path, options)
      insert_cache(state, response);
    end
    u = parse_redirect(host, port, path, response)
    if ( not(u) ) then
      break
    end
    location = location or {}
    table.insert(location, response.header.location)
  until( not(redir_check(u)) )
  response.location = location
  return response
end

---Parses a URL and calls <code>http.get</code> with the result. The URL can contain
-- all the standard fields, protocol://host:port/path
--
-- @param u The URL of the host.
-- @param options [optional] A table that lets the caller control socket timeouts, HTTP headers, and other parameters. For full documentation, see the module documentation (above).
-- @return A response table, see module documentation for description.
-- @see http.get
function get_url( u, options )
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  local parsed = url.parse( u )
  local port = {}

  port.service = parsed.scheme
  port.number = parsed.port or get_default_port(parsed.scheme) or 80

  local path = parsed.path or "/"
  if parsed.query then
    path = path .. "?" .. parsed.query
  end

  return get( parsed.host, port, path, options )
end

---Fetches a resource with a HEAD request.
--
-- Like <code>get</code>, this is a simple wrapper around
-- <code>generic_request</code> with response caching. This function also has
-- support for HTTP redirects. Redirects are followed only if they pass all the
-- validation rules of the redirect_ok function. This function may be
-- overridden by supplying a custom function in the <code>redirect_ok</code>
-- field of the options array. The default function redirects the request if
-- the destination is:
-- * Within the same host or domain
-- * Has the same port number
-- * Stays within the current scheme
-- * Does not exceed <code>MAX_REDIRECT_COUNT</code> count of redirects
--
-- Caching and redirects can be controlled in the <code>options</code> array,
-- see module documentation for more information.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket
--                timeouts, HTTP headers, and other parameters. For full
--                documentation, see the module documentation (above).
-- @return A response table, see module documentation for description.
-- @see http.generic_request
function head(host, port, path, options)
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  local redir_check = get_redirect_ok(host, port, options)
  local response, state, location
  local u = { host = host, port = port, path = path }
  repeat
    response, state = lookup_cache("HEAD", u.host, u.port, u.path, options);
    if response == nil then
      response = generic_request(u.host, u.port, "HEAD", u.path, options)
      insert_cache(state, response);
    end
    u = parse_redirect(host, port, path, response)
    if ( not(u) ) then
      break
    end
    location = location or {}
    table.insert(location, response.header.location)
  until( not(redir_check(u)) )
  response.location = location
  return response
end

---Fetches a resource with a POST request.
--
-- Like <code>get</code>, this is a simple wrapper around
-- <code>generic_request</code> except that postdata is handled properly.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket
--                timeouts, HTTP headers, and other parameters. For full
--                documentation, see the module documentation (above).
-- @param ignored Ignored for backwards compatibility.
-- @param postdata A string or a table of data to be posted. If a table, the
--                 keys and values must be strings, and they will be encoded
--                 into an application/x-www-form-encoded form submission.
-- @return A response table, see module documentation for description.
-- @see http.generic_request
function post( host, port, path, options, ignored, postdata )
  if(not(validate_options(options))) then
    return http_error("Options failed to validate.")
  end
  local mod_options = {
    content = postdata,
  }
  table_augment(mod_options, options or {})
  return generic_request(host, port, "POST", path, mod_options)
end

-- Deprecated pipeline functions
function pGet( host, port, path, options, ignored, allReqs )
  stdnse.debug1("WARNING: pGet() is deprecated. Use pipeline_add() instead.")
  return pipeline_add(path, options, allReqs, 'GET')
end
function pHead( host, port, path, options, ignored, allReqs )
  stdnse.debug1("WARNING: pHead() is deprecated. Use pipeline_add instead.")
  return pipeline_add(path, options, allReqs, 'HEAD')
end
function addPipeline(host, port, path, options, ignored, allReqs, method)
  stdnse.debug1("WARNING: addPipeline() is deprecated! Use pipeline_add instead.")
  return pipeline_add(path, options, allReqs, method)
end
function pipeline(host, port, allReqs)
  stdnse.debug1("WARNING: pipeline() is deprecated. Use pipeline_go() instead.")
  return pipeline_go(host, port, allReqs)
end


---Adds a pending request to the HTTP pipeline.
--
-- The HTTP pipeline is a set of requests that will all be sent at the same
-- time, or as close as the server allows. This allows more efficient code,
-- since requests are automatically buffered and sent simultaneously.
--
-- The <code>all_requests</code> argument contains the current list of queued
-- requests (if this is the first time calling <code>pipeline_add</code>, it
-- should be <code>nil</code>). After adding the request to end of the queue,
-- the queue is returned and can be passed to the next
-- <code>pipeline_add</code> call.
--
-- When all requests have been queued, call <code>pipeline_go</code> with the
-- all_requests table that has been built.
--
-- @param path The path to retrieve.
-- @param options [optional] A table that lets the caller control socket
--                timeouts, HTTP headers, and other parameters. For full
--                documentation, see the module documentation (above).
-- @param all_requests [optional] The current pipeline queue (returned from a
--                     previous <code>add_pipeline</code> call), or nil if it's
--                     the first call.
-- @param method [optional] The HTTP method ('GET', 'HEAD', 'POST', etc).
--                          Default: 'GET'.
-- @return Table with the pipeline requests (plus this new one)
-- @see http.pipeline_go
function pipeline_add(path, options, all_requests, method)
  if(not(validate_options(options))) then
    return nil
  end
  method = method or 'GET'
  all_requests = all_requests or {}

  local mod_options = {
    header = {
      ["Connection"] = "keep-alive"
    }
  }
  table_augment(mod_options, options or {})

  local object = { method=method, path=path, options=mod_options }
  table.insert(all_requests, object)

  return all_requests
end

---Performs all queued requests in the all_requests variable (created by the
-- <code>pipeline_add</code> function).
--
-- Returns an array of responses, each of which is a table as defined in the
-- module documentation above.
--
-- @param host The host to connect to.
-- @param port The port to connect to.
-- @param all_requests A table with all the previously built pipeline requests
-- @return A list of responses, in the same order as the requests were queued.
--         Each response is a table as described in the module documentation.
--         The response list may be either nil or shorter than expected (up to
--         and including being completely empty) due to communication issues.
function pipeline_go(host, port, all_requests)
  local responses
  local response
  local partial

  responses = {}

  -- Check for an empty request
  if (not all_requests or #all_requests == 0) then
    stdnse.debug1("Warning: empty set of requests passed to http.pipeline_go()")
    return responses
  end
  stdnse.debug1("Total number of pipelined requests: " .. #all_requests)

  local socket, bopt

  -- We'll try a first request with keep-alive, just to check if the server
  -- supports and how many requests we can send into one socket!
  local request = build_request(host, port, all_requests[1].method, all_requests[1].path, all_requests[1].options)

  socket, partial, bopt = comm.tryssl(host, port, request, {recv_before=false})
  if not socket then
    return nil
  end

  response, partial = next_response(socket, all_requests[1].method, partial)
  if not response then
    return nil
  end

  table.insert(responses, response)

  local limit = getPipelineMax(response) -- how many requests to send on one connection
  limit = limit > #all_requests and #all_requests or limit
  local max_pipeline = stdnse.get_script_args("http.max-pipeline") or limit -- how many requests should be pipelined
  local count = 1
  stdnse.debug1("Number of requests allowed by pipeline: " .. limit)

  while #responses < #all_requests do
    local j, batch_end
    -- we build a table with many requests, upper limited by the var "limit"
    local requests = {}

    if #responses + limit < #all_requests then
      batch_end = #responses + limit
    else
      batch_end = #all_requests
    end

    j = #responses + 1
    while j <= batch_end do
      if j == batch_end then
        all_requests[j].options.header["Connection"] = "close"
      end
      if j~= batch_end and all_requests[j].options.header["Connection"] ~= 'keep-alive' then
        all_requests[j].options.header["Connection"] = 'keep-alive'
      end
      table.insert(requests, build_request(host, port, all_requests[j].method, all_requests[j].path, all_requests[j].options))
      -- to avoid calling build_request more than one time on the same request,
      -- we might want to build all the requests once, above the main while loop
      j = j + 1
    end

    if count >= limit or not socket:get_info() then
      socket:connect(host, port, bopt)
      partial = ""
      count = 0
    end
    socket:set_timeout(10000)

    local start = 1
    local len = #requests
    local req_sent = 0
    -- start sending the requests and pipeline them in batches of max_pipeline elements
    while start <= len do
      stdnse.debug2("HTTP pipeline: number of requests in current batch: %d, already sent: %d, responses from current batch: %d, all responses received: %d",len,start-1,count,#responses)
      local req = {}
      if max_pipeline == limit then
        req = requests
      else
        for i=start,start+max_pipeline-1,1 do
          table.insert(req, requests[i])
        end
      end
      local num_req = #req
      req = table.concat(req, "")
      start = start + max_pipeline
      socket:send(req)
      req_sent = req_sent + num_req
      local inner_count = 0
      local fail = false
      -- collect responses for the last batch
      while inner_count < num_req and #responses < #all_requests do
        response, partial = next_response(socket, all_requests[#responses + 1].method, partial)
        if not response then
          stdnse.debug1("HTTP pipeline: there was a problem while receiving responses.")
          stdnse.debug3("The request was:\n%s",req)
          fail = true
          break
        end
        count = count + 1
        inner_count = inner_count + 1
        responses[#responses + 1] = response
      end
      if fail then break end
    end

    socket:close()

    if count == 0 then
      stdnse.debug1("Received 0 of %d expected responses.\nGiving up on pipeline.", limit);
      break
    elseif count < req_sent then
      stdnse.debug1("Received only %d of %d expected responses.\nDecreasing max pipelined requests to %d.", count, req_sent, count)
      limit = count
    end
  end

  stdnse.debug1("Number of received responses: " .. #responses)

  return responses
end


-- Parsing of specific headers. skip_space and the read_* functions return the
-- byte index following whatever they have just read, or nil on error.

-- Skip whitespace (that has already been folded from LWS). See RFC 2616,
-- section 2.2, definition of LWS.
local function skip_space(s, pos)
  local _

  _, pos = string.find(s, "^[ \t]*", pos)

  return pos + 1
end

-- See RFC 2616, section 2.2.
local function read_token(s, pos)
  local _, token

  pos = skip_space(s, pos)
  -- 1*<any CHAR except CTLs or separators>. CHAR is only byte values 0-127.
  _, pos, token = string.find(s, "^([^\0\001-\031()<>@,;:\\\"/?={} \t%[%]\127-\255]+)", pos)

  if token then
    return pos + 1, token
  else
    return nil
  end
end

-- See RFC 2616, section 2.2. Here we relax the restriction that TEXT may not
-- contain CTLs.
local function read_quoted_string(s, pos)
  local chars = {}

  if string.sub(s, pos, pos) ~= "\"" then
    return nil
  end
  pos = pos + 1
  pos = skip_space(s, pos)
  while pos <= #s and string.sub(s, pos, pos) ~= "\"" do
    local c

    c = string.sub(s, pos, pos)
    if c == "\\" then
      if pos < #s then
        pos = pos + 1
        c = string.sub(s, pos, pos)
      else
        return nil
      end
    end

    chars[#chars + 1] = c
    pos = pos + 1
  end
  if pos > #s or string.sub(s, pos, pos) ~= "\"" then
    return nil
  end

  return pos + 1, table.concat(chars)
end

local function read_token_or_quoted_string(s, pos)
  pos = skip_space(s, pos)
  if string.sub(s, pos, pos) == "\"" then
    return read_quoted_string(s, pos)
  else
    return read_token(s, pos)
  end
end

--- Create a pattern to find a tag
--
-- Case-insensitive search for tags
-- @param tag The name of the tag to find
-- @param endtag Boolean true if you are looking for an end tag, otherwise it will look for a start tag
-- @return A pattern to find the tag
function tag_pattern(tag, endtag)
  local patt = {}
  if endtag then
    patt[1] = "</%s*"
  else
    patt[1] = "<%s*"
  end
  local up, down = tag:upper(), tag:lower()
  for i = 1, #tag do
    patt[#patt+1] = string.format("[%s%s]", up:sub(i,i), down:sub(i,i))
  end
  if endtag then
    patt[#patt+1] = "%f[%s>].->"
  else
    patt[#patt+1] = "%f[%s/>].->"
  end
  return table.concat(patt)
end

---
-- Finds forms in html code
--
-- returns table of found forms, in plaintext.
-- @param body A <code>response.body</code> in which to search for forms
-- @return A list of forms.
function grab_forms(body)
  local forms = {}
  if not body then return forms end
  local form_start_expr = tag_pattern("form")
  local form_end_expr = tag_pattern("form", true)

  local form_opening = string.find(body, form_start_expr)
  local forms = {}

  while form_opening do
    local form_closing = string.find(body, form_end_expr, form_opening+1)
    if form_closing == nil then --html code contains errors
      break
    end
    forms[#forms+1] = string.sub(body, form_opening, form_closing-1)
    if form_closing+1 <= #body then
      form_opening = string.find(body, form_start_expr, form_closing+1)
    else
      break
    end
  end
  return forms
end

local function get_attr (html, name)
  local lhtml = html:lower()
  local lname = name:lower()
  -- try the attribute-value syntax first
  local _, pos = lhtml:find('%s' .. lname .. '%s*=%s*[^%s]')
  if not pos then
    -- try the empty attribute syntax and, if found,
    -- return zero-length string as its value; nil otherwise
    return lhtml:match('[^%s=]%s+' .. lname .. '[%s/>]') and "" or nil
  end
  local value
  _, value = html:match('^([\'"])(.-)%1', pos)
  if not value then
    value = html:match('^[^%s<>=\'"`]+', pos)
  end
  return slaxml.parser.unescape(value)
end
---
-- Parses a form, that is, finds its action and fields.
-- @param form A plaintext representation of form
-- @return A dictionary with keys: <code>action</code>,
-- <code>method</code> if one is specified, <code>fields</code>
-- which is a list of fields found in the form each of which has a
-- <code>name</code> attribute and <code>type</code> if specified.
function parse_form(form)
  local parsed = {}
  local fields = {}
  local form_action = get_attr(form, "action")
  if form_action then
    parsed["action"] = form_action
  end

  -- determine if the form is using get or post
  local form_method = get_attr(form, "method")
  if form_method then
    parsed["method"] = string.lower(form_method)
  end

  -- get the id of the form
  local form_id = get_attr(form, "id")
  if form_id then
    parsed["id"] = string.lower(form_id)
  end

  -- now identify the fields
  local input_type
  local input_name
  local input_value

  -- first find regular inputs
  for f in string.gmatch(form, tag_pattern("input")) do
    input_type = get_attr(f, "type")
    input_name = get_attr(f, "name")
    input_value = get_attr(f, "value")
    local next_field_index = #fields+1
    if input_name then
      fields[next_field_index] = {}
      fields[next_field_index]["name"] = input_name
      if input_type then
        fields[next_field_index]["type"] = string.lower(input_type)
      end
      if input_value then
        fields[next_field_index]["value"] = input_value
      end
    end
  end

  -- now search for textareas
  for f in string.gmatch(form, tag_pattern("textarea")) do
    input_name = get_attr(f, "name")
    local next_field_index = #fields+1
    if input_name then
      fields[next_field_index] = {}
      fields[next_field_index]["name"] = input_name
      fields[next_field_index]["type"] = "textarea"
    end
  end
  parsed["fields"] = fields
  return parsed
end

local MONTH_MAP = {
  Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
  Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12
}

--- Parses an HTTP date string
--
-- Supports any of the following formats from section 3.3.1 of RFC 2616:
-- * Sun, 06 Nov 1994 08:49:37 GMT  (RFC 822, updated by RFC 1123)
-- * Sunday, 06-Nov-94 08:49:37 GMT (RFC 850, obsoleted by RFC 1036)
-- * Sun Nov  6 08:49:37 1994       (ANSI C's <code>asctime()</code> format)
-- @param s the date string.
-- @return a table with keys <code>year</code>, <code>month</code>,
-- <code>day</code>, <code>hour</code>, <code>min</code>, <code>sec</code>, and
-- <code>isdst</code>, relative to GMT, suitable for input to
-- <code>os.time</code>.
function parse_date(s)
  local day, month, year, hour, min, sec, tz, month_name

  -- Handle RFC 1123 and 1036 at once.
  day, month_name, year, hour, min, sec, tz = s:match("^%w+, (%d+)[- ](%w+)[- ](%d+) (%d+):(%d+):(%d+) (%w+)$")
  if not day then
    month_name, day, hour, min, sec, year = s:match("%w+ (%w+)  ?(%d+) (%d+):(%d+):(%d+) (%d+)")
    tz = "GMT"
  end
  if not day then
    stdnse.debug1("http.parse_date: can't parse date \"%s\": unknown format.", s)
    return nil
  end
  -- Look up the numeric code for month.
  month = MONTH_MAP[month_name]
  if not month then
    stdnse.debug1("http.parse_date: unknown month name \"%s\".", month_name)
    return nil
  end
  if tz ~= "GMT" then
    stdnse.debug1("http.parse_date: don't know time zone \"%s\", only \"GMT\".", tz)
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

-- See RFC 2617, section 1.2. This function returns a table with keys "scheme"
-- and "params".
local function read_auth_challenge(s, pos)
  local _, scheme, params

  pos, scheme = read_token(s, pos)
  if not scheme then
    return nil
  end

  params = {}
  pos = skip_space(s, pos)
  while pos < #s do
    local name, val
    local tmp_pos

    -- We need to peek ahead at this point. It's possible that we've hit the
    -- end of one challenge and the beginning of another. Section 14.33 says
    -- that the header value can be 1#challenge, in other words several
    -- challenges separated by commas. Because the auth-params are also
    -- separated by commas, the only way we can tell is if we find a token not
    -- followed by an equals sign.
    tmp_pos = pos
    tmp_pos, name = read_token(s, tmp_pos)
    if not name then
      pos = skip_space(s, pos + 1)
      return pos, { scheme = scheme, params = nil }
    end
    tmp_pos = skip_space(s, tmp_pos)
    if string.sub(s, tmp_pos, tmp_pos) ~= "=" then
      -- No equals sign, must be the beginning of another challenge.
      break
    end
    tmp_pos = tmp_pos + 1

    pos = tmp_pos
    pos, val = read_token_or_quoted_string(s, pos)
    if not val then
      return nil
    end
    if params[name] then
      return nil
    end
    params[name] = val
    pos = skip_space(s, pos)
    if string.sub(s, pos, pos) == "," then
      pos = skip_space(s, pos + 1)
      if pos > #s then
        return nil
      end
    end
  end

  return pos, { scheme = scheme, params = params }
end

---Parses the WWW-Authenticate header as described in RFC 2616, section 14.47
-- and RFC 2617, section 1.2.
--
-- The return value is an array of challenges. Each challenge is a table with
-- the keys <code>scheme</code> and <code>params</code>.
-- @param s The header value text.
-- @return An array of challenges, or <code>nil</code> on error.
function parse_www_authenticate(s)
  local challenges = {}
  local pos

  pos = 1
  while pos <= #s do
    local challenge

    pos, challenge = read_auth_challenge(s, pos)
    if not challenge then
      return nil
    end
    challenges[#challenges + 1] = challenge
  end

  return challenges
end


---Take the data returned from a HTTP request and return the status string.
-- Useful for <code>stdnse.debug</code> messages and even advanced output.
--
-- @param data The response table from any HTTP request
-- @return The best status string we could find: either the actual status string, the status code, or <code>"<unknown status>"</code>.
function get_status_string(data)
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
    return (string.sub(data['status-line'], space + 1)):gsub('\r?\n', '')
  end
end

---Determine whether or not the server supports HEAD.
--
-- Tests by requesting / and verifying that it returns 200, and doesn't return
-- data. We implement the check like this because can't always rely on OPTIONS
-- to tell the truth.
--
-- Note: If <code>identify_404</code> returns a 200 status, HEAD requests
-- should be disabled. Sometimes, servers use a 200 status code with a message
-- explaining that the page wasn't found. In this case, to actually identify
-- a 404 page, we need the full body that a HEAD request doesn't supply.
-- This is determined automatically if the <code>result_404</code> field is
-- set.
--
-- @param host The host object.
-- @param port The port to use.
-- @param result_404 [optional] The result when an unknown page is requested.
--                   This is returned by <code>identify_404</code>. If the 404
--                   page returns a 200 code, then we disable HEAD requests.
-- @param path The path to request; by default, / is used.
-- @return A boolean value: true if HEAD is usable, false otherwise.
-- @return If HEAD is usable, the result of the HEAD request is returned (so
--         potentially, a script can avoid an extra call to HEAD)
function can_use_head(host, port, result_404, path)
  -- If the 404 result is 200, don't use HEAD.
  if(result_404 == 200) then
    return false
  end

  -- Default path
  if(path == nil) then
    path = '/'
  end

  -- Perform a HEAD request and see what happens.
  local data = head( host, port, path )
  if data then
    if data.status and data.status == 302 and data.header and data.header.location then
      stdnse.debug1("HTTP: Warning: Host returned 302 and not 200 when performing HEAD.")
      return false
    end

    if data.status and data.status == 200 and data.header then
      -- check that a body wasn't returned
      if #data.body > 0 then
        stdnse.debug1("HTTP: Warning: Host returned data when performing HEAD.")
        return false
      end

      stdnse.debug1("HTTP: Host supports HEAD.")
      return true, data
    end

    stdnse.debug1("HTTP: Didn't receive expected response to HEAD request (got %s).", get_status_string(data))
    return false
  end

  stdnse.debug1("HTTP: HEAD request completely failed.")
  return false
end

--- Try to remove anything that might change within a 404.
--
-- For example:
-- * A file path (includes URI)
-- * A time
-- * A date
-- * An execution time (numbers in general, really)
--
-- The intention is that two 404 pages from different URIs and taken hours
-- apart should, whenever possible, look the same.
--
-- During this function, we're likely going to over-trim things. This is fine
-- -- we want enough to match on that it'll a) be unique, and b) have the best
-- chance of not changing. Even if we remove bits and pieces from the file, as
-- long as it isn't a significant amount, it'll remain unique.
--
-- One case this doesn't cover is if the server generates a random haiku for
-- the user.
--
-- @param body The body of the page.
function clean_404(body)
  if ( not(body) ) then
    return
  end

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

local function cache_404_response(host, port, response)
  if type(host) == "table" and host.registry then
    host.registry.http_404 = host.registry.http_404 or {}
    local portnum = port
    if type(port) == "table" then
      portnum = port.number
    end
    host.registry.http_404[portnum] = response
  end
  return table.unpack(response)
end

---Try requesting a non-existent file to determine how the server responds to
-- unknown pages ("404 pages")
--
-- This tells us
-- * what to expect when a non-existent page is requested, and
-- * if the server will be impossible to scan.
--
-- If the server responds with a 404 status code, as it is supposed to, then
-- this function simply returns 404. If it contains one of a series of common
-- status codes, including unauthorized, moved, and others, it is returned like
-- a 404.
--
-- I (Ron Bowes) have observed one host that responds differently for three
-- scenarios:
-- * A non-existent page, all lowercase (a login page)
-- * A non-existent page, with uppercase (a weird error page that says,
--   "Filesystem is corrupt.")
-- * A page in a non-existent directory (a login page with different font
--   colours)
--
-- As a result, I've devised three different 404 tests, one to check each of
-- these conditions. They all have to match, the tests can proceed; if any of
-- them are different, we can't check 404s properly.
--
-- @param host The host object.
-- @param port The port to which we are establishing the connection.
-- @return status Did we succeed?
-- @return result If status is false, result is an error message. Otherwise,
--                it's the code to expect (typically, but not necessarily,
--                '404').
-- @return body Body is a hash of the cleaned-up body that can be used when
--              detecting a 404 page that doesn't return a 404 error code.
function identify_404(host, port)
  if type(host) == "table" and host.registry and host.registry.http_404 then
    local portnum = port
    if type(port) == "table" then
      portnum = port.number
    end
    local result = host.registry.http_404[portnum]
    if result then
      return table.unpack(result)
    end
  end
  local data
  local bad_responses = { 301, 302, 400, 401, 403, 499, 501, 503 }

  -- The URLs used to check 404s
  local URL_404_1 = '/nmaplowercheck' .. os.time(os.date('*t'))
  local URL_404_2 = '/NmapUpperCheck' .. os.time(os.date('*t'))
  local URL_404_3 = '/Nmap/folder/check' .. os.time(os.date('*t'))

  data = get(host, port, URL_404_1,{redirect_ok=false})
  if(data == nil) then
    stdnse.debug1("HTTP: Failed while testing for 404 status code")
    -- do not cache; maybe it will work next time?
    return false, "Failed while testing for 404 error message"
  end

  if(data.status and data.status == 404) then
    stdnse.debug1("HTTP: Host returns proper 404 result.")
    return cache_404_response(host, port, {true, 404})
  end

  if(data.status and data.status == 200) then
    stdnse.debug1("HTTP: Host returns 200 instead of 404.")

    -- Clean up the body (for example, remove the URI). This makes it easier to validate later
    if(data.body) then
      -- Obtain a couple more 404 pages to test different conditions
      local data2 = get(host, port, URL_404_2)
      local data3 = get(host, port, URL_404_3)
      if(data2 == nil or data3 == nil) then
        stdnse.debug1("HTTP: Failed while testing for extra 404 error messages")
        -- do not cache; maybe it will work next time?
        return false, "Failed while testing for extra 404 error messages"
      end

      -- Check if the return code became something other than 200.
      -- Status code: -1 represents unknown.
      -- If the status is nil or the string "unknown" we switch to -1.
      if(data2.status ~= 200) then
        if(type(data2.status) ~= "number") then
          data2.status = -1
        end
        stdnse.debug1("HTTP: HTTP 404 status changed for second request (became %d).", data2.status)
        return cache_404_response(host, port, {false,
            string.format("HTTP 404 status changed for second request (became %d).", data2.status)
          })
      end

      -- Check if the return code became something other than 200
      if(data3.status ~= 200) then
        if(type(data3.status) ~= "number") then
          data3.status = -1
        end
        stdnse.debug1("HTTP: HTTP 404 status changed for third request (became %d).", data3.status)
        return cache_404_response(host, port, {false,
            string.format("HTTP 404 status changed for third request (became %d).", data3.status)
          })
      end

      -- Check if the returned bodies (once cleaned up) matches the first returned body
      local clean_body  = clean_404(data.body)
      local clean_body2 = clean_404(data2.body)
      local clean_body3 = clean_404(data3.body)
      if(clean_body ~= clean_body2) then
        stdnse.debug1("HTTP: Two known 404 pages returned valid and different pages; unable to identify valid response.")
        stdnse.debug1("HTTP: If you investigate the server and it's possible to clean up the pages, please post to nmap-dev mailing list.")
        return cache_404_response(host, port, {false,
            "Two known 404 pages returned valid and different pages; unable to identify valid response."
          })
      end

      if(clean_body ~= clean_body3) then
        stdnse.debug1("HTTP: Two known 404 pages returned valid and different pages; unable to identify valid response (happened when checking a folder).")
        stdnse.debug1("HTTP: If you investigate the server and it's possible to clean up the pages, please post to nmap-dev mailing list.")
        return cache_404_response(host, port, {false,
            "Two known 404 pages returned valid and different pages; unable to identify valid response (happened when checking a folder)."
          })
      end

      cache_404_response(host, port, {true, 200, clean_body})
      return true, 200, clean_body
    end

    stdnse.debug1("HTTP: The 200 response didn't contain a body.")
    return cache_404_response(host, port, {true, 200})
  end

  -- Loop through any expected error codes
  for _,code in pairs(bad_responses) do
    if(data.status and data.status == code) then
      stdnse.debug1("HTTP: Host returns %s instead of 404 File Not Found.", get_status_string(data))
      return cache_404_response(host, port, {true, code})
    end
  end

  stdnse.debug1("Unexpected response returned for 404 check: %s", get_status_string(data))

  return cache_404_response(host, port, {true, data.status})
end

--- Determine whether or not the page that was returned is a 404 page.
--
-- This is actually a pretty simple function, but it's best to keep this logic
-- close to <code>identify_404</code>, since they will generally be used
-- together.
--
-- @param data The data returned by the HTTP request
-- @param result_404 The status code to expect for non-existent pages. This is
--                   returned by <code>identify_404</code>.
-- @param known_404 The 404 page itself, if <code>result_404</code> is 200. If
--                  <code>result_404</code> is something else, this parameter
--                  is ignored and can be set to <code>nil</code>. This is
--                  returned by <code>identify_404</code>.
-- @param page The page being requested (used in error messages).
-- @param displayall [optional] If set to true, don't exclude non-404 errors
--                   (such as 500).
-- @return A boolean value: true if the page appears to exist, and false if it
--         does not.
function page_exists(data, result_404, known_404, page, displayall)
  if(data and data.status) then
    -- Handle the most complicated case first: the "200 Ok" response
    if(data.status == 200) then
      if(result_404 == 200) then
        -- If the 404 response is also "200", deal with it (check if the body matches)
        if(#data.body == 0) then
          -- I observed one server that returned a blank string instead of an error, on some occasions
          stdnse.debug1("HTTP: Page returned a totally empty body; page likely doesn't exist")
          return false
        elseif(clean_404(data.body) ~= known_404) then
          stdnse.debug1("HTTP: Page returned a body that doesn't match known 404 body, therefore it exists (%s)", page)
          return true
        else
          return false
        end
      else
        -- If 404s return something other than 200, and we got a 200, we're good to go
        stdnse.debug1("HTTP: Page was '%s', it exists! (%s)", get_status_string(data), page)
        return true
      end
    else
      -- If the result isn't a 200, check if it's a 404 or returns the same code as a 404 returned
      if(data.status ~= 404 and data.status ~= result_404) then
        -- If this check succeeded, then the page isn't a standard 404 -- it could be a redirect, authentication request, etc. Unless the user
        -- asks for everything (with a script argument), only display 401 Authentication Required here.
        stdnse.debug1("HTTP: Page didn't match the 404 response (%s) (%s)", get_status_string(data), page)

        if(data.status == 401) then -- "Authentication Required"
          return true
        elseif(displayall) then
          return true
        end

        return false
      else
        -- Page was a 404, or looked like a 404
        return false
      end
    end
  else
    stdnse.debug1("HTTP: HTTP request failed (is the host still up?)")
    return false
  end
end

---Check if the response variable contains the given text.
--
-- Response variable could be a return from a http.get, http.post,
-- http.pipeline_go, etc. The text can be:
-- * Part of a header ('content-type', 'text/html', '200 OK', etc)
-- * An entire header ('Content-type: text/html', 'Content-length: 123', etc)
-- * Part of the body
--
-- The search text is treated as a Lua pattern.
--
--@param response The full response table from a HTTP request.
--@param pattern The pattern we're searching for. Don't forget to escape '-',
--               for example, 'Content%-type'. The pattern can also contain
--               captures, like 'abc(.*)def', which will be returned if
--               successful.
--@param case_sensitive [optional] Set to <code>true</code> for case-sensitive
--                      searches. Default: not case sensitive.
--@return result True if the string matched, false otherwise
--@return matches An array of captures from the match, if any
function response_contains(response, pattern, case_sensitive)
  local result, _
  local m = {}

  -- If they're searching for the empty string or nil, it's true
  if(pattern == '' or pattern == nil) then
    return true
  end

  -- Create a function that either lowercases everything or doesn't, depending on case sensitivity
  local case = function(pattern) return string.lower(pattern or '') end
  if(case_sensitive == true) then
    case = function(pattern) return (pattern or '') end
  end

  -- Set the case of the pattern
  pattern = case(pattern)

  -- Check the status line (eg, 'HTTP/1.1 200 OK')
  m = {string.match(case(response['status-line']), pattern)};
  if(m and #m > 0) then
    return true, m
  end

  -- Check the headers
  for _, header in pairs(response['rawheader']) do
    m = {string.match(case(header), pattern)}
    if(m and #m > 0) then
      return true, m
    end
  end

  -- Check the body
  m = {string.match(case(response['body']), pattern)}
  if(m and #m > 0) then
    return true, m
  end

  return false
end

---This function should be called whenever a valid path (a path that doesn't
-- contain a known 404 page) is discovered.
--
-- It will add the path to the registry in several ways, allowing other scripts
-- to take advantage of it in interesting ways.
--
--@param host The host the path was discovered on (not necessarily the host
--            being scanned).
--@param port The port the path was discovered on (not necessarily the port
--            being scanned).
--@param path The path discovered. Calling this more than once with the same
--            path is okay; it'll update the data as much as possible instead
--            of adding a duplicate entry
--@param status [optional] The status code (200, 404, 500, etc). This can be
--              left off if it isn't known.
--@param links_to [optional] A table of paths that this page links to.
--@param linked_from [optional] A table of paths that link to this page.
--@param contenttype [optional] The content-type value for the path, if it's known.
function save_path(host, port, path, status, links_to, linked_from, contenttype)
  -- Make sure we have a proper hostname and port
  host = stdnse.get_hostname(host)
  if(type(port) == 'table') then
    port = port['number']
  end

  -- Parse the path
  local parsed = url.parse(path)

  -- contains both query and fragment
  parsed['raw_querystring'] = parsed['query']

  if parsed['fragment'] then
    parsed['raw_querystring'] = ( parsed['raw_querystring'] or "" ) .. '#' .. parsed['fragment']
  end

  if parsed['raw_querystring'] then
    parsed['path_query'] = parsed['path'] .. '?' .. parsed['raw_querystring']
  else
    parsed['path_query'] = parsed['path']
  end

  -- Split up the query, if necessary
  if(parsed['raw_querystring']) then
    parsed['querystring'] = {}
    local values = stdnse.strsplit('&', parsed['raw_querystring'])
    for i, v in ipairs(values) do
      local name, value = table.unpack(stdnse.strsplit('=', v))
      parsed['querystring'][name] = value
    end
  end

  -- Add to the 'all_pages' key
  stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'all_pages'}, parsed['path'])

  -- Add the URL with querystring to all_pages_full_query
  stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'all_pages_full_query'}, parsed['path_query'])

  -- Add the URL to a key matching the response code
  if(status) then
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'status_codes', status}, parsed['path'])
  end

  -- If it's a directory, add it to the directories list; otherwise, add it to the files list
  if(parsed['is_folder']) then
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'directories'}, parsed['path'])
  else
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'files'}, parsed['path'])
  end


  -- If we have an extension, add it to the extensions key
  if(parsed['extension']) then
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'extensions', parsed['extension']}, parsed['path'])
  end

  -- Add an entry for the page and its arguments
  if(parsed['querystring']) then
    -- Add all scripts with a querystring to the 'cgi' and 'cgi_full_query' keys
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'cgi'}, parsed['path'])
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'cgi_full_query'}, parsed['path_query'])

    -- Add the query string alone to the registry (probably not necessary)
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'cgi_querystring', parsed['path'] }, parsed['raw_querystring'])

    -- Add the individual arguments for the page, along with their values
    for key, value in pairs(parsed['querystring']) do
      stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'cgi_args', parsed['path']}, parsed['querystring'])
    end
  end

  -- Save the pages it links to
  if(links_to) then
    if(type(links_to) == 'string') then
      links_to = {links_to}
    end

    for _, v in ipairs(links_to) do
      stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'links_to', parsed['path_query']}, v)
    end
  end

  -- Save the pages it's linked from (we save these in the 'links_to' key, reversed)
  if(linked_from) then
    if(type(linked_from) == 'string') then
      linked_from = {linked_from}
    end

    for _, v in ipairs(linked_from) do
      stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'links_to', v}, parsed['path_query'])
    end
  end

  -- Save it as a content-type, if we have one
  if(contenttype) then
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'content-type', contenttype}, parsed['path_query'])
  end
end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

do
  local cookie_tests = {
    { -- #844
      " SESSIONID=IgAAABjN8b3xxxNsLRIiSpHLPn1lE=&IgAAAxxxMT6Bw==&Huawei USG6320&langfrombrows=en-US&copyright=2014;secure", {
        name = "SESSIONID",
        value = "IgAAABjN8b3xxxNsLRIiSpHLPn1lE=&IgAAAxxxMT6Bw==&Huawei USG6320&langfrombrows=en-US&copyright=2014",
        secure = true
      }
    },
    { -- #866
      " SID=c98fefa3ad659caa20b89582419bb14f; Max-Age=1200; Version=1", {
        name = "SID",
        value = "c98fefa3ad659caa20b89582419bb14f",
        ["max-age"] = "1200",
        version = "1"
      }
    },
    { -- #731
      "session_id=76ca8bc8c19;", {
        name = "session_id",
        value = "76ca8bc8c19"
        }
    },
    { -- #229
      "c1=aaa; path=/bbb/ccc,ddd/eee", {
        name = "c1",
        value = "aaa",
        path = "/bbb/ccc,ddd/eee"
      }
    },
  }

  for _, test in ipairs(cookie_tests) do
    local parsed = parse_set_cookie(test[1])
    test_suite:add_test(unittest.keys_equal(parsed, test[2], test[1]))
  end
end

return _ENV;
