---
-- Functions for proxy testing.
--
-- @author Joao Correa <joao@livewire.com.br>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local bin = require "bin"
local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("proxy", stdnse.seeall)

-- Start of local functions

--- check function, checks for all valid returned status
--- If any of the HTTP status below is found, the proxy is potentially open
--- The script tries to split header from body before checking for status
--@param result connection result
--@return true if any of the status is found, otherwise false
local function check_code(result)
  if result then
    local header
    if result:match( "\r?\n\r?\n" ) then
      result = result:match( "^(.-)\r?\n\r?\n(.*)$" )
    end
    if result:lower():match("^http/%d%.%d%s*200") then return true end
    if result:lower():match("^http/%d%.%d%s*30[12]") then return true end
  end
  return false
end

--- check pattern, searches a pattern inside a response with multiple lines
--@param result Connection result
--@param pattern The pattern to be searched
--@return true if pattern is found, otherwise false
local function check_pattern(result, pattern)
  local lines = stdnse.strsplit("\n", result)
  for i, line in ipairs(lines) do
    if line:lower():match(pattern:lower()) then return true end
  end
  return false
end

--- check, decides what kind of check should be done on the response,
--- depending if a specific pattern is being used
--@param result Connection result
--@param pattern The pattern that should be checked (must be false, in case of
--code check)
--@return true, if the performed check returns true, otherwise false
local function check(result, pattern)
  local s_pattern = false
  local s_code = check_code(result)
  if s_code and pattern then
    s_pattern = check_pattern(result, pattern)
  end
  return s_code, s_pattern
end

--- Performs a request to the web server and calls check to check if
--  the response is a valid result
--
--@param socket The socket to send the request through
--@param req  The request to be sent
--@param pattern The pattern to check for valid result
--@return check_status True or false. If pattern was used, depends on pattern check result. If not, depends on code check result.
--@return result The result of the request
--@return code_status True or false. If pattern was used, returns the result of code checking for the same result. If pattern was not used, is nil.
local function test(socket, req, pattern)
  local status, result = socket:send(req)
  if not status then
    socket:close()
    return false, result
  end
  status, result = socket:receive()
  if not status then
    socket:close()
    return false, result
  end
  socket:close()
  local s_code, s_pattern = check(result, pattern)
  if result and pattern then return s_pattern, result, s_code end
  if result then return s_code, result, nil end
  return false, nil, nil
end

--- Builds the GET request and calls test
-- @param host The host table
-- @param port The port table
-- @param proxyType The proxy type to be tested, might be 'socks4', 'socks5' or 'http'
-- @param test_url The url to send the request
-- @param hostname The hostname of the server to send the request
-- @param pattern The pattern to check for valid result
-- @return the result of the function test (status and the request result)
function test_get(host, port, proxyType, test_url, hostname, pattern)
  local status, socket = connectProxy(host, port, proxyType, hostname)
  if not status then
    return false, socket
  end
  local req = "GET " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
  stdnse.debug1("GET Request: " .. req)
  return test(socket, req, pattern)
end

--- Builds the HEAD request and calls test
-- @param host The host table
-- @param port The port table
-- @param proxyType The proxy type to be tested, might be 'socks4', 'socks5' or 'http'
-- @param test_url The url te send the request
-- @param hostname The hostname of the server to send the request
-- @param pattern The pattern to check for valid result
-- @return the result of the function test (status and the request result)
function test_head(host, port, proxyType, test_url, hostname, pattern)
  local status, socket = connectProxy(host, port, proxyType, hostname)
  if not status then
    return false, socket
  end
  local req = "HEAD " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
  stdnse.debug1("HEAD Request: " .. req)
  return test(socket, req, pattern)
end

--- Builds the CONNECT request and calls test
-- @param host The host table
-- @param port The port table
-- @param proxyType The proxy type to be tested, might be 'socks4', 'socks5' or 'http'
-- @param hostname The hostname of the server to send the request
-- @return the result of the function test (status and the request result)
function test_connect(host, port, proxyType, hostname)
  local status, socket = connectProxy(host, port, proxyType, hostname)
  if not status then
    return false, socket
  end
  local req = "CONNECT " .. hostname .. ":80 HTTP/1.0\r\n\r\n"
  stdnse.debug1("CONNECT Request: " .. req)
  return test(socket, req, false)
end

--- Function that resolves IP address for hostname and
--- returns it as hex values
--@param hostname Hostname to resolve
--@return Ip address of hostname in hex
function hex_resolve(hostname)
  local a, b, c, d;
  local dns_status, ip = dns.query(hostname)
  if not dns_status then
    return false
  end
  local t, err = ipOps.get_parts_as_number(ip)
  if t and not err
    then a, b, c, d = table.unpack(t)
    else return false
  end
  local sip = string.format("%.2x ", a) .. string.format("%.2x ", b) .. string.format("%.2x ", c) .. string.format("%.2x ",d)
  return true, sip
end

--- Checks if any parameter was used in old or new syntax
--  and return the parameters
--  @return url the proxy.url parameter
--  @return pattern the proxy.pattern parameter
function return_args()
  local url = false
  local pattern = false
  if nmap.registry.args['proxy.url']
    then url = nmap.registry.args['proxy.url']
  elseif nmap.registry.args.proxy and nmap.registry.args.proxy.url
    then url = nmap.registry.args.proxy.url
  end
  if nmap.registry.args['proxy.pattern']
    then pattern = nmap.registry.args['proxy.pattern']
  elseif nmap.registry.args.proxy and nmap.registry.args.proxy.url
    then pattern = nmap.registry.args.proxy.pattern
  end
  return url, pattern
end

--- Creates a socket, performs proxy handshake if necessary
--- and returns it
--  @param host The host table
--  @param port The port table
--  @param proxyType A string with the proxy type. Might be "http","socks4" or "socks5"
--  @param hostname The proxy destination hostname
--  @return status True if handshake succeeded, false otherwise
--  @return socket A socket with the handshake already done, or an error if
function connectProxy(host, port, proxyType, hostname)
  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local status, err = socket:connect(host, port)
  if not status then
    socket:close()
    return false, err
  end
  if proxyType == "http" then return true, socket end
  if proxyType == "socks4" then return socksHandshake(socket, 4, hostname) end
  if proxyType == "socks5" then return socksHandshake(socket, 5, hostname) end
  socket:close()
  return false, "Invalid proxyType"
end

--- Performs a socks handshake on a socket and returns it
--  @param socket The socket where the handshake will be performed
--  @param version The socks version (might be 4 or 5)
--  @param hostname The proxy destination hostname
--  @return status True if handshake succeeded, false otherwise
--  @return socket A socket with the handshake already done, or an error if
--                 status is false
function socksHandshake(socket, version, hostname)
  local resolve, sip, paystring, payload
  resolve, sip = hex_resolve(hostname)
  if not resolve then
    return false, "Unable to resolve hostname"
  end
  if version == 4 then
    paystring = '04 01 00 50 ' .. sip .. ' 6e 6d 61 70 00'
    payload = bin.pack("H",paystring)
    local status, response = socket:send(payload)
    if not status then
      socket:close()
      return false, response
    end
    status, response = socket:receive()
    if not status then
      socket:close()
      return false, response
    end
    if #response < 2 then
      socket:close()
      return false, "Invalid or unknown SOCKS response"
    end
    local request_status = string.byte(response, 2)
    local err = string.format("Unknown response (0x%02x)", request_status)
    if(request_status == 0x5a) then
      stdnse.debug1('Socks4: Received "Request Granted" from proxy server')
      return true, socket
    end
    if(request_status == 0x5b) then
      err = "Request rejected or failed"
    elseif (request_status == 0x5c) then
      err = "request failed because client is not running identd"
    elseif (request_status == 0x5d) then
      err = "request failed because client program and identd report different user-ids"
    end
    stdnse.debug1('Socks4: Received "%s" from proxy server', err)
    return false, err
  end
  if version == 5 then
    local payload = bin.pack("H",'05 01 00')
    local status, err = socket:send(payload)
    if not status then
      socket:close()
      return false, err
    end
    local auth
    status, auth = socket:receive()
    local r2 = string.byte(auth,2)

    -- If Auth is required, proxy is closed, skip next test
    if(r2 ~= 0x00) then
      err = "Authentication Required"
    else
      -- If no Auth is required, try to establish connection
      stdnse.debug1("Socks5: No authentication required")
      -- Socks5 second payload: Version, Command, Null, Address type, Ip-Address, Port number
      paystring = '05 01 00 01 ' .. sip .. '00 50'
      payload = bin.pack("H",paystring)
      status, err = socket:send(payload)
      if not status then
        socket:close()
        return false, err
      end
      local z
      status, z = socket:receive()
      if not status then
        socket:close()
        return false, z
      end
      local request_status = string.byte(z, 2)
      err = string.format("Unknown response (0x%02x)", request_status)
      if (request_status == 0x00) then
        stdnse.debug1('Socks5: Received "Request Granted" from proxy server')
        return true, socket
      elseif(request_status == 0x01) then
        err = "General Failure"
      elseif (request_status == 0x02) then
        err = "Connection not allowed by ruleset"
      elseif (request_status == 0x03) then
        err = "Network unreachable"
      elseif (request_status == 0x04) then
        err = "Host unreachable"
      elseif (request_status == 0x05) then
        err = "Connection refused by destination host"
      elseif (request_status == 0x06) then
        err = "TTL Expired"
      elseif (request_status == 0x07) then
        err = "command not supported / protocol error"
      elseif (request_status == 0x08) then
        err = "Address type not supported"
      end
    end
    stdnse.debug1('Socks5: Received "%s" from proxy server', err)
    return false, err
  end
  return false, "Invalid SOCKS version"
end

--- Checks if two different responses are equal,
--  if true, the proxy server might be redirecting the requests
--  to a default page
--
--  Functions splits body from head before comparing, to avoid session
--  variables, cookies...
--
--  @param resp1 A string with the response for the first request
--  @param resp2 A string with the response for the second request
--  @return bool true if both responses are equal, otherwise false
function redirectCheck(resp1, resp2)
  local body1, body2, _
  if resp1:match( "\r?\n\r?\n" ) then
    local body1
    _, body1 = resp1:match( "^(.-)\r?\n\r?\n(.*)$" )
    if resp2:match( "\r?\n\r?\n" ) then
      _, body2 = resp2:match( "^(.-)\r?\n\r?\n(.*)$" )
      if body1 == body2 then
        return true
      end
    end
  end
  return false
end

return _ENV;
