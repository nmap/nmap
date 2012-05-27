---
-- Functions for proxy testing.
--
-- @author Joao Correa <joao@livewire.com.br>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local bin = require "bin"
local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("proxy", stdnse.seeall)

-- Start of local functions

--- check function, makes checkings for all valid returned status
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
  local _, result, s_code, s_pattern
  socket:send(req)
  _, result = socket:receive()
  socket:close()
  s_code, s_pattern = check(result, pattern)
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
  local socket = connectProxy(host, port, proxyType, hostname)
  if not socket then return false end
  local req = "GET " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
  stdnse.print_debug("GET Request: " .. req)
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
  local socket = connectProxy(host, port, proxyType, hostname)
  if not socket then return false end
  local req = "HEAD " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
  stdnse.print_debug("HEAD Request: " .. req)
  return test(socket, req, pattern)
end

--- Builds the CONNECT request and calls test
-- @param host The host table
-- @param port The port table
-- @param proxyType The proxy type to be tested, might be 'socks4', 'socks5' or 'http'
-- @param hostname The hostname of the server to send the request
-- @return the result of the function test (status and the request result)
function test_connect(host, port, proxyType, hostname)
  local socket = connectProxy(host, port, proxyType, hostname)
  if not socket then return false end
  local req = "CONNECT " .. hostname .. ":80 HTTP/1.0\r\n\r\n"
  stdnse.print_debug("CONNECT Request: " .. req)
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
--  @return socket A socket with the handshake already done
function connectProxy(host, port, proxyType, hostname)
  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local try = nmap.new_try(function() socket:close() return false end)
  try(socket:connect(host, port))
  if proxyType == "http" then return socket end
  if proxyType == "socks4" then return socksHandshake(socket, 4, hostname) end
  if proxyType == "socks5" then return socksHandshake(socket, 5, hostname) end
  return false
end

--- Performs a socks handshake on a socket and returns it
--  @param socket The socket where the handshake will be performed
--  @param version The socks version (might be 4 or 5)
--  @param hostname The proxy destination hostname
--  @return socket A socket with the handshake already done
function socksHandshake(socket, version, hostname)
  local resolve, sip, paystring, payload
  resolve, sip = hex_resolve(hostname)
  local try = nmap.new_try(function() socket:close() return false end)
  if not resolve then
    stdnse.print_debug("Unable to resolve hostname.")
    return false
  end
  if version == 4 then
    paystring = '04 01 00 50 ' .. sip .. ' 6e 6d 61 70 00'
    payload = bin.pack("H",paystring) 
    try(socket:send(payload))
    local response = try(socket:receive())
    local request_status = string.byte(response, 2)
    if(request_status == 0x5a) then
      stdnse.print_debug("Socks4: Received \"Request Granted\" from proxy server\n")
      return socket
    end
    if(request_status == 0x5b) then 
      stdnse.print_debug("Socks4: Received \"Request rejected or failed\" from proxy server")
    elseif (request_status == 0x5c) then 
      stdnse.print_debug("Socks4: Received \"request failed because client is not running identd\" from proxy server")
    elseif (request_status == 0x5d) then 
      stdnse.print_debug("Socks4: Received \"request failed because client's identd could not confirm" ..
      			 "\nthe user ID string in the request from proxy server")
    end
    return false
  end
  if version == 5 then
    local payload = bin.pack("H",'05 01 00')
    try(socket:send(payload))
    local auth = try(socket:receive())
    local r2 = string.byte(auth,2)
	
    -- If Auth is required, proxy is closed, skip next test
    if(r2 ~= 0x00) then 
      stdnse.print_debug("Socks5: Authentication required")
    else
      -- If no Auth is required, try to estabilish connection
      stdnse.print_debug("Socks5: No authentication required")
      -- Socks5 second payload: Version, Command, Null, Address type, Ip-Address, Port number	
      paystring = '05 01 00 01 ' .. sip .. '00 50'
      payload = bin.pack("H",paystring)	
      try(socket:send(payload))
      local z = try(socket:receive())	
      local request_status = string.byte(z, 2)
      if (request_status == 0x00) then
	stdnse.print_debug("Socks5: Received \"Request Granted\" from proxy server\n")
	return socket
      elseif(request_status == 0x01) then 
	stdnse.print_debug("Socks5: Received \"General failure\" from proxy server")
      elseif (request_status == 0x02) then 
	stdnse.print_debug("Socks5: Received \"Connection not allowed by ruleset\" from proxy server")
      elseif (request_status == 0x03) then 
	stdnse.print_debug("Socks5: Received \"Network unreachable\" from proxy server")
      elseif (request_status == 0x04) then 
	stdnse.print_debug("Socks5: Received \"Host unreachable\" from proxy server")
      elseif (request_status == 0x05) then 
	stdnse.print_debug("Socks5: Received \"Connection refused by destination host\" from proxy server")
      elseif (request_status == 0x06) then 
	stdnse.print_debug("Socks5: Received \"TTL Expired\" from proxy server")
      elseif (request_status == 0x07) then
	stdnse.print_debug("Socks5: Received \"command not supported / protocol error\" from proxy server")
      elseif (request_status == 0x08) then
	stdnse.print_debug("Socks5: Received \"Address type not supported\" from proxy server")
      end
    end
    return false
  end			
  stdnse.print_debug("Unrecognized proxy type");
  return false
end

--- Checks if two different responses are equal,
--  if true, the proxy server might be redirecting the requests
--  to a default page
--
--  Functions slipts body from head before comparing, to avoid session
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
